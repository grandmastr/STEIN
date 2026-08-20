use std::collections::BTreeSet;
use std::fs;
use std::future::Future;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value as JsonValue;
use stein_core::{
    ActorId, AuditKind, AuditRecord, AuditRecordId, CandidateId, ClientId, DataCategory, DeviceId,
    DurableRepository, EvidenceRole, EvidenceSummary, ExplicitPreferences, FocusSession,
    FocusSessionId, FocusSessionState, Goal, GoalCreateReceipt, GoalId, GoalState, GrantState,
    IdempotencyKey, Intervention, InterventionDecisionWrite, InterventionId, InterventionOutcome,
    InterventionState, InterventionTone, ModelHandlingProfile, ModelPlacement, ModelRouteApproval,
    ModelRouteApprovalId, NativeResourceCleanup, OperationKind, OperationReceipt, OutboxEntryId,
    OutboxState, PendingInterventionDelivery, PermissionGrant, PermissionGrantId, PermissionScope,
    PolicyDecision, PolicyDecisionId, PolicyOutcome, ProviderRetentionPolicy, ProviderTrainingUse,
    RepositoryErrorKind, ResourceBinding, ResourceId, ResourceKind, Revision, SecretKey,
    SteinIdentity, USER_PREFERENCES_SCHEMA_V1, Urgency,
};
use stein_store_sqlite::SqliteRepository;
use tempfile::tempdir;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const UUID_BASE: u128 = 0x0198_0000_0000_7000_8000_0000_0000_0000;

fn uuid(offset: u128) -> Uuid {
    Uuid::from_u128(UUID_BASE + offset)
}

fn actor() -> ActorId {
    ActorId::from_uuid(uuid(0x101))
}

fn other_actor() -> ActorId {
    ActorId::from_uuid(uuid(0x102))
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn run_repository_future<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the SQLite repository future unexpectedly yielded"),
    }
}

fn goal_for(owner: ActorId, offset: u128) -> (Goal, GoalCreateReceipt) {
    let id = GoalId::from_uuid(uuid(offset + 1));
    let key = IdempotencyKey::from_uuid(uuid(offset + 2));
    let goal = Goal {
        id,
        owner,
        title: "Prepare the synthetic release".to_owned(),
        success_statement: "The deterministic acceptance ledger is green.".to_owned(),
        deadline: Some(now() + Duration::hours(1)),
        state: GoalState::Active,
        revision: Revision::INITIAL,
        created_at: now(),
        updated_at: now(),
    };
    let receipt = GoalCreateReceipt {
        actor: owner,
        idempotency_key: key,
        goal_id: id,
        title: goal.title.clone(),
        success_statement: goal.success_statement.clone(),
        deadline: goal.deadline,
    };
    (goal, receipt)
}

fn creation_audit(
    owner: ActorId,
    id_offset: u128,
    kind: AuditKind,
    subject_id: Uuid,
) -> AuditRecord {
    AuditRecord {
        id: AuditRecordId::from_uuid(uuid(id_offset)),
        owner,
        kind,
        subject_id,
        correlation_id: uuid(id_offset + 1),
        reason_codes: vec!["synthetic_creation".to_owned()],
        evidence_categories: BTreeSet::new(),
        evidence_age_ms: None,
        confidence_basis_points: None,
        occurred_at: now(),
        expires_at: now() + Duration::days(30),
    }
}

#[derive(Clone)]
struct SyntheticGraph {
    identity: SteinIdentity,
    preferences: ExplicitPreferences,
    goal: Goal,
    receipt: GoalCreateReceipt,
    resource: ResourceBinding,
    route: ModelRouteApproval,
    route_receipt: OperationReceipt,
    route_audit: AuditRecord,
    initial_grants: Vec<PermissionGrant>,
    grant_receipts: Vec<OperationReceipt>,
    grant_audits: Vec<AuditRecord>,
    bound_grants: Vec<PermissionGrant>,
    session: FocusSession,
    start_receipt: OperationReceipt,
    start_audit: AuditRecord,
    policy: PolicyDecision,
    decision_audit: AuditRecord,
    intervention: Intervention,
    delivery: PendingInterventionDelivery,
}

fn synthetic_graph(owner: ActorId, offset: u128) -> SyntheticGraph {
    let (goal, receipt) = goal_for(owner, offset);
    let resource_id = ResourceId::from_uuid(uuid(offset + 3));
    let route_id = ModelRouteApprovalId::from_uuid(uuid(offset + 4));
    let session_id = FocusSessionId::from_uuid(uuid(offset + 5));
    let observation_grant_id = PermissionGrantId::from_uuid(uuid(offset + 6));
    let reasoning_grant_id = PermissionGrantId::from_uuid(uuid(offset + 7));
    let notification_grant_id = PermissionGrantId::from_uuid(uuid(offset + 8));
    let client_id = ClientId::from_uuid(uuid(offset + 9));
    let device_id = DeviceId::from_uuid(uuid(offset + 10));
    let policy_id = PolicyDecisionId::from_uuid(uuid(offset + 11));
    let intervention_id = InterventionId::from_uuid(uuid(offset + 12));
    let candidate_id = CandidateId::from_uuid(uuid(offset + 13));

    let resource = ResourceBinding {
        id: resource_id,
        owner,
        kind: ResourceKind::Application,
        opaque_reference: "synthetic-resource-token".to_owned(),
        display_label: "Synthetic editor".to_owned(),
        revision: 1,
        created_at: now(),
    };
    let route = ModelRouteApproval {
        id: route_id,
        revision: 1,
        owner,
        authenticated_client: client_id,
        provider: "synthetic-provider".to_owned(),
        account_profile: "synthetic-account".to_owned(),
        model: "synthetic-model".to_owned(),
        secret_ref: SecretKey::new("synthetic-provider-reference"),
        placement: ModelPlacement::Remote,
        allowed_categories: BTreeSet::from([
            DataCategory::Goal,
            DataCategory::FocusSession,
            DataCategory::EvidenceAggregates,
        ]),
        handling: ModelHandlingProfile {
            profile_id: "synthetic-handling-v1".to_owned(),
            retention: ProviderRetentionPolicy::Transient,
            training_use: ProviderTrainingUse::Excluded,
            data_residency: None,
            core_persists_prompt_or_response: false,
            tools_enabled: false,
        },
        purpose: "Evaluate a synthetic deadline fixture.".to_owned(),
        maximum_input_tokens: 8_000,
        maximum_output_tokens: 512,
        fallback: None,
        fallback_allowed: false,
        effective_at: now(),
        expires_at: Some(now() + Duration::days(30)),
        revoked_at: None,
        disclosure_version: "synthetic-disclosure-v1".to_owned(),
    };

    let make_grant = |id, scope, resource, placement| PermissionGrant {
        id,
        revision: 1,
        owner,
        goal_id: goal.id,
        authenticated_client: client_id,
        device_id,
        focus_session_id: None,
        scope,
        selected_resource_id: resource,
        model_route_approval_id: None,
        purpose: "Synthetic focus-session permission.".to_owned(),
        placement,
        client_disconnect_allowed: true,
        daemon_restart_allowed: true,
        issued_at: now(),
        effective_at: now(),
        expires_at: now() + Duration::hours(8),
        state: GrantState::Active,
        revoked_at: None,
        revocation_reason: None,
        consent_copy_version: "synthetic-consent-v1".to_owned(),
    };
    let initial_grants = vec![
        make_grant(
            observation_grant_id,
            PermissionScope::ObserveDesktopForegroundApplication,
            Some(resource_id),
            None,
        ),
        make_grant(
            reasoning_grant_id,
            PermissionScope::ReasonFocusContext,
            None,
            Some(ModelPlacement::Remote),
        ),
        make_grant(
            notification_grant_id,
            PermissionScope::InterveneDesktopNotification,
            None,
            None,
        ),
    ];
    let bound_grants = initial_grants
        .iter()
        .cloned()
        .map(|mut grant| {
            grant.revision = 2;
            grant.focus_session_id = Some(session_id);
            if grant.scope == PermissionScope::ReasonFocusContext {
                grant.model_route_approval_id = Some(route_id);
            }
            grant
        })
        .collect::<Vec<_>>();
    let grant_ids = bound_grants.iter().map(|grant| grant.id).collect();
    let session = FocusSession {
        id: session_id,
        revision: 1,
        owner,
        goal_id: goal.id,
        goal_revision: goal.revision.get(),
        state: FocusSessionState::Active,
        muted: false,
        source_degraded: false,
        client_disconnect_allowed: true,
        daemon_restart_allowed: true,
        permission_grant_ids: grant_ids,
        selected_resource_ids: BTreeSet::from([resource_id]),
        model_route_approval_id: route_id,
        requested_at: now(),
        started_at: Some(now() + Duration::seconds(1)),
        ended_at: None,
        updated_at: now() + Duration::seconds(1),
        failure_reason: None,
    };
    let policy = PolicyDecision {
        id: policy_id,
        candidate_id,
        candidate_revision: 1,
        owner,
        focus_session_id: session_id,
        outcome: PolicyOutcome::Allow,
        reason_codes: vec!["synthetic_deadline_risk".to_owned()],
        permission_grant_revisions: bound_grants
            .iter()
            .map(|grant| (grant.id, grant.revision))
            .collect(),
        model_route_revision: route.revision,
        channel: "windows.native_notification".to_owned(),
        policy_version: "phase2-focus-v1".to_owned(),
        issued_at: now() + Duration::seconds(2),
        expires_at: now() + Duration::seconds(32),
    };
    let intervention = Intervention {
        id: intervention_id,
        candidate_id,
        candidate_revision: 1,
        policy_decision_id: policy_id,
        revision: 1,
        owner,
        focus_session_id: session_id,
        goal_id: goal.id,
        state: InterventionState::Allowed,
        outcome: InterventionOutcome::Unacknowledged,
        user_visible_text: "Synthetic recommendation: choose an option.".to_owned(),
        reason_code: "synthetic_deadline_risk".to_owned(),
        evidence_summary: "Synthetic evidence is incomplete.".to_owned(),
        evidence: vec![EvidenceSummary {
            category: DataCategory::EvidenceAggregates,
            observed_from: now(),
            observed_until: now() + Duration::seconds(2),
            confidence_basis_points: 8_000,
            role: EvidenceRole::SupportsDeadlineRisk,
        }],
        urgency: Urgency::Normal,
        created_at: now() + Duration::seconds(2),
        expires_at: now() + Duration::minutes(15),
        updated_at: now() + Duration::seconds(2),
        delivery_channel: Some("windows.native_notification".to_owned()),
        delivered_at: None,
        outcome_at: None,
        correction_summary: None,
    };
    let delivery = PendingInterventionDelivery {
        id: OutboxEntryId::from_uuid(uuid(offset + 14)),
        owner,
        intervention_id,
        candidate_revision: 1,
        policy_decision_id: policy_id,
        permission_grant_ids: BTreeSet::from([notification_grant_id]),
        user_visible_text: intervention.user_visible_text.clone(),
        reason_code: intervention.reason_code.clone(),
        urgency: intervention.urgency,
        sensitivity: "personal".to_owned(),
        permitted_channels: BTreeSet::from(["windows.native_notification".to_owned()]),
        deduplication_key: uuid(offset + 15),
        state: OutboxState::Queued,
        attempt_count: 0,
        created_at: now() + Duration::seconds(2),
        not_before: now() + Duration::seconds(2),
        expires_at: now() + Duration::minutes(15),
        last_attempt_at: None,
    };
    let route_receipt = OperationReceipt {
        owner,
        kind: OperationKind::ApproveModelRoute,
        idempotency_key: IdempotencyKey::from_uuid(uuid(offset + 20)),
        request_digest: [1; 32],
        result_id: route_id.as_uuid(),
    };
    let grant_receipts = bound_grants
        .iter()
        .enumerate()
        .map(|(index, grant)| OperationReceipt {
            owner,
            kind: OperationKind::GrantSessionPermission,
            idempotency_key: IdempotencyKey::from_uuid(uuid(offset + 21 + index as u128)),
            request_digest: [u8::try_from(index + 2).unwrap(); 32],
            result_id: grant.id.as_uuid(),
        })
        .collect::<Vec<_>>();
    let grant_audits = bound_grants
        .iter()
        .enumerate()
        .map(|(index, grant)| {
            creation_audit(
                owner,
                offset + 32 + (index as u128 * 2),
                AuditKind::PermissionGranted,
                grant.id.as_uuid(),
            )
        })
        .collect::<Vec<_>>();
    let start_receipt = OperationReceipt {
        owner,
        kind: OperationKind::StartFocusSession,
        idempotency_key: IdempotencyKey::from_uuid(uuid(offset + 24)),
        request_digest: [5; 32],
        result_id: session_id.as_uuid(),
    };

    let decision_audit = AuditRecord {
        id: AuditRecordId::from_uuid(policy_id.as_uuid()),
        owner,
        kind: AuditKind::InterventionDecision,
        subject_id: candidate_id.as_uuid(),
        correlation_id: candidate_id.as_uuid(),
        reason_codes: policy.reason_codes.clone(),
        evidence_categories: BTreeSet::from([DataCategory::EvidenceAggregates]),
        evidence_age_ms: Some(1_000),
        confidence_basis_points: Some(8_000),
        occurred_at: policy.issued_at,
        expires_at: now() + Duration::days(30),
    };

    SyntheticGraph {
        identity: SteinIdentity::shipped_v1(owner, now()),
        preferences: ExplicitPreferences {
            intervention_tone: InterventionTone::Concise,
            default_focus_minutes: 30,
            maximum_interventions_per_session: 3,
            ..ExplicitPreferences::phase2_defaults(owner, now())
        },
        goal,
        receipt,
        resource,
        route,
        route_receipt,
        route_audit: creation_audit(
            owner,
            offset + 30,
            AuditKind::ModelRouteApproved,
            route_id.as_uuid(),
        ),
        initial_grants,
        grant_receipts,
        grant_audits,
        bound_grants,
        session,
        start_receipt,
        start_audit: creation_audit(
            owner,
            offset + 38,
            AuditKind::FocusSessionStateChanged,
            session_id.as_uuid(),
        ),
        policy,
        decision_audit,
        intervention,
        delivery,
    }
}

fn allow_decision_write(graph: &SyntheticGraph) -> InterventionDecisionWrite {
    InterventionDecisionWrite {
        decision: graph.policy.clone(),
        audit: graph.decision_audit.clone(),
        intervention: Some(graph.intervention.clone()),
        expected_intervention_revision: None,
    }
}

fn install_graph(
    repository: &SqliteRepository,
    graph: &SyntheticGraph,
    with_delivery: bool,
    with_audit: bool,
) {
    install_graph_foundation(repository, graph);
    run_repository_future(repository.commit_intervention_decision(&allow_decision_write(graph)))
        .unwrap();
    if with_delivery {
        repository.enqueue_delivery(&graph.delivery).unwrap();
    }
    if with_audit {
        append_graph_audit(repository, graph);
    }
}

fn install_graph_foundation(repository: &SqliteRepository, graph: &SyntheticGraph) {
    repository.save_identity(&graph.identity, None).unwrap();
    repository
        .save_preferences(&graph.preferences, None)
        .unwrap();
    repository.create_goal(&graph.goal, &graph.receipt).unwrap();
    repository.save_resource(&graph.resource).unwrap();
    repository
        .create_model_route(&graph.route, &graph.route_receipt, &graph.route_audit)
        .unwrap();
    for ((grant, receipt), audit) in graph
        .initial_grants
        .iter()
        .zip(&graph.grant_receipts)
        .zip(&graph.grant_audits)
    {
        repository.create_grant(grant, receipt, audit).unwrap();
    }
    let bound = graph
        .bound_grants
        .iter()
        .cloned()
        .map(|grant| (grant, 1))
        .collect::<Vec<_>>();
    repository
        .bind_grants_and_create_focus_session(
            &graph.session,
            &bound,
            &graph.start_receipt,
            &graph.start_audit,
        )
        .unwrap();
}

fn append_graph_audit(repository: &SqliteRepository, graph: &SyntheticGraph) {
    let subjects = std::iter::once(graph.goal.id.as_uuid())
        .chain(std::iter::once(graph.resource.id.as_uuid()))
        .chain(graph.bound_grants.iter().map(|grant| grant.id.as_uuid()))
        .chain(std::iter::once(graph.session.id.as_uuid()))
        .chain(std::iter::once(graph.policy.id.as_uuid()))
        .chain(std::iter::once(graph.intervention.id.as_uuid()));
    for (index, subject_id) in subjects.enumerate() {
        repository
            .append_audit(&AuditRecord {
                id: AuditRecordId::from_uuid(uuid(0x900 + index as u128)),
                owner: graph.goal.owner,
                kind: AuditKind::InterventionDecision,
                subject_id,
                correlation_id: uuid(0xa00 + index as u128),
                reason_codes: vec!["synthetic_audit".to_owned()],
                evidence_categories: BTreeSet::from([DataCategory::EvidenceAggregates]),
                evidence_age_ms: Some(1_000),
                confidence_basis_points: Some(8_000),
                occurred_at: now() + Duration::seconds(index as i64),
                expires_at: now() + Duration::days(30),
            })
            .unwrap();
    }
}

fn downgrade_current_database_to_v1(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             BEGIN EXCLUSIVE;
             CREATE TABLE permission_records_v1 (
                 id BLOB PRIMARY KEY NOT NULL,
                 owner BLOB NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision > 0),
                 session_id BLOB,
                 payload TEXT NOT NULL
             );
             INSERT INTO permission_records_v1(id,owner,revision,session_id,payload)
                 SELECT id,owner,revision,session_id,payload FROM permission_records;
             DROP TABLE permission_records;
             ALTER TABLE permission_records_v1 RENAME TO permission_records;
             CREATE INDEX permissions_owner_idx ON permission_records(owner);

             CREATE TABLE policy_records_v1 (
                 id BLOB PRIMARY KEY NOT NULL,
                 owner BLOB NOT NULL,
                 payload TEXT NOT NULL
             );
             INSERT INTO policy_records_v1(id,owner,payload)
                 SELECT id,owner,payload FROM policy_records;
             DROP TABLE policy_records;
             ALTER TABLE policy_records_v1 RENAME TO policy_records;
             CREATE INDEX policy_owner_idx ON policy_records(owner);

             CREATE TABLE outbox_records_v1 (
                 id BLOB PRIMARY KEY NOT NULL,
                 owner BLOB NOT NULL,
                 intervention_id BLOB NOT NULL REFERENCES intervention_records(id) ON DELETE CASCADE,
                 deduplication_key BLOB NOT NULL UNIQUE,
                 state TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 payload TEXT NOT NULL
             );
             INSERT INTO outbox_records_v1(
                 id,owner,intervention_id,deduplication_key,state,expires_at,payload
             ) SELECT id,owner,intervention_id,deduplication_key,state,expires_at,payload
               FROM outbox_records;
             DROP TABLE outbox_records;
             ALTER TABLE outbox_records_v1 RENAME TO outbox_records;
             CREATE INDEX outbox_owner_state_idx ON outbox_records(owner,state);

             DROP TABLE operation_receipts;
             DROP TABLE device_records;
             DROP TABLE goal_deletion_tombstones;
             DROP TABLE resource_deletion_tombstones;
             DROP TABLE native_resource_cleanup_records;
             DELETE FROM schema_migrations
             WHERE migration_id IN (
                 'identity-permissions-v2-goal-links',
                 'intervention-v2-workflow-links',
                 'application-v3-operation-receipts',
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts'
             );
             PRAGMA user_version=1;
             COMMIT;
             PRAGMA foreign_keys=ON;",
        )
        .unwrap();
}

fn downgrade_current_database_to_v2(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "BEGIN EXCLUSIVE;
             DROP TABLE operation_receipts;
             DROP TABLE device_records;
             DROP TABLE goal_deletion_tombstones;
             DROP TABLE resource_deletion_tombstones;
             DROP TABLE native_resource_cleanup_records;
             DELETE FROM schema_migrations WHERE migration_id IN (
                 'application-v3-operation-receipts',
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts'
             );
             PRAGMA user_version=2;
             COMMIT;",
        )
        .unwrap();
}

fn downgrade_current_database_to_v3(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "BEGIN EXCLUSIVE;
             CREATE TABLE preference_records_v3 (
                 owner BLOB PRIMARY KEY NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision > 0),
                 payload TEXT NOT NULL
             );
             INSERT INTO preference_records_v3(owner,revision,payload)
                 SELECT owner,revision,payload FROM preference_records;
             DROP TABLE preference_records;
             ALTER TABLE preference_records_v3 RENAME TO preference_records;
             DROP TABLE device_records;
             DROP TABLE goal_deletion_tombstones;
             DROP TABLE resource_deletion_tombstones;
             DROP TABLE native_resource_cleanup_records;
             DELETE FROM schema_migrations
             WHERE migration_id IN (
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts'
             );
             PRAGMA user_version=3;
             COMMIT;",
        )
        .unwrap();
}

#[test]
fn state_and_atomic_owner_snapshot_survive_repository_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("stein.db");
    let graph = synthetic_graph(actor(), 0x200);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        assert_eq!(repository.schema_version().unwrap(), 5);
        install_graph(&repository, &graph, true, false);
        repository.health().unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    let snapshot = repository.load_owner_state(actor()).unwrap();
    assert_eq!(snapshot.goals, vec![graph.goal.clone()]);
    assert_eq!(snapshot.identity, Some(graph.identity));
    assert_eq!(snapshot.preferences, Some(graph.preferences));
    assert_eq!(snapshot.resources, vec![graph.resource]);
    assert_eq!(snapshot.grants, graph.bound_grants);
    assert_eq!(snapshot.model_routes, vec![graph.route]);
    assert_eq!(snapshot.focus_sessions, vec![graph.session]);
    assert_eq!(snapshot.interventions, vec![graph.intervention]);
    assert_eq!(snapshot.policy_decisions, vec![graph.policy]);
    assert_eq!(snapshot.pending_deliveries, vec![graph.delivery]);
    assert_eq!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::ApproveModelRoute,
                graph.route_receipt.idempotency_key,
            )
            .unwrap(),
        Some(graph.route_receipt.clone())
    );
    assert_eq!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::StartFocusSession,
                graph.start_receipt.idempotency_key,
            )
            .unwrap(),
        Some(graph.start_receipt.clone())
    );
    assert_eq!(
        repository
            .find_goal_create(actor(), graph.receipt.idempotency_key)
            .unwrap(),
        Some((graph.receipt, graph.goal))
    );
    assert_eq!(
        repository.load_owner_state(other_actor()).unwrap(),
        Default::default()
    );
}

#[test]
fn revisions_and_goal_receipt_are_atomic() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("atomic-goal.db")).unwrap();
    let (goal, receipt) = goal_for(actor(), 0x300);
    repository.create_goal(&goal, &receipt).unwrap();

    let (second_goal, mut duplicate_receipt) = goal_for(actor(), 0x400);
    duplicate_receipt.idempotency_key = receipt.idempotency_key;
    let error = repository
        .create_goal(&second_goal, &duplicate_receipt)
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(repository.load_goals(actor()).unwrap(), vec![goal.clone()]);

    let mut updated = goal.clone();
    updated.title = "Prepare the revised synthetic release".to_owned();
    updated.revision = Revision::new(2).unwrap();
    repository.update_goal(&updated, 1).unwrap();
    let stale = repository.update_goal(&updated, 1).unwrap_err();
    assert_eq!(stale.kind, RepositoryErrorKind::Conflict);
    assert_eq!(repository.load_goals(actor()).unwrap(), vec![updated]);
}

#[test]
fn aggregate_receipt_and_audit_creation_is_atomic() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("atomic-receipts.db")).unwrap();
    let first = synthetic_graph(actor(), 0x420);
    repository
        .create_model_route(&first.route, &first.route_receipt, &first.route_audit)
        .unwrap();

    let mut duplicate_key = synthetic_graph(actor(), 0x460);
    duplicate_key.route_receipt.idempotency_key = first.route_receipt.idempotency_key;
    let error = repository
        .create_model_route(
            &duplicate_key.route,
            &duplicate_key.route_receipt,
            &duplicate_key.route_audit,
        )
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_model_routes(actor()).unwrap(),
        vec![first.route.clone()]
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .all(|record| record.id != duplicate_key.route_audit.id)
    );

    let mut duplicate_audit = synthetic_graph(actor(), 0x4a0);
    duplicate_audit.route_audit.id = first.route_audit.id;
    let error = repository
        .create_model_route(
            &duplicate_audit.route,
            &duplicate_audit.route_receipt,
            &duplicate_audit.route_audit,
        )
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::ApproveModelRoute,
                duplicate_audit.route_receipt.idempotency_key,
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repository.load_model_routes(actor()).unwrap(),
        vec![first.route.clone()]
    );

    repository.create_goal(&first.goal, &first.receipt).unwrap();
    repository.save_resource(&first.resource).unwrap();
    let mut grant_audit = first.grant_audits[0].clone();
    grant_audit.id = first.route_audit.id;
    let error = repository
        .create_grant(
            &first.initial_grants[0],
            &first.grant_receipts[0],
            &grant_audit,
        )
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert!(repository.load_grants(actor()).unwrap().is_empty());
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::GrantSessionPermission,
                first.grant_receipts[0].idempotency_key,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn intervention_decision_commit_survives_restart_and_audit_is_privacy_bounded() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("atomic-decision.db");
    let mut graph = synthetic_graph(actor(), 0x4e0);
    graph.intervention.user_visible_text = "synthetic-private-intervention-text".to_owned();
    graph.intervention.evidence_summary = "synthetic-private-evidence-detail".to_owned();
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph_foundation(&repository, &graph);
        run_repository_future(
            repository.commit_intervention_decision(&allow_decision_write(&graph)),
        )
        .unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(
        repository.find_policy_decision(graph.policy.id).unwrap(),
        Some(graph.policy.clone())
    );
    assert_eq!(
        repository.load_interventions(actor()).unwrap(),
        vec![graph.intervention.clone()]
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .contains(&graph.decision_audit)
    );
    drop(repository);

    let connection = Connection::open(&path).unwrap();
    let audit_payload: String = connection
        .query_row(
            "SELECT payload FROM audit_records WHERE id=?1",
            [graph.decision_audit.id.as_uuid().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!audit_payload.contains("synthetic-private-intervention-text"));
    assert!(!audit_payload.contains("synthetic-private-evidence-detail"));
    assert_no_prohibited_keys(&serde_json::from_str(&audit_payload).unwrap());
}

#[test]
fn conflicting_decision_audit_rolls_back_deliverable_intervention() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("decision-audit-conflict.db");
    let graph = synthetic_graph(actor(), 0x520);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph_foundation(&repository, &graph);
        repository.append_audit(&graph.decision_audit).unwrap();

        let error = run_repository_future(
            repository.commit_intervention_decision(&allow_decision_write(&graph)),
        )
        .unwrap_err();
        assert_eq!(error.kind, RepositoryErrorKind::Conflict);
        assert!(
            repository
                .find_policy_decision(graph.policy.id)
                .unwrap()
                .is_none()
        );
        assert!(repository.load_interventions(actor()).unwrap().is_empty());
    }

    let restarted = SqliteRepository::open(&path).unwrap();
    assert!(
        restarted
            .find_policy_decision(graph.policy.id)
            .unwrap()
            .is_none()
    );
    assert!(restarted.load_interventions(actor()).unwrap().is_empty());
    assert_eq!(
        restarted
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .filter(|record| record.id == graph.decision_audit.id)
            .count(),
        1
    );
}

#[test]
fn stale_intervention_revision_rolls_back_decision_and_audit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("decision-stale-revision.db");
    let graph = synthetic_graph(actor(), 0x560);
    let mut recovery = allow_decision_write(&graph);
    recovery.decision.id = PolicyDecisionId::from_uuid(uuid(0x5f0));
    recovery.audit.id = AuditRecordId::from_uuid(uuid(0x5f1));
    let intervention = recovery.intervention.as_mut().unwrap();
    intervention.policy_decision_id = recovery.decision.id;
    intervention.revision = 2;
    intervention.state = InterventionState::Delivering;
    intervention.updated_at += Duration::seconds(1);
    recovery.expected_intervention_revision = Some(99);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph_foundation(&repository, &graph);
        run_repository_future(
            repository.commit_intervention_decision(&allow_decision_write(&graph)),
        )
        .unwrap();

        let error =
            run_repository_future(repository.commit_intervention_decision(&recovery)).unwrap_err();
        assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    }

    let restarted = SqliteRepository::open(&path).unwrap();
    assert!(
        restarted
            .find_policy_decision(recovery.decision.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restarted.load_interventions(actor()).unwrap(),
        vec![graph.intervention]
    );
    assert!(
        restarted
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .all(|record| record.id != recovery.audit.id)
    );
}

#[test]
fn decision_replay_conflicts_without_duplicate_rows() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("decision-replay.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x5c0);
    install_graph_foundation(&repository, &graph);
    let write = allow_decision_write(&graph);
    run_repository_future(repository.commit_intervention_decision(&write)).unwrap();
    let error = run_repository_future(repository.commit_intervention_decision(&write)).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(repository.load_interventions(actor()).unwrap().len(), 1);
    assert_eq!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .filter(|record| record.id == graph.decision_audit.id)
            .count(),
        1
    );
}

#[test]
fn dropped_unpolled_decision_future_never_commits_later() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("decision-cancel.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x620);
    install_graph_foundation(&repository, &graph);
    let write = allow_decision_write(&graph);
    drop(repository.commit_intervention_decision(&write));

    assert!(
        repository
            .find_policy_decision(graph.policy.id)
            .unwrap()
            .is_none()
    );
    assert!(repository.load_interventions(actor()).unwrap().is_empty());
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .all(|record| record.id != graph.decision_audit.id)
    );
}

#[test]
fn decision_shape_is_validated_and_deny_commits_without_intervention() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("decision-shape.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x660);
    install_graph_foundation(&repository, &graph);

    let mut invalid = allow_decision_write(&graph);
    invalid.intervention = None;
    assert_eq!(
        run_repository_future(repository.commit_intervention_decision(&invalid))
            .unwrap_err()
            .kind,
        RepositoryErrorKind::Corrupt
    );

    let mut denied = invalid;
    denied.decision.outcome = PolicyOutcome::Deny;
    run_repository_future(repository.commit_intervention_decision(&denied)).unwrap();
    assert_eq!(
        repository.find_policy_decision(denied.decision.id).unwrap(),
        Some(denied.decision)
    );
    assert!(repository.load_interventions(actor()).unwrap().is_empty());
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .contains(&denied.audit)
    );
}

#[test]
fn grant_binding_rolls_back_every_update_on_revision_conflict() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("atomic-bind.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x500);
    repository.create_goal(&graph.goal, &graph.receipt).unwrap();
    repository.save_resource(&graph.resource).unwrap();
    repository
        .create_model_route(&graph.route, &graph.route_receipt, &graph.route_audit)
        .unwrap();
    for ((grant, receipt), audit) in graph
        .initial_grants
        .iter()
        .zip(&graph.grant_receipts)
        .zip(&graph.grant_audits)
    {
        repository.create_grant(grant, receipt, audit).unwrap();
    }

    let mut conflicting = graph.bound_grants.clone();
    conflicting[1].revision = 1_000;
    let changes = vec![
        (conflicting[0].clone(), 1),
        (conflicting[1].clone(), 999),
        (conflicting[2].clone(), 1),
    ];
    let error = repository
        .bind_grants_and_create_focus_session(
            &graph.session,
            &changes,
            &graph.start_receipt,
            &graph.start_audit,
        )
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_grants(actor()).unwrap(),
        graph.initial_grants
    );
    assert!(
        repository
            .find_focus_session(graph.session.id)
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::StartFocusSession,
                graph.start_receipt.idempotency_key,
            )
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .all(|record| record.id != graph.start_audit.id)
    );

    let valid = graph
        .bound_grants
        .iter()
        .cloned()
        .map(|grant| (grant, 1))
        .collect::<Vec<_>>();
    repository
        .bind_grants_and_create_focus_session(
            &graph.session,
            &valid,
            &graph.start_receipt,
            &graph.start_audit,
        )
        .unwrap();
    assert_eq!(
        repository.find_focus_session(graph.session.id).unwrap(),
        Some(graph.session)
    );
    assert_eq!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::StartFocusSession,
                graph.start_receipt.idempotency_key,
            )
            .unwrap(),
        Some(graph.start_receipt)
    );
}

#[test]
fn owner_snapshot_never_observes_half_bound_session_transaction() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("snapshot-race.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x5a0);
    repository.create_goal(&graph.goal, &graph.receipt).unwrap();
    repository.save_resource(&graph.resource).unwrap();
    repository
        .create_model_route(&graph.route, &graph.route_receipt, &graph.route_audit)
        .unwrap();
    for ((grant, receipt), audit) in graph
        .initial_grants
        .iter()
        .zip(&graph.grant_receipts)
        .zip(&graph.grant_audits)
    {
        repository.create_grant(grant, receipt, audit).unwrap();
    }

    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = Arc::clone(&barrier);
    let writer_repository = repository.clone();
    let writer_graph = graph.clone();
    let writer = std::thread::spawn(move || {
        let bound = writer_graph
            .bound_grants
            .iter()
            .cloned()
            .map(|grant| (grant, 1))
            .collect::<Vec<_>>();
        writer_barrier.wait();
        writer_repository
            .bind_grants_and_create_focus_session(
                &writer_graph.session,
                &bound,
                &writer_graph.start_receipt,
                &writer_graph.start_audit,
            )
            .unwrap();
    });
    barrier.wait();

    for _ in 0..32 {
        let snapshot = repository.load_owner_state(actor()).unwrap();
        let session_present = snapshot
            .focus_sessions
            .iter()
            .any(|session| session.id == graph.session.id);
        let bound_grants = snapshot
            .grants
            .iter()
            .filter(|grant| grant.focus_session_id == Some(graph.session.id))
            .count();
        assert!(
            (!session_present && bound_grants == 0)
                || (session_present && bound_grants == graph.bound_grants.len())
        );
    }
    writer.join().unwrap();
    let snapshot = repository.load_owner_state(actor()).unwrap();
    assert_eq!(snapshot.focus_sessions, vec![graph.session]);
    assert_eq!(snapshot.grants, graph.bound_grants);
}

#[test]
fn v1_fixture_upgrades_once_and_preserves_linked_state() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("upgrade.db");
    let graph = synthetic_graph(actor(), 0x600);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, false);
    }
    downgrade_current_database_to_v1(&path);

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(repository.schema_version().unwrap(), 5);
    let snapshot = repository.load_owner_state(actor()).unwrap();
    assert_eq!(snapshot.focus_sessions, vec![graph.session.clone()]);
    assert_eq!(snapshot.grants, graph.bound_grants.clone());
    assert_eq!(snapshot.policy_decisions, vec![graph.policy.clone()]);
    assert_eq!(snapshot.pending_deliveries, vec![graph.delivery.clone()]);
    drop(repository);

    let restarted = SqliteRepository::open(&path).unwrap();
    assert_eq!(restarted.load_owner_state(actor()).unwrap(), snapshot);
}

#[test]
fn v2_fixture_upgrades_without_mutating_aggregates() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("upgrade-from-v2.db");
    let graph = synthetic_graph(actor(), 0x680);
    let expected = {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, false);
        repository.load_owner_state(actor()).unwrap()
    };
    downgrade_current_database_to_v2(&path);

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(repository.schema_version().unwrap(), 5);
    assert_eq!(repository.load_owner_state(actor()).unwrap(), expected);
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::ApproveModelRoute,
                graph.route_receipt.idempotency_key,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn immediately_preceding_v3_preferences_apply_defaults_and_canonicalize_once() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("upgrade-from-v3.db");
    let graph = synthetic_graph(actor(), 0x6c0);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository
            .save_preferences(&graph.preferences, None)
            .unwrap();
    }
    downgrade_current_database_to_v3(&path);
    {
        let connection = Connection::open(&path).unwrap();
        let payload: String = connection
            .query_row("SELECT payload FROM preference_records", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut legacy: JsonValue = serde_json::from_str(&payload).unwrap();
        let fields = legacy.as_object_mut().unwrap();
        for field in [
            "schema_version",
            "maximum_model_requests_per_hour",
            "minimum_intervention_cooldown_seconds",
            "proactive_interventions_muted",
            "do_not_disturb_windows",
            "allowed_delivery_channels",
            "remote_processing_enabled",
        ] {
            fields.remove(field);
        }
        connection
            .execute(
                "UPDATE preference_records SET payload=?1",
                [serde_json::to_string(&legacy).unwrap()],
            )
            .unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(repository.schema_version().unwrap(), 5);
    assert_eq!(
        repository.load_preferences(actor()).unwrap(),
        Some(graph.preferences.clone())
    );
    drop(repository);

    let connection = Connection::open(&path).unwrap();
    let (schema_version, payload): (i64, String) = connection
        .query_row(
            "SELECT schema_version,payload FROM preference_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(schema_version, i64::from(USER_PREFERENCES_SCHEMA_V1));
    let canonical: JsonValue = serde_json::from_str(&payload).unwrap();
    for field in [
        "schema_version",
        "maximum_model_requests_per_hour",
        "minimum_intervention_cooldown_seconds",
        "proactive_interventions_muted",
        "do_not_disturb_windows",
        "allowed_delivery_channels",
        "remote_processing_enabled",
    ] {
        assert!(canonical.get(field).is_some(), "missing canonical {field}");
    }
}

#[test]
fn failed_v3_preferences_migration_rolls_back_without_advancing_catalog() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("failed-preferences-upgrade.db");
    let graph = synthetic_graph(actor(), 0x6e0);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository
            .save_preferences(&graph.preferences, None)
            .unwrap();
    }
    downgrade_current_database_to_v3(&path);
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE preference_records SET payload='{malformed-json'",
                [],
            )
            .unwrap();
    }

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let partial_table: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_schema WHERE name='preference_records_next'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert!(partial_table.is_none());
    let migration_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM schema_migrations
             WHERE migration_id='identity-permissions-v4-explicit-preferences-v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_count, 0);
}

#[test]
fn unsupported_preferences_schema_version_fails_closed() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("preferences-version.db")).unwrap();
    let mut preferences = ExplicitPreferences::phase2_defaults(actor(), now());
    preferences.schema_version = USER_PREFERENCES_SCHEMA_V1 + 1;

    let error = repository.save_preferences(&preferences, None).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert!(repository.load_preferences(actor()).unwrap().is_none());
}

#[test]
fn rolled_back_partial_migration_retries_cleanly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rolled-back.db");
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.health().unwrap();
    }
    downgrade_current_database_to_v1(&path);
    {
        let mut connection = Connection::open(&path).unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute_batch("CREATE TABLE permission_records_next(partial INTEGER);")
            .unwrap();
        transaction.rollback().unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(repository.schema_version().unwrap(), 5);
    repository.health().unwrap();
}

#[test]
fn failed_v1_data_migration_leaves_original_schema_unchanged() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("failed-upgrade.db");
    let graph = synthetic_graph(actor(), 0x700);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, false, false);
    }
    downgrade_current_database_to_v1(&path);
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE permission_records SET payload='{malformed-json'
                 WHERE id=?1",
                [graph.initial_grants[0].id.as_uuid().as_bytes().to_vec()],
            )
            .unwrap();
    }

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
    let partial_table: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_schema WHERE name='permission_records_next'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert!(partial_table.is_none());
    let goal_count: i64 = connection
        .query_row("SELECT count(*) FROM goals_records", [], |row| row.get(0))
        .unwrap();
    assert_eq!(goal_count, 1);
}

#[test]
fn migration_catalog_uses_full_checksums_and_mismatch_fails_closed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("checksums.db");
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.health().unwrap();
    }
    let connection = Connection::open(&path).unwrap();
    let migrations: Vec<(String, String, String)> = {
        let mut statement = connection
            .prepare(
                "SELECT owner,migration_id,checksum FROM schema_migrations
                 ORDER BY owner,migration_id",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(migrations.len(), 10);
    for (_, _, checksum) in &migrations {
        assert_eq!(checksum.len(), "sha256:".len() + 64);
        assert!(checksum.starts_with("sha256:"));
        assert!(
            checksum["sha256:".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }
    connection
        .execute(
            "UPDATE schema_migrations SET checksum='sha256:tampered'
             WHERE migration_id='goals-v1'",
            [],
        )
        .unwrap();
    drop(connection);

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
}

#[test]
fn unknown_schema_fails_closed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("future.db");
    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Unavailable);
}

#[test]
fn foreign_key_corruption_fails_startup_health() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("foreign-key.db");
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.health().unwrap();
    }
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO focus_records(id,owner,goal_id,revision,payload)
             VALUES(?1,?2,?3,1,'{}')",
            params![
                uuid(0xb01).as_bytes().to_vec(),
                actor().as_uuid().as_bytes().to_vec(),
                uuid(0xb02).as_bytes().to_vec(),
            ],
        )
        .unwrap();
    drop(connection);

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
}

#[test]
fn relational_payload_corruption_fails_startup_health() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("relational-corruption.db");
    let (goal, receipt) = goal_for(actor(), 0xb20);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.create_goal(&goal, &receipt).unwrap();
    }
    let mut corrupt = goal;
    corrupt.owner = other_actor();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE goals_records SET payload=?1 WHERE id=?2",
            params![
                serde_json::to_string(&corrupt).unwrap(),
                corrupt.id.as_uuid().as_bytes().to_vec(),
            ],
        )
        .unwrap();
    drop(connection);

    let error = SqliteRepository::open(&path).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
}

#[test]
fn interrupted_delivery_recovers_as_unknown_without_retry() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("outbox-crash.db");
    let graph = synthetic_graph(actor(), 0xc00);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, false);
        let mut delivering = graph.delivery.clone();
        delivering.state = OutboxState::Delivering;
        delivering.attempt_count = 1;
        delivering.last_attempt_at = Some(now() + Duration::seconds(3));
        repository.save_delivery(&delivering).unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    let recovered = repository.load_pending_deliveries(actor()).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].state, OutboxState::DeliveryUnknown);
    assert_eq!(recovered[0].attempt_count, 1);
    assert!(recovered[0].user_visible_text.is_empty());
    drop(repository);

    let restarted = SqliteRepository::open(&path).unwrap();
    assert_eq!(
        restarted.load_pending_deliveries(actor()).unwrap()[0].state,
        OutboxState::DeliveryUnknown
    );
}

#[test]
fn outbox_bounds_and_state_machine_fail_closed() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("outbox-bounds.db")).unwrap();
    let graph = synthetic_graph(actor(), 0xd00);
    install_graph(&repository, &graph, true, false);

    let mut invalid_transition = graph.delivery.clone();
    invalid_transition.state = OutboxState::AcceptedByChannel;
    assert_eq!(
        repository
            .save_delivery(&invalid_transition)
            .unwrap_err()
            .kind,
        RepositoryErrorKind::Conflict
    );

    for index in 1_u128..5 {
        let mut delivery = graph.delivery.clone();
        delivery.id = OutboxEntryId::from_uuid(uuid(0xd20 + index));
        delivery.deduplication_key = uuid(0xd40 + index);
        repository.enqueue_delivery(&delivery).unwrap();
    }
    let mut overflow = graph.delivery.clone();
    overflow.id = OutboxEntryId::from_uuid(uuid(0xd80));
    overflow.deduplication_key = uuid(0xd81);
    assert_eq!(
        repository.enqueue_delivery(&overflow).unwrap_err().kind,
        RepositoryErrorKind::Conflict
    );

    let mut oversized = graph.delivery.clone();
    oversized.id = OutboxEntryId::from_uuid(uuid(0xd82));
    oversized.deduplication_key = uuid(0xd83);
    oversized.user_visible_text = "x".repeat(513);
    assert_eq!(
        repository.enqueue_delivery(&oversized).unwrap_err().kind,
        RepositoryErrorKind::Conflict
    );

    let mut expired = graph.delivery.clone();
    expired.state = OutboxState::Expired;
    repository.save_delivery(&expired).unwrap();
    let persisted = repository
        .load_pending_deliveries(actor())
        .unwrap()
        .into_iter()
        .find(|delivery| delivery.id == expired.id)
        .unwrap();
    assert!(persisted.user_visible_text.is_empty());
}

#[test]
fn selected_resource_removal_is_idempotent_and_retains_native_cleanup() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("resource-removal.db");
    let graph = synthetic_graph(actor(), 0xdc0);
    let deleted_at = now() + Duration::seconds(7);
    let expected_cleanup = NativeResourceCleanup {
        owner: actor(),
        resource_id: graph.resource.id,
        opaque_reference: graph.resource.opaque_reference.clone(),
        created_at: deleted_at,
    };

    let tombstone = {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.save_resource(&graph.resource).unwrap();

        let result = repository
            .remove_resource(
                actor(),
                graph.resource.id,
                graph.resource.revision,
                deleted_at,
            )
            .unwrap();
        assert!(!result.already_removed);
        assert_eq!(result.tombstone.owner, actor());
        assert_eq!(result.tombstone.resource_id, graph.resource.id);
        assert_eq!(result.tombstone.deleted_revision, graph.resource.revision);
        assert_eq!(result.tombstone.deleted_at, deleted_at);
        assert!(repository.load_resources(actor()).unwrap().is_empty());
        assert_eq!(
            repository
                .find_resource_deletion(actor(), graph.resource.id)
                .unwrap(),
            Some(result.tombstone.clone())
        );
        assert_eq!(
            repository.load_native_resource_cleanups(actor()).unwrap(),
            vec![expected_cleanup.clone()]
        );
        result.tombstone
    };

    let repository = SqliteRepository::open(&path).unwrap();
    let replay = repository
        .remove_resource(
            actor(),
            graph.resource.id,
            graph.resource.revision,
            deleted_at + Duration::hours(1),
        )
        .unwrap();
    assert!(replay.already_removed);
    assert_eq!(replay.tombstone, tombstone);
    assert_eq!(
        repository.load_native_resource_cleanups(actor()).unwrap(),
        vec![expected_cleanup]
    );
    assert_eq!(
        repository
            .remove_resource(
                actor(),
                graph.resource.id,
                graph.resource.revision + 1,
                deleted_at,
            )
            .unwrap_err()
            .kind,
        RepositoryErrorKind::Conflict
    );

    repository
        .complete_native_resource_cleanup(actor(), graph.resource.id)
        .unwrap();
    repository
        .complete_native_resource_cleanup(actor(), graph.resource.id)
        .unwrap();
    assert!(
        repository
            .load_native_resource_cleanups(actor())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn goal_delete_cascades_private_graph_but_preserves_identity_and_route() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("cascade.db")).unwrap();
    let graph = synthetic_graph(actor(), 0xe00);
    install_graph(&repository, &graph, true, true);
    let mut unbound_grant = graph.initial_grants[0].clone();
    unbound_grant.id = PermissionGrantId::from_uuid(uuid(0xe80));
    let unbound_receipt = OperationReceipt {
        owner: actor(),
        kind: OperationKind::GrantSessionPermission,
        idempotency_key: IdempotencyKey::from_uuid(uuid(0xe81)),
        request_digest: [0xe; 32],
        result_id: unbound_grant.id.as_uuid(),
    };
    let unbound_audit = creation_audit(
        actor(),
        0xe82,
        AuditKind::PermissionGranted,
        unbound_grant.id.as_uuid(),
    );
    repository
        .create_grant(&unbound_grant, &unbound_receipt, &unbound_audit)
        .unwrap();
    let audit_count = repository
        .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
        .unwrap()
        .len();

    let summary = repository
        .delete_goal_cascade(actor(), graph.goal.id, 1)
        .unwrap();
    assert_eq!(summary.goals, 1);
    assert_eq!(summary.focus_sessions, 1);
    assert_eq!(summary.grants, 4);
    assert_eq!(summary.interventions, 1);
    assert_eq!(summary.outbox_entries, 1);
    assert_eq!(summary.audit_records, audit_count as u64 - 1);
    assert_eq!(summary.resource_bindings, 1);

    let snapshot = repository.load_owner_state(actor()).unwrap();
    assert!(snapshot.goals.is_empty());
    assert!(snapshot.resources.is_empty());
    assert!(snapshot.grants.is_empty());
    assert!(snapshot.focus_sessions.is_empty());
    assert!(snapshot.interventions.is_empty());
    assert!(snapshot.policy_decisions.is_empty());
    assert!(snapshot.pending_deliveries.is_empty());
    assert_eq!(snapshot.identity, Some(graph.identity));
    assert_eq!(snapshot.preferences, Some(graph.preferences));
    assert_eq!(snapshot.model_routes, vec![graph.route]);
    assert_eq!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap(),
        vec![graph.route_audit.clone()]
    );
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::StartFocusSession,
                graph.start_receipt.idempotency_key,
            )
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::GrantSessionPermission,
                graph.grant_receipts[0].idempotency_key,
            )
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::GrantSessionPermission,
                unbound_receipt.idempotency_key,
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repository
            .find_operation_receipt(
                actor(),
                OperationKind::ApproveModelRoute,
                graph.route_receipt.idempotency_key,
            )
            .unwrap(),
        Some(graph.route_receipt)
    );
    assert!(
        repository
            .find_policy_decision(graph.policy.id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn goal_delete_preserves_a_resource_and_its_audit_while_another_goal_references_it() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("shared-resource.db")).unwrap();
    let graph = synthetic_graph(actor(), 0xec0);
    install_graph(&repository, &graph, false, true);

    let mut remaining = synthetic_graph(actor(), 0xf40);
    remaining.initial_grants[0].selected_resource_id = Some(graph.resource.id);
    remaining.bound_grants[0].selected_resource_id = Some(graph.resource.id);
    remaining.session.selected_resource_ids = BTreeSet::from([graph.resource.id]);
    repository
        .create_goal(&remaining.goal, &remaining.receipt)
        .unwrap();
    repository
        .create_model_route(
            &remaining.route,
            &remaining.route_receipt,
            &remaining.route_audit,
        )
        .unwrap();
    for ((grant, receipt), audit) in remaining
        .initial_grants
        .iter()
        .zip(&remaining.grant_receipts)
        .zip(&remaining.grant_audits)
    {
        repository.create_grant(grant, receipt, audit).unwrap();
    }
    let changes = remaining
        .bound_grants
        .iter()
        .cloned()
        .map(|grant| (grant, 1))
        .collect::<Vec<_>>();
    repository
        .bind_grants_and_create_focus_session(
            &remaining.session,
            &changes,
            &remaining.start_receipt,
            &remaining.start_audit,
        )
        .unwrap();

    let summary = repository
        .delete_goal_cascade(actor(), graph.goal.id, 1)
        .unwrap();
    assert_eq!(summary.resource_bindings, 0);
    assert_eq!(
        repository.load_goals(actor()).unwrap(),
        vec![remaining.goal]
    );
    assert_eq!(
        repository.load_resources(actor()).unwrap(),
        vec![graph.resource.clone()]
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .any(|record| record.subject_id == graph.resource.id.as_uuid())
    );
    assert_eq!(
        repository.load_grants(actor()).unwrap(),
        remaining.bound_grants
    );
    assert_eq!(
        repository.load_focus_sessions(actor()).unwrap(),
        vec![remaining.session]
    );
}

#[test]
fn audit_expiry_is_exact_and_idempotent() {
    let directory = tempdir().unwrap();
    let repository = SqliteRepository::open(directory.path().join("audit-expiry.db")).unwrap();
    let graph = synthetic_graph(actor(), 0xf00);
    install_graph(&repository, &graph, false, true);
    let count = repository
        .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
        .unwrap()
        .len() as u64;
    assert_eq!(
        repository
            .purge_expired_audit(now() + Duration::days(30) - Duration::nanoseconds(1))
            .unwrap(),
        0
    );
    assert_eq!(
        repository
            .purge_expired_audit(now() + Duration::days(30))
            .unwrap(),
        count
    );
    assert_eq!(
        repository
            .purge_expired_audit(now() + Duration::days(31))
            .unwrap(),
        0
    );
}

#[test]
fn audit_write_fails_closed_while_database_is_exclusively_busy() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("busy-audit.db");
    let repository = SqliteRepository::open(&path).unwrap();
    let lock = Connection::open(&path).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    let audit = creation_audit(
        actor(),
        0x1400,
        AuditKind::InterventionDelivery,
        uuid(0x1402),
    );

    let error = repository.append_audit(&audit).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    lock.execute_batch("ROLLBACK;").unwrap();
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn recovery_copy_is_sqlite_consistent_and_preserves_snapshot() {
    let directory = tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let copy_path = directory.path().join("recovery.db");
    let graph = synthetic_graph(actor(), 0x1100);
    let source = SqliteRepository::open(&source_path).unwrap();
    install_graph(&source, &graph, true, false);
    let expected = source.load_owner_state(actor()).unwrap();
    source.create_recovery_copy(&copy_path).unwrap();

    let copy = SqliteRepository::open(&copy_path).unwrap();
    copy.health().unwrap();
    assert_eq!(copy.load_owner_state(actor()).unwrap(), expected);
}

#[test]
fn schema_and_payloads_exclude_prohibited_private_record_shapes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("privacy.db");
    let graph = synthetic_graph(actor(), 0x1200);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, true);
        let debug = format!("{repository:?}");
        assert!(!debug.contains(path.to_string_lossy().as_ref()));
    }
    let connection = Connection::open(&path).unwrap();
    let schema: String = connection
        .query_row(
            "SELECT group_concat(sql, ' ') FROM sqlite_schema WHERE sql IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let lower = schema.to_ascii_lowercase();
    for prohibited in [
        "observation_payload",
        "working_context",
        "model_prompt",
        "model_response",
        "credential_value",
        "broker_capability",
        "screenshot",
        "screen_frame",
        "ui_tree",
    ] {
        assert!(!lower.contains(prohibited), "schema contains {prohibited}");
    }

    for table in [
        "goals_records",
        "goals_create_receipts",
        "identity_records",
        "preference_records",
        "resource_records",
        "permission_records",
        "route_records",
        "focus_records",
        "intervention_records",
        "policy_records",
        "audit_records",
        "outbox_records",
        "operation_receipts",
    ] {
        let mut statement = connection
            .prepare(&format!("SELECT payload FROM {table}"))
            .unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap();
        for payload in rows {
            assert_no_prohibited_keys(&serde_json::from_str(&payload.unwrap()).unwrap());
        }
    }

    drop(connection);
    let bytes = fs::read(path).unwrap();
    let database = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    for prohibited in [
        "raw-observation-sentinel",
        "model-prompt-sentinel",
        "provider-secret-value-sentinel",
        "broker-capability-sentinel",
    ] {
        assert!(!database.contains(prohibited));
    }
    assert!(!directory.path().join("privacy.db-wal").exists());
    assert!(!directory.path().join("privacy.db-shm").exists());
    assert!(!directory.path().join("privacy.db-journal").exists());
}

fn assert_no_prohibited_keys(value: &JsonValue) {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                assert_no_prohibited_keys(value);
            }
        }
        JsonValue::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    !matches!(
                        key.as_str(),
                        "observation"
                            | "observation_payload"
                            | "raw_observation"
                            | "raw_source_artifact"
                            | "working_context"
                            | "model_prompt"
                            | "model_request"
                            | "model_response"
                            | "provider_response"
                            | "chain_of_thought"
                            | "credential"
                            | "credential_value"
                            | "broker_capability"
                            | "screenshot"
                            | "screen_frame"
                            | "ui_tree"
                    ),
                    "payload contains prohibited key {key}"
                );
                assert_no_prohibited_keys(value);
            }
        }
        _ => {}
    }
}
