use std::collections::BTreeSet;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value as JsonValue;
use stein_core::{
    ActorId, AuditKind, AuditRecord, AuditRecordId, CandidateId, ClientId, DataCategory, DeviceId,
    DurableRepository, EvidenceRole, EvidenceSummary, ExplicitPreferences, FocusSession,
    FocusSessionId, FocusSessionLifecycleWrite, FocusSessionState, Goal, GoalCreateReceipt, GoalId,
    GoalState, GrantState, IdempotencyKey, Intervention, InterventionDecisionWrite, InterventionId,
    InterventionOutcome, InterventionState, InterventionTone, InterventionTransitionWrite,
    ManualClock, MemoryRepository, ModelHandlingProfile, ModelPlacement, ModelRouteApproval,
    ModelRouteApprovalId, NativeResourceCleanup, OperationKind, OperationReceipt, OutboxEntryId,
    OutboxState, PendingDeliveryTransition, PendingInterventionDelivery, PermissionGrant,
    PermissionGrantId, PermissionGrantRevocationWrite, PermissionScope, PolicyDecision,
    PolicyDecisionId, PolicyOutcome, PolicyTrace, ProviderRetentionPolicy, ProviderTrainingUse,
    RepositoryErrorKind, ResourceBinding, ResourceId, ResourceKind, Revision, SecondMindConfig,
    SecondMindPorts, SecondMindRuntime, SecretDeletionCleanup, SteinIdentity,
    USER_PREFERENCES_SCHEMA_V1, UnavailableEmergencyControlPort, UnavailableModelGateway,
    UnavailableNativeStatusPort, UnavailableNotificationPort, UnavailableObservationPort,
    UnavailableResourceSelectionPort, UnavailableSecretStore, Urgency,
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

fn policy_trace(seed: u8) -> PolicyTrace {
    PolicyTrace {
        policy_profile_id: "phase2-focus-v1".to_owned(),
        user_preferences_revision: 1,
        proposed_input_schema_version: PolicyTrace::INPUT_SCHEMA_V1,
        proposed_input_digest: [seed.max(1); 32],
    }
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
        policy_trace: None,
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
        secret_ref: ModelRouteApproval::approval_scoped_secret_ref(route_id),
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
    let decision_policy_trace = policy_trace(0x44);
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
        policy_trace: decision_policy_trace.clone(),
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
        expires_at: now() + Duration::seconds(32),
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
        expires_at: now() + Duration::seconds(32),
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
        policy_trace: Some(decision_policy_trace),
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
    repository: &dyn DurableRepository,
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

fn install_graph_foundation(repository: &dyn DurableRepository, graph: &SyntheticGraph) {
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

fn append_graph_audit(repository: &dyn DurableRepository, graph: &SyntheticGraph) {
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
                policy_trace: Some(policy_trace(u8::try_from(index + 1).unwrap_or(u8::MAX))),
                occurred_at: now() + Duration::seconds(index as i64),
                expires_at: now() + Duration::days(30),
            })
            .unwrap();
    }
}

fn sqlite_artifact_paths(path: &Path) -> Vec<PathBuf> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut artifact = path.as_os_str().to_os_string();
            artifact.push(suffix);
            PathBuf::from(artifact)
        })
        .collect()
}

fn artifact_contains(bytes: &[u8], marker: &str) -> bool {
    bytes
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
}

fn assert_sqlite_artifacts_exclude(path: &Path, markers: &[&str]) {
    for artifact in sqlite_artifact_paths(path) {
        if !artifact.exists() {
            continue;
        }
        let bytes = fs::read(&artifact).unwrap();
        for marker in markers {
            assert!(
                !artifact_contains(&bytes, marker),
                "{} retained synthetic marker {marker}",
                artifact.display()
            );
        }
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
             DROP TABLE secret_deletion_cleanup_records;
             DELETE FROM schema_migrations
             WHERE migration_id IN (
                 'identity-permissions-v2-goal-links',
                 'intervention-v2-workflow-links',
                 'application-v3-operation-receipts',
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts',
                 'identity-permissions-v6-secret-deletion-cleanup'
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
             DROP TABLE secret_deletion_cleanup_records;
             DELETE FROM schema_migrations WHERE migration_id IN (
                 'application-v3-operation-receipts',
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts',
                 'identity-permissions-v6-secret-deletion-cleanup'
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
             DROP TABLE secret_deletion_cleanup_records;
             DELETE FROM schema_migrations
             WHERE migration_id IN (
                 'identity-permissions-v4-explicit-preferences-v1',
                 'identity-permissions-v5-private-product-contracts',
                 'identity-permissions-v6-secret-deletion-cleanup'
             );
             PRAGMA user_version=3;
             COMMIT;",
        )
        .unwrap();
}

fn downgrade_current_database_to_v5(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "BEGIN EXCLUSIVE;
             DROP TABLE secret_deletion_cleanup_records;
             DELETE FROM schema_migrations
             WHERE migration_id='identity-permissions-v6-secret-deletion-cleanup';
             PRAGMA user_version=5;
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
        assert_eq!(repository.schema_version().unwrap(), 6);
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
fn phase2_identity_sqlite_revision_conflicts_preserve_identity_and_preferences() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("identity-revisions.db")).unwrap();

    let identity_v1 = SteinIdentity::shipped_v1(actor(), now());
    let identity_v1_revision = identity_v1.revision;
    repository.save_identity(&identity_v1, None).unwrap();
    let mut winning_identity = identity_v1.clone();
    winning_identity.revision = 2;
    winning_identity.updated_at += Duration::seconds(1);
    winning_identity.provenance.recorded_at = winning_identity.updated_at;
    repository
        .save_identity(&winning_identity, Some(identity_v1_revision))
        .unwrap();

    let mut stale_identity = identity_v1;
    stale_identity.revision = 2;
    stale_identity.updated_at += Duration::seconds(2);
    stale_identity.provenance.recorded_at = stale_identity.updated_at;
    let identity_error = repository
        .save_identity(&stale_identity, Some(identity_v1_revision))
        .unwrap_err();
    assert_eq!(identity_error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_identity(actor()).unwrap(),
        Some(winning_identity)
    );

    let preferences_v1 = ExplicitPreferences::phase2_defaults(actor(), now());
    let preferences_v1_revision = preferences_v1.revision;
    repository.save_preferences(&preferences_v1, None).unwrap();
    let mut winning_preferences = preferences_v1.clone();
    winning_preferences.revision = 2;
    winning_preferences.proactive_interventions_muted = true;
    winning_preferences.updated_at += Duration::seconds(1);
    repository
        .save_preferences(&winning_preferences, Some(preferences_v1_revision))
        .unwrap();

    let mut stale_preferences = preferences_v1;
    stale_preferences.revision = 2;
    stale_preferences.preferred_form_of_address = Some("Stale synthetic value".to_owned());
    stale_preferences.updated_at += Duration::seconds(2);
    let preferences_error = repository
        .save_preferences(&stale_preferences, Some(preferences_v1_revision))
        .unwrap_err();
    assert_eq!(preferences_error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_preferences(actor()).unwrap(),
        Some(winning_preferences)
    );
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
fn model_route_creation_rejects_a_shared_secret_reference_without_partial_state() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("approval-scoped-secret-ref.db")).unwrap();
    let mut graph = synthetic_graph(actor(), 0x4b0);
    graph.route.secret_ref = stein_core::SecretRef::new("shared-provider-route-name");

    let error = repository
        .create_model_route(&graph.route, &graph.route_receipt, &graph.route_audit)
        .unwrap_err();

    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
    assert!(repository.load_model_routes(actor()).unwrap().is_empty());
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
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn memory_focus_lifecycle_transition_commits_session_and_audit_together() {
    let repository = MemoryRepository::default();
    let graph = synthetic_graph(actor(), 0x4c0);
    repository.save_focus_session(&graph.session, None).unwrap();
    let mut stopping = graph.session.clone();
    stopping.state = FocusSessionState::Stopping;
    stopping.revision += 1;
    stopping.updated_at += Duration::seconds(1);
    let mut audit = creation_audit(
        actor(),
        0x4d0,
        AuditKind::FocusSessionStateChanged,
        stopping.id.as_uuid(),
    );
    audit.reason_codes = vec!["focus_session_stopping".to_owned()];
    let write = FocusSessionLifecycleWrite {
        session: stopping.clone(),
        expected_revision: graph.session.revision,
        audit: audit.clone(),
    };

    repository.save_focus_session_transition(&write).unwrap();

    assert_eq!(
        repository.find_focus_session(stopping.id).unwrap(),
        Some(stopping)
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .contains(&audit)
    );
}

#[test]
fn sqlite_focus_lifecycle_transition_rolls_back_when_audit_conflicts() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("atomic-focus-lifecycle.db");
    let graph = synthetic_graph(actor(), 0x520);
    let repository = SqliteRepository::open(&path).unwrap();
    install_graph_foundation(&repository, &graph);
    let original = graph.session.clone();
    let mut stopping = original.clone();
    stopping.state = FocusSessionState::Stopping;
    stopping.revision += 1;
    stopping.updated_at += Duration::seconds(1);
    let mut audit = creation_audit(
        actor(),
        0x5f0,
        AuditKind::FocusSessionStateChanged,
        stopping.id.as_uuid(),
    );
    audit.reason_codes = vec!["focus_session_stopping".to_owned()];
    let write = FocusSessionLifecycleWrite {
        session: stopping.clone(),
        expected_revision: original.revision,
        audit: audit.clone(),
    };

    repository.save_focus_session_transition(&write).unwrap();
    drop(repository);

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(
        repository.find_focus_session(stopping.id).unwrap(),
        Some(stopping.clone())
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .contains(&audit)
    );

    let mut ended = stopping.clone();
    ended.state = FocusSessionState::Ended;
    ended.revision += 1;
    ended.ended_at = Some(now() + Duration::seconds(3));
    ended.updated_at = now() + Duration::seconds(3);
    let conflicting = FocusSessionLifecycleWrite {
        session: ended,
        expected_revision: stopping.revision,
        audit,
    };
    let error = repository
        .save_focus_session_transition(&conflicting)
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.find_focus_session(stopping.id).unwrap(),
        Some(stopping)
    );
}

#[test]
fn memory_permission_and_intervention_transitions_commit_with_their_audits() {
    let repository = MemoryRepository::default();
    let graph = synthetic_graph(actor(), 0x620);
    let original_grant = graph.bound_grants[0].clone();
    repository.save_grant(&original_grant, None).unwrap();
    let mut revoked = original_grant.clone();
    revoked.revision += 1;
    revoked.state = GrantState::Revoked;
    revoked.revoked_at = Some(now() + Duration::seconds(3));
    revoked.revocation_reason = Some("synthetic_revocation".to_owned());
    let permission_audit = creation_audit(
        actor(),
        0x680,
        AuditKind::PermissionRevoked,
        revoked.id.as_uuid(),
    );
    repository
        .save_permission_grant_revocation(&PermissionGrantRevocationWrite {
            grant: revoked.clone(),
            expected_revision: original_grant.revision,
            audit: permission_audit.clone(),
        })
        .unwrap();

    repository
        .save_intervention(&graph.intervention, None)
        .unwrap();
    repository.save_policy_decision(&graph.policy).unwrap();
    let mut delivering = graph.intervention.clone();
    delivering.revision += 1;
    delivering.state = InterventionState::Delivering;
    delivering.updated_at = now() + Duration::seconds(3);
    let mut attempt_audit = creation_audit(
        actor(),
        0x690,
        AuditKind::InterventionDelivery,
        delivering.id.as_uuid(),
    );
    attempt_audit.policy_trace = Some(graph.policy.policy_trace.clone());
    repository
        .save_intervention_transition(&InterventionTransitionWrite {
            intervention: delivering.clone(),
            expected_revision: graph.intervention.revision,
            audit: attempt_audit.clone(),
            delivery: None,
        })
        .unwrap();

    let mut delivered = delivering.clone();
    delivered.revision += 1;
    delivered.state = InterventionState::AcceptedByChannel;
    delivered.delivered_at = Some(now() + Duration::seconds(4));
    delivered.updated_at = now() + Duration::seconds(4);
    let mut delivery_audit = creation_audit(
        actor(),
        0x692,
        AuditKind::InterventionDelivery,
        delivered.id.as_uuid(),
    );
    delivery_audit.policy_trace = Some(graph.policy.policy_trace.clone());
    repository
        .save_intervention_transition(&InterventionTransitionWrite {
            intervention: delivered.clone(),
            expected_revision: delivering.revision,
            audit: delivery_audit.clone(),
            delivery: None,
        })
        .unwrap();

    assert_eq!(repository.load_grants(actor()).unwrap(), vec![revoked]);
    assert_eq!(
        repository.load_interventions(actor()).unwrap(),
        vec![delivered]
    );
    let audit = repository
        .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
        .unwrap();
    assert!(audit.contains(&permission_audit));
    assert!(audit.contains(&attempt_audit));
    assert!(audit.contains(&delivery_audit));
}

#[test]
fn sqlite_permission_revocation_rolls_back_when_its_audit_conflicts() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("permission-revocation-atomic.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x6a0);
    install_graph_foundation(&repository, &graph);
    let original = graph.bound_grants[0].clone();
    let mut revoked = original.clone();
    revoked.revision += 1;
    revoked.state = GrantState::Revoked;
    revoked.revoked_at = Some(now() + Duration::seconds(3));
    revoked.revocation_reason = Some("synthetic_revocation".to_owned());
    let mut audit = creation_audit(
        actor(),
        0x6f0,
        AuditKind::PermissionRevoked,
        revoked.id.as_uuid(),
    );
    audit.id = graph.route_audit.id;

    let error = repository
        .save_permission_grant_revocation(&PermissionGrantRevocationWrite {
            grant: revoked,
            expected_revision: original.revision,
            audit,
        })
        .unwrap_err();

    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository
            .load_grants(actor())
            .unwrap()
            .into_iter()
            .find(|grant| grant.id == original.id),
        Some(original)
    );
}

#[test]
fn sqlite_intervention_delivery_and_feedback_roll_back_on_audit_conflict() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("intervention-transition-atomic.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x720);
    install_graph(&repository, &graph, false, false);

    let mut queued = graph.intervention.clone();
    queued.revision += 1;
    queued.state = InterventionState::Queued;
    queued.updated_at = now() + Duration::seconds(3);
    let mut delivery_audit = creation_audit(
        actor(),
        0x780,
        AuditKind::InterventionDelivery,
        queued.id.as_uuid(),
    );
    delivery_audit.id = graph.route_audit.id;
    delivery_audit.policy_trace = Some(graph.policy.policy_trace.clone());
    let error = repository
        .save_intervention_transition(&InterventionTransitionWrite {
            intervention: queued,
            expected_revision: graph.intervention.revision,
            audit: delivery_audit,
            delivery: Some(PendingDeliveryTransition::Enqueue(graph.delivery.clone())),
        })
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_interventions(actor()).unwrap(),
        vec![graph.intervention.clone()]
    );
    assert!(
        repository
            .load_pending_deliveries(actor())
            .unwrap()
            .is_empty()
    );

    let mut accepted = graph.intervention.clone();
    accepted.revision += 1;
    accepted.outcome = InterventionOutcome::Accepted;
    accepted.outcome_at = Some(now() + Duration::seconds(4));
    accepted.updated_at = now() + Duration::seconds(4);
    let mut outcome_audit = creation_audit(
        actor(),
        0x790,
        AuditKind::InterventionOutcome,
        accepted.id.as_uuid(),
    );
    outcome_audit.id = graph.route_audit.id;
    outcome_audit.policy_trace = Some(graph.policy.policy_trace.clone());
    let error = repository
        .save_intervention_transition(&InterventionTransitionWrite {
            intervention: accepted,
            expected_revision: graph.intervention.revision,
            audit: outcome_audit,
            delivery: None,
        })
        .unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_interventions(actor()).unwrap(),
        vec![graph.intervention]
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
fn standalone_policy_audit_without_a_complete_trace_is_rejected() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("incomplete-policy-audit.db")).unwrap();
    let audit = creation_audit(actor(), 0x51a, AuditKind::SignificanceDecision, uuid(0x51b));

    let error = repository.append_audit(&audit).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 10)
            .unwrap()
            .is_empty()
    );
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
fn mismatched_policy_trace_rolls_back_decision_audit_and_intervention() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("decision-policy-trace-conflict.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x548);
    install_graph_foundation(&repository, &graph);
    let mut write = allow_decision_write(&graph);
    write.audit.policy_trace = Some(policy_trace(0x55));

    let error = run_repository_future(repository.commit_intervention_decision(&write)).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
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
fn legacy_policy_and_audit_payloads_decode_without_becoming_authoritative() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy-policy-trace.db");
    let graph = synthetic_graph(actor(), 0x558);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph_foundation(&repository, &graph);
        run_repository_future(
            repository.commit_intervention_decision(&allow_decision_write(&graph)),
        )
        .unwrap();
    }
    {
        let connection = Connection::open(&path).unwrap();
        let policy_payload: String = connection
            .query_row(
                "SELECT payload FROM policy_records WHERE id=?1",
                [graph.policy.id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .unwrap();
        let mut legacy_policy: JsonValue = serde_json::from_str(&policy_payload).unwrap();
        legacy_policy
            .as_object_mut()
            .unwrap()
            .remove("policy_trace");
        connection
            .execute(
                "UPDATE policy_records SET payload=?1 WHERE id=?2",
                params![
                    serde_json::to_string(&legacy_policy).unwrap(),
                    graph.policy.id.as_uuid().as_bytes().to_vec()
                ],
            )
            .unwrap();

        let audit_payload: String = connection
            .query_row(
                "SELECT payload FROM audit_records WHERE id=?1",
                [graph.decision_audit.id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .unwrap();
        let mut legacy_audit: JsonValue = serde_json::from_str(&audit_payload).unwrap();
        legacy_audit.as_object_mut().unwrap().remove("policy_trace");
        connection
            .execute(
                "UPDATE audit_records SET payload=?1 WHERE id=?2",
                params![
                    serde_json::to_string(&legacy_audit).unwrap(),
                    graph.decision_audit.id.as_uuid().as_bytes().to_vec()
                ],
            )
            .unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    let legacy_decision = repository
        .find_policy_decision(graph.policy.id)
        .unwrap()
        .unwrap();
    assert!(!legacy_decision.policy_trace.is_complete());
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .find(|record| record.id == graph.decision_audit.id)
            .is_some_and(|record| record.policy_trace.is_none())
    );
    let mut replay_as_new = legacy_decision;
    replay_as_new.id = PolicyDecisionId::from_uuid(uuid(0x559));
    let error = repository.save_policy_decision(&replay_as_new).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Corrupt);
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
    intervention.revision = 100;
    intervention.state = InterventionState::Queued;
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
fn queued_revalidation_cannot_overwrite_intervention_content() {
    let directory = tempdir().unwrap();
    let repository =
        SqliteRepository::open(directory.path().join("decision-revalidation-shape.db")).unwrap();
    let graph = synthetic_graph(actor(), 0x5a0);
    install_graph(&repository, &graph, false, false);

    let mut queued = graph.intervention.clone();
    queued.revision += 1;
    queued.state = InterventionState::Queued;
    queued.updated_at += Duration::seconds(1);
    let mut queue_audit = creation_audit(
        actor(),
        0x5a1,
        AuditKind::InterventionDelivery,
        queued.id.as_uuid(),
    );
    queue_audit.policy_trace = Some(graph.policy.policy_trace.clone());
    repository
        .save_intervention_transition(&InterventionTransitionWrite {
            intervention: queued.clone(),
            expected_revision: graph.intervention.revision,
            audit: queue_audit,
            delivery: Some(PendingDeliveryTransition::Enqueue(graph.delivery.clone())),
        })
        .unwrap();

    let mut revalidation = allow_decision_write(&graph);
    revalidation.decision.id = PolicyDecisionId::from_uuid(uuid(0x5a2));
    revalidation.audit.id = AuditRecordId::from_uuid(uuid(0x5a3));
    let next = revalidation.intervention.as_mut().unwrap();
    *next = queued.clone();
    next.policy_decision_id = revalidation.decision.id;
    next.revision += 1;
    next.updated_at += Duration::seconds(1);
    next.user_visible_text = "synthetic-overwrite-must-not-commit".to_owned();
    revalidation.expected_intervention_revision = Some(queued.revision);

    let error =
        run_repository_future(repository.commit_intervention_decision(&revalidation)).unwrap_err();
    assert_eq!(error.kind, RepositoryErrorKind::Conflict);
    assert_eq!(
        repository.load_interventions(actor()).unwrap(),
        vec![queued]
    );
    assert!(
        repository
            .find_policy_decision(revalidation.decision.id)
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .all(|record| record.id != revalidation.audit.id)
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
    assert_eq!(repository.schema_version().unwrap(), 6);
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
    assert_eq!(repository.schema_version().unwrap(), 6);
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
fn immediately_preceding_v5_adds_private_secret_cleanup_storage() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("upgrade-from-v5.db");
    let graph = synthetic_graph(actor(), 0x6a0);
    let expected = {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, false);
        repository.load_owner_state(actor()).unwrap()
    };
    downgrade_current_database_to_v5(&path);

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(repository.schema_version().unwrap(), 6);
    assert_eq!(repository.load_owner_state(actor()).unwrap(), expected);
    assert!(
        repository
            .load_secret_deletion_cleanups(actor())
            .unwrap()
            .is_empty()
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
    assert_eq!(repository.schema_version().unwrap(), 6);
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
    assert_eq!(repository.schema_version().unwrap(), 6);
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
    assert_eq!(migrations.len(), 11);
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
fn legacy_outbox_only_unknown_recovers_atomically_without_retry() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("outbox-crash.db");
    let graph = synthetic_graph(actor(), 0xc00);
    {
        let repository = SqliteRepository::open(&path).unwrap();
        install_graph(&repository, &graph, true, false);
        let mut intervention = graph.intervention.clone();
        intervention.state = InterventionState::Delivering;
        intervention.revision += 1;
        intervention.updated_at = now() + Duration::seconds(3);
        let mut delivering = graph.delivery.clone();
        delivering.state = OutboxState::Delivering;
        delivering.attempt_count = 1;
        delivering.last_attempt_at = Some(now() + Duration::seconds(3));
        let mut attempt_audit = creation_audit(
            actor(),
            0xc80,
            AuditKind::InterventionDelivery,
            intervention.id.as_uuid(),
        );
        attempt_audit.reason_codes = vec!["delivery_attempt_started".to_owned()];
        attempt_audit.policy_trace = Some(graph.policy.policy_trace.clone());
        repository
            .save_intervention_transition(&InterventionTransitionWrite {
                intervention,
                expected_revision: graph.intervention.revision,
                audit: attempt_audit,
                delivery: Some(PendingDeliveryTransition::Update {
                    delivery: delivering.clone(),
                    expected_state: OutboxState::Queued,
                }),
            })
            .unwrap();
        // Older repository-open recovery mutated only the outbox. Preserve
        // that historical mismatch as a restart fixture.
        delivering.state = OutboxState::DeliveryUnknown;
        delivering.user_visible_text.clear();
        repository.save_delivery(&delivering).unwrap();
    }

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(
        repository.load_pending_deliveries(actor()).unwrap()[0].state,
        OutboxState::DeliveryUnknown,
        "repository open must not perform an unaudited semantic recovery"
    );
    assert_eq!(
        repository.load_interventions(actor()).unwrap()[0].state,
        InterventionState::Delivering
    );
    let runtime = SecondMindRuntime::new(
        SecondMindConfig::default(),
        SecondMindPorts {
            repository: Arc::new(repository.clone()),
            clock: Arc::new(ManualClock::new(now() + Duration::seconds(4))),
            observation: Arc::new(UnavailableObservationPort),
            model: Arc::new(UnavailableModelGateway),
            notification: Arc::new(UnavailableNotificationPort),
            native_status: Arc::new(UnavailableNativeStatusPort),
            emergency_control: Arc::new(UnavailableEmergencyControlPort),
            secret_store: Arc::new(UnavailableSecretStore::default()),
            resource_selection: Arc::new(UnavailableResourceSelectionPort),
        },
    )
    .unwrap();
    assert_eq!(
        runtime
            .reconcile_interrupted_deliveries(actor())
            .unwrap()
            .len(),
        1
    );
    assert!(
        runtime
            .reconcile_interrupted_deliveries(actor())
            .unwrap()
            .is_empty(),
        "runtime recovery must be idempotent"
    );
    let recovered = repository.load_pending_deliveries(actor()).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].state, OutboxState::DeliveryUnknown);
    assert_eq!(recovered[0].attempt_count, 1);
    assert!(recovered[0].user_visible_text.is_empty());
    assert_eq!(
        repository.load_interventions(actor()).unwrap()[0].state,
        InterventionState::DeliveryUnknown
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .any(|record| {
                record.kind == AuditKind::InterventionDelivery
                    && record
                        .reason_codes
                        .iter()
                        .any(|reason| reason == "delivery_unknown_after_restart")
            })
    );
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
fn memory_and_sqlite_reject_terminal_pointer_replacement_with_identical_results() {
    let directory = tempdir().unwrap();
    let sqlite = SqliteRepository::open(directory.path().join("outbox-pointer-parity.db")).unwrap();
    let memory = MemoryRepository::default();
    let graph = synthetic_graph(actor(), 0xda0);
    install_graph(&sqlite, &graph, true, false);
    install_graph(&memory, &graph, true, false);

    for repository in [
        &memory as &dyn DurableRepository,
        &sqlite as &dyn DurableRepository,
    ] {
        let mut invalid_terminal = graph.delivery.clone();
        invalid_terminal.state = OutboxState::Cancelled;
        invalid_terminal.policy_decision_id = PolicyDecisionId::from_uuid(uuid(0xdff));
        invalid_terminal.user_visible_text.clear();
        assert_eq!(
            repository
                .save_delivery(&invalid_terminal)
                .unwrap_err()
                .kind,
            RepositoryErrorKind::Conflict,
            "only queued -> delivering may adopt a fresh policy decision"
        );

        let mut invalid_bypass = graph.delivery.clone();
        invalid_bypass.state = OutboxState::AcceptedByChannel;
        invalid_bypass.user_visible_text.clear();
        assert_eq!(
            repository.save_delivery(&invalid_bypass).unwrap_err().kind,
            RepositoryErrorKind::Conflict,
            "a queued record cannot bypass the durable attempt marker"
        );

        let mut valid_terminal = graph.delivery.clone();
        valid_terminal.state = OutboxState::Cancelled;
        repository.save_delivery(&valid_terminal).unwrap();
        let persisted = repository
            .load_pending_deliveries(actor())
            .unwrap()
            .into_iter()
            .find(|delivery| delivery.id == valid_terminal.id)
            .unwrap();
        assert!(
            persisted.user_visible_text.is_empty(),
            "both repositories scrub caller-supplied text at terminal save"
        );
    }
}

#[test]
fn memory_and_sqlite_require_a_delivering_intervention_before_delivery_failed() {
    let directory = tempdir().unwrap();
    let sqlite =
        SqliteRepository::open(directory.path().join("delivery-marker-parity.db")).unwrap();
    let memory = MemoryRepository::default();
    let graph = synthetic_graph(actor(), 0xdb0);

    for repository in [
        &memory as &dyn DurableRepository,
        &sqlite as &dyn DurableRepository,
    ] {
        install_graph(repository, &graph, false, false);
        let mut queued = graph.intervention.clone();
        queued.revision = queued.revision.saturating_add(1);
        queued.state = InterventionState::Queued;
        queued.updated_at = now() + Duration::seconds(3);
        let mut queued_audit = creation_audit(
            actor(),
            0xdc8,
            AuditKind::InterventionDelivery,
            queued.id.as_uuid(),
        );
        queued_audit.policy_trace = Some(graph.policy.policy_trace.clone());
        repository
            .save_intervention_transition(&InterventionTransitionWrite {
                intervention: queued.clone(),
                expected_revision: graph.intervention.revision,
                audit: queued_audit,
                delivery: Some(PendingDeliveryTransition::Enqueue(graph.delivery.clone())),
            })
            .unwrap();

        let mut bypass = queued.clone();
        bypass.revision = bypass.revision.saturating_add(1);
        bypass.state = InterventionState::DeliveryFailed;
        bypass.updated_at = now() + Duration::seconds(4);
        let mut bypass_audit = creation_audit(
            actor(),
            0xdca,
            AuditKind::InterventionDelivery,
            bypass.id.as_uuid(),
        );
        bypass_audit.policy_trace = Some(graph.policy.policy_trace.clone());
        assert_eq!(
            repository
                .save_intervention_transition(&InterventionTransitionWrite {
                    intervention: bypass,
                    expected_revision: queued.revision,
                    audit: bypass_audit,
                    delivery: None,
                })
                .unwrap_err()
                .kind,
            RepositoryErrorKind::Conflict
        );
        assert_eq!(
            repository
                .load_interventions(actor())
                .unwrap()
                .into_iter()
                .find(|intervention| intervention.id == queued.id),
            Some(queued)
        );
    }
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
fn revoked_route_and_secret_cleanup_are_atomic_and_survive_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("secret-cleanup.db");
    let graph = synthetic_graph(actor(), 0xdd0);
    let revoked_at = now() + Duration::seconds(11);
    let mut revoked = graph.route.clone();
    let expected_revision = revoked.revision;
    revoked.revision = revoked.revision.saturating_add(1);
    revoked.revoked_at = Some(revoked_at);
    let cleanup = SecretDeletionCleanup {
        owner: actor(),
        model_route_approval_id: revoked.id,
        secret_ref: revoked.secret_ref.clone(),
        created_at: revoked_at,
    };
    let audit = creation_audit(
        actor(),
        0xdf8,
        AuditKind::ModelRouteRevoked,
        revoked.id.as_uuid(),
    );

    {
        let repository = SqliteRepository::open(&path).unwrap();
        repository.save_model_route(&graph.route, None).unwrap();
        repository
            .save_revoked_model_route_with_cleanup(&revoked, expected_revision, &cleanup, &audit)
            .unwrap();
        assert_eq!(
            repository.load_model_routes(actor()).unwrap(),
            vec![revoked.clone()]
        );
        assert_eq!(
            repository.load_secret_deletion_cleanups(actor()).unwrap(),
            vec![cleanup.clone()]
        );
    }

    let repository = SqliteRepository::open(&path).unwrap();
    assert_eq!(
        repository.load_model_routes(actor()).unwrap(),
        vec![revoked]
    );
    assert_eq!(
        repository.load_secret_deletion_cleanups(actor()).unwrap(),
        vec![cleanup]
    );
    assert!(
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .iter()
            .any(|record| record.id == audit.id)
    );
    repository
        .complete_secret_deletion_cleanup(actor(), graph.route.id)
        .unwrap();
    repository
        .complete_secret_deletion_cleanup(actor(), graph.route.id)
        .unwrap();
    assert!(
        repository
            .load_secret_deletion_cleanups(actor())
            .unwrap()
            .is_empty()
    );
    assert!(
        repository.load_model_routes(actor()).unwrap()[0]
            .revoked_at
            .is_some()
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
fn phase2_retention_sqlite_delete_scrubs_all_reads_restart_and_recovery_copy() {
    const INTERVENTION_MARKER: &str = "synthetic-retention-private-intervention-v1";
    const EVIDENCE_MARKER: &str = "synthetic-retention-private-evidence-v1";
    const OUTBOX_MARKER: &str = "synthetic-retention-private-outbox-v1";
    const MARKERS: &[&str] = &[INTERVENTION_MARKER, EVIDENCE_MARKER, OUTBOX_MARKER];

    let directory = tempdir().unwrap();
    let database_path = directory.path().join("retention-delete.db");
    let recovery_path = directory.path().join("retention-delete-recovery.db");
    let mut graph = synthetic_graph(actor(), 0xe90);
    graph.intervention.user_visible_text = INTERVENTION_MARKER.to_owned();
    graph.intervention.evidence_summary = EVIDENCE_MARKER.to_owned();
    graph.delivery.user_visible_text = OUTBOX_MARKER.to_owned();

    {
        let repository = SqliteRepository::open(&database_path).unwrap();
        install_graph(&repository, &graph, true, true);
        let encoded = serde_json::to_vec(&(
            repository.load_interventions(actor()).unwrap(),
            repository.load_pending_deliveries(actor()).unwrap(),
        ))
        .unwrap();
        for marker in MARKERS {
            assert!(artifact_contains(&encoded, marker));
        }
    }

    let bytes_before_delete = fs::read(&database_path).unwrap();
    for marker in MARKERS {
        assert!(
            artifact_contains(&bytes_before_delete, marker),
            "the pre-delete database did not contain synthetic marker {marker}"
        );
    }

    let assert_deleted_reads = |repository: &dyn DurableRepository| {
        let snapshot = repository.load_owner_state(actor()).unwrap();
        assert!(snapshot.goals.is_empty());
        assert!(snapshot.resources.is_empty());
        assert!(snapshot.grants.is_empty());
        assert!(snapshot.focus_sessions.is_empty());
        assert!(snapshot.interventions.is_empty());
        assert!(snapshot.policy_decisions.is_empty());
        assert!(snapshot.pending_deliveries.is_empty());
        assert_eq!(snapshot.identity.as_ref(), Some(&graph.identity));
        assert_eq!(snapshot.preferences.as_ref(), Some(&graph.preferences));
        assert_eq!(snapshot.model_routes, vec![graph.route.clone()]);

        assert!(repository.load_goals(actor()).unwrap().is_empty());
        assert!(repository.load_resources(actor()).unwrap().is_empty());
        assert!(repository.load_grants(actor()).unwrap().is_empty());
        assert!(repository.load_focus_sessions(actor()).unwrap().is_empty());
        assert!(repository.load_interventions(actor()).unwrap().is_empty());
        assert!(
            repository
                .load_pending_deliveries(actor())
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .find_policy_decision(graph.policy.id)
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
        for receipt in &graph.grant_receipts {
            assert!(
                repository
                    .find_operation_receipt(
                        actor(),
                        OperationKind::GrantSessionPermission,
                        receipt.idempotency_key,
                    )
                    .unwrap()
                    .is_none()
            );
        }
        let audits = repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap();
        assert_eq!(audits, vec![graph.route_audit.clone()]);
        let encoded = serde_json::to_vec(&audits).unwrap();
        for marker in MARKERS {
            assert!(!artifact_contains(&encoded, marker));
        }
        let replay = repository
            .delete_goal_with_tombstone(
                actor(),
                graph.goal.id,
                graph.goal.revision.get(),
                now() + Duration::hours(1),
            )
            .unwrap();
        assert!(replay.already_deleted);
        assert_eq!(replay.tombstone.goal_id, graph.goal.id);
        assert_eq!(replay.tombstone.deleted_revision, graph.goal.revision.get());
        assert_eq!(replay.tombstone.deleted_at, now() + Duration::seconds(3));
    };

    {
        let repository = SqliteRepository::open(&database_path).unwrap();
        let result = repository
            .delete_goal_with_tombstone(
                actor(),
                graph.goal.id,
                graph.goal.revision.get(),
                now() + Duration::seconds(3),
            )
            .unwrap();
        assert!(!result.already_deleted);
        assert_eq!(result.tombstone.summary.goals, 1);
        assert_eq!(result.tombstone.summary.focus_sessions, 1);
        assert_eq!(result.tombstone.summary.interventions, 1);
        assert_eq!(result.tombstone.summary.outbox_entries, 1);
        assert_deleted_reads(&repository);
        repository.create_recovery_copy(&recovery_path).unwrap();
    }

    assert_sqlite_artifacts_exclude(&database_path, MARKERS);
    assert_sqlite_artifacts_exclude(&recovery_path, MARKERS);

    let restarted = SqliteRepository::open(&database_path).unwrap();
    restarted.health().unwrap();
    assert_deleted_reads(&restarted);
    drop(restarted);

    let recovery = SqliteRepository::open(&recovery_path).unwrap();
    recovery.health().unwrap();
    assert_deleted_reads(&recovery);
    drop(recovery);

    assert_sqlite_artifacts_exclude(&database_path, MARKERS);
    assert_sqlite_artifacts_exclude(&recovery_path, MARKERS);
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
    const AUDIT_MARKER: &str = "synthetic-retention-audit-marker-v1";
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("audit-expiry.db");
    let recovery_path = directory.path().join("audit-expiry-recovery.db");
    let count = {
        let repository = SqliteRepository::open(&database_path).unwrap();
        let graph = synthetic_graph(actor(), 0xf00);
        install_graph(&repository, &graph, false, true);
        let mut marker = creation_audit(
            actor(),
            0xff0,
            AuditKind::FocusSessionStateChanged,
            uuid(0xff1),
        );
        marker.reason_codes = vec![AUDIT_MARKER.to_owned()];
        repository.append_audit(&marker).unwrap();
        repository
            .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
            .unwrap()
            .len() as u64
    };
    assert!(artifact_contains(
        &fs::read(&database_path).unwrap(),
        AUDIT_MARKER
    ));

    {
        let repository = SqliteRepository::open(&database_path).unwrap();
        assert_eq!(
            repository
                .purge_expired_audit(now() + Duration::days(30) - Duration::nanoseconds(1))
                .unwrap(),
            0
        );
        assert_eq!(
            repository
                .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .len() as u64,
            count
        );
        assert_eq!(
            repository
                .purge_expired_audit(now() + Duration::days(30))
                .unwrap(),
            count
        );
        assert!(
            repository
                .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            repository
                .purge_expired_audit(now() + Duration::days(31))
                .unwrap(),
            0
        );
        repository.create_recovery_copy(&recovery_path).unwrap();
    }

    assert_sqlite_artifacts_exclude(&database_path, &[AUDIT_MARKER]);
    assert_sqlite_artifacts_exclude(&recovery_path, &[AUDIT_MARKER]);
    for path in [&database_path, &recovery_path] {
        let repository = SqliteRepository::open(path).unwrap();
        repository.health().unwrap();
        assert!(
            repository
                .load_audit(actor(), OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .is_empty()
        );
    }
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
