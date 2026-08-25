use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::{
    ActorId, AuditKind, AuditRecord, DeviceId, DeviceRegistration, ExplicitPreferences,
    FocusSession, FocusSessionState, Goal, GoalId, GrantState, IdempotencyKey, Intervention,
    InterventionDecisionWrite, InterventionOutcome, InterventionState, ModelRouteApproval,
    OutboxState, PendingInterventionDelivery, PermissionGrant, PolicyDecision, PortFuture,
    ResourceBinding, SelectedResourceDeletionTombstone, SteinIdentity,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnerStateSnapshot {
    pub current_device: Option<DeviceRegistration>,
    pub goals: Vec<Goal>,
    pub identity: Option<SteinIdentity>,
    pub preferences: Option<ExplicitPreferences>,
    pub resources: Vec<ResourceBinding>,
    pub grants: Vec<PermissionGrant>,
    pub model_routes: Vec<ModelRouteApproval>,
    pub focus_sessions: Vec<FocusSession>,
    pub interventions: Vec<Intervention>,
    pub policy_decisions: Vec<PolicyDecision>,
    pub pending_deliveries: Vec<PendingInterventionDelivery>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryErrorKind {
    Conflict,
    NotFound,
    Corrupt,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryError {
    pub kind: RepositoryErrorKind,
    pub summary: &'static str,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.summary)
    }
}

impl std::error::Error for RepositoryError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalCreateReceipt {
    pub actor: ActorId,
    pub idempotency_key: IdempotencyKey,
    pub goal_id: GoalId,
    pub title: String,
    pub success_statement: String,
    pub deadline: Option<OffsetDateTime>,
}

/// Actor-and-command scoped identity for an aggregate-creating operation.
///
/// The string representation is durable schema, so adapters must store the
/// value returned by [`Self::wire_name`] rather than a Rust discriminant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ApproveModelRoute,
    GrantSessionPermission,
    StartFocusSession,
    RegisterSelectedResource,
}

impl OperationKind {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ApproveModelRoute => "approve_model_route",
            Self::GrantSessionPermission => "grant_session_permission",
            Self::StartFocusSession => "start_focus_session",
            Self::RegisterSelectedResource => "register_selected_resource",
        }
    }

    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "approve_model_route" => Some(Self::ApproveModelRoute),
            "grant_session_permission" => Some(Self::GrantSessionPermission),
            "start_focus_session" => Some(Self::StartFocusSession),
            "register_selected_resource" => Some(Self::RegisterSelectedResource),
            _ => None,
        }
    }
}

/// Durable replay receipt. `request_digest` is a SHA-256 digest of the typed
/// public request body; it contains no credential or captured/private payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationReceipt {
    pub owner: ActorId,
    pub kind: OperationKind,
    pub idempotency_key: IdempotencyKey,
    pub request_digest: [u8; 32],
    pub result_id: uuid::Uuid,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeletionSummary {
    pub goals: u64,
    pub focus_sessions: u64,
    pub grants: u64,
    pub interventions: u64,
    pub outbox_entries: u64,
    pub audit_records: u64,
    pub resource_bindings: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalDeletionTombstone {
    pub owner: ActorId,
    pub goal_id: GoalId,
    pub deleted_revision: u64,
    pub deleted_at: OffsetDateTime,
    pub summary: DeletionSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalDeletionResult {
    pub tombstone: GoalDeletionTombstone,
    pub already_deleted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedResourceDeletionResult {
    pub tombstone: SelectedResourceDeletionTombstone,
    pub already_removed: bool,
}

/// Private durable cleanup obligation. It never enters snapshots, events, or
/// protocol DTOs; retaining it lets CORE retry native registry cleanup without
/// restoring removed authority.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeResourceCleanup {
    pub owner: ActorId,
    pub resource_id: crate::ResourceId,
    pub opaque_reference: String,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for NativeResourceCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeResourceCleanup")
            .field("owner", &self.owner)
            .field("resource_id", &self.resource_id)
            .field("opaque_reference", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Drop for NativeResourceCleanup {
    fn drop(&mut self) {
        self.opaque_reference.zeroize();
    }
}

/// Private durable obligation to delete a provider credential after its model
/// route authority has already been revoked. The opaque secret reference is
/// bounded metadata, never the secret value, and never enters public views.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretDeletionCleanup {
    pub owner: ActorId,
    pub model_route_approval_id: crate::ModelRouteApprovalId,
    pub secret_ref: crate::SecretRef,
    pub created_at: OffsetDateTime,
}

/// One durable focus-workflow state transition and its content-free lifecycle
/// audit. Repositories commit this write as one atomic unit so a crash cannot
/// leave the new authority/lifecycle state without its corresponding audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusSessionLifecycleWrite {
    pub session: FocusSession,
    pub expected_revision: u64,
    pub audit: AuditRecord,
}

impl FocusSessionLifecycleWrite {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.expected_revision == u64::MAX
            || self.session.revision != self.expected_revision + 1
            || self.audit.owner != self.session.owner
            || self.audit.kind != AuditKind::FocusSessionStateChanged
            || self.audit.subject_id != self.session.id.as_uuid()
            || self.audit.reason_codes.is_empty()
            || self.audit.expires_at <= self.audit.occurred_at
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A focus-session lifecycle audit does not match its revision transition.",
            });
        }
        Ok(())
    }

    pub fn validate_against(&self, current: &FocusSession) -> Result<(), RepositoryError> {
        self.validate()?;
        if current.id != self.session.id
            || current.owner != self.session.owner
            || current.goal_id != self.session.goal_id
            || current.goal_revision != self.session.goal_revision
            || current.revision != self.expected_revision
            || !valid_focus_session_state_transition(current.state, self.session.state)
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The focus-session lifecycle transition is stale or invalid.",
            });
        }
        Ok(())
    }
}

const fn valid_focus_session_state_transition(
    current: FocusSessionState,
    next: FocusSessionState,
) -> bool {
    matches!(
        (current, next),
        (FocusSessionState::Requested, FocusSessionState::Starting)
            | (FocusSessionState::Requested, FocusSessionState::Stopping)
            | (FocusSessionState::Requested, FocusSessionState::Ended)
            | (FocusSessionState::Requested, FocusSessionState::Failed)
            | (FocusSessionState::Starting, FocusSessionState::Active)
            | (FocusSessionState::Starting, FocusSessionState::Recovering)
            | (FocusSessionState::Starting, FocusSessionState::Stopping)
            | (FocusSessionState::Starting, FocusSessionState::Ended)
            | (FocusSessionState::Starting, FocusSessionState::Failed)
            | (FocusSessionState::Active, FocusSessionState::Recovering)
            | (FocusSessionState::Active, FocusSessionState::Stopping)
            | (FocusSessionState::Active, FocusSessionState::Ended)
            | (FocusSessionState::Active, FocusSessionState::Failed)
            | (FocusSessionState::Recovering, FocusSessionState::Active)
            | (FocusSessionState::Recovering, FocusSessionState::Stopping)
            | (FocusSessionState::Recovering, FocusSessionState::Ended)
            | (FocusSessionState::Recovering, FocusSessionState::Failed)
            | (FocusSessionState::Stopping, FocusSessionState::Ended)
    )
}

/// One permission-grant revocation and its content-free audit record.
/// Repositories commit both records atomically before adapter cleanup begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionGrantRevocationWrite {
    pub grant: PermissionGrant,
    pub expected_revision: u64,
    pub audit: AuditRecord,
}

impl PermissionGrantRevocationWrite {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.expected_revision == u64::MAX
            || self.grant.revision != self.expected_revision + 1
            || self.grant.state != GrantState::Revoked
            || self.grant.revoked_at.is_none()
            || self
                .grant
                .revocation_reason
                .as_ref()
                .is_none_or(String::is_empty)
            || self.audit.owner != self.grant.owner
            || self.audit.kind != AuditKind::PermissionRevoked
            || self.audit.subject_id != self.grant.id.as_uuid()
            || self.audit.reason_codes.is_empty()
            || self.audit.expires_at <= self.audit.occurred_at
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A permission-revocation audit does not match its revision transition.",
            });
        }
        Ok(())
    }

    pub fn validate_against(&self, current: &PermissionGrant) -> Result<(), RepositoryError> {
        self.validate()?;
        let mut expected = current.clone();
        expected.revision = self.grant.revision;
        expected.state = GrantState::Revoked;
        expected.revoked_at = self.grant.revoked_at;
        expected
            .revocation_reason
            .clone_from(&self.grant.revocation_reason);
        if current.revision != self.expected_revision
            || current.state != GrantState::Active
            || expected != self.grant
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The permission-grant revocation is stale or invalid.",
            });
        }
        Ok(())
    }
}

/// Optional outbox mutation committed with an intervention transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingDeliveryTransition {
    Enqueue(PendingInterventionDelivery),
    Update {
        delivery: PendingInterventionDelivery,
        expected_state: OutboxState,
    },
    /// Repairs a pre-existing intervention/outbox state mismatch during
    /// startup. This is the only typed path that may reconcile an unmarked
    /// queued intervention to an already-terminal or attempted outbox state.
    ReconcileLegacy {
        delivery: PendingInterventionDelivery,
        expected_state: OutboxState,
    },
}

impl InterventionDecisionWrite {
    /// Validates the shape of an initial decision or queued-delivery
    /// revalidation before a repository transaction begins.
    pub fn validate(&self) -> Result<(), RepositoryError> {
        let decision = &self.decision;
        if self.audit.owner != decision.owner
            || self.audit.kind != AuditKind::InterventionDecision
            || self.audit.subject_id != decision.candidate_id.as_uuid()
            || self.audit.reason_codes != decision.reason_codes
            || !decision.policy_trace.is_complete()
            || decision.policy_version != decision.policy_trace.policy_profile_id
            || self.audit.policy_trace.as_ref() != Some(&decision.policy_trace)
            || (decision.outcome == crate::PolicyOutcome::Allow) != self.intervention.is_some()
            || decision.issued_at >= decision.expires_at
            || (decision.outcome == crate::PolicyOutcome::Allow
                && (decision.permission_grant_revisions.is_empty() || decision.channel.is_empty()))
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "An intervention decision audit does not match its decision.",
            });
        }

        match (&self.intervention, self.expected_intervention_revision) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "An intervention revision was supplied without an intervention.",
            }),
            (Some(intervention), None)
                if intervention.owner == decision.owner
                    && intervention.candidate_id == decision.candidate_id
                    && intervention.candidate_revision == decision.candidate_revision
                    && intervention.policy_decision_id == decision.id
                    && intervention.focus_session_id == decision.focus_session_id
                    && intervention.revision == 1
                    && intervention.state == InterventionState::Allowed
                    && intervention.outcome == InterventionOutcome::Unacknowledged
                    && intervention.outcome_at.is_none()
                    && intervention.delivered_at.is_none()
                    && intervention.correction_summary.is_none()
                    && intervention.created_at < intervention.expires_at
                    && intervention.expires_at <= decision.expires_at
                    && intervention.delivery_channel.as_deref() == Some(&decision.channel)
                    && intervention.created_at == intervention.updated_at =>
            {
                Ok(())
            }
            (Some(intervention), Some(expected_revision))
                if expected_revision != u64::MAX
                    && intervention.owner == decision.owner
                    && intervention.candidate_id == decision.candidate_id
                    && intervention.candidate_revision == decision.candidate_revision
                    && intervention.policy_decision_id == decision.id
                    && intervention.focus_session_id == decision.focus_session_id
                    && intervention.revision == expected_revision + 1
                    && intervention.state == InterventionState::Queued
                    && intervention.expires_at >= decision.expires_at
                    && intervention.delivery_channel.as_deref() == Some(&decision.channel) =>
            {
                Ok(())
            }
            (Some(_), _) => Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "An intervention record does not match its policy decision.",
            }),
        }
    }

    /// Validates that the intervention side of this decision is either a new
    /// Allowed record or a narrowly scoped Queued-to-Queued revalidation.
    pub fn validate_against(&self, current: Option<&Intervention>) -> Result<(), RepositoryError> {
        self.validate()?;
        let Some(next) = &self.intervention else {
            return Ok(());
        };
        match (current, self.expected_intervention_revision) {
            (None, None) => Ok(()),
            (Some(current), Some(expected_revision)) => {
                let mut expected = current.clone();
                expected.policy_decision_id = self.decision.id;
                expected.revision = next.revision;
                expected.updated_at = next.updated_at;
                if current.state == InterventionState::Queued
                    && current.revision == expected_revision
                    && expected == *next
                {
                    Ok(())
                } else {
                    Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "The queued intervention revalidation is stale or invalid.",
                    })
                }
            }
            (Some(_), None) | (None, Some(_)) => Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The intervention decision revision changed.",
            }),
        }
    }
}

impl PendingDeliveryTransition {
    #[must_use]
    pub const fn delivery(&self) -> &PendingInterventionDelivery {
        match self {
            Self::Enqueue(delivery)
            | Self::Update { delivery, .. }
            | Self::ReconcileLegacy { delivery, .. } => delivery,
        }
    }

    pub fn validate_against(
        &self,
        current: Option<&PendingInterventionDelivery>,
    ) -> Result<(), RepositoryError> {
        match (self, current) {
            (Self::Enqueue(next), None) => validate_new_pending_delivery(next),
            (
                Self::Update {
                    delivery: next,
                    expected_state,
                }
                | Self::ReconcileLegacy {
                    delivery: next,
                    expected_state,
                },
                Some(current),
            ) if current.state == *expected_state => {
                validate_pending_delivery_update(current, next)
            }
            (Self::Enqueue(_), Some(_))
            | (Self::Update { .. } | Self::ReconcileLegacy { .. }, None) => Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The pending-delivery transition is stale.",
            }),
            (Self::Update { .. } | Self::ReconcileLegacy { .. }, Some(_)) => Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The pending-delivery state changed concurrently.",
            }),
        }
    }
}

/// One intervention delivery/outcome revision, its required audit, and the
/// optional outbox state written by that same logical transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterventionTransitionWrite {
    pub intervention: Intervention,
    pub expected_revision: u64,
    pub audit: AuditRecord,
    pub delivery: Option<PendingDeliveryTransition>,
}

impl InterventionTransitionWrite {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.expected_revision == u64::MAX
            || self.intervention.revision != self.expected_revision + 1
            || self.audit.owner != self.intervention.owner
            || self.audit.subject_id != self.intervention.id.as_uuid()
            || !matches!(
                self.audit.kind,
                AuditKind::InterventionDelivery | AuditKind::InterventionOutcome
            )
            || self.audit.reason_codes.is_empty()
            || self.audit.expires_at <= self.audit.occurred_at
            || self
                .audit
                .policy_trace
                .as_ref()
                .is_some_and(|trace| !trace.is_complete())
            || (self.audit.kind == AuditKind::InterventionOutcome && self.delivery.is_some())
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "An intervention audit does not match its revision transition.",
            });
        }
        if let Some(delivery) = &self.delivery {
            let delivery = delivery.delivery();
            if delivery.owner != self.intervention.owner
                || delivery.intervention_id != self.intervention.id
                || delivery.candidate_revision != self.intervention.candidate_revision
                || (delivery.policy_decision_id != self.intervention.policy_decision_id
                    && !matches!(
                        delivery.state,
                        OutboxState::Expired | OutboxState::Cancelled
                    ))
                || !delivery_state_matches_intervention(delivery.state, self.intervention.state)
            {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Corrupt,
                    summary: "A pending delivery does not match its intervention transition.",
                });
            }
        }
        Ok(())
    }

    pub fn validate_against(&self, current: &Intervention) -> Result<(), RepositoryError> {
        self.validate()?;
        if current.id != self.intervention.id
            || current.owner != self.intervention.owner
            || current.goal_id != self.intervention.goal_id
            || current.focus_session_id != self.intervention.focus_session_id
            || current.candidate_id != self.intervention.candidate_id
            || current.candidate_revision != self.intervention.candidate_revision
            || current.created_at != self.intervention.created_at
            || current.expires_at != self.intervention.expires_at
            || current.revision != self.expected_revision
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The intervention transition is stale or changed its identity.",
            });
        }
        match self.audit.kind {
            AuditKind::InterventionOutcome => {
                let mut expected = current.clone();
                expected.revision = self.intervention.revision;
                expected.outcome = self.intervention.outcome;
                expected.outcome_at = self.intervention.outcome_at;
                expected
                    .correction_summary
                    .clone_from(&self.intervention.correction_summary);
                expected.updated_at = self.intervention.updated_at;
                if self.intervention.outcome == InterventionOutcome::Unacknowledged
                    || expected != self.intervention
                {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "The intervention outcome transition is invalid.",
                    });
                }
            }
            AuditKind::InterventionDelivery => {
                let legacy_reconciliation = matches!(
                    self.delivery,
                    Some(PendingDeliveryTransition::ReconcileLegacy { .. })
                );
                if !valid_intervention_delivery_transition(
                    current.state,
                    self.intervention.state,
                    legacy_reconciliation,
                ) || !valid_intervention_delivery_update(current, &self.intervention)
                    || (legacy_reconciliation
                        && !valid_legacy_intervention_reconciliation(self, current))
                {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "The intervention delivery transition is invalid.",
                    });
                }
            }
            _ => unreachable!("validated intervention audit kind"),
        }
        Ok(())
    }

    /// Binds every intervention revision to the exact durable allow decision
    /// referenced by the intervention. This is repository-independent so the
    /// in-memory and SQLite adapters enforce identical policy provenance.
    pub fn validate_policy_against(
        &self,
        decision: Option<&PolicyDecision>,
    ) -> Result<(), RepositoryError> {
        let Some(decision) = decision else {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "The intervention policy decision is unavailable.",
            });
        };
        let trace_matches = if decision.policy_trace.is_complete() {
            self.audit.policy_trace.as_ref() == Some(&decision.policy_trace)
                && decision.policy_version == decision.policy_trace.policy_profile_id
        } else {
            self.audit.policy_trace.is_none()
        };
        if decision.id != self.intervention.policy_decision_id
            || decision.owner != self.intervention.owner
            || decision.focus_session_id != self.intervention.focus_session_id
            || decision.candidate_id != self.intervention.candidate_id
            || decision.candidate_revision != self.intervention.candidate_revision
            || decision.outcome != crate::PolicyOutcome::Allow
            || !trace_matches
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "The intervention revision does not match its policy decision.",
            });
        }
        Ok(())
    }
}

fn valid_intervention_delivery_transition(
    current: InterventionState,
    next: InterventionState,
    legacy_reconciliation: bool,
) -> bool {
    matches!(
        (current, next),
        (
            InterventionState::Allowed,
            InterventionState::Queued
                | InterventionState::Delivering
                | InterventionState::Expired
                | InterventionState::Cancelled
        ) | (
            InterventionState::Queued,
            InterventionState::Delivering
                | InterventionState::Expired
                | InterventionState::Cancelled
        ) | (
            InterventionState::Delivering,
            InterventionState::AcceptedByChannel
                | InterventionState::DeliveryUnknown
                | InterventionState::DeliveryFailed
                | InterventionState::Expired
                | InterventionState::Cancelled
        )
    ) || (legacy_reconciliation
        && current == InterventionState::Queued
        && matches!(
            next,
            InterventionState::AcceptedByChannel
                | InterventionState::DeliveryUnknown
                | InterventionState::DeliveryFailed
                | InterventionState::Expired
                | InterventionState::Cancelled
        ))
}

fn valid_intervention_delivery_update(current: &Intervention, next: &Intervention) -> bool {
    if next.updated_at < current.updated_at {
        return false;
    }
    let private_content_same = next.user_visible_text == current.user_visible_text
        && next.evidence_summary == current.evidence_summary
        && next.evidence == current.evidence;
    let private_content_cleared = next.user_visible_text.is_empty()
        && next.evidence_summary.is_empty()
        && next.evidence.is_empty();
    if !private_content_same && !private_content_cleared {
        return false;
    }

    let mut expected = current.clone();
    expected.revision = next.revision;
    expected.state = next.state;
    expected.updated_at = next.updated_at;
    if private_content_cleared {
        expected.user_visible_text.clear();
        expected.evidence_summary.clear();
        expected.evidence.clear();
    }

    match next.state {
        InterventionState::Queued | InterventionState::Delivering => {
            if !private_content_same {
                return false;
            }
        }
        InterventionState::AcceptedByChannel => {
            if next.delivered_at.is_none() {
                return false;
            }
            expected.delivered_at = next.delivered_at;
        }
        InterventionState::DeliveryUnknown => {}
        InterventionState::DeliveryFailed => {
            if next.reason_code.is_empty() {
                return false;
            }
            expected.reason_code.clone_from(&next.reason_code);
        }
        InterventionState::Expired | InterventionState::Cancelled => {
            if !private_content_cleared
                || next.outcome != InterventionOutcome::Expired
                || next.outcome_at.is_none()
                || next.reason_code.is_empty()
            {
                return false;
            }
            expected.outcome = next.outcome;
            expected.outcome_at = next.outcome_at;
            expected.reason_code.clone_from(&next.reason_code);
        }
        InterventionState::Candidate | InterventionState::Denied | InterventionState::Allowed => {
            return false;
        }
    }
    expected == *next
}

fn valid_legacy_intervention_reconciliation(
    write: &InterventionTransitionWrite,
    current: &Intervention,
) -> bool {
    let Some(PendingDeliveryTransition::ReconcileLegacy {
        delivery,
        expected_state,
    }) = &write.delivery
    else {
        return false;
    };
    current.state == InterventionState::Queued
        && *expected_state != OutboxState::Queued
        && delivery_state_matches_intervention(delivery.state, write.intervention.state)
}

const fn delivery_state_matches_intervention(
    delivery: OutboxState,
    intervention: InterventionState,
) -> bool {
    matches!(
        (delivery, intervention),
        (OutboxState::Queued, InterventionState::Queued)
            | (OutboxState::Delivering, InterventionState::Delivering)
            | (
                OutboxState::AcceptedByChannel,
                InterventionState::AcceptedByChannel
            )
            | (
                OutboxState::DeliveryUnknown,
                InterventionState::DeliveryUnknown
            )
            | (
                OutboxState::DeliveryFailed,
                InterventionState::DeliveryFailed
            )
            | (OutboxState::Expired, InterventionState::Expired)
            | (OutboxState::Cancelled, InterventionState::Cancelled)
    )
}

fn validate_new_pending_delivery(
    value: &PendingInterventionDelivery,
) -> Result<(), RepositoryError> {
    if value.state != OutboxState::Queued
        || value.attempt_count != 0
        || value.last_attempt_at.is_some()
        || value.created_at > value.not_before
        || value.not_before >= value.expires_at
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The pending delivery does not satisfy the bounded queue contract.",
        });
    }
    Ok(())
}

fn validate_pending_delivery_update(
    current: &PendingInterventionDelivery,
    next: &PendingInterventionDelivery,
) -> Result<(), RepositoryError> {
    let transition_allowed = current.state == next.state
        || matches!(
            (current.state, next.state),
            (OutboxState::Queued, OutboxState::Delivering)
                | (OutboxState::Queued, OutboxState::Expired)
                | (OutboxState::Queued, OutboxState::Cancelled)
                | (
                    OutboxState::Delivering,
                    OutboxState::AcceptedByChannel
                        | OutboxState::DeliveryUnknown
                        | OutboxState::DeliveryFailed
                        | OutboxState::Cancelled
                )
        );
    let attempt_metadata_valid =
        if current.state == OutboxState::Queued && next.state == OutboxState::Delivering {
            next.attempt_count == current.attempt_count.saturating_add(1)
                && next.last_attempt_at.is_some()
        } else {
            next.attempt_count == current.attempt_count
                && next.last_attempt_at == current.last_attempt_at
        };
    let terminal_text_valid = if matches!(next.state, OutboxState::Queued | OutboxState::Delivering)
    {
        next.user_visible_text == current.user_visible_text
    } else {
        next.user_visible_text.is_empty()
    };
    let mut expected = current.clone();
    expected.state = next.state;
    expected.attempt_count = next.attempt_count;
    expected.last_attempt_at = next.last_attempt_at;
    expected
        .user_visible_text
        .clone_from(&next.user_visible_text);
    // A fresh recovery decision is adopted only by the durable pre-attempt
    // marker. Definite non-attempt cancellation/expiry must preserve the
    // queued record's prior decision reference.
    if current.state == OutboxState::Queued && next.state == OutboxState::Delivering {
        expected.policy_decision_id = next.policy_decision_id;
    }
    if transition_allowed && attempt_metadata_valid && terminal_text_valid && expected == *next {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The pending delivery state transition is invalid.",
        })
    }
}

impl fmt::Debug for SecretDeletionCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretDeletionCleanup")
            .field("owner", &self.owner)
            .field("model_route_approval_id", &self.model_route_approval_id)
            .field("secret_ref", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Durable repositories are typed by owned aggregate. A concrete adapter may
/// use one physical database, but callers cannot issue SQL or inspect another
/// owner's tables.
pub trait DurableRepository: Send + Sync {
    fn health(&self) -> Result<(), RepositoryError>;
    fn load_owner_state(&self, owner: ActorId) -> Result<OwnerStateSnapshot, RepositoryError>;
    fn load_or_issue_device(
        &self,
        owner: ActorId,
        candidate: DeviceId,
        issued_at: OffsetDateTime,
    ) -> Result<DeviceRegistration, RepositoryError> {
        let _ = (owner, candidate, issued_at);
        Err(RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "Durable device identity is unavailable.",
        })
    }

    fn load_goals(&self, owner: ActorId) -> Result<Vec<Goal>, RepositoryError>;
    fn find_goal_create(
        &self,
        owner: ActorId,
        key: IdempotencyKey,
    ) -> Result<Option<(GoalCreateReceipt, Goal)>, RepositoryError>;
    fn create_goal(&self, goal: &Goal, receipt: &GoalCreateReceipt) -> Result<(), RepositoryError>;
    fn find_operation_receipt(
        &self,
        owner: ActorId,
        kind: OperationKind,
        key: IdempotencyKey,
    ) -> Result<Option<OperationReceipt>, RepositoryError>;
    fn update_goal(&self, goal: &Goal, expected_revision: u64) -> Result<(), RepositoryError>;
    fn find_goal_deletion(
        &self,
        _owner: ActorId,
        _goal_id: GoalId,
    ) -> Result<Option<GoalDeletionTombstone>, RepositoryError> {
        Ok(None)
    }
    fn delete_goal_cascade(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
    ) -> Result<DeletionSummary, RepositoryError>;
    fn delete_goal_with_tombstone(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<GoalDeletionResult, RepositoryError> {
        let summary = self.delete_goal_cascade(owner, goal_id, expected_revision)?;
        Ok(GoalDeletionResult {
            tombstone: GoalDeletionTombstone {
                owner,
                goal_id,
                deleted_revision: expected_revision,
                deleted_at,
                summary,
            },
            already_deleted: false,
        })
    }

    fn load_identity(&self, owner: ActorId) -> Result<Option<SteinIdentity>, RepositoryError>;
    fn save_identity(
        &self,
        value: &SteinIdentity,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;
    fn load_preferences(
        &self,
        owner: ActorId,
    ) -> Result<Option<ExplicitPreferences>, RepositoryError>;
    fn save_preferences(
        &self,
        value: &ExplicitPreferences,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;

    fn load_resources(&self, owner: ActorId) -> Result<Vec<ResourceBinding>, RepositoryError>;
    fn save_resource(&self, value: &ResourceBinding) -> Result<(), RepositoryError>;
    fn create_resource(
        &self,
        value: &ResourceBinding,
        receipt: &OperationReceipt,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::RegisterSelectedResource,
            value.owner,
            value.id.as_uuid(),
        )?;
        self.save_resource(value)
    }
    fn remove_resource(
        &self,
        owner: ActorId,
        resource_id: crate::ResourceId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<SelectedResourceDeletionResult, RepositoryError> {
        let _ = (owner, resource_id, expected_revision, deleted_at);
        Err(RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "Selected-resource removal is unavailable.",
        })
    }
    fn find_resource_deletion(
        &self,
        _owner: ActorId,
        _resource_id: crate::ResourceId,
    ) -> Result<Option<SelectedResourceDeletionTombstone>, RepositoryError> {
        Ok(None)
    }
    fn save_native_resource_cleanup(
        &self,
        _cleanup: &NativeResourceCleanup,
    ) -> Result<(), RepositoryError> {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "Durable native resource cleanup is unavailable.",
        })
    }
    fn load_native_resource_cleanups(
        &self,
        _owner: ActorId,
    ) -> Result<Vec<NativeResourceCleanup>, RepositoryError> {
        Ok(Vec::new())
    }
    fn complete_native_resource_cleanup(
        &self,
        _owner: ActorId,
        _resource_id: crate::ResourceId,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }
    /// Atomically revokes the route and records the credential-deletion
    /// obligation before any fallible platform secret-store call begins.
    fn save_revoked_model_route_with_cleanup(
        &self,
        value: &ModelRouteApproval,
        expected_revision: u64,
        cleanup: &SecretDeletionCleanup,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError>;
    fn load_secret_deletion_cleanups(
        &self,
        owner: ActorId,
    ) -> Result<Vec<SecretDeletionCleanup>, RepositoryError>;
    fn complete_secret_deletion_cleanup(
        &self,
        owner: ActorId,
        model_route_approval_id: crate::ModelRouteApprovalId,
    ) -> Result<(), RepositoryError>;
    fn load_grants(&self, owner: ActorId) -> Result<Vec<PermissionGrant>, RepositoryError>;
    fn save_grant(
        &self,
        value: &PermissionGrant,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;
    /// Atomically persists one active-to-revoked grant revision and its audit.
    fn save_permission_grant_revocation(
        &self,
        value: &PermissionGrantRevocationWrite,
    ) -> Result<(), RepositoryError>;
    /// Atomically persists the grant, replay receipt, and audit record.
    fn create_grant(
        &self,
        value: &PermissionGrant,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError>;
    fn load_model_routes(&self, owner: ActorId)
    -> Result<Vec<ModelRouteApproval>, RepositoryError>;
    fn save_model_route(
        &self,
        value: &ModelRouteApproval,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;
    /// Atomically persists the route, replay receipt, and audit record.
    fn create_model_route(
        &self,
        value: &ModelRouteApproval,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError>;

    fn load_focus_sessions(&self, owner: ActorId) -> Result<Vec<FocusSession>, RepositoryError>;
    fn find_focus_session(
        &self,
        id: crate::FocusSessionId,
    ) -> Result<Option<FocusSession>, RepositoryError>;
    /// Atomically consumes the selected goal-scoped grants and creates the
    /// focus session. A crash or revision conflict must leave both unchanged.
    fn bind_grants_and_create_focus_session(
        &self,
        session: &FocusSession,
        grants: &[(PermissionGrant, u64)],
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError>;
    fn save_focus_session(
        &self,
        value: &FocusSession,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;
    /// Atomically persists an existing focus-session state/revision transition
    /// and its required lifecycle audit. Neither record may be visible alone.
    fn save_focus_session_transition(
        &self,
        value: &FocusSessionLifecycleWrite,
    ) -> Result<(), RepositoryError>;
    fn load_interventions(&self, owner: ActorId) -> Result<Vec<Intervention>, RepositoryError>;
    fn save_intervention(
        &self,
        value: &Intervention,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError>;
    /// Atomically persists a delivery/outcome revision, its required audit,
    /// and an optional matching outbox enqueue/update.
    fn save_intervention_transition(
        &self,
        value: &InterventionTransitionWrite,
    ) -> Result<(), RepositoryError>;
    fn save_policy_decision(&self, value: &PolicyDecision) -> Result<(), RepositoryError>;
    /// Atomically persists one candidate-specific policy decision, its required
    /// pre-delivery audit acknowledgement, and the optional intervention
    /// create/update. Returning success is the audit acknowledgement consumed by
    /// the action boundary. The future is cancellation-safe: dropping it before
    /// success must roll back the whole transaction and must not commit later in
    /// background work.
    fn commit_intervention_decision<'a>(
        &'a self,
        value: &'a InterventionDecisionWrite,
    ) -> PortFuture<'a, Result<(), RepositoryError>>;
    fn find_policy_decision(
        &self,
        id: crate::PolicyDecisionId,
    ) -> Result<Option<PolicyDecision>, RepositoryError>;

    fn append_audit(&self, value: &AuditRecord) -> Result<(), RepositoryError>;
    fn load_audit(
        &self,
        owner: ActorId,
        since: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, RepositoryError>;
    fn purge_expired_audit(&self, now: OffsetDateTime) -> Result<u64, RepositoryError>;

    fn enqueue_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError>;
    fn save_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError>;
    fn load_pending_deliveries(
        &self,
        owner: ActorId,
    ) -> Result<Vec<PendingInterventionDelivery>, RepositoryError>;
}

#[derive(Default)]
struct MemoryState {
    devices: HashMap<ActorId, DeviceRegistration>,
    goals: HashMap<GoalId, Goal>,
    goal_receipts: HashMap<(ActorId, IdempotencyKey), GoalCreateReceipt>,
    operation_receipts: HashMap<(ActorId, OperationKind, IdempotencyKey), OperationReceipt>,
    identities: HashMap<ActorId, SteinIdentity>,
    preferences: HashMap<ActorId, ExplicitPreferences>,
    resources: HashMap<crate::ResourceId, ResourceBinding>,
    goal_deletions: HashMap<(ActorId, GoalId), GoalDeletionTombstone>,
    resource_deletions: HashMap<(ActorId, crate::ResourceId), SelectedResourceDeletionTombstone>,
    native_resource_cleanups: HashMap<(ActorId, crate::ResourceId), NativeResourceCleanup>,
    secret_deletion_cleanups:
        HashMap<(ActorId, crate::ModelRouteApprovalId), SecretDeletionCleanup>,
    grants: HashMap<crate::PermissionGrantId, PermissionGrant>,
    routes: HashMap<crate::ModelRouteApprovalId, ModelRouteApproval>,
    sessions: HashMap<crate::FocusSessionId, FocusSession>,
    interventions: HashMap<crate::InterventionId, Intervention>,
    policy_decisions: HashMap<crate::PolicyDecisionId, PolicyDecision>,
    audit: HashMap<crate::AuditRecordId, AuditRecord>,
    outbox: HashMap<crate::OutboxEntryId, PendingInterventionDelivery>,
}

/// Deterministic repository used by platform-neutral semantic tests. It obeys
/// the same optimistic-revision and cascade contracts as the SQLite adapter.
#[derive(Clone, Default)]
pub struct MemoryRepository {
    state: Arc<Mutex<MemoryState>>,
    #[cfg(test)]
    decision_commit_delay: Arc<Mutex<Option<Duration>>>,
}

impl fmt::Debug for MemoryRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryRepository")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl MemoryRepository {
    pub(crate) fn set_decision_commit_delay(&self, delay: Option<Duration>) {
        *self
            .decision_commit_delay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = delay;
    }
}

fn revision_error() -> RepositoryError {
    RepositoryError {
        kind: RepositoryErrorKind::Conflict,
        summary: "The durable record revision changed.",
    }
}

fn check_revision(current: Option<u64>, expected: Option<u64>) -> Result<(), RepositoryError> {
    match (current, expected) {
        (None, None) => Ok(()),
        (Some(current), Some(expected)) if current == expected => Ok(()),
        _ => Err(revision_error()),
    }
}

fn validate_operation_receipt(
    receipt: &OperationReceipt,
    expected_kind: OperationKind,
    expected_owner: ActorId,
    expected_result_id: uuid::Uuid,
) -> Result<(), RepositoryError> {
    if receipt.kind != expected_kind
        || receipt.owner != expected_owner
        || receipt.result_id != expected_result_id
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "An operation receipt does not match its aggregate.",
        });
    }
    Ok(())
}

fn validate_secret_deletion_cleanup(
    route: &ModelRouteApproval,
    cleanup: &SecretDeletionCleanup,
) -> Result<(), RepositoryError> {
    validate_model_route_secret_reference(route)?;
    if route.revoked_at.is_none()
        || route.owner != cleanup.owner
        || route.id != cleanup.model_route_approval_id
        || route.secret_ref != cleanup.secret_ref
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A secret-deletion cleanup obligation does not match its revoked route.",
        });
    }
    Ok(())
}

fn validate_model_route_secret_reference(
    route: &ModelRouteApproval,
) -> Result<(), RepositoryError> {
    if route.has_approval_scoped_secret_ref() {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A model-route secret reference is not scoped to its approval.",
        })
    }
}

impl DurableRepository for MemoryRepository {
    fn health(&self) -> Result<(), RepositoryError> {
        drop(self.state.lock().map_err(|_| RepositoryError {
            kind: RepositoryErrorKind::Internal,
            summary: "The in-memory repository lock is poisoned.",
        })?);
        Ok(())
    }

    fn load_owner_state(&self, owner: ActorId) -> Result<OwnerStateSnapshot, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        let mut snapshot = OwnerStateSnapshot {
            current_device: state.devices.get(&owner).cloned(),
            goals: state
                .goals
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            identity: state.identities.get(&owner).cloned(),
            preferences: state.preferences.get(&owner).cloned(),
            resources: state
                .resources
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            grants: state
                .grants
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            model_routes: state
                .routes
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            focus_sessions: state
                .sessions
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            interventions: state
                .interventions
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            policy_decisions: state
                .policy_decisions
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
            pending_deliveries: state
                .outbox
                .values()
                .filter(|value| value.owner == owner)
                .cloned()
                .collect(),
        };
        snapshot.goals.sort_by_key(|value| value.id);
        snapshot.resources.sort_by_key(|value| value.id);
        snapshot.grants.sort_by_key(|value| value.id);
        snapshot.model_routes.sort_by_key(|value| value.id);
        snapshot.focus_sessions.sort_by_key(|value| value.id);
        snapshot.interventions.sort_by_key(|value| value.id);
        snapshot.policy_decisions.sort_by_key(|value| value.id);
        snapshot.pending_deliveries.sort_by_key(|value| value.id);
        Ok(snapshot)
    }

    fn load_or_issue_device(
        &self,
        owner: ActorId,
        candidate: DeviceId,
        issued_at: OffsetDateTime,
    ) -> Result<DeviceRegistration, RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .devices
            .entry(owner)
            .or_insert_with(|| DeviceRegistration {
                owner,
                device_id: candidate,
                issued_at,
            })
            .clone())
    }

    fn load_goals(&self, owner: ActorId) -> Result<Vec<Goal>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        let mut values: Vec<_> = state
            .goals
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect();
        values.sort_by_key(|value| value.id);
        Ok(values)
    }

    fn find_goal_create(
        &self,
        owner: ActorId,
        key: IdempotencyKey,
    ) -> Result<Option<(GoalCreateReceipt, Goal)>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        let Some(receipt) = state.goal_receipts.get(&(owner, key)).cloned() else {
            return Ok(None);
        };
        let goal = state
            .goals
            .get(&receipt.goal_id)
            .cloned()
            .ok_or(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A goal idempotency receipt references a missing goal.",
            })?;
        Ok(Some((receipt, goal)))
    }

    fn create_goal(&self, goal: &Goal, receipt: &GoalCreateReceipt) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if state.goals.contains_key(&goal.id)
            || state
                .goal_receipts
                .contains_key(&(receipt.actor, receipt.idempotency_key))
        {
            return Err(revision_error());
        }
        state.goals.insert(goal.id, goal.clone());
        state
            .goal_receipts
            .insert((receipt.actor, receipt.idempotency_key), receipt.clone());
        Ok(())
    }

    fn find_operation_receipt(
        &self,
        owner: ActorId,
        kind: OperationKind,
        key: IdempotencyKey,
    ) -> Result<Option<OperationReceipt>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .operation_receipts
            .get(&(owner, kind, key))
            .cloned())
    }

    fn update_goal(&self, goal: &Goal, expected_revision: u64) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let current = state.goals.get(&goal.id).ok_or(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The durable goal was not found.",
        })?;
        if current.revision.get() != expected_revision || current.owner != goal.owner {
            return Err(revision_error());
        }
        state.goals.insert(goal.id, goal.clone());
        Ok(())
    }

    fn delete_goal_cascade(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
    ) -> Result<DeletionSummary, RepositoryError> {
        self.delete_goal_with_tombstone(
            owner,
            goal_id,
            expected_revision,
            OffsetDateTime::now_utc(),
        )
        .map(|result| result.tombstone.summary)
    }

    fn delete_goal_with_tombstone(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<GoalDeletionResult, RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if let Some(tombstone) = state.goal_deletions.get(&(owner, goal_id)) {
            if tombstone.deleted_revision != expected_revision {
                return Err(revision_error());
            }
            return Ok(GoalDeletionResult {
                tombstone: tombstone.clone(),
                already_deleted: true,
            });
        }
        let goal = state.goals.get(&goal_id).ok_or(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The durable goal was not found.",
        })?;
        if goal.owner != owner || goal.revision.get() != expected_revision {
            return Err(revision_error());
        }

        let removed_sessions: Vec<_> = state
            .sessions
            .values()
            .filter(|value| value.owner == owner && value.goal_id == goal_id)
            .map(|value| value.id)
            .collect();
        let removed_grants: Vec<_> = state
            .grants
            .values()
            .filter(|value| value.owner == owner && value.goal_id == goal_id)
            .map(|value| value.id)
            .collect();
        let removed_interventions: Vec<_> = state
            .interventions
            .values()
            .filter(|value| value.owner == owner && value.goal_id == goal_id)
            .map(|value| value.id)
            .collect();
        let removed_policies: Vec<_> = state
            .policy_decisions
            .values()
            .filter(|value| {
                value.owner == owner && removed_sessions.contains(&value.focus_session_id)
            })
            .map(|value| value.id)
            .collect();
        let mut candidate_resources: BTreeSet<_> = state
            .grants
            .values()
            .filter(|value| removed_grants.contains(&value.id))
            .filter_map(|value| value.selected_resource_id)
            .collect();
        for session in state
            .sessions
            .values()
            .filter(|value| removed_sessions.contains(&value.id))
        {
            candidate_resources.extend(session.selected_resource_ids.iter().copied());
        }

        state.goals.remove(&goal_id);
        state
            .goal_receipts
            .retain(|_, receipt| receipt.goal_id != goal_id);
        let mut summary = DeletionSummary {
            goals: 1,
            focus_sessions: u64::try_from(removed_sessions.len()).unwrap_or(u64::MAX),
            grants: u64::try_from(removed_grants.len()).unwrap_or(u64::MAX),
            interventions: u64::try_from(removed_interventions.len()).unwrap_or(u64::MAX),
            ..DeletionSummary::default()
        };
        state
            .sessions
            .retain(|_, value| !removed_sessions.contains(&value.id));
        state
            .grants
            .retain(|_, value| !removed_grants.contains(&value.id));
        state
            .interventions
            .retain(|_, value| !removed_interventions.contains(&value.id));
        state
            .policy_decisions
            .retain(|_, value| !removed_policies.contains(&value.id));

        let before = state.outbox.len();
        state.outbox.retain(|_, value| {
            value.owner != owner || !removed_interventions.contains(&value.intervention_id)
        });
        summary.outbox_entries = u64::try_from(before - state.outbox.len()).unwrap_or(u64::MAX);

        let removable_resources: Vec<_> = candidate_resources
            .into_iter()
            .filter(|resource_id| {
                !state.grants.values().any(|value| {
                    value.owner == owner && value.selected_resource_id == Some(*resource_id)
                }) && !state.sessions.values().any(|value| {
                    value.owner == owner && value.selected_resource_ids.contains(resource_id)
                })
            })
            .collect();
        let resources_before = state.resources.len();
        for resource_id in &removable_resources {
            if let Some(opaque_reference) = state
                .resources
                .get(resource_id)
                .map(|resource| resource.opaque_reference.clone())
            {
                state.native_resource_cleanups.insert(
                    (owner, *resource_id),
                    NativeResourceCleanup {
                        owner,
                        resource_id: *resource_id,
                        opaque_reference,
                        created_at: deleted_at,
                    },
                );
            }
        }
        state
            .resources
            .retain(|id, value| value.owner != owner || !removable_resources.contains(id));
        summary.resource_bindings =
            u64::try_from(resources_before - state.resources.len()).unwrap_or(u64::MAX);

        let removed_result_ids: BTreeSet<_> = removed_grants
            .iter()
            .map(|id| id.as_uuid())
            .chain(removed_sessions.iter().map(|id| id.as_uuid()))
            .collect();
        state.operation_receipts.retain(|_, receipt| {
            receipt.owner != owner || !removed_result_ids.contains(&receipt.result_id)
        });

        let subjects: Vec<_> = removed_sessions
            .iter()
            .map(|id| id.as_uuid())
            .chain(removed_interventions.iter().map(|id| id.as_uuid()))
            .chain(removed_grants.iter().map(|id| id.as_uuid()))
            .chain(removed_policies.iter().map(|id| id.as_uuid()))
            .chain(removable_resources.iter().map(|id| id.as_uuid()))
            .chain(std::iter::once(goal_id.as_uuid()))
            .collect();
        let before = state.audit.len();
        state
            .audit
            .retain(|_, value| value.owner != owner || !subjects.contains(&value.subject_id));
        summary.audit_records = u64::try_from(before - state.audit.len()).unwrap_or(u64::MAX);
        let tombstone = GoalDeletionTombstone {
            owner,
            goal_id,
            deleted_revision: expected_revision,
            deleted_at,
            summary,
        };
        state
            .goal_deletions
            .insert((owner, goal_id), tombstone.clone());
        Ok(GoalDeletionResult {
            tombstone,
            already_deleted: false,
        })
    }

    fn find_goal_deletion(
        &self,
        owner: ActorId,
        goal_id: GoalId,
    ) -> Result<Option<GoalDeletionTombstone>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .goal_deletions
            .get(&(owner, goal_id))
            .cloned())
    }

    fn load_identity(&self, owner: ActorId) -> Result<Option<SteinIdentity>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .identities
            .get(&owner)
            .cloned())
    }

    fn save_identity(
        &self,
        value: &SteinIdentity,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        if !value.has_shipped_v1_invariants() {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "Only the shipped STEIN identity may be persisted.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state
                .identities
                .get(&value.owner)
                .map(|current| current.revision),
            expected_revision,
        )?;
        state.identities.insert(value.owner, value.clone());
        Ok(())
    }

    fn load_preferences(
        &self,
        owner: ActorId,
    ) -> Result<Option<ExplicitPreferences>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .preferences
            .get(&owner)
            .cloned())
    }

    fn save_preferences(
        &self,
        value: &ExplicitPreferences,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state
                .preferences
                .get(&value.owner)
                .map(|current| current.revision),
            expected_revision,
        )?;
        state.preferences.insert(value.owner, value.clone());
        Ok(())
    }

    fn load_resources(&self, owner: ActorId) -> Result<Vec<ResourceBinding>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .resources
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }

    fn save_resource(&self, value: &ResourceBinding) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if state.resources.contains_key(&value.id) {
            return Err(revision_error());
        }
        state.resources.insert(value.id, value.clone());
        Ok(())
    }

    fn create_resource(
        &self,
        value: &ResourceBinding,
        receipt: &OperationReceipt,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::RegisterSelectedResource,
            value.owner,
            value.id.as_uuid(),
        )?;
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let receipt_key = (receipt.owner, receipt.kind, receipt.idempotency_key);
        if state.resources.contains_key(&value.id)
            || state.operation_receipts.contains_key(&receipt_key)
        {
            return Err(revision_error());
        }
        state.resources.insert(value.id, value.clone());
        state
            .operation_receipts
            .insert(receipt_key, receipt.clone());
        Ok(())
    }

    fn remove_resource(
        &self,
        owner: ActorId,
        resource_id: crate::ResourceId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<SelectedResourceDeletionResult, RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if let Some(tombstone) = state.resource_deletions.get(&(owner, resource_id)) {
            if tombstone.deleted_revision != expected_revision {
                return Err(revision_error());
            }
            return Ok(SelectedResourceDeletionResult {
                tombstone: tombstone.clone(),
                already_removed: true,
            });
        }
        let resource = state.resources.get(&resource_id).ok_or(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The selected resource was not found.",
        })?;
        if resource.owner != owner || resource.revision != expected_revision {
            return Err(revision_error());
        }
        if state.grants.values().any(|grant| {
            grant.owner == owner
                && grant.selected_resource_id == Some(resource_id)
                && matches!(grant.state, crate::GrantState::Active)
        }) || state.sessions.values().any(|session| {
            session.owner == owner
                && session.selected_resource_ids.contains(&resource_id)
                && session.is_working()
        }) {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The selected resource is still used by active authority.",
            });
        }
        let opaque_reference = resource.opaque_reference.clone();
        state.resources.remove(&resource_id);
        let tombstone = SelectedResourceDeletionTombstone {
            owner,
            resource_id,
            deleted_revision: expected_revision,
            deleted_at,
        };
        state
            .resource_deletions
            .insert((owner, resource_id), tombstone.clone());
        state.native_resource_cleanups.insert(
            (owner, resource_id),
            NativeResourceCleanup {
                owner,
                resource_id,
                opaque_reference,
                created_at: deleted_at,
            },
        );
        Ok(SelectedResourceDeletionResult {
            tombstone,
            already_removed: false,
        })
    }

    fn find_resource_deletion(
        &self,
        owner: ActorId,
        resource_id: crate::ResourceId,
    ) -> Result<Option<SelectedResourceDeletionTombstone>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .resource_deletions
            .get(&(owner, resource_id))
            .cloned())
    }

    fn save_native_resource_cleanup(
        &self,
        cleanup: &NativeResourceCleanup,
    ) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        state
            .native_resource_cleanups
            .entry((cleanup.owner, cleanup.resource_id))
            .or_insert_with(|| cleanup.clone());
        Ok(())
    }

    fn load_native_resource_cleanups(
        &self,
        owner: ActorId,
    ) -> Result<Vec<NativeResourceCleanup>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .native_resource_cleanups
            .values()
            .filter(|cleanup| cleanup.owner == owner)
            .cloned()
            .collect())
    }

    fn complete_native_resource_cleanup(
        &self,
        owner: ActorId,
        resource_id: crate::ResourceId,
    ) -> Result<(), RepositoryError> {
        self.state
            .lock()
            .map_err(|_| revision_error())?
            .native_resource_cleanups
            .remove(&(owner, resource_id));
        Ok(())
    }

    fn save_revoked_model_route_with_cleanup(
        &self,
        value: &ModelRouteApproval,
        expected_revision: u64,
        cleanup: &SecretDeletionCleanup,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_secret_deletion_cleanup(value, cleanup)?;
        if audit.owner != value.owner
            || audit.kind != AuditKind::ModelRouteRevoked
            || audit.subject_id != value.id.as_uuid()
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A model-route revocation audit does not match its aggregate.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state.routes.get(&value.id).map(|current| current.revision),
            Some(expected_revision),
        )?;
        if state.audit.contains_key(&audit.id) {
            return Err(revision_error());
        }
        state.routes.insert(value.id, value.clone());
        state
            .secret_deletion_cleanups
            .entry((cleanup.owner, cleanup.model_route_approval_id))
            .or_insert_with(|| cleanup.clone());
        state.audit.insert(audit.id, audit.clone());
        Ok(())
    }

    fn load_secret_deletion_cleanups(
        &self,
        owner: ActorId,
    ) -> Result<Vec<SecretDeletionCleanup>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .secret_deletion_cleanups
            .values()
            .filter(|cleanup| cleanup.owner == owner)
            .cloned()
            .collect())
    }

    fn complete_secret_deletion_cleanup(
        &self,
        owner: ActorId,
        model_route_approval_id: crate::ModelRouteApprovalId,
    ) -> Result<(), RepositoryError> {
        self.state
            .lock()
            .map_err(|_| revision_error())?
            .secret_deletion_cleanups
            .remove(&(owner, model_route_approval_id));
        Ok(())
    }

    fn load_grants(&self, owner: ActorId) -> Result<Vec<PermissionGrant>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .grants
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }

    fn save_grant(
        &self,
        value: &PermissionGrant,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state.grants.get(&value.id).map(|current| current.revision),
            expected_revision,
        )?;
        state.grants.insert(value.id, value.clone());
        Ok(())
    }

    fn save_permission_grant_revocation(
        &self,
        value: &PermissionGrantRevocationWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let current = state
            .grants
            .get(&value.grant.id)
            .cloned()
            .ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable permission grant was not found.",
            })?;
        value.validate_against(&current)?;
        if state.audit.contains_key(&value.audit.id) {
            return Err(revision_error());
        }
        state.grants.insert(value.grant.id, value.grant.clone());
        state.audit.insert(value.audit.id, value.audit.clone());
        Ok(())
    }

    fn create_grant(
        &self,
        value: &PermissionGrant,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::GrantSessionPermission,
            value.owner,
            value.id.as_uuid(),
        )?;
        if audit.owner != value.owner || audit.subject_id != value.id.as_uuid() {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A permission audit record does not match its aggregate.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let receipt_key = (receipt.owner, receipt.kind, receipt.idempotency_key);
        if state.grants.contains_key(&value.id)
            || state.operation_receipts.contains_key(&receipt_key)
            || state.audit.contains_key(&audit.id)
        {
            return Err(revision_error());
        }
        state.grants.insert(value.id, value.clone());
        state
            .operation_receipts
            .insert(receipt_key, receipt.clone());
        state.audit.insert(audit.id, audit.clone());
        Ok(())
    }

    fn load_model_routes(
        &self,
        owner: ActorId,
    ) -> Result<Vec<ModelRouteApproval>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .routes
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }

    fn save_model_route(
        &self,
        value: &ModelRouteApproval,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        validate_model_route_secret_reference(value)?;
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state.routes.get(&value.id).map(|current| current.revision),
            expected_revision,
        )?;
        state.routes.insert(value.id, value.clone());
        Ok(())
    }

    fn create_model_route(
        &self,
        value: &ModelRouteApproval,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_model_route_secret_reference(value)?;
        validate_operation_receipt(
            receipt,
            OperationKind::ApproveModelRoute,
            value.owner,
            value.id.as_uuid(),
        )?;
        if audit.owner != value.owner || audit.subject_id != value.id.as_uuid() {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A model-route audit record does not match its aggregate.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let receipt_key = (receipt.owner, receipt.kind, receipt.idempotency_key);
        if state.routes.contains_key(&value.id)
            || state.operation_receipts.contains_key(&receipt_key)
            || state.audit.contains_key(&audit.id)
        {
            return Err(revision_error());
        }
        state.routes.insert(value.id, value.clone());
        state
            .operation_receipts
            .insert(receipt_key, receipt.clone());
        state.audit.insert(audit.id, audit.clone());
        Ok(())
    }

    fn load_focus_sessions(&self, owner: ActorId) -> Result<Vec<FocusSession>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .sessions
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }

    fn find_focus_session(
        &self,
        id: crate::FocusSessionId,
    ) -> Result<Option<FocusSession>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .sessions
            .get(&id)
            .cloned())
    }

    fn bind_grants_and_create_focus_session(
        &self,
        session: &FocusSession,
        grants: &[(PermissionGrant, u64)],
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::StartFocusSession,
            session.owner,
            session.id.as_uuid(),
        )?;
        if audit.owner != session.owner || audit.subject_id != session.id.as_uuid() {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A focus-session audit record does not match its aggregate.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let receipt_key = (receipt.owner, receipt.kind, receipt.idempotency_key);
        if state.sessions.contains_key(&session.id)
            || state.operation_receipts.contains_key(&receipt_key)
            || state.audit.contains_key(&audit.id)
        {
            return Err(revision_error());
        }
        for (grant, expected_revision) in grants {
            let current = state.grants.get(&grant.id).ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "A focus-session permission was not found.",
            })?;
            if current.owner != session.owner || current.revision != *expected_revision {
                return Err(revision_error());
            }
        }
        for (grant, _) in grants {
            state.grants.insert(grant.id, grant.clone());
        }
        state.sessions.insert(session.id, session.clone());
        state
            .operation_receipts
            .insert(receipt_key, receipt.clone());
        state.audit.insert(audit.id, audit.clone());
        Ok(())
    }

    fn save_focus_session(
        &self,
        value: &FocusSession,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state
                .sessions
                .get(&value.id)
                .map(|current| current.revision),
            expected_revision,
        )?;
        state.sessions.insert(value.id, value.clone());
        Ok(())
    }

    fn save_focus_session_transition(
        &self,
        value: &FocusSessionLifecycleWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let current = state
            .sessions
            .get(&value.session.id)
            .ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable focus session was not found.",
            })?;
        value.validate_against(current)?;
        if state.audit.contains_key(&value.audit.id) {
            return Err(revision_error());
        }
        state
            .sessions
            .insert(value.session.id, value.session.clone());
        state.audit.insert(value.audit.id, value.audit.clone());
        Ok(())
    }

    fn load_interventions(&self, owner: ActorId) -> Result<Vec<Intervention>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .interventions
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }

    fn save_intervention(
        &self,
        value: &Intervention,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        check_revision(
            state
                .interventions
                .get(&value.id)
                .map(|current| current.revision),
            expected_revision,
        )?;
        state.interventions.insert(value.id, value.clone());
        Ok(())
    }

    fn save_intervention_transition(
        &self,
        value: &InterventionTransitionWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let current = state
            .interventions
            .get(&value.intervention.id)
            .cloned()
            .ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable intervention was not found.",
            })?;
        value.validate_against(&current)?;
        value.validate_policy_against(
            state
                .policy_decisions
                .get(&value.intervention.policy_decision_id),
        )?;
        if state.audit.contains_key(&value.audit.id) {
            return Err(revision_error());
        }
        if let Some(transition) = &value.delivery {
            let delivery = transition.delivery();
            let current_delivery = state.outbox.get(&delivery.id);
            transition.validate_against(current_delivery)?;
            if matches!(transition, PendingDeliveryTransition::Enqueue(_))
                && state
                    .outbox
                    .values()
                    .any(|current| current.deduplication_key == delivery.deduplication_key)
            {
                return Err(revision_error());
            }
        }
        state
            .interventions
            .insert(value.intervention.id, value.intervention.clone());
        if let Some(transition) = &value.delivery {
            let delivery = transition.delivery();
            state.outbox.insert(delivery.id, delivery.clone());
        }
        state.audit.insert(value.audit.id, value.audit.clone());
        Ok(())
    }

    fn save_policy_decision(&self, value: &PolicyDecision) -> Result<(), RepositoryError> {
        if !value.policy_trace.is_complete()
            || value.policy_version != value.policy_trace.policy_profile_id
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A policy decision has incomplete trace provenance.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if state
            .policy_decisions
            .insert(value.id, value.clone())
            .is_some()
        {
            return Err(revision_error());
        }
        Ok(())
    }

    fn commit_intervention_decision<'a>(
        &'a self,
        value: &'a InterventionDecisionWrite,
    ) -> PortFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            #[cfg(test)]
            {
                let delay = *self
                    .decision_commit_delay
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
            }
            value.validate()?;
            let decision = &value.decision;

            let mut state = self.state.lock().map_err(|_| revision_error())?;
            if state.policy_decisions.contains_key(&decision.id)
                || state.audit.contains_key(&value.audit.id)
            {
                return Err(revision_error());
            }
            if let Some(intervention) = &value.intervention {
                value.validate_against(state.interventions.get(&intervention.id))?;
            }

            state.policy_decisions.insert(decision.id, decision.clone());
            state.audit.insert(value.audit.id, value.audit.clone());
            if let Some(intervention) = &value.intervention {
                state
                    .interventions
                    .insert(intervention.id, intervention.clone());
            }
            Ok(())
        })
    }

    fn find_policy_decision(
        &self,
        id: crate::PolicyDecisionId,
    ) -> Result<Option<PolicyDecision>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| revision_error())?
            .policy_decisions
            .get(&id)
            .cloned())
    }

    fn append_audit(&self, value: &AuditRecord) -> Result<(), RepositoryError> {
        if matches!(
            value.kind,
            AuditKind::SignificanceDecision | AuditKind::InterventionDecision
        ) && !value
            .policy_trace
            .as_ref()
            .is_some_and(crate::PolicyTrace::is_complete)
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A policy audit has incomplete trace provenance.",
            });
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if state.audit.insert(value.id, value.clone()).is_some() {
            return Err(revision_error());
        }
        Ok(())
    }

    fn load_audit(
        &self,
        owner: ActorId,
        since: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        let mut values: Vec<_> = state
            .audit
            .values()
            .filter(|value| value.owner == owner && value.occurred_at >= since)
            .cloned()
            .collect();
        values.sort_by_key(|value| value.occurred_at);
        values.truncate(limit);
        Ok(values)
    }

    fn purge_expired_audit(&self, now: OffsetDateTime) -> Result<u64, RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let before = state.audit.len();
        state.audit.retain(|_, value| value.expires_at > now);
        Ok(u64::try_from(before - state.audit.len()).unwrap_or(u64::MAX))
    }

    fn enqueue_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError> {
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        if state.outbox.contains_key(&value.id)
            || state
                .outbox
                .values()
                .any(|current| current.deduplication_key == value.deduplication_key)
        {
            return Err(revision_error());
        }
        state.outbox.insert(value.id, value.clone());
        Ok(())
    }

    fn save_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError> {
        let mut value = value.clone();
        if !matches!(value.state, OutboxState::Queued | OutboxState::Delivering) {
            value.user_visible_text.clear();
        }
        let mut state = self.state.lock().map_err(|_| revision_error())?;
        let current = state.outbox.get(&value.id).ok_or(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The pending delivery was not found.",
        })?;
        validate_pending_delivery_update(current, &value)?;
        state.outbox.insert(value.id, value);
        Ok(())
    }

    fn load_pending_deliveries(
        &self,
        owner: ActorId,
    ) -> Result<Vec<PendingInterventionDelivery>, RepositoryError> {
        let state = self.state.lock().map_err(|_| revision_error())?;
        Ok(state
            .outbox
            .values()
            .filter(|value| value.owner == owner)
            .cloned()
            .collect())
    }
}
