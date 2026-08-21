use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::view_publication::{
    CaptureViewProjection, CoreEvent, EventContext, FocusSessionViewChange,
    InterventionHistoryViewChange, PermissionRecord, PermissionViewChange, PublicationBinding,
    ViewPublication,
};
use crate::{
    ActorId, AuditKind, AuditRecord, AuditRecordId, CandidateId, CapabilityHealth, CapabilityState,
    ChannelAcknowledgement, ClientId, Clock, CreateGoal, DataCategory, DoNotDisturbWindow,
    DurableRepository, EmergencyCommand, EmergencyCommandAcknowledgement, EmergencyCommandStatus,
    EmergencyControlPort, ExplicitPreferences, FocusSession, FocusSessionId,
    FocusSessionLifecycleWrite, FocusSessionState, Goal, GoalCreateReceipt, GoalId, GoalPatch,
    GoalState, GrantState, Intervention, InterventionDecisionWrite, InterventionId,
    InterventionOutcome, InterventionState, InterventionTransitionWrite, ModelGateway,
    ModelGatewayErrorKind, ModelReasoningOutput, ModelReasoningRequest, ModelRouteApproval,
    ModelRouteApprovalId, NativeCaptureStatus, NativeResourceBinding, NativeResourceStatus,
    NativeStatusAcknowledgement, NativeStatusHeartbeat, NativeStatusPort, NormalizedObservation,
    NormalizedObservationValue, NotificationDelivery, NotificationPort, ObservationAdapterEvent,
    ObservationLimits, ObservationPort, ObservationSourceStatus, ObservationStartRequest,
    ObservationSubscription, OperationKind, OperationReceipt, OutboxEntryId, OutboxState,
    PendingDeliveryTransition, PendingInterventionDelivery, PermissionGrant, PermissionGrantId,
    PermissionGrantRevocationWrite, PermissionScope, PlatformPortAvailability, PolicyDecision,
    PolicyDecisionId, PolicyOutcome, PolicyTrace, RepositoryError, RepositoryErrorKind,
    ResourceBinding, ResourceId, ResourceKind, ResourceSelectionErrorKind, ResourceSelectionPort,
    Revision, SecretStore, SensitiveText, SteinIdentity, SystemClock, USER_PREFERENCES_SCHEMA_V1,
    UpdateGoal, Urgency, WorkingContextItem,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAssurance {
    Diagnostic,
    PrivateCapabilityBound,
    NativeEmergencyControl,
}

impl ClientAssurance {
    const fn permits_private(self) -> bool {
        matches!(
            self,
            Self::PrivateCapabilityBound | Self::NativeEmergencyControl
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecondMindConfig {
    pub observation_ttl: Duration,
    pub retention_maintenance_interval: Duration,
    pub source_freshness: Duration,
    pub native_status_heartbeat_timeout: Duration,
    pub maximum_observation_bytes: usize,
    pub model_deadline: Duration,
    pub significance_evaluation_interval: Duration,
    pub model_request_cooldown: Duration,
    pub maximum_model_requests_per_hour: u16,
    pub deadline_risk_horizon: Duration,
    pub maximum_model_evidence_age: Duration,
    pub policy_validity: Duration,
    pub intervention_cooldown: Duration,
    pub maximum_interventions_per_session: u16,
    pub outbox_capacity_per_user: usize,
    pub outbox_capacity_per_session: usize,
    pub outbox_entry_ttl: Duration,
    pub recovery_batch_size: usize,
    pub recovery_batch_interval: Duration,
    pub audit_append_deadline: Duration,
    pub notification_attempt_deadline: Duration,
    pub resource_selection_deadline: Duration,
    pub resource_release_deadline: Duration,
    pub audit_ttl: Duration,
    pub minimum_candidate_confidence_basis_points: u16,
}

impl Default for SecondMindConfig {
    fn default() -> Self {
        Self {
            observation_ttl: Duration::from_secs(10 * 60),
            retention_maintenance_interval: Duration::from_secs(60),
            source_freshness: Duration::from_secs(30),
            native_status_heartbeat_timeout: Duration::from_secs(10),
            maximum_observation_bytes: 16 * 1024,
            model_deadline: Duration::from_secs(30),
            significance_evaluation_interval: Duration::from_secs(60),
            model_request_cooldown: Duration::from_secs(5 * 60),
            maximum_model_requests_per_hour: 12,
            deadline_risk_horizon: Duration::from_secs(30 * 60),
            maximum_model_evidence_age: Duration::from_secs(2 * 60),
            policy_validity: Duration::from_secs(30),
            intervention_cooldown: Duration::from_secs(15 * 60),
            maximum_interventions_per_session: 3,
            outbox_capacity_per_user: 20,
            outbox_capacity_per_session: 5,
            outbox_entry_ttl: Duration::from_secs(15 * 60),
            recovery_batch_size: 3,
            recovery_batch_interval: Duration::from_secs(10),
            audit_append_deadline: Duration::from_secs(2),
            notification_attempt_deadline: Duration::from_secs(5),
            resource_selection_deadline: Duration::from_secs(60),
            resource_release_deadline: Duration::from_secs(5),
            audit_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            minimum_candidate_confidence_basis_points: 6_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecondMindErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Unavailable,
    DeadlineExceeded,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecondMindError {
    pub code: SecondMindErrorCode,
    pub summary: &'static str,
    pub retryable: bool,
    pub current_revision: Option<u64>,
}

impl SecondMindError {
    fn invalid(summary: &'static str) -> Self {
        Self {
            code: SecondMindErrorCode::InvalidArgument,
            summary,
            retryable: false,
            current_revision: None,
        }
    }

    fn permission(summary: &'static str) -> Self {
        Self {
            code: SecondMindErrorCode::PermissionDenied,
            summary,
            retryable: false,
            current_revision: None,
        }
    }

    fn unavailable(summary: &'static str) -> Self {
        Self {
            code: SecondMindErrorCode::Unavailable,
            summary,
            retryable: true,
            current_revision: None,
        }
    }

    fn cancelled(summary: &'static str) -> Self {
        Self {
            code: SecondMindErrorCode::Cancelled,
            summary,
            retryable: false,
            current_revision: None,
        }
    }

    fn deadline_exceeded(summary: &'static str) -> Self {
        Self {
            code: SecondMindErrorCode::DeadlineExceeded,
            summary,
            retryable: true,
            current_revision: None,
        }
    }

    fn conflict(current_revision: u64) -> Self {
        Self {
            code: SecondMindErrorCode::Conflict,
            summary: "The record changed; refresh and retry.",
            retryable: false,
            current_revision: Some(current_revision),
        }
    }

    fn idempotency_conflict() -> Self {
        Self {
            code: SecondMindErrorCode::Conflict,
            summary: "The idempotency key was already used for different input.",
            retryable: false,
            current_revision: None,
        }
    }
}

impl From<RepositoryError> for SecondMindError {
    fn from(error: RepositoryError) -> Self {
        let (code, retryable) = match error.kind {
            RepositoryErrorKind::Conflict => (SecondMindErrorCode::Conflict, false),
            RepositoryErrorKind::NotFound => (SecondMindErrorCode::NotFound, false),
            RepositoryErrorKind::Unavailable => (SecondMindErrorCode::Unavailable, true),
            RepositoryErrorKind::Corrupt | RepositoryErrorKind::Internal => {
                (SecondMindErrorCode::Internal, false)
            }
        };
        Self {
            code,
            summary: error.summary,
            retryable,
            current_revision: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GrantPermission {
    pub idempotency: IdempotencyContext,
    pub owner: ActorId,
    pub goal_id: GoalId,
    pub client_id: ClientId,
    pub device_id: crate::DeviceId,
    pub scope: PermissionScope,
    pub selected_resource_id: Option<ResourceId>,
    pub purpose: String,
    pub client_disconnect_allowed: bool,
    pub daemon_restart_allowed: bool,
    pub effective_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consent_copy_version: String,
}

#[derive(Clone, Debug)]
pub struct StartFocusSession {
    pub idempotency: IdempotencyContext,
    pub owner: ActorId,
    pub session_id: FocusSessionId,
    pub goal_id: GoalId,
    pub expected_goal_revision: u64,
    pub selected_resource_ids: BTreeSet<ResourceId>,
    pub grant_ids: BTreeSet<PermissionGrantId>,
    pub model_route_approval_id: ModelRouteApprovalId,
    pub client_disconnect_allowed: bool,
    pub daemon_restart_allowed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyContext {
    pub key: crate::IdempotencyKey,
    pub request_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndFocusReason {
    UserRequested,
    GoalCompleted,
    GoalAbandoned,
    GoalDeleted,
    RequiredPermissionRevoked,
    EmergencyStop,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReasoningCycleResult {
    Silence { reason_code: String },
    Intervention(Box<Intervention>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRequestReceiptOutcome {
    InFlight,
    CompletedStrictSilence,
    CompletedStrictCandidate,
    Cancelled,
    DeadlineExceeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRequestReceipt {
    pub request_id: Uuid,
    pub focus_session_id: FocusSessionId,
    pub model_route_approval_id: ModelRouteApprovalId,
    pub model_route_revision: u64,
    pub started_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub outcome: ModelRequestReceiptOutcome,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetentionMaintenanceResult {
    pub removed_observations: usize,
    pub purged_audit_records: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupMaintenanceResult {
    pub native_resource_attempts: usize,
    pub native_resource_completed: usize,
    pub native_resource_pending: usize,
    pub secret_deletion_attempts: usize,
    pub secret_deletion_completed: usize,
    pub secret_deletion_pending: usize,
}

#[derive(Clone, Debug)]
struct EphemeralSession {
    observations: VecDeque<NormalizedObservation>,
    source_health: BTreeMap<PermissionGrantId, ObservationSourceStatus>,
    /// Owns observation/status lifecycle cancellation for the whole session.
    cancellation: CancellationToken,
    /// Separately gates model use and intervention delivery. Direct-user mute
    /// and proactive preference changes cancel this token without stopping
    /// observation authority.
    proactive_cancellation: CancellationToken,
    last_delivery_elapsed: Option<Duration>,
    intervention_count: u16,
    presence: crate::PresenceState,
    correction: Option<SensitiveText>,
    significance_generation: u64,
    last_evaluated_generation: u64,
    last_significance_evaluation_elapsed: Option<Duration>,
    model_request_in_flight: bool,
    model_request_history: VecDeque<Duration>,
    latest_model_request_receipt: Option<ModelRequestReceipt>,
    deadline_risk_active: bool,
    native_status_revision: Option<u64>,
    last_native_status_heartbeat_at: Option<OffsetDateTime>,
}

impl Default for EphemeralSession {
    fn default() -> Self {
        Self::with_cancellation(CancellationToken::new())
    }
}

impl EphemeralSession {
    fn with_cancellation(cancellation: CancellationToken) -> Self {
        let proactive_cancellation = cancellation.child_token();
        Self {
            observations: VecDeque::new(),
            source_health: BTreeMap::new(),
            cancellation,
            proactive_cancellation,
            last_delivery_elapsed: None,
            intervention_count: 0,
            presence: crate::PresenceState::Unknown,
            correction: None,
            significance_generation: 0,
            last_evaluated_generation: 0,
            last_significance_evaluation_elapsed: None,
            model_request_in_flight: false,
            model_request_history: VecDeque::new(),
            latest_model_request_receipt: None,
            deadline_risk_active: false,
            native_status_revision: None,
            last_native_status_heartbeat_at: None,
        }
    }
}

#[derive(Default)]
struct EphemeralState {
    sessions: HashMap<FocusSessionId, EphemeralSession>,
    activations: BTreeSet<FocusSessionId>,
    last_recovery_batch_elapsed: HashMap<ActorId, Duration>,
}

#[cfg(test)]
type TestOneShotHook = Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

struct FocusActivationPermit {
    ephemeral: Arc<Mutex<EphemeralState>>,
    session_id: FocusSessionId,
}

impl Drop for FocusActivationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.ephemeral.lock() {
            state.activations.remove(&self.session_id);
        }
    }
}

struct ModelRequestPermit {
    ephemeral: Arc<Mutex<EphemeralState>>,
    session_id: FocusSessionId,
}

impl Drop for ModelRequestPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.ephemeral.lock()
            && let Some(session) = state.sessions.get_mut(&self.session_id)
        {
            session.model_request_in_flight = false;
        }
    }
}

#[derive(Clone)]
pub struct SecondMindPorts {
    pub repository: Arc<dyn DurableRepository>,
    pub clock: Arc<dyn Clock>,
    pub observation: Arc<dyn ObservationPort>,
    pub model: Arc<dyn ModelGateway>,
    pub notification: Arc<dyn NotificationPort>,
    pub native_status: Arc<dyn NativeStatusPort>,
    pub emergency_control: Arc<dyn EmergencyControlPort>,
    /// Typed platform boundary for model credentials. Runtime revocation uses
    /// this port only after the durable route has been made unusable.
    pub secret_store: Arc<dyn SecretStore>,
    pub resource_selection: Arc<dyn ResourceSelectionPort>,
}

struct AuditDetails {
    reason_codes: Vec<String>,
    evidence_categories: BTreeSet<DataCategory>,
    evidence_age_ms: Option<u64>,
    confidence_basis_points: Option<u16>,
    policy_trace: Option<PolicyTrace>,
}

impl AuditDetails {
    fn new(reason_codes: Vec<String>, evidence_categories: BTreeSet<DataCategory>) -> Self {
        Self {
            reason_codes,
            evidence_categories,
            evidence_age_ms: None,
            confidence_basis_points: None,
            policy_trace: None,
        }
    }

    fn with_candidate_evidence(
        mut self,
        evidence_age_ms: u64,
        confidence_basis_points: u16,
    ) -> Self {
        self.evidence_age_ms = Some(evidence_age_ms);
        self.confidence_basis_points = Some(confidence_basis_points);
        self
    }

    fn with_policy_trace(mut self, policy_trace: PolicyTrace) -> Self {
        self.policy_trace = Some(policy_trace);
        self
    }

    fn with_optional_policy_trace(mut self, policy_trace: Option<PolicyTrace>) -> Self {
        self.policy_trace = policy_trace;
        self
    }
}

const NATIVE_NOTIFICATION_CHANNEL: &str = "windows.native_notification";
const POLICY_PROFILE_ID: &str = "phase2-focus-v1";

#[derive(Serialize)]
struct PolicyContextInputV1<'a> {
    category: DataCategory,
    value: &'a str,
    source_id: &'a str,
    resource_id: Option<Uuid>,
    observed_at: OffsetDateTime,
    age_ms: u64,
    confidence_basis_points: u16,
}

impl<'a> From<&'a WorkingContextItem> for PolicyContextInputV1<'a> {
    fn from(value: &'a WorkingContextItem) -> Self {
        Self {
            category: value.category,
            value: value.value.expose(),
            source_id: &value.source_id,
            resource_id: value.resource_id.map(ResourceId::as_uuid),
            observed_at: value.observed_at,
            age_ms: value.age_ms,
            confidence_basis_points: value.confidence_basis_points,
        }
    }
}

#[derive(Serialize)]
struct EffectivePreferencesInputV1<'a> {
    revision: u64,
    maximum_interventions_per_session: u16,
    maximum_model_requests_per_hour: u16,
    intervention_cooldown_ms: u64,
    proactive_interventions_enabled: bool,
    proactive_interventions_muted: bool,
    do_not_disturb_windows: &'a [DoNotDisturbWindow],
    allowed_delivery_channels: &'a BTreeSet<String>,
    remote_processing_enabled: bool,
    restart_continuity_default: bool,
}

impl<'a> From<&'a EffectivePreferences> for EffectivePreferencesInputV1<'a> {
    fn from(value: &'a EffectivePreferences) -> Self {
        Self {
            revision: value.revision,
            maximum_interventions_per_session: value.maximum_interventions_per_session,
            maximum_model_requests_per_hour: value.maximum_model_requests_per_hour,
            intervention_cooldown_ms: duration_millis_u64(value.intervention_cooldown),
            proactive_interventions_enabled: value.proactive_interventions_enabled,
            proactive_interventions_muted: value.proactive_interventions_muted,
            do_not_disturb_windows: &value.do_not_disturb_windows,
            allowed_delivery_channels: &value.allowed_delivery_channels,
            remote_processing_enabled: value.remote_processing_enabled,
            restart_continuity_default: value.restart_continuity_default,
        }
    }
}

#[derive(Serialize)]
struct SignificancePolicyInputV1<'a> {
    schema: &'static str,
    policy_profile_id: &'static str,
    preferences: EffectivePreferencesInputV1<'a>,
    owner: Uuid,
    focus_session_id: Uuid,
    focus_session_revision: u64,
    goal_id: Uuid,
    goal_revision: u64,
    goal_deadline: Option<OffsetDateTime>,
    evaluated_at: OffsetDateTime,
    monotonic_elapsed_ms: u64,
    deadline_risk_horizon_ms: u64,
    evaluation_interval_ms: u64,
    significance_generation: u64,
    last_evaluated_generation: u64,
    prior_deadline_risk_active: bool,
    deadline_risk_active: bool,
    last_evaluation_elapsed_ms: Option<u64>,
    context: Vec<PolicyContextInputV1<'a>>,
}

enum SignificanceGateResult {
    Skipped(&'static str),
    Evaluated {
        reason_code: Option<&'static str>,
        policy_trace: PolicyTrace,
    },
}

#[derive(Serialize)]
struct PriorInterventionPolicyInputV1 {
    intervention_id: Uuid,
    candidate_id: Uuid,
    candidate_revision: u64,
    focus_session_id: Uuid,
    state: InterventionState,
    updated_at: OffsetDateTime,
}

#[derive(Serialize)]
struct PendingDeliveryPolicyInputV1 {
    entry_id: Uuid,
    intervention_id: Uuid,
    state: OutboxState,
}

#[derive(Serialize)]
struct InterventionPolicyInputV1<'a> {
    schema: &'static str,
    policy_profile_id: &'static str,
    preferences: EffectivePreferencesInputV1<'a>,
    evaluated_at: OffsetDateTime,
    owner: Uuid,
    focus_session_id: Uuid,
    focus_session_revision: u64,
    goal_id: Uuid,
    goal_revision: u64,
    goal_state: GoalState,
    goal_deadline: Option<OffsetDateTime>,
    session_muted: bool,
    candidate_id: Uuid,
    candidate_revision: u64,
    user_visible_text: &'a str,
    reason_code: &'a str,
    evidence_summary: &'a str,
    urgency: Urgency,
    confidence_basis_points: u16,
    context: Vec<PolicyContextInputV1<'a>>,
    permission_grant_revisions: Vec<(Uuid, u64)>,
    model_route_approval_id: Uuid,
    model_route_revision: u64,
    channel: &'static str,
    notification_available: bool,
    prior_interventions: Vec<PriorInterventionPolicyInputV1>,
    pending_deliveries: Vec<PendingDeliveryPolicyInputV1>,
    ephemeral_intervention_count: u16,
    ephemeral_presence: &'static str,
    ephemeral_last_delivery_elapsed_ms: Option<u64>,
    monotonic_elapsed_ms: u64,
}

#[derive(Serialize)]
struct RecoveryPolicyInputV1<'a> {
    schema: &'static str,
    policy_profile_id: &'static str,
    preferences: EffectivePreferencesInputV1<'a>,
    evaluated_at: OffsetDateTime,
    owner: Uuid,
    focus_session_id: Uuid,
    focus_session_revision: u64,
    focus_session_state: FocusSessionState,
    focus_session_muted: bool,
    goal_id: Uuid,
    goal_revision: u64,
    goal_state: GoalState,
    goal_deadline: Option<OffsetDateTime>,
    model_route_approval_id: Uuid,
    model_route_revision: u64,
    permission_grant_revisions: Vec<(Uuid, u64)>,
    intervention_id: Uuid,
    intervention_revision: u64,
    candidate_id: Uuid,
    candidate_revision: u64,
    prior_policy_decision_id: Uuid,
    prior_policy_trace_digest: [u8; 32],
    outbox_entry_id: Uuid,
    queued_text: &'a str,
    reason_code: &'a str,
    urgency: Urgency,
    sensitivity: &'a str,
    permitted_channels: &'a BTreeSet<String>,
    deduplication_key: Uuid,
    created_at: OffsetDateTime,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
    channel: &'static str,
    presence_active: bool,
    sources_healthy: bool,
    entry_grants_current: bool,
    decision_grants_current: bool,
    decision_matches: bool,
    route_current: bool,
    goal_current: bool,
    preferences_allow: bool,
    duplicate_terminal: bool,
    delivered_count: usize,
    cooldown_active: bool,
    notification_available: bool,
}

#[derive(Clone, Debug)]
struct EffectivePreferences {
    revision: u64,
    maximum_interventions_per_session: u16,
    maximum_model_requests_per_hour: u16,
    intervention_cooldown: Duration,
    proactive_interventions_enabled: bool,
    proactive_interventions_muted: bool,
    do_not_disturb_windows: Vec<DoNotDisturbWindow>,
    allowed_delivery_channels: BTreeSet<String>,
    remote_processing_enabled: bool,
    restart_continuity_default: bool,
}

impl EffectivePreferences {
    fn from_record(
        config: &SecondMindConfig,
        owner: ActorId,
        now: OffsetDateTime,
        record: Option<ExplicitPreferences>,
    ) -> Self {
        let value = record.unwrap_or_else(|| ExplicitPreferences::phase2_defaults(owner, now));
        Self {
            revision: value.revision,
            maximum_interventions_per_session: value
                .maximum_interventions_per_session
                .min(config.maximum_interventions_per_session),
            maximum_model_requests_per_hour: value
                .maximum_model_requests_per_hour
                .min(config.maximum_model_requests_per_hour),
            intervention_cooldown: Duration::from_secs(
                value
                    .minimum_intervention_cooldown_seconds
                    .max(config.intervention_cooldown.as_secs()),
            ),
            proactive_interventions_enabled: value.proactive_interventions_enabled,
            proactive_interventions_muted: value.proactive_interventions_muted,
            do_not_disturb_windows: value.do_not_disturb_windows,
            allowed_delivery_channels: value.allowed_delivery_channels,
            remote_processing_enabled: value.remote_processing_enabled,
            restart_continuity_default: value.restart_continuity_default,
        }
    }

    fn is_do_not_disturb(&self, now: OffsetDateTime) -> bool {
        self.do_not_disturb_windows
            .iter()
            .copied()
            .any(|window| do_not_disturb_contains(window, now))
    }

    fn permits_native_notification(&self) -> bool {
        self.allowed_delivery_channels
            .contains(NATIVE_NOTIFICATION_CHANNEL)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicy {
    pub policy_profile_id: &'static str,
    pub user_preferences_revision: u64,
    pub source_stale_after: Duration,
    pub maximum_model_evidence_age: Duration,
    pub model_request_cooldown: Duration,
    pub maximum_model_requests_per_hour: u16,
    pub intervention_cooldown: Duration,
    pub maximum_interventions_per_session: u16,
    pub proactive_interventions_enabled: bool,
    pub proactive_interventions_muted: bool,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindow>,
    pub allowed_delivery_channels: BTreeSet<String>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
    pub outbox_capacity_per_user: usize,
    pub outbox_capacity_per_session: usize,
}

#[derive(Clone)]
pub struct SecondMindRuntime {
    config: SecondMindConfig,
    repository: Arc<dyn DurableRepository>,
    clock: Arc<dyn Clock>,
    observation: Arc<dyn ObservationPort>,
    model: Arc<dyn ModelGateway>,
    notification: Arc<dyn NotificationPort>,
    native_status: Arc<dyn NativeStatusPort>,
    emergency_control: Arc<dyn EmergencyControlPort>,
    secret_store: Arc<dyn SecretStore>,
    resource_selection: Arc<dyn ResourceSelectionPort>,
    last_emergency_command_revision: Arc<Mutex<u64>>,
    ephemeral: Arc<Mutex<EphemeralState>>,
    publication: PublicationBinding,
    #[cfg(test)]
    before_queue_commit: TestOneShotHook,
    #[cfg(test)]
    before_permission_revocation_commit: TestOneShotHook,
    #[cfg(test)]
    after_recovery_revalidation_commit: TestOneShotHook,
}

impl SecondMindRuntime {
    pub fn new(config: SecondMindConfig, ports: SecondMindPorts) -> Result<Self, SecondMindError> {
        validate_config(&config)?;
        ports.repository.health()?;
        Ok(Self {
            config,
            repository: ports.repository,
            clock: ports.clock,
            observation: ports.observation,
            model: ports.model,
            notification: ports.notification,
            native_status: ports.native_status,
            emergency_control: ports.emergency_control,
            secret_store: ports.secret_store,
            resource_selection: ports.resource_selection,
            last_emergency_command_revision: Arc::new(Mutex::new(0)),
            ephemeral: Arc::new(Mutex::new(EphemeralState::default())),
            publication: Arc::new(std::sync::OnceLock::new()),
            #[cfg(test)]
            before_queue_commit: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_permission_revocation_commit: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_recovery_revalidation_commit: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    fn set_before_queue_commit_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .before_queue_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    #[cfg(test)]
    fn run_before_queue_commit_hook(&self) {
        let hook = self
            .before_queue_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    fn set_before_permission_revocation_commit_hook(
        &self,
        hook: impl Fn() + Send + Sync + 'static,
    ) {
        *self
            .before_permission_revocation_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    #[cfg(test)]
    fn run_before_permission_revocation_commit_hook(&self) {
        let hook = self
            .before_permission_revocation_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    fn set_after_recovery_revalidation_commit_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .after_recovery_revalidation_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    #[cfg(test)]
    fn run_after_recovery_revalidation_commit_hook(&self) {
        let hook = self
            .after_recovery_revalidation_commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn attach_publication(&self, publication: ViewPublication) -> Result<(), ()> {
        self.publication.set(publication).map_err(|_| ())
    }

    fn commit<T>(
        &self,
        context: EventContext,
        operation: impl FnOnce(&mut Vec<CoreEvent>) -> Result<T, SecondMindError>,
    ) -> Result<T, SecondMindError> {
        if let Some(publication) = self.publication.get() {
            publication.commit(context, |_state, events| operation(events))
        } else {
            operation(&mut Vec::new())
        }
    }

    fn daemon_context(&self) -> EventContext {
        self.publication.get().map_or_else(
            || EventContext::direct(ActorId::new_v7()),
            ViewPublication::fresh_daemon_context,
        )
    }

    fn acquire_focus_activation(
        &self,
        session_id: FocusSessionId,
        current_revision: u64,
    ) -> Result<FocusActivationPermit, SecondMindError> {
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        if !state.activations.insert(session_id) {
            return Err(SecondMindError::conflict(current_revision));
        }
        drop(state);
        Ok(FocusActivationPermit {
            ephemeral: Arc::clone(&self.ephemeral),
            session_id,
        })
    }

    fn remove_focus_ephemeral(&self, session_id: FocusSessionId) {
        if let Ok(mut state) = self.ephemeral.lock()
            && let Some(ephemeral) = state.sessions.remove(&session_id)
        {
            ephemeral.cancellation.cancel();
        }
    }

    async fn cleanup_focus_activation(
        &self,
        session_id: FocusSessionId,
        native_status_revision: u64,
        cancellation: &CancellationToken,
        started: &[PermissionGrantId],
    ) {
        cancellation.cancel();
        self.remove_focus_ephemeral(session_id);
        stop_started(&*self.observation, session_id, started).await;
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.native_status.clear(session_id, native_status_revision),
        )
        .await;
    }

    fn effective_preferences(
        &self,
        owner: ActorId,
    ) -> Result<EffectivePreferences, SecondMindError> {
        let now = self.clock.now_utc();
        Ok(EffectivePreferences::from_record(
            &self.config,
            owner,
            now,
            self.repository.load_preferences(owner)?,
        ))
    }

    fn reconcile_proactive_cancellation_for_owner(
        &self,
        owner: ActorId,
        proactive_enabled: bool,
        proactive_muted: bool,
    ) -> Result<(), SecondMindError> {
        let sessions = self.repository.load_focus_sessions(owner)?;
        let goals = self.repository.load_goals(owner)?;
        let now = self.clock.now_utc();
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        for session in sessions {
            let Some(ephemeral) = state.sessions.get_mut(&session.id) else {
                continue;
            };
            let allowed = session.is_working()
                && !session.muted
                && proactive_enabled
                && !proactive_muted
                && !ephemeral.cancellation.is_cancelled();
            let goal_is_current = goals.iter().any(|goal| {
                goal.id == session.goal_id
                    && goal.state == GoalState::Active
                    && goal.revision.get() == session.goal_revision
                    && goal.deadline.is_none_or(|deadline| now < deadline)
            });
            reconcile_proactive_cancellation(ephemeral, allowed && goal_is_current);
        }
        Ok(())
    }

    fn reconcile_proactive_cancellation_for_session(
        &self,
        session: &FocusSession,
        preferences: &EffectivePreferences,
    ) -> Result<(), SecondMindError> {
        let now = self.clock.now_utc();
        let goal_is_current = self
            .get_goal(session.owner, session.goal_id)
            .is_ok_and(|goal| {
                goal.state == GoalState::Active
                    && goal.revision.get() == session.goal_revision
                    && goal.deadline.is_none_or(|deadline| now < deadline)
            });
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        if let Some(ephemeral) = state.sessions.get_mut(&session.id) {
            let allowed = session.is_working()
                && !session.muted
                && preferences.proactive_interventions_enabled
                && !preferences.proactive_interventions_muted
                && !ephemeral.cancellation.is_cancelled()
                && goal_is_current;
            reconcile_proactive_cancellation(ephemeral, allowed);
        }
        Ok(())
    }

    fn cancel_proactive_cancellation(
        &self,
        session_id: FocusSessionId,
    ) -> Result<(), SecondMindError> {
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        if let Some(ephemeral) = state.sessions.get_mut(&session_id) {
            ephemeral.proactive_cancellation.cancel();
        }
        Ok(())
    }

    fn cancel_proactive_for_owner(&self, owner: ActorId) -> Result<(), SecondMindError> {
        let session_ids: BTreeSet<_> = self
            .repository
            .load_focus_sessions(owner)?
            .into_iter()
            .filter(FocusSession::is_working)
            .map(|session| session.id)
            .collect();
        self.cancel_proactive_for_session_ids(&session_ids)
    }

    fn cancel_proactive_for_goal(
        &self,
        owner: ActorId,
        goal_id: GoalId,
    ) -> Result<BTreeSet<FocusSessionId>, SecondMindError> {
        let session_ids: BTreeSet<_> = self
            .repository
            .load_focus_sessions(owner)?
            .into_iter()
            .filter(|session| session.goal_id == goal_id && session.is_working())
            .map(|session| session.id)
            .collect();
        self.cancel_proactive_for_session_ids(&session_ids)?;
        Ok(session_ids)
    }

    fn cancel_proactive_for_session_ids(
        &self,
        session_ids: &BTreeSet<FocusSessionId>,
    ) -> Result<(), SecondMindError> {
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        for session_id in session_ids {
            if let Some(session) = state.sessions.get_mut(session_id) {
                session.proactive_cancellation.cancel();
            }
        }
        Ok(())
    }

    fn policy_trace<T: Serialize>(
        &self,
        user_preferences_revision: u64,
        input: &T,
    ) -> Result<PolicyTrace, SecondMindError> {
        let encoded = serde_json::to_vec(input).map_err(|_| {
            SecondMindError::unavailable("The policy input could not be canonicalized.")
        })?;
        Ok(PolicyTrace {
            policy_profile_id: POLICY_PROFILE_ID.to_owned(),
            user_preferences_revision,
            proposed_input_schema_version: PolicyTrace::INPUT_SCHEMA_V1,
            proposed_input_digest: Sha256::digest(encoded).into(),
        })
    }

    fn persisted_policy_trace(
        &self,
        decision_id: PolicyDecisionId,
    ) -> Result<Option<PolicyTrace>, SecondMindError> {
        Ok(self
            .repository
            .find_policy_decision(decision_id)?
            .map(|decision| decision.policy_trace)
            .filter(PolicyTrace::is_complete))
    }

    fn significance_gate(
        &self,
        session: &FocusSession,
        goal: &Goal,
        context: &[WorkingContextItem],
        preferences: &EffectivePreferences,
    ) -> Result<SignificanceGateResult, SecondMindError> {
        let now = self.clock.now_utc();
        let elapsed = self.clock.monotonic_elapsed();
        let deadline_risk_active = goal.deadline.is_some_and(|deadline| {
            let remaining = deadline - now;
            remaining.is_positive()
                && remaining
                    <= time::Duration::try_from(self.config.deadline_risk_horizon)
                        .unwrap_or(time::Duration::MAX)
        });
        let (
            significance_generation,
            last_evaluated_generation,
            prior_deadline_risk_active,
            last_evaluation_elapsed,
        ) = {
            let mut state = self
                .ephemeral
                .lock()
                .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
            let ephemeral = state.sessions.get_mut(&session.id).ok_or_else(|| {
                SecondMindError::unavailable("The session has no live ephemeral context.")
            })?;
            let prior_deadline_risk_active = ephemeral.deadline_risk_active;
            if deadline_risk_active && !ephemeral.deadline_risk_active {
                ephemeral.significance_generation =
                    ephemeral.significance_generation.saturating_add(1);
            }
            ephemeral.deadline_risk_active = deadline_risk_active;
            if ephemeral.significance_generation == ephemeral.last_evaluated_generation {
                return Ok(SignificanceGateResult::Skipped("no_relevant_state_change"));
            }
            if ephemeral
                .last_significance_evaluation_elapsed
                .is_some_and(|last| {
                    elapsed.saturating_sub(last) < self.config.significance_evaluation_interval
                })
            {
                return Ok(SignificanceGateResult::Skipped("significance_rate_limited"));
            }
            let significance_generation = ephemeral.significance_generation;
            let last_evaluated_generation = ephemeral.last_evaluated_generation;
            let last_evaluation_elapsed = ephemeral.last_significance_evaluation_elapsed;
            ephemeral.last_significance_evaluation_elapsed = Some(elapsed);
            ephemeral.last_evaluated_generation = ephemeral.significance_generation;
            (
                significance_generation,
                last_evaluated_generation,
                prior_deadline_risk_active,
                last_evaluation_elapsed,
            )
        };

        let reason_code = if let Some(deadline) = goal.deadline {
            let remaining = deadline - now;
            if remaining.is_negative() || remaining.is_zero() {
                Some("goal_deadline_elapsed")
            } else if remaining
                > time::Duration::try_from(self.config.deadline_risk_horizon)
                    .unwrap_or(time::Duration::MAX)
            {
                Some("outside_deadline_risk_horizon")
            } else if !context.iter().any(|item| {
                matches!(
                    item.category,
                    DataCategory::Goal
                        | DataCategory::BrowserLocation
                        | DataCategory::VisibleText
                        | DataCategory::SelectedDocument
                        | DataCategory::ScreenPixels
                        | DataCategory::WorkspaceActivity
                )
            }) {
                Some("no_fresh_significant_evidence")
            } else {
                None
            }
        } else {
            Some("deadline_not_configured")
        };

        let input = SignificancePolicyInputV1 {
            schema: "stein.significance-policy-input.v1",
            policy_profile_id: POLICY_PROFILE_ID,
            preferences: preferences.into(),
            owner: session.owner.as_uuid(),
            focus_session_id: session.id.as_uuid(),
            focus_session_revision: session.revision,
            goal_id: goal.id.as_uuid(),
            goal_revision: goal.revision.get(),
            goal_deadline: goal.deadline,
            evaluated_at: now,
            monotonic_elapsed_ms: duration_millis_u64(elapsed),
            deadline_risk_horizon_ms: duration_millis_u64(self.config.deadline_risk_horizon),
            evaluation_interval_ms: duration_millis_u64(
                self.config.significance_evaluation_interval,
            ),
            significance_generation,
            last_evaluated_generation,
            prior_deadline_risk_active,
            deadline_risk_active,
            last_evaluation_elapsed_ms: last_evaluation_elapsed.map(duration_millis_u64),
            context: context.iter().map(PolicyContextInputV1::from).collect(),
        };
        Ok(SignificanceGateResult::Evaluated {
            reason_code,
            policy_trace: self.policy_trace(preferences.revision, &input)?,
        })
    }

    fn begin_model_request(
        &self,
        session_id: FocusSessionId,
        maximum_per_hour: u16,
    ) -> Result<Result<ModelRequestPermit, &'static str>, SecondMindError> {
        let elapsed = self.clock.monotonic_elapsed();
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
            SecondMindError::unavailable("The session has no live ephemeral context.")
        })?;
        if session.model_request_in_flight {
            return Ok(Err("model_request_in_flight"));
        }
        while session
            .model_request_history
            .front()
            .is_some_and(|started| elapsed.saturating_sub(*started) >= Duration::from_secs(60 * 60))
        {
            session.model_request_history.pop_front();
        }
        if maximum_per_hour == 0
            || session.model_request_history.len() >= usize::from(maximum_per_hour)
        {
            return Ok(Err("model_hourly_budget_exhausted"));
        }
        if session
            .model_request_history
            .back()
            .is_some_and(|last| elapsed.saturating_sub(*last) < self.config.model_request_cooldown)
        {
            return Ok(Err("model_request_cooldown"));
        }
        session.model_request_in_flight = true;
        session.model_request_history.push_back(elapsed);
        drop(state);
        Ok(Ok(ModelRequestPermit {
            ephemeral: self.ephemeral.clone(),
            session_id,
        }))
    }

    fn record_model_request_started(
        &self,
        receipt: ModelRequestReceipt,
    ) -> Result<bool, SecondMindError> {
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let Some(session) = state.sessions.get_mut(&receipt.focus_session_id) else {
            // Session end/deletion owns removal. A racing model start is an
            // expected denied action, not an availability failure, and must
            // never recreate erased ephemeral evidence.
            return Ok(false);
        };
        if session.cancellation.is_cancelled() || session.proactive_cancellation.is_cancelled() {
            return Ok(false);
        }
        session.latest_model_request_receipt = Some(receipt);
        Ok(true)
    }

    fn record_model_request_completed(
        &self,
        session_id: FocusSessionId,
        request_id: Uuid,
        outcome: ModelRequestReceiptOutcome,
    ) -> Result<(), SecondMindError> {
        debug_assert_ne!(outcome, ModelRequestReceiptOutcome::InFlight);
        let completed_at = self.clock.now_utc();
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let Some(session) = state.sessions.get_mut(&session_id) else {
            // Ending a focus session erases its ephemeral state. A late model
            // completion must not recreate the receipt after that boundary.
            return Ok(());
        };
        if let Some(receipt) = session
            .latest_model_request_receipt
            .as_mut()
            .filter(|receipt| receipt.request_id == request_id)
        {
            receipt.completed_at = Some(completed_at);
            receipt.outcome = outcome;
        }
        Ok(())
    }

    fn pre_model_delivery_gate(
        &self,
        session: &FocusSession,
        preferences: &EffectivePreferences,
    ) -> Result<Option<&'static str>, SecondMindError> {
        if !preferences.proactive_interventions_enabled {
            return Ok(Some("proactive_interventions_disabled"));
        }
        let now = self.clock.now_utc();
        let interventions = self.repository.load_interventions(session.owner)?;
        let delivered_count = interventions
            .iter()
            .filter(|intervention| {
                intervention.focus_session_id == session.id
                    && matches!(
                        intervention.state,
                        InterventionState::AcceptedByChannel | InterventionState::DeliveryUnknown
                    )
            })
            .count();
        if delivered_count >= usize::from(preferences.maximum_interventions_per_session) {
            return Ok(Some("session_intervention_cap"));
        }
        let durable_cooldown = interventions.iter().any(|intervention| {
            let age = now - intervention.updated_at;
            intervention.focus_session_id == session.id
                && consumes_intervention_cooldown(intervention.state)
                && (age.is_negative()
                    || age
                        < time::Duration::try_from(preferences.intervention_cooldown)
                            .unwrap_or(time::Duration::MAX))
        });
        let ephemeral_cooldown = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?
            .sessions
            .get(&session.id)
            .is_some_and(|ephemeral| {
                ephemeral.last_delivery_elapsed.is_some_and(|last| {
                    self.clock.monotonic_elapsed().saturating_sub(last)
                        < preferences.intervention_cooldown
                })
            });
        if durable_cooldown || ephemeral_cooldown {
            return Ok(Some("intervention_cooldown"));
        }
        if !self.notification.availability().is_available() {
            let pending = self.repository.load_pending_deliveries(session.owner)?;
            let queued: Vec<_> = pending
                .iter()
                .filter(|entry| entry.state == OutboxState::Queued)
                .collect();
            let session_ids: BTreeSet<_> = interventions
                .iter()
                .filter(|intervention| intervention.focus_session_id == session.id)
                .map(|intervention| intervention.id)
                .collect();
            if queued.len() >= self.config.outbox_capacity_per_user
                || queued
                    .iter()
                    .filter(|entry| session_ids.contains(&entry.intervention_id))
                    .count()
                    >= self.config.outbox_capacity_per_session
            {
                return Ok(Some("outbox_capacity"));
            }
        }
        Ok(None)
    }

    /// Fail-closed durable revalidation. Startup uses this before ephemeral
    /// sources are reactivated; live delivery adds presence/source checks.
    fn durable_delivery_authority_is_current(
        &self,
        decision: &PolicyDecision,
        goal_id: GoalId,
        intervention_id: InterventionId,
    ) -> bool {
        let now = self.clock.now_utc();
        if decision.outcome != PolicyOutcome::Allow
            || now >= decision.expires_at
            || !decision.policy_trace.is_complete()
            || decision.policy_version != POLICY_PROFILE_ID
            || decision.policy_trace.policy_profile_id != POLICY_PROFILE_ID
        {
            return false;
        }
        let Ok(session) = find_session(&*self.repository, decision.focus_session_id) else {
            return false;
        };
        if session.owner != decision.owner
            || session.goal_id != goal_id
            || session.state != FocusSessionState::Active
            || session.muted
        {
            return false;
        }
        let Ok(goal) = self.get_goal(decision.owner, goal_id) else {
            return false;
        };
        if goal.state != GoalState::Active
            || goal.revision.get() != session.goal_revision
            || goal.deadline.is_some_and(|deadline| deadline <= now)
        {
            return false;
        }
        let Ok(route) = find_route(
            &*self.repository,
            decision.owner,
            session.model_route_approval_id,
        ) else {
            return false;
        };
        let Ok(preferences) = self.effective_preferences(decision.owner) else {
            return false;
        };
        if decision.policy_trace.user_preferences_revision != preferences.revision
            || route.revision != decision.model_route_revision
            || !route.is_current_at(now)
            || (route.placement == crate::ModelPlacement::Remote
                && !preferences.remote_processing_enabled)
            || !preferences.proactive_interventions_enabled
            || preferences.proactive_interventions_muted
            || preferences.is_do_not_disturb(now)
            || !preferences.permits_native_notification()
        {
            return false;
        }
        let Ok(grants) = self.repository.load_grants(decision.owner) else {
            return false;
        };
        if decision.permission_grant_revisions.is_empty()
            || !decision
                .permission_grant_revisions
                .iter()
                .all(|(id, revision)| {
                    grants.iter().any(|grant| {
                        grant.id == *id
                            && grant.revision == *revision
                            && grant.focus_session_id == Some(session.id)
                            && grant.is_current_at(now)
                    })
                })
        {
            return false;
        }
        let Ok(interventions) = self.repository.load_interventions(decision.owner) else {
            return false;
        };
        let delivered_count = interventions
            .iter()
            .filter(|intervention| {
                intervention.id != intervention_id
                    && intervention.focus_session_id == session.id
                    && matches!(
                        intervention.state,
                        InterventionState::AcceptedByChannel | InterventionState::DeliveryUnknown
                    )
            })
            .count();
        let cooldown_active = interventions.iter().any(|intervention| {
            let age = now - intervention.updated_at;
            intervention.id != intervention_id
                && intervention.focus_session_id == session.id
                && consumes_intervention_cooldown(intervention.state)
                && (age.is_negative()
                    || age
                        < time::Duration::try_from(preferences.intervention_cooldown)
                            .unwrap_or(time::Duration::MAX))
        });
        if delivered_count >= usize::from(preferences.maximum_interventions_per_session)
            || cooldown_active
        {
            return false;
        }
        true
    }

    /// Fail-closed, side-effect-free revalidation used immediately before a
    /// notification attempt and after a definite non-delivery result.
    fn delivery_authority_is_current(
        &self,
        decision: &PolicyDecision,
        goal_id: GoalId,
        intervention_id: InterventionId,
    ) -> bool {
        if !self.durable_delivery_authority_is_current(decision, goal_id, intervention_id) {
            return false;
        }
        let now = self.clock.now_utc();
        let Ok(session) = find_session(&*self.repository, decision.focus_session_id) else {
            return false;
        };
        let Ok(grants) = self.repository.load_grants(decision.owner) else {
            return false;
        };
        self.ephemeral.lock().is_ok_and(|state| {
            state.sessions.get(&session.id).is_some_and(|ephemeral| {
                ephemeral.presence == crate::PresenceState::Active
                    && grants
                        .iter()
                        .filter(|grant| {
                            grant.scope.is_observation()
                                && decision
                                    .permission_grant_revisions
                                    .iter()
                                    .any(|(id, _)| *id == grant.id)
                        })
                        .all(|grant| {
                            ephemeral
                                .source_health
                                .get(&grant.id)
                                .is_some_and(|status| {
                                    status.health == crate::SourceHealth::Healthy
                                        && now - status.observed_at
                                            <= time::Duration::try_from(
                                                self.config.source_freshness,
                                            )
                                            .unwrap_or(time::Duration::MAX)
                                })
                        })
            })
        })
    }

    fn note_goal_state_change(&self, owner: ActorId, goal_id: GoalId) {
        let Ok(sessions) = self.repository.load_focus_sessions(owner) else {
            return;
        };
        let affected: BTreeSet<_> = sessions
            .into_iter()
            .filter(|session| {
                session.goal_id == goal_id && session.state == FocusSessionState::Active
            })
            .map(|session| session.id)
            .collect();
        if let Ok(mut state) = self.ephemeral.lock() {
            for session_id in affected {
                if let Some(session) = state.sessions.get_mut(&session_id) {
                    session.significance_generation =
                        session.significance_generation.saturating_add(1);
                }
            }
        }
    }

    fn capture_projection(&self, session: &FocusSession) -> CaptureViewProjection {
        let grants = self
            .repository
            .load_grants(session.owner)
            .unwrap_or_default();
        let mut source_statuses: Vec<ObservationSourceStatus> = self
            .ephemeral
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .sessions
                    .get(&session.id)
                    .map(|value| value.source_health.values().cloned().collect())
            })
            .unwrap_or_default();
        source_statuses.sort_by_key(|status: &ObservationSourceStatus| status.grant_id);
        CaptureViewProjection {
            session: session.clone(),
            grants,
            source_statuses,
            native_status_available: self.native_status.availability().is_available(),
            emergency_control_available: self.emergency_control.availability().is_available(),
        }
    }

    fn push_focus_and_capture(
        &self,
        events: &mut Vec<CoreEvent>,
        change: FocusSessionViewChange,
        session: &FocusSession,
    ) {
        events.push(CoreEvent::FocusSessionViewChanged {
            change,
            focus_session: session.clone(),
        });
        events.push(CoreEvent::CaptureStateChanged {
            capture: self.capture_projection(session),
        });
    }

    fn push_intervention_update(
        events: &mut Vec<CoreEvent>,
        intervention: &Intervention,
        history_change: InterventionHistoryViewChange,
    ) {
        events.push(CoreEvent::InterventionViewChanged {
            intervention: intervention.clone(),
        });
        events.push(CoreEvent::InterventionHistoryChanged {
            change: history_change,
            owner: intervention.owner,
            intervention_id: intervention.id,
            entry: Some(intervention.clone()),
        });
    }

    pub fn repository(&self) -> &Arc<dyn DurableRepository> {
        &self.repository
    }

    pub fn owner_state_snapshot(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
    ) -> Result<crate::OwnerStateSnapshot, SecondMindError> {
        require_private(assurance)?;
        if let Some(publication) = self.publication.get() {
            publication.capture(|_state, _receiver| self.owner_state_snapshot_unpublished(owner))
        } else {
            self.owner_state_snapshot_unpublished(owner)
        }
    }

    pub(crate) fn owner_state_snapshot_unpublished(
        &self,
        owner: ActorId,
    ) -> Result<crate::OwnerStateSnapshot, SecondMindError> {
        Ok(self.repository.load_owner_state(owner)?)
    }

    pub fn observation_source_statuses(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        session_id: FocusSessionId,
    ) -> Result<Vec<ObservationSourceStatus>, SecondMindError> {
        require_private(assurance)?;
        let session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError {
                code: SecondMindErrorCode::NotFound,
                summary: "The focus session was not found.",
                retryable: false,
                current_revision: None,
            });
        }
        let state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let mut statuses: Vec<_> = state
            .sessions
            .get(&session_id)
            .map(|ephemeral| ephemeral.source_health.values().cloned().collect())
            .unwrap_or_default();
        statuses.sort_by_key(|status| status.grant_id);
        Ok(statuses)
    }

    pub fn latest_model_request_receipt(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        session_id: FocusSessionId,
    ) -> Result<Option<ModelRequestReceipt>, SecondMindError> {
        require_private(assurance)?;
        let session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError {
                code: SecondMindErrorCode::NotFound,
                summary: "The focus session was not found.",
                retryable: false,
                current_revision: None,
            });
        }
        let state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        Ok(state
            .sessions
            .get(&session_id)
            .and_then(|ephemeral| ephemeral.latest_model_request_receipt.clone()))
    }

    pub fn notification_availability(&self) -> PlatformPortAvailability {
        self.notification.availability()
    }

    pub fn native_status_availability(&self) -> PlatformPortAvailability {
        self.native_status.availability()
    }

    pub fn emergency_control_availability(&self) -> PlatformPortAvailability {
        self.emergency_control.availability()
    }

    pub async fn run_emergency_control_loop(
        &self,
        owner: ActorId,
        shutdown: CancellationToken,
    ) -> Result<(), SecondMindError> {
        loop {
            let envelope = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                command = self.emergency_control.next_command() => {
                    command.map_err(|_| SecondMindError::unavailable(
                        "The independent emergency-control channel failed.",
                    ))?
                }
            };
            let now = self.clock.now_utc();
            let revision_is_new = {
                let mut last_revision =
                    self.last_emergency_command_revision.lock().map_err(|_| {
                        SecondMindError::unavailable(
                            "The emergency-control revision state is unavailable.",
                        )
                    })?;
                if envelope.revision == 0 || envelope.revision <= *last_revision {
                    false
                } else {
                    *last_revision = envelope.revision;
                    true
                }
            };
            let valid = revision_is_new
                && envelope.command_id.get_version_num() == 7
                && envelope.issued_at <= now + time::Duration::seconds(1);
            let status = if !valid {
                EmergencyCommandStatus::Rejected
            } else {
                match envelope.command {
                    // CORE has no launch/presentation port. Reject instead of
                    // acknowledging a UI action that no component performed.
                    EmergencyCommand::OpenStein => EmergencyCommandStatus::Rejected,
                    EmergencyCommand::SetInterventionsMuted { session_id, muted } => {
                        let session = find_session(&*self.repository, session_id)?;
                        match self
                            .set_interventions_muted(
                                ClientAssurance::NativeEmergencyControl,
                                owner,
                                session_id,
                                session.revision,
                                muted,
                            )
                            .await
                        {
                            Ok(_) => EmergencyCommandStatus::Accepted,
                            Err(_) => EmergencyCommandStatus::Rejected,
                        }
                    }
                    EmergencyCommand::StopAllObservation => {
                        let mut stopping = Vec::new();
                        for session in self.repository.load_focus_sessions(owner)? {
                            if !session.is_working() {
                                continue;
                            }
                            match self.end_focus_session(
                                ClientAssurance::NativeEmergencyControl,
                                owner,
                                session.id,
                                session.revision,
                                EndFocusReason::EmergencyStop,
                            ) {
                                Ok(value) => stopping.push(value),
                                Err(_) => {
                                    stopping.clear();
                                    break;
                                }
                            }
                        }
                        if stopping.is_empty()
                            && self
                                .repository
                                .load_focus_sessions(owner)?
                                .iter()
                                .any(FocusSession::is_working)
                        {
                            EmergencyCommandStatus::Rejected
                        } else {
                            let mut cleanup_incomplete = false;
                            for session in stopping {
                                if self
                                    .finish_end_focus_session(owner, session.id, session.revision)
                                    .await
                                    .is_err()
                                {
                                    cleanup_incomplete = true;
                                }
                            }
                            if cleanup_incomplete {
                                EmergencyCommandStatus::CleanupIncomplete
                            } else {
                                EmergencyCommandStatus::Accepted
                            }
                        }
                    }
                }
            };
            let acknowledgement = EmergencyCommandAcknowledgement {
                command_id: envelope.command_id,
                revision: envelope.revision,
                status,
                acknowledged_at: self.clock.now_utc(),
            };
            let receipt = self
                .emergency_control
                .acknowledge(acknowledgement.clone())
                .await
                .map_err(|_| {
                    SecondMindError::unavailable("The emergency-control acknowledgement failed.")
                })?;
            if receipt.command_id != acknowledgement.command_id
                || receipt.revision != acknowledgement.revision
            {
                return Err(SecondMindError::unavailable(
                    "The emergency-control acknowledgement identity was invalid.",
                ));
            }
        }
    }

    pub fn create_goal(
        &self,
        assurance: ClientAssurance,
        command: CreateGoal,
    ) -> Result<Goal, SecondMindError> {
        self.create_goal_unpublished(assurance, command)
    }

    pub(crate) fn create_goal_unpublished(
        &self,
        assurance: ClientAssurance,
        command: CreateGoal,
    ) -> Result<Goal, SecondMindError> {
        require_private(assurance)?;
        validate_text(&command.title, 1, 200, "Goal title is invalid.")?;
        validate_text(
            &command.success_statement,
            1,
            2_000,
            "Goal success statement is invalid.",
        )?;
        if let Some((receipt, goal)) = self
            .repository
            .find_goal_create(command.actor, command.idempotency_key)?
        {
            if receipt.title == command.title
                && receipt.success_statement == command.success_statement
                && receipt.deadline == command.deadline
            {
                return Ok(goal);
            }
            return Err(SecondMindError::idempotency_conflict());
        }
        let now = self.clock.now_utc();
        let goal = Goal {
            id: GoalId::new_v7(),
            owner: command.actor,
            title: command.title.clone(),
            success_statement: command.success_statement.clone(),
            deadline: command.deadline,
            state: GoalState::Active,
            revision: Revision::INITIAL,
            created_at: now,
            updated_at: now,
        };
        self.repository.create_goal(
            &goal,
            &GoalCreateReceipt {
                actor: command.actor,
                idempotency_key: command.idempotency_key,
                goal_id: goal.id,
                title: command.title,
                success_statement: command.success_statement,
                deadline: command.deadline,
            },
        )?;
        Ok(goal)
    }

    pub fn update_goal(
        &self,
        assurance: ClientAssurance,
        command: UpdateGoal,
    ) -> Result<Goal, SecondMindError> {
        self.update_goal_unpublished(assurance, command)
    }

    pub(crate) fn update_goal_unpublished(
        &self,
        assurance: ClientAssurance,
        command: UpdateGoal,
    ) -> Result<Goal, SecondMindError> {
        require_private(assurance)?;
        if command.patch.is_empty() {
            return Err(SecondMindError::invalid("A goal patch cannot be empty."));
        }
        if let Some(value) = &command.patch.title {
            validate_text(value, 1, 200, "Goal title is invalid.")?;
        }
        if let Some(value) = &command.patch.success_statement {
            validate_text(value, 1, 2_000, "Goal success statement is invalid.")?;
        }
        let mut goal = self.get_goal(command.actor, command.id)?;
        if goal.revision != command.expected_revision {
            return Err(SecondMindError::conflict(goal.revision.get()));
        }
        let affected_sessions = self.cancel_proactive_for_goal(goal.owner, goal.id)?;
        apply_goal_patch(&mut goal, command.patch);
        let expected = goal.revision.get();
        goal.revision = goal.revision.next();
        goal.updated_at = self.clock.now_utc();
        if let Err(error) = self.repository.update_goal(&goal, expected) {
            if let Ok(preferences) = self.effective_preferences(goal.owner) {
                let _ = self.reconcile_proactive_cancellation_for_owner(
                    goal.owner,
                    preferences.proactive_interventions_enabled,
                    preferences.proactive_interventions_muted,
                );
            }
            return Err(error.into());
        }
        for session_id in affected_sessions {
            self.cancel_queued_interventions(
                goal.owner,
                Some(session_id),
                None,
                "goal_revision_changed",
                self.daemon_context(),
            )?;
        }
        self.note_goal_state_change(goal.owner, goal.id);
        Ok(goal)
    }

    pub async fn set_goal_state(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        state: GoalState,
    ) -> Result<Goal, SecondMindError> {
        self.set_goal_state_with_context(
            assurance,
            owner,
            goal_id,
            expected_revision,
            state,
            self.daemon_context(),
        )
        .await
    }

    pub(crate) async fn set_goal_state_with_context(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        state: GoalState,
        context: EventContext,
    ) -> Result<Goal, SecondMindError> {
        require_private(assurance)?;
        if state == GoalState::Active {
            return Err(SecondMindError::invalid(
                "A terminal goal command must complete or abandon the goal.",
            ));
        }
        let mut goal = self.get_goal(owner, goal_id)?;
        if goal.revision.get() != expected_revision {
            return Err(SecondMindError::conflict(goal.revision.get()));
        }
        self.cancel_proactive_for_goal(owner, goal_id)?;
        let expected = goal.revision.get();
        goal.state = state;
        goal.revision = goal.revision.next();
        goal.updated_at = self.clock.now_utc();
        let save_result = self.commit(context, |events| {
            self.repository.update_goal(&goal, expected)?;
            events.push(CoreEvent::GoalViewChanged {
                change: match state {
                    GoalState::Completed => crate::GoalViewChange::Completed,
                    GoalState::Abandoned => crate::GoalViewChange::Abandoned,
                    GoalState::Active => crate::GoalViewChange::Updated,
                },
                goal: goal.clone(),
            });
            Ok(())
        });
        if let Err(error) = save_result {
            if let Ok(preferences) = self.effective_preferences(owner) {
                let _ = self.reconcile_proactive_cancellation_for_owner(
                    owner,
                    preferences.proactive_interventions_enabled,
                    preferences.proactive_interventions_muted,
                );
            }
            return Err(error);
        }
        for session in self.repository.load_focus_sessions(owner)? {
            if session.goal_id == goal_id && session.is_working() {
                let stopping = self.end_focus_session(
                    ClientAssurance::NativeEmergencyControl,
                    owner,
                    session.id,
                    session.revision,
                    if state == GoalState::Completed {
                        EndFocusReason::GoalCompleted
                    } else {
                        EndFocusReason::GoalAbandoned
                    },
                )?;
                let _ = self
                    .finish_end_focus_session(owner, session.id, stopping.revision)
                    .await;
            }
        }
        Ok(goal)
    }

    pub async fn delete_goal(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
    ) -> Result<crate::GoalDeletionResult, SecondMindError> {
        self.delete_goal_with_context(
            assurance,
            owner,
            goal_id,
            expected_revision,
            self.daemon_context(),
        )
        .await
    }

    pub(crate) async fn delete_goal_with_context(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        context: EventContext,
    ) -> Result<crate::GoalDeletionResult, SecondMindError> {
        require_private(assurance)?;
        // The publication fence orders the cleanup-plan read with all other
        // application mutations. The repository transaction then validates
        // the exact goal revision and revokes every durable authority before
        // any fallible adapter cleanup begins.
        let deletion_result = self.commit(context, |events| {
            let deleted_sessions: Vec<_> = self
                .repository
                .load_focus_sessions(owner)?
                .into_iter()
                .filter(|session| session.goal_id == goal_id)
                .collect();
            let deleted_session_ids = deleted_sessions
                .iter()
                .filter(|session| session.is_working())
                .map(|session| session.id)
                .collect();
            self.cancel_proactive_for_session_ids(&deleted_session_ids)?;
            let deleted_grants: Vec<_> = self
                .repository
                .load_grants(owner)?
                .into_iter()
                .filter(|grant| grant.goal_id == goal_id)
                .collect();
            let result = self.repository.delete_goal_with_tombstone(
                owner,
                goal_id,
                expected_revision,
                self.clock.now_utc(),
            )?;
            if !result.already_deleted {
                events.push(CoreEvent::GoalDeleted {
                    tombstone: result.tombstone.clone(),
                });
            }
            Ok((result, deleted_sessions, deleted_grants))
        });
        let (result, deleted_sessions, deleted_grants) = match deletion_result {
            Ok(result) => result,
            Err(error) => {
                if let Ok(preferences) = self.effective_preferences(owner) {
                    let _ = self.reconcile_proactive_cancellation_for_owner(
                        owner,
                        preferences.proactive_interventions_enabled,
                        preferences.proactive_interventions_muted,
                    );
                }
                return Err(error);
            }
        };
        // The content-free, checksummed tombstone is the atomic durable
        // deletion marker. A second fallible audit append here would make a
        // completed delete look failed and could never be repaired on retry.
        if !result.already_deleted {
            self.cleanup_deleted_focus_sessions(&deleted_sessions, &deleted_grants)
                .await?;
        }
        // Retained native cleanup obligations are retried even when this is a
        // response-loss replay of an already committed deletion.
        self.drain_native_resource_cleanups(owner).await?;
        Ok(result)
    }

    async fn cleanup_deleted_focus_sessions(
        &self,
        sessions: &[FocusSession],
        grants: &[PermissionGrant],
    ) -> Result<(), SecondMindError> {
        let mut cleanup_incomplete = false;
        for session in sessions {
            if let Ok(mut state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.remove(&session.id)
            {
                ephemeral.cancellation.cancel();
            }
            for grant_id in &session.permission_grant_ids {
                if !grants
                    .iter()
                    .any(|grant| grant.id == *grant_id && grant.scope.is_observation())
                {
                    continue;
                }
                let stopped = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.observation.stop(session.id, *grant_id),
                )
                .await;
                if !matches!(stopped, Ok(Ok(()))) {
                    cleanup_incomplete = true;
                }
            }
            let cleared = tokio::time::timeout(
                Duration::from_secs(5),
                self.native_status.clear(session.id, session.revision),
            )
            .await;
            if !matches!(
                cleared,
                Ok(Ok(NativeStatusAcknowledgement {
                    session_id,
                    revision,
                    ..
                })) if session_id == session.id && revision == session.revision
            ) {
                cleanup_incomplete = true;
            }
        }
        if cleanup_incomplete {
            return Err(SecondMindError::unavailable(
                "The goal was deleted and its authority remains revoked, but bounded adapter cleanup is incomplete.",
            ));
        }
        Ok(())
    }

    pub fn get_goal(&self, owner: ActorId, goal_id: GoalId) -> Result<Goal, SecondMindError> {
        self.repository
            .load_goals(owner)?
            .into_iter()
            .find(|goal| goal.id == goal_id)
            .ok_or(SecondMindError {
                code: SecondMindErrorCode::NotFound,
                summary: "The goal was not found.",
                retryable: false,
                current_revision: None,
            })
    }

    pub fn list_goals(&self, owner: ActorId) -> Result<Vec<Goal>, SecondMindError> {
        Ok(self.repository.load_goals(owner)?)
    }

    pub fn stein_identity(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
    ) -> Result<SteinIdentity, SecondMindError> {
        require_private(assurance)?;
        if let Some(identity) = self.repository.load_identity(owner)? {
            if !identity.has_shipped_v1_invariants() {
                return Err(SecondMindError::unavailable(
                    "The installed STEIN identity requires a product migration.",
                ));
            }
            return Ok(identity);
        }
        let identity = SteinIdentity::shipped_v1(owner, self.clock.now_utc());
        match self.repository.save_identity(&identity, None) {
            Ok(()) => Ok(identity),
            Err(error) if error.kind == RepositoryErrorKind::Conflict => self
                .repository
                .load_identity(owner)?
                .filter(SteinIdentity::has_shipped_v1_invariants)
                .ok_or_else(|| {
                    SecondMindError::unavailable(
                        "The installed STEIN identity requires a product migration.",
                    )
                }),
            Err(error) => Err(error.into()),
        }
    }

    pub fn user_preferences(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
    ) -> Result<ExplicitPreferences, SecondMindError> {
        require_private(assurance)?;
        if let Some(preferences) = self.repository.load_preferences(owner)? {
            return Ok(preferences);
        }
        let preferences = ExplicitPreferences::phase2_defaults(owner, self.clock.now_utc());
        match self.repository.save_preferences(&preferences, None) {
            Ok(()) => Ok(preferences),
            Err(error) if error.kind == RepositoryErrorKind::Conflict => self
                .repository
                .load_preferences(owner)?
                .ok_or_else(|| SecondMindError::unavailable("User preferences are unavailable.")),
            Err(error) => Err(error.into()),
        }
    }

    pub fn current_device(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
    ) -> Result<crate::DeviceRegistration, SecondMindError> {
        require_private(assurance)?;
        Ok(self.repository.load_or_issue_device(
            owner,
            crate::DeviceId::new_v7(),
            self.clock.now_utc(),
        )?)
    }

    pub fn effective_policy_view(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
    ) -> Result<EffectivePolicy, SecondMindError> {
        require_private(assurance)?;
        let preferences = self.user_preferences(assurance, owner)?;
        let effective = EffectivePreferences::from_record(
            &self.config,
            owner,
            self.clock.now_utc(),
            Some(preferences),
        );
        Ok(self.effective_policy_from(effective))
    }

    fn effective_policy_from(&self, effective: EffectivePreferences) -> EffectivePolicy {
        EffectivePolicy {
            policy_profile_id: POLICY_PROFILE_ID,
            user_preferences_revision: effective.revision,
            source_stale_after: self.config.source_freshness,
            maximum_model_evidence_age: self.config.maximum_model_evidence_age,
            model_request_cooldown: self.config.model_request_cooldown,
            maximum_model_requests_per_hour: effective.maximum_model_requests_per_hour,
            intervention_cooldown: effective.intervention_cooldown,
            maximum_interventions_per_session: effective.maximum_interventions_per_session,
            proactive_interventions_enabled: effective.proactive_interventions_enabled,
            proactive_interventions_muted: effective.proactive_interventions_muted,
            do_not_disturb_windows: effective.do_not_disturb_windows,
            allowed_delivery_channels: effective.allowed_delivery_channels,
            remote_processing_enabled: effective.remote_processing_enabled,
            restart_continuity_default: effective.restart_continuity_default,
            outbox_capacity_per_user: self.config.outbox_capacity_per_user,
            outbox_capacity_per_session: self.config.outbox_capacity_per_session,
        }
    }

    pub fn save_preferences(
        &self,
        assurance: ClientAssurance,
        value: ExplicitPreferences,
        expected_revision: Option<u64>,
    ) -> Result<ExplicitPreferences, SecondMindError> {
        self.save_preferences_with_context(
            assurance,
            value,
            expected_revision,
            self.daemon_context(),
        )
    }

    pub(crate) fn save_preferences_with_context(
        &self,
        assurance: ClientAssurance,
        mut value: ExplicitPreferences,
        expected_revision: Option<u64>,
        context: EventContext,
    ) -> Result<ExplicitPreferences, SecondMindError> {
        require_private(assurance)?;
        if let Some(value) = &value.preferred_form_of_address {
            validate_text(value, 1, 80, "The preferred form of address is invalid.")?;
        }
        if value.schema_version != USER_PREFERENCES_SCHEMA_V1
            || value.default_focus_minutes == 0
            || value.default_focus_minutes > 24 * 60
            || value.maximum_interventions_per_session
                > self.config.maximum_interventions_per_session
            || value.maximum_model_requests_per_hour > self.config.maximum_model_requests_per_hour
            || value.minimum_intervention_cooldown_seconds
                < self.config.intervention_cooldown.as_secs()
            || value.do_not_disturb_windows.len() > 16
            || value
                .do_not_disturb_windows
                .iter()
                .any(|window| !valid_do_not_disturb_window(*window))
            || value.allowed_delivery_channels.len() > 8
            || value.allowed_delivery_channels.iter().any(|channel| {
                channel.is_empty() || channel.len() > 64 || channel.chars().any(char::is_control)
            })
        {
            return Err(SecondMindError::invalid("Preference limits are invalid."));
        }
        value.revision = expected_revision.map_or(1, |revision| revision.saturating_add(1));
        value.updated_at = self.clock.now_utc();
        value.provenance = crate::RecordProvenance {
            source: crate::RecordProvenanceSource::DirectUser,
            version: "user-preferences-v1".to_owned(),
            recorded_at: value.updated_at,
        };
        let effective_preferences = EffectivePreferences::from_record(
            &self.config,
            value.owner,
            value.updated_at,
            Some(value.clone()),
        );
        // Every preference revision invalidates the exact policy trace, even
        // when the new value is equally permissive. Cancel the old token before
        // the durable boundary; a successful commit rotates fresh authority
        // only after stale queued content has been scrubbed.
        self.cancel_proactive_for_owner(value.owner)?;
        let effective_policy = self.effective_policy_from(effective_preferences.clone());
        let save_result = self.commit(context, |events| {
            self.repository
                .save_preferences(&value, expected_revision)?;
            events.push(CoreEvent::UserPreferencesViewChanged {
                preferences: value.clone(),
                effective_policy,
            });
            Ok(())
        });
        if let Err(error) = save_result {
            // A failed permissive update must not leave newly armed authority.
            // A failed restrictive update may remain conservatively cancelled
            // if the current record cannot be reloaded.
            if let Ok(current) = self.effective_preferences(value.owner) {
                let _ = self.reconcile_proactive_cancellation_for_owner(
                    value.owner,
                    current.proactive_interventions_enabled,
                    current.proactive_interventions_muted,
                );
            }
            return Err(error);
        }
        self.cancel_queued_interventions(
            value.owner,
            None,
            None,
            if effective_preferences.proactive_interventions_muted {
                "interventions_muted"
            } else if !effective_preferences.proactive_interventions_enabled {
                "proactive_interventions_disabled"
            } else {
                "preferences_revision_changed"
            },
            context,
        )?;
        // Reconcile against the now-current record and session/goal state. A
        // permissive revision gets a fresh token; restrictive/stale sessions
        // remain cancelled.
        self.reconcile_proactive_cancellation_for_owner(
            value.owner,
            effective_preferences.proactive_interventions_enabled,
            effective_preferences.proactive_interventions_muted,
        )?;
        Ok(value)
    }

    pub fn save_resource_binding(
        &self,
        assurance: ClientAssurance,
        value: ResourceBinding,
    ) -> Result<ResourceBinding, SecondMindError> {
        self.save_resource_binding_with_context(assurance, value, self.daemon_context())
    }

    pub(crate) async fn select_and_register_resource_with_context(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        kind: crate::ResourceKind,
        idempotency: IdempotencyContext,
        cancellation: CancellationToken,
        context: EventContext,
    ) -> Result<ResourceBinding, SecondMindError> {
        require_private(assurance)?;
        if let Some(result_id) =
            self.replayed_result(owner, OperationKind::RegisterSelectedResource, idempotency)?
        {
            return find_resource(&*self.repository, owner, ResourceId::from_uuid(result_id));
        }

        let selection_cancellation = cancellation.child_token();
        let selected = match tokio::time::timeout(
            self.config.resource_selection_deadline,
            self.resource_selection
                .select(kind, selection_cancellation.clone()),
        )
        .await
        {
            Ok(Ok(Some(selected))) => selected,
            Ok(Ok(None)) => {
                selection_cancellation.cancel();
                return Err(SecondMindError::cancelled(
                    "Native resource selection was cancelled.",
                ));
            }
            Ok(Err(error)) if error.kind == ResourceSelectionErrorKind::Cancelled => {
                selection_cancellation.cancel();
                return Err(SecondMindError::cancelled(error.summary));
            }
            Ok(Err(error)) => return Err(SecondMindError::unavailable(error.summary)),
            Err(_) => {
                selection_cancellation.cancel();
                return Err(SecondMindError::deadline_exceeded(
                    "Native resource selection timed out.",
                ));
            }
        };
        let resource_id = ResourceId::new_v7();
        let rollback_binding = selected.binding.clone();
        if selected.kind != kind {
            self.release_or_retain_native_cleanup(owner, resource_id, rollback_binding)
                .await?;
            return Err(SecondMindError::unavailable(
                "The native picker returned a different resource kind.",
            ));
        }
        if cancellation.is_cancelled() {
            self.release_or_retain_native_cleanup(owner, resource_id, rollback_binding)
                .await?;
            return Err(SecondMindError::cancelled(
                "Native resource registration was cancelled.",
            ));
        }
        if let Err(error) = validate_text(
            selected.binding.as_str(),
            1,
            512,
            "Resource reference is invalid.",
        ) {
            self.release_or_retain_native_cleanup(owner, resource_id, rollback_binding)
                .await?;
            return Err(error);
        }
        if let Err(error) = validate_text(
            &selected.safe_display_label,
            1,
            120,
            "Resource label is invalid.",
        ) {
            self.release_or_retain_native_cleanup(owner, resource_id, rollback_binding)
                .await?;
            return Err(error);
        }
        let value = ResourceBinding {
            id: resource_id,
            owner,
            kind,
            opaque_reference: selected.binding.into_inner(),
            display_label: selected.safe_display_label,
            revision: 1,
            created_at: self.clock.now_utc(),
        };
        let receipt = OperationReceipt {
            owner,
            kind: OperationKind::RegisterSelectedResource,
            idempotency_key: idempotency.key,
            request_digest: idempotency.request_digest,
            result_id: value.id.as_uuid(),
        };
        let committed = self.commit(context, |events| {
            self.repository.create_resource(&value, &receipt)?;
            events.push(CoreEvent::SelectedResourceViewChanged {
                change: crate::SelectedResourceViewChange::Registered,
                owner,
                resource: Some(value.clone()),
                tombstone: None,
            });
            Ok(value.clone())
        });
        match committed {
            Ok(value) => Ok(value),
            Err(error) => {
                let replayed = if error.code == SecondMindErrorCode::Conflict {
                    self.replayed_result(
                        owner,
                        OperationKind::RegisterSelectedResource,
                        idempotency,
                    )?
                } else {
                    None
                };
                let cleanup = self
                    .release_or_retain_native_cleanup(owner, resource_id, rollback_binding)
                    .await;
                if let Some(result_id) = replayed {
                    // A committed idempotent result wins even if cleanup of
                    // this losing picker candidate reports a bounded failure.
                    return find_resource(
                        &*self.repository,
                        owner,
                        ResourceId::from_uuid(result_id),
                    );
                }
                cleanup?;
                Err(error)
            }
        }
    }

    async fn release_native_binding(
        &self,
        binding: NativeResourceBinding,
    ) -> Result<(), SecondMindError> {
        let cancellation = CancellationToken::new();
        match tokio::time::timeout(
            self.config.resource_release_deadline,
            self.resource_selection
                .release(binding, cancellation.clone()),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(SecondMindError::unavailable(
                "Native resource cleanup failed after durable authority changed.",
            )),
            Err(_) => {
                cancellation.cancel();
                Err(SecondMindError::deadline_exceeded(
                    "Native resource cleanup timed out after durable authority changed.",
                ))
            }
        }
    }

    async fn release_or_retain_native_cleanup(
        &self,
        owner: ActorId,
        resource_id: ResourceId,
        binding: NativeResourceBinding,
    ) -> Result<(), SecondMindError> {
        let opaque_reference = binding.as_str().to_owned();
        match self.release_native_binding(binding).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.repository
                    .save_native_resource_cleanup(&crate::NativeResourceCleanup {
                        owner,
                        resource_id,
                        opaque_reference,
                        created_at: self.clock.now_utc(),
                    })?;
                Err(error)
            }
        }
    }

    async fn drain_native_resource_cleanups(&self, owner: ActorId) -> Result<(), SecondMindError> {
        for mut cleanup in self.repository.load_native_resource_cleanups(owner)? {
            let binding = NativeResourceBinding::new(std::mem::take(&mut cleanup.opaque_reference));
            self.release_native_binding(binding).await?;
            self.repository
                .complete_native_resource_cleanup(owner, cleanup.resource_id)?;
        }
        Ok(())
    }

    /// Retries a bounded batch of private cleanup obligations without
    /// recreating or consulting them as authority. Individual platform
    /// failures remain pending and are reported only as content-free counts;
    /// repository/invariant failures stop maintenance fail-closed.
    pub async fn recover_cleanup_obligations(
        &self,
        owner: ActorId,
    ) -> Result<CleanupMaintenanceResult, SecondMindError> {
        let native_cleanups = self.repository.load_native_resource_cleanups(owner)?;
        let secret_cleanups = self.repository.load_secret_deletion_cleanups(owner)?;
        let resources = self.repository.load_resources(owner)?;
        let routes = self.repository.load_model_routes(owner)?;
        let mut result = CleanupMaintenanceResult {
            native_resource_pending: native_cleanups.len(),
            secret_deletion_pending: secret_cleanups.len(),
            ..CleanupMaintenanceResult::default()
        };

        for mut cleanup in native_cleanups
            .into_iter()
            .take(self.config.recovery_batch_size)
        {
            if resources
                .iter()
                .any(|resource| resource.id == cleanup.resource_id)
            {
                return Err(SecondMindError::unavailable(
                    "A native cleanup obligation still has live resource authority.",
                ));
            }
            result.native_resource_attempts = result.native_resource_attempts.saturating_add(1);
            let binding = NativeResourceBinding::new(std::mem::take(&mut cleanup.opaque_reference));
            if self.release_native_binding(binding).await.is_ok() {
                self.repository
                    .complete_native_resource_cleanup(owner, cleanup.resource_id)?;
                result.native_resource_completed =
                    result.native_resource_completed.saturating_add(1);
                result.native_resource_pending = result.native_resource_pending.saturating_sub(1);
            }
        }

        for cleanup in secret_cleanups
            .into_iter()
            .take(self.config.recovery_batch_size)
        {
            let route_is_revoked = routes.iter().any(|route| {
                route.id == cleanup.model_route_approval_id
                    && route.owner == owner
                    && route.revoked_at.is_some()
                    && route.secret_ref == cleanup.secret_ref
            });
            if !route_is_revoked {
                return Err(SecondMindError::unavailable(
                    "A secret cleanup obligation is not fenced by revoked route authority.",
                ));
            }
            result.secret_deletion_attempts = result.secret_deletion_attempts.saturating_add(1);
            if self.secret_store.delete(&cleanup.secret_ref).is_ok() {
                self.repository
                    .complete_secret_deletion_cleanup(owner, cleanup.model_route_approval_id)?;
                result.secret_deletion_completed =
                    result.secret_deletion_completed.saturating_add(1);
                result.secret_deletion_pending = result.secret_deletion_pending.saturating_sub(1);
            }
        }

        Ok(result)
    }

    pub(crate) fn save_resource_binding_with_context(
        &self,
        assurance: ClientAssurance,
        value: ResourceBinding,
        context: EventContext,
    ) -> Result<ResourceBinding, SecondMindError> {
        require_private(assurance)?;
        validate_text(
            &value.opaque_reference,
            1,
            512,
            "Resource reference is invalid.",
        )?;
        validate_text(&value.display_label, 1, 120, "Resource label is invalid.")?;
        self.commit(context, |events| {
            self.repository.save_resource(&value)?;
            events.push(CoreEvent::SelectedResourceViewChanged {
                change: crate::SelectedResourceViewChange::Registered,
                owner: value.owner,
                resource: Some(value.clone()),
                tombstone: None,
            });
            Ok(())
        })?;
        Ok(value)
    }

    pub async fn remove_resource_binding(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        resource_id: ResourceId,
        expected_revision: u64,
    ) -> Result<crate::SelectedResourceDeletionTombstone, SecondMindError> {
        self.remove_resource_binding_with_context(
            assurance,
            owner,
            resource_id,
            expected_revision,
            self.daemon_context(),
        )
        .await
    }

    pub(crate) async fn remove_resource_binding_with_context(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        resource_id: ResourceId,
        expected_revision: u64,
        context: EventContext,
    ) -> Result<crate::SelectedResourceDeletionTombstone, SecondMindError> {
        require_private(assurance)?;
        let result = self.commit(context, |events| {
            let result = self.repository.remove_resource(
                owner,
                resource_id,
                expected_revision,
                self.clock.now_utc(),
            )?;
            if !result.already_removed {
                events.push(CoreEvent::SelectedResourceViewChanged {
                    change: crate::SelectedResourceViewChange::Removed,
                    owner,
                    resource: None,
                    tombstone: Some(result.tombstone.clone()),
                });
            }
            Ok(result)
        })?;
        self.drain_native_resource_cleanups(owner).await?;
        Ok(result.tombstone)
    }

    pub fn approve_model_route(
        &self,
        assurance: ClientAssurance,
        idempotency: IdempotencyContext,
        value: ModelRouteApproval,
    ) -> Result<ModelRouteApproval, SecondMindError> {
        require_private(assurance)?;
        if let Some(result_id) =
            self.replayed_result(value.owner, OperationKind::ApproveModelRoute, idempotency)?
        {
            return find_route(
                &*self.repository,
                value.owner,
                ModelRouteApprovalId::from_uuid(result_id),
            );
        }
        validate_model_route(&value, self.clock.now_utc())?;
        let audit = self.build_audit_record(
            value.owner,
            AuditKind::ModelRouteApproved,
            value.id.as_uuid(),
            AuditDetails::new(
                vec!["model_route_approved".to_owned()],
                value.allowed_categories.clone(),
            ),
        );
        let receipt = OperationReceipt {
            owner: value.owner,
            kind: OperationKind::ApproveModelRoute,
            idempotency_key: idempotency.key,
            request_digest: idempotency.request_digest,
            result_id: value.id.as_uuid(),
        };
        let context = self.daemon_context();
        match self.commit(context, |events| {
            self.repository
                .create_model_route(&value, &receipt, &audit)?;
            events.push(CoreEvent::PermissionViewChanged {
                change: PermissionViewChange::Granted,
                permission: PermissionRecord::ModelRouteApproval(value.clone()),
            });
            Ok(value.clone())
        }) {
            Ok(value) => Ok(value),
            Err(error) if error.code == SecondMindErrorCode::Conflict => {
                let result_id = self
                    .replayed_result(receipt.owner, receipt.kind, idempotency)?
                    .ok_or(error)?;
                find_route(
                    &*self.repository,
                    receipt.owner,
                    ModelRouteApprovalId::from_uuid(result_id),
                )
            }
            Err(error) => Err(error),
        }
    }

    pub fn grant_permission(
        &self,
        assurance: ClientAssurance,
        command: GrantPermission,
    ) -> Result<PermissionGrant, SecondMindError> {
        require_private(assurance)?;
        if let Some(result_id) = self.replayed_result(
            command.owner,
            OperationKind::GrantSessionPermission,
            command.idempotency,
        )? {
            return find_grant(
                &*self.repository,
                command.owner,
                PermissionGrantId::from_uuid(result_id),
            );
        }
        validate_grant_input(&command, self.clock.now_utc())?;
        let goal = self.get_goal(command.owner, command.goal_id)?;
        if goal.state != GoalState::Active {
            return Err(SecondMindError::invalid(
                "Only an active goal can receive a focus-session permission.",
            ));
        }
        if goal
            .deadline
            .is_some_and(|deadline| command.expires_at > deadline)
        {
            return Err(SecondMindError::invalid(
                "Permission expiry cannot extend beyond the goal deadline.",
            ));
        }
        if let Some(resource_id) = command.selected_resource_id {
            let resources = self.repository.load_resources(command.owner)?;
            let resource = resources
                .iter()
                .find(|resource| resource.id == resource_id)
                .ok_or_else(|| {
                    SecondMindError::invalid("The selected resource binding does not exist.")
                })?;
            if !resource_kind_matches_scope(command.scope, resource.kind) {
                return Err(SecondMindError::invalid(
                    "The selected resource kind does not match the permission scope.",
                ));
            }
            if command.daemon_restart_allowed && resource.kind == ResourceKind::BrowserSurface {
                return Err(SecondMindError::invalid(
                    "Browser permission cannot continue after a daemon restart; select the tab again.",
                ));
            }
        }
        let grant = PermissionGrant {
            id: PermissionGrantId::new_v7(),
            revision: 1,
            owner: command.owner,
            goal_id: command.goal_id,
            authenticated_client: command.client_id,
            device_id: command.device_id,
            focus_session_id: None,
            scope: command.scope,
            selected_resource_id: command.selected_resource_id,
            model_route_approval_id: None,
            purpose: command.purpose,
            placement: None,
            client_disconnect_allowed: command.client_disconnect_allowed,
            daemon_restart_allowed: command.daemon_restart_allowed,
            issued_at: self.clock.now_utc(),
            effective_at: command.effective_at,
            expires_at: command.expires_at,
            state: GrantState::Active,
            revoked_at: None,
            revocation_reason: None,
            consent_copy_version: command.consent_copy_version,
        };
        let audit = self.build_audit_record(
            grant.owner,
            AuditKind::PermissionGranted,
            grant.id.as_uuid(),
            AuditDetails::new(
                vec![grant.scope.wire_name().to_owned()],
                BTreeSet::from([category_for_scope(grant.scope)]),
            ),
        );
        let receipt = OperationReceipt {
            owner: grant.owner,
            kind: OperationKind::GrantSessionPermission,
            idempotency_key: command.idempotency.key,
            request_digest: command.idempotency.request_digest,
            result_id: grant.id.as_uuid(),
        };
        let context = self.daemon_context();
        match self.commit(context, |events| {
            self.repository.create_grant(&grant, &receipt, &audit)?;
            events.push(CoreEvent::PermissionViewChanged {
                change: PermissionViewChange::Granted,
                permission: PermissionRecord::SessionGrant(grant.clone()),
            });
            Ok(grant.clone())
        }) {
            Ok(grant) => Ok(grant),
            Err(error) if error.code == SecondMindErrorCode::Conflict => {
                let result_id = self
                    .replayed_result(receipt.owner, receipt.kind, command.idempotency)?
                    .ok_or(error)?;
                find_grant(
                    &*self.repository,
                    receipt.owner,
                    PermissionGrantId::from_uuid(result_id),
                )
            }
            Err(error) => Err(error),
        }
    }

    pub async fn revoke_model_route(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        route_id: ModelRouteApprovalId,
        expected_revision: u64,
        reason: String,
    ) -> Result<ModelRouteApproval, SecondMindError> {
        require_private(assurance)?;
        let mut route = find_route(&*self.repository, owner, route_id)?;
        if route.revision != expected_revision {
            return Err(SecondMindError::conflict(route.revision));
        }
        if route.revoked_at.is_some() {
            return Err(SecondMindError::invalid(
                "The model route approval is already revoked.",
            ));
        }
        validate_text(&reason, 1, 120, "The revocation reason is invalid.")?;
        let expected = route.revision;
        route.revision = route.revision.saturating_add(1);
        route.revoked_at = Some(self.clock.now_utc());
        let cleanup = crate::SecretDeletionCleanup {
            owner,
            model_route_approval_id: route.id,
            secret_ref: route.secret_ref.clone(),
            created_at: self.clock.now_utc(),
        };
        let audit = self.build_audit_record(
            owner,
            AuditKind::ModelRouteRevoked,
            route.id.as_uuid(),
            AuditDetails::new(
                vec!["model_route_revoked".to_owned()],
                route.allowed_categories.clone(),
            ),
        );
        let affected_sessions: Vec<_> = self
            .repository
            .load_focus_sessions(owner)?
            .into_iter()
            .filter(|session| session.model_route_approval_id == route_id && session.is_working())
            .collect();
        for session in &affected_sessions {
            if let Ok(state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.get(&session.id)
            {
                ephemeral.cancellation.cancel();
            }
        }
        self.commit(self.daemon_context(), |events| {
            self.repository
                .save_revoked_model_route_with_cleanup(&route, expected, &cleanup, &audit)?;
            events.push(CoreEvent::PermissionViewChanged {
                change: PermissionViewChange::Revoked,
                permission: PermissionRecord::ModelRouteApproval(route.clone()),
            });
            Ok(())
        })?;
        for session in affected_sessions {
            self.cancel_queued_interventions(
                owner,
                Some(session.id),
                None,
                "model_route_revoked",
                self.daemon_context(),
            )?;
            let stopping = self.end_focus_session(
                ClientAssurance::NativeEmergencyControl,
                owner,
                session.id,
                session.revision,
                EndFocusReason::RequiredPermissionRevoked,
            )?;
            self.finish_end_focus_session(owner, session.id, stopping.revision)
                .await?;
        }
        self.secret_store.delete(&route.secret_ref).map_err(|_| {
            SecondMindError::unavailable(
                "The model route is revoked, but its native credential cleanup remains pending.",
            )
        })?;
        self.repository
            .complete_secret_deletion_cleanup(owner, route.id)?;
        Ok(route)
    }

    pub fn request_focus_session(
        &self,
        assurance: ClientAssurance,
        command: StartFocusSession,
    ) -> Result<FocusSession, SecondMindError> {
        require_private(assurance)?;
        if let Some(result_id) = self.replayed_result(
            command.owner,
            OperationKind::StartFocusSession,
            command.idempotency,
        )? {
            return find_owned_session(
                &*self.repository,
                command.owner,
                FocusSessionId::from_uuid(result_id),
            );
        }
        let now = self.clock.now_utc();
        let goal = self.get_goal(command.owner, command.goal_id)?;
        if goal.state != GoalState::Active || goal.deadline.is_some_and(|deadline| now >= deadline)
        {
            return Err(SecondMindError::invalid(
                "Only an active goal can be focused.",
            ));
        }
        if goal.revision.get() != command.expected_goal_revision {
            return Err(SecondMindError::conflict(goal.revision.get()));
        }
        if self
            .repository
            .load_focus_sessions(command.owner)?
            .iter()
            .any(|session| session.id == command.session_id || session.is_working())
        {
            return Err(SecondMindError::invalid(
                "A focus session with this identity or owner is already active.",
            ));
        }
        let route = find_route(
            &*self.repository,
            command.owner,
            command.model_route_approval_id,
        )?;
        validate_model_route(&route, now)?;
        let mut grants = resolve_grants_for_start(
            &*self.repository,
            command.owner,
            command.goal_id,
            command.session_id,
            &command.grant_ids,
            now,
        )?;
        let selected_resources: BTreeSet<_> = grants
            .iter()
            .filter_map(|grant| grant.selected_resource_id)
            .collect();
        if selected_resources != command.selected_resource_ids {
            return Err(SecondMindError::permission(
                "The selected resources do not exactly match the permission grants.",
            ));
        }
        if !grants
            .iter()
            .any(|grant| grant.scope == PermissionScope::ReasonFocusContext)
            || !grants
                .iter()
                .any(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
        {
            return Err(SecondMindError::permission(
                "Reasoning and notification grants are required.",
            ));
        }
        if !grants
            .iter()
            .any(|grant| grant.scope == PermissionScope::ObserveDesktopPresence)
        {
            return Err(SecondMindError::permission(
                "A presence grant is required for safe proactive delivery.",
            ));
        }
        if !route.allowed_categories.contains(&DataCategory::Goal)
            || !grants.iter().any(|grant| {
                grant.scope == PermissionScope::ReasonFocusContext
                    && (grant.model_route_approval_id.is_none()
                        || grant.model_route_approval_id == Some(route.id))
            })
        {
            return Err(SecondMindError::permission(
                "The reasoning grant and route do not authorize the goal packet.",
            ));
        }
        let initial_observation_grants: Vec<_> = grants
            .iter()
            .filter(|grant| grant.scope.is_observation())
            .cloned()
            .collect();
        if initial_observation_grants.is_empty() {
            return Err(SecondMindError::permission(
                "At least one observation grant is required.",
            ));
        }
        if command.daemon_restart_allowed
            && (!grants.iter().all(|grant| grant.daemon_restart_allowed)
                || !command.client_disconnect_allowed)
        {
            return Err(SecondMindError::permission(
                "Session continuity cannot exceed its grants.",
            ));
        }

        let session = FocusSession {
            id: command.session_id,
            revision: 1,
            owner: command.owner,
            goal_id: command.goal_id,
            goal_revision: command.expected_goal_revision,
            state: FocusSessionState::Starting,
            muted: false,
            source_degraded: false,
            client_disconnect_allowed: command.client_disconnect_allowed,
            daemon_restart_allowed: command.daemon_restart_allowed,
            permission_grant_ids: command.grant_ids,
            selected_resource_ids: command.selected_resource_ids,
            model_route_approval_id: command.model_route_approval_id,
            requested_at: now,
            started_at: None,
            ended_at: None,
            updated_at: now,
            failure_reason: None,
        };
        let mut bound_grants = Vec::with_capacity(grants.len());
        for grant in &mut grants {
            let expected = grant.revision;
            grant.focus_session_id = Some(session.id);
            if grant.scope == PermissionScope::ReasonFocusContext {
                grant.model_route_approval_id = Some(route.id);
            }
            grant.revision = grant.revision.saturating_add(1);
            bound_grants.push((grant.clone(), expected));
        }
        let audit = self.build_audit_record(
            session.owner,
            AuditKind::FocusSessionStateChanged,
            session.id.as_uuid(),
            AuditDetails::new(vec!["focus_session_starting".to_owned()], BTreeSet::new()),
        );
        let receipt = OperationReceipt {
            owner: session.owner,
            kind: OperationKind::StartFocusSession,
            idempotency_key: command.idempotency.key,
            request_digest: command.idempotency.request_digest,
            result_id: session.id.as_uuid(),
        };
        let context = self.daemon_context();
        match self.commit(context, |events| {
            self.repository.bind_grants_and_create_focus_session(
                &session,
                &bound_grants,
                &receipt,
                &audit,
            )?;
            events.push(CoreEvent::FocusSessionViewChanged {
                change: FocusSessionViewChange::Requested,
                focus_session: session.clone(),
            });
            events.extend(
                bound_grants
                    .iter()
                    .map(|(grant, _)| CoreEvent::PermissionViewChanged {
                        change: PermissionViewChange::Updated,
                        permission: PermissionRecord::SessionGrant(grant.clone()),
                    }),
            );
            events.push(CoreEvent::CaptureStateChanged {
                capture: self.capture_projection(&session),
            });
            Ok(session.clone())
        }) {
            Ok(session) => Ok(session),
            Err(error) if error.code == SecondMindErrorCode::Conflict => {
                let result_id = self
                    .replayed_result(receipt.owner, receipt.kind, command.idempotency)?
                    .ok_or(error)?;
                find_owned_session(
                    &*self.repository,
                    receipt.owner,
                    FocusSessionId::from_uuid(result_id),
                )
            }
            Err(error) => Err(error),
        }
    }

    pub async fn activate_focus_session(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        session_id: FocusSessionId,
        expected_revision: u64,
    ) -> Result<FocusSession, SecondMindError> {
        require_private(assurance)?;
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError::permission(
                "The focus session belongs to another actor.",
            ));
        }
        if session.revision != expected_revision {
            return Err(SecondMindError::conflict(session.revision));
        }
        if session.state != FocusSessionState::Starting {
            return Err(SecondMindError::invalid(
                "Only a starting focus session can activate its adapters.",
            ));
        }
        let _activation = self.acquire_focus_activation(session.id, session.revision)?;
        let now = self.clock.now_utc();
        let goal = self.get_goal(owner, session.goal_id)?;
        if goal.state != GoalState::Active
            || goal.revision.get() != session.goal_revision
            || goal.deadline.is_some_and(|deadline| now >= deadline)
        {
            return self.fail_start(&mut session, "goal_changed_before_activation");
        }
        let route = find_route(&*self.repository, owner, session.model_route_approval_id)?;
        if validate_model_route(&route, now).is_err() {
            return self.fail_start(&mut session, "model_route_invalid_before_activation");
        }
        let grants = match resolve_grants(
            &*self.repository,
            owner,
            session.id,
            &session.permission_grant_ids,
            now,
        ) {
            Ok(grants) => grants,
            Err(_) => return self.fail_start(&mut session, "permission_invalid_before_activation"),
        };
        let selected_resources: BTreeSet<_> = grants
            .iter()
            .filter_map(|grant| grant.selected_resource_id)
            .collect();
        if selected_resources != session.selected_resource_ids {
            return self.fail_start(&mut session, "resource_changed_before_activation");
        }
        let mut observation_grants: Vec<_> = grants
            .iter()
            .filter(|grant| grant.scope.is_observation())
            .cloned()
            .collect();
        observation_grants.sort_by_key(|grant| observation_start_tier(grant.scope));
        let resources = self.repository.load_resources(owner)?;
        let preferences = self.effective_preferences(session.owner)?;
        let cancellation = CancellationToken::new();

        let published_at = self.clock.now_utc();
        let mut status = NativeCaptureStatus {
            revision: session.revision,
            session_id: session.id,
            active_scopes: observation_grants.iter().map(|grant| grant.scope).collect(),
            resources: resource_statuses(&*self.repository, owner, &observation_grants)?,
            muted: false,
            source_degraded: false,
            published_at,
            heartbeat_deadline: published_at + time::Duration::seconds(10),
        };
        let status_ack = tokio::time::timeout(
            self.config.native_status_heartbeat_timeout,
            self.native_status.publish(&status),
        )
        .await;
        if !self.native_status.availability().is_available()
            || !self.emergency_control.availability().is_available()
            || !matches!(
                status_ack,
                Ok(Ok(ref acknowledgement))
                    if valid_status_acknowledgement(&status, acknowledgement)
            )
        {
            self.cleanup_focus_activation(session.id, status.revision, &cancellation, &[])
                .await;
            return self.fail_start(&mut session, "native_status_unavailable");
        }

        let mut started = Vec::new();
        let mut source_health = BTreeMap::new();
        let mut subscriptions = Vec::new();
        for grant in &observation_grants {
            if !self.observation.availability(grant.scope).is_available() {
                self.cleanup_focus_activation(session.id, status.revision, &cancellation, &started)
                    .await;
                return self.fail_start(&mut session, "observation_source_unavailable");
            }
            let resource = grant
                .selected_resource_id
                .and_then(|id| resources.iter().find(|resource| resource.id == id).cloned());
            let request = ObservationStartRequest {
                grant: grant.clone(),
                resource,
                limits: observation_limits(&self.config, grant.scope),
            };
            match tokio::time::timeout(
                self.config.native_status_heartbeat_timeout,
                self.observation.start(&request, cancellation.child_token()),
            )
            .await
            {
                Ok(Ok(subscription)) => {
                    if validate_source_status(grant, &subscription.initial_status).is_err() {
                        started.push(grant.id);
                        self.cleanup_focus_activation(
                            session.id,
                            status.revision,
                            &cancellation,
                            &started,
                        )
                        .await;
                        return self.fail_start(&mut session, "observation_source_status_invalid");
                    }
                    source_health.insert(grant.id, subscription.initial_status.clone());
                    started.push(grant.id);
                    subscriptions.push((grant.id, subscription));
                }
                Ok(Err(_)) | Err(_) => {
                    started.push(grant.id);
                    self.cleanup_focus_activation(
                        session.id,
                        status.revision,
                        &cancellation,
                        &started,
                    )
                    .await;
                    return self.fail_start(&mut session, "observation_source_start_failed");
                }
            }
        }

        let source_degraded = source_health
            .values()
            .any(|value| value.health != crate::SourceHealth::Healthy);
        let active_revision = session.revision.saturating_add(1);
        let mut ephemeral = EphemeralSession {
            source_health,
            native_status_revision: Some(active_revision),
            ..EphemeralSession::with_cancellation(cancellation.clone())
        };
        reconcile_proactive_cancellation(
            &mut ephemeral,
            !session.muted
                && preferences.proactive_interventions_enabled
                && !preferences.proactive_interventions_muted,
        );
        let install_result = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))
            .and_then(|mut state| {
                if state.sessions.contains_key(&session.id) {
                    return Err(SecondMindError::unavailable(
                        "The focus session already has live ephemeral context.",
                    ));
                }
                state.sessions.insert(session.id, ephemeral);
                Ok(())
            });
        if install_result.is_err() {
            self.cleanup_focus_activation(session.id, status.revision, &cancellation, &started)
                .await;
            return self.fail_start(&mut session, "ephemeral_context_unavailable");
        }

        let expected = session.revision;
        session.state = FocusSessionState::Active;
        session.started_at = Some(self.clock.now_utc());
        session.updated_at = self.clock.now_utc();
        session.source_degraded = source_degraded;
        session.revision = active_revision;
        if let Err(error) = self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                &session,
                expected,
                AuditDetails::new(vec!["focus_session_active".to_owned()], BTreeSet::new()),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::Started, &session);
            Ok(())
        }) {
            self.cleanup_focus_activation(session.id, status.revision, &cancellation, &started)
                .await;
            return Err(error);
        }
        status.revision = session.revision;
        status.source_degraded = session.source_degraded;
        status.published_at = self.clock.now_utc();
        status.heartbeat_deadline = status.published_at + time::Duration::seconds(10);
        let acknowledgement = tokio::time::timeout(
            self.config.native_status_heartbeat_timeout,
            self.native_status.publish(&status),
        )
        .await;
        if !matches!(
            acknowledgement,
            Ok(Ok(ref acknowledgement))
                if valid_status_acknowledgement(&status, acknowledgement)
        ) {
            self.cleanup_focus_activation(session.id, status.revision, &cancellation, &started)
                .await;
            return self.fail_start(&mut session, "native_status_acknowledgement_lost");
        }
        for (grant_id, subscription) in subscriptions {
            self.spawn_observation_subscription(
                session.id,
                grant_id,
                cancellation.child_token(),
                subscription,
            );
        }
        self.spawn_native_status_monitor(session.id, cancellation.child_token());
        self.spawn_native_status_heartbeat(session.id, cancellation.child_token());
        Ok(session)
    }

    pub async fn start_focus_session(
        &self,
        assurance: ClientAssurance,
        command: StartFocusSession,
    ) -> Result<FocusSession, SecondMindError> {
        let starting = self.request_focus_session(assurance, command)?;
        self.activate_focus_session(assurance, starting.owner, starting.id, starting.revision)
            .await
    }

    pub(crate) async fn fail_detached_focus_activation(
        &self,
        owner: ActorId,
        session_id: FocusSessionId,
        include_active: bool,
        reason: &'static str,
    ) -> Result<(), SecondMindError> {
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError::permission(
                "The focus session belongs to another actor.",
            ));
        }
        if session.state != FocusSessionState::Starting
            && !(include_active && session.state == FocusSessionState::Active)
        {
            return Ok(());
        }
        let started = self
            .repository
            .load_grants(owner)
            .map(|grants| {
                grants
                    .into_iter()
                    .filter(|grant| {
                        session.permission_grant_ids.contains(&grant.id)
                            && grant.scope.is_observation()
                    })
                    .map(|grant| grant.id)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|_| session.permission_grant_ids.iter().copied().collect());
        self.cleanup_focus_activation(
            session.id,
            session.revision,
            &CancellationToken::new(),
            &started,
        )
        .await;
        self.mark_focus_start_failed(&mut session, reason)
    }

    fn fail_start(
        &self,
        session: &mut FocusSession,
        reason: &'static str,
    ) -> Result<FocusSession, SecondMindError> {
        self.mark_focus_start_failed(session, reason)?;
        Err(SecondMindError::unavailable(
            "A required observation source could not start.",
        ))
    }

    fn mark_focus_start_failed(
        &self,
        session: &mut FocusSession,
        reason: &'static str,
    ) -> Result<(), SecondMindError> {
        session.state = FocusSessionState::Failed;
        session.failure_reason = Some(reason.to_owned());
        session.updated_at = self.clock.now_utc();
        let expected = session.revision;
        session.revision += 1;
        self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                session,
                expected,
                AuditDetails::new(
                    vec!["focus_session_failed".to_owned(), reason.to_owned()],
                    BTreeSet::new(),
                ),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::Failed, session);
            Ok(())
        })?;
        Ok(())
    }

    fn mark_focus_recovery_pending(
        &self,
        session: &mut FocusSession,
        reason: &'static str,
    ) -> Result<(), SecondMindError> {
        let expected = session.revision;
        session.state = FocusSessionState::Recovering;
        session.source_degraded = true;
        session.failure_reason = Some(reason.to_owned());
        session.updated_at = self.clock.now_utc();
        session.revision = session.revision.saturating_add(1);
        self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                session,
                expected,
                AuditDetails::new(
                    vec![
                        "focus_session_recovery_pending".to_owned(),
                        reason.to_owned(),
                    ],
                    BTreeSet::new(),
                ),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::RecoveryStarted, session);
            Ok(())
        })?;
        Ok(())
    }

    fn spawn_observation_subscription(
        &self,
        session_id: FocusSessionId,
        grant_id: PermissionGrantId,
        cancellation: CancellationToken,
        mut subscription: ObservationSubscription,
    ) {
        let runtime = self.clone();
        let terminal_status = subscription.initial_status.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    event = subscription.events.recv() => {
                        match event {
                            Some(ObservationAdapterEvent::Observation(observation)) => {
                                let _ = runtime.accept_observation(*observation);
                            }
                            Some(ObservationAdapterEvent::SourceStatus(status)) => {
                                let _ = runtime
                                    .accept_source_status(session_id, grant_id, status)
                                    .await;
                            }
                            None => {
                                if !cancellation.is_cancelled() {
                                    let mut status = terminal_status;
                                    status.health = crate::SourceHealth::Unavailable;
                                    status.detail = "The observation source event stream closed.";
                                    status.observed_at = runtime.clock.now_utc();
                                    let _ = runtime
                                        .accept_source_status(session_id, grant_id, status)
                                        .await;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    pub async fn accept_source_status(
        &self,
        session_id: FocusSessionId,
        grant_id: PermissionGrantId,
        status: ObservationSourceStatus,
    ) -> Result<(), SecondMindError> {
        let now = self.clock.now_utc();
        let mut session = find_session(&*self.repository, session_id)?;
        if !session.is_working() || !session.permission_grant_ids.contains(&grant_id) {
            return Err(SecondMindError::permission(
                "Late source health for an inactive session was rejected.",
            ));
        }
        let grant = self
            .repository
            .load_grants(session.owner)?
            .into_iter()
            .find(|grant| grant.id == grant_id)
            .ok_or_else(|| SecondMindError::permission("The source grant is missing."))?;
        validate_source_status(&grant, &status)?;
        if status.observed_at > now + time::Duration::seconds(1) {
            return Err(SecondMindError::invalid(
                "The source health timestamp is invalid.",
            ));
        }
        self.commit(self.daemon_context(), |events| {
            let degraded = {
                let mut state = self.ephemeral.lock().map_err(|_| {
                    SecondMindError::unavailable("Ephemeral context is unavailable.")
                })?;
                let ephemeral = state.sessions.get_mut(&session_id).ok_or_else(|| {
                    SecondMindError::unavailable("The session has no live ephemeral context.")
                })?;
                if status.health != crate::SourceHealth::Healthy {
                    ephemeral
                        .observations
                        .retain(|observation| observation.grant_id != grant_id);
                }
                ephemeral.source_health.insert(grant_id, status);
                ephemeral
                    .source_health
                    .values()
                    .any(|value| value.health != crate::SourceHealth::Healthy)
            };
            if session.source_degraded != degraded {
                let expected = session.revision;
                session.source_degraded = degraded;
                session.updated_at = self.clock.now_utc();
                session.revision = session.revision.saturating_add(1);
                self.repository
                    .save_focus_session(&session, Some(expected))?;
            }
            events.push(CoreEvent::CaptureStateChanged {
                capture: self.capture_projection(&session),
            });
            events.push(CoreEvent::CapabilityHealthChanged {
                capability: CapabilityHealth {
                    id: "observation.desktop",
                    state: if degraded {
                        CapabilityState::Unavailable
                    } else {
                        CapabilityState::Available
                    },
                    detail: if degraded {
                        "One or more authorized observation sources are degraded."
                    } else {
                        "Authorized observation sources are healthy."
                    },
                },
            });
            Ok(())
        })?;
        if self.publish_native_status(&session).await.is_err() {
            if let Ok(state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.get(&session_id)
            {
                ephemeral.cancellation.cancel();
            }
            if !session.source_degraded {
                let expected = session.revision;
                session.source_degraded = true;
                session.updated_at = self.clock.now_utc();
                session.revision = session.revision.saturating_add(1);
                self.commit(self.daemon_context(), |events| {
                    self.repository
                        .save_focus_session(&session, Some(expected))?;
                    events.push(CoreEvent::CaptureStateChanged {
                        capture: self.capture_projection(&session),
                    });
                    events.push(CoreEvent::CapabilityHealthChanged {
                        capability: CapabilityHealth {
                            id: "platform.native_status",
                            state: CapabilityState::Unavailable,
                            detail: "Native capture status acknowledgement was lost.",
                        },
                    });
                    Ok(())
                })?;
            }
            return Err(SecondMindError::unavailable(
                "Native capture status acknowledgement was lost.",
            ));
        }
        Ok(())
    }

    fn spawn_native_status_heartbeat(
        &self,
        session_id: FocusSessionId,
        cancellation: CancellationToken,
    ) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    _ = interval.tick() => {
                        let Ok(mut session) = find_session(&*runtime.repository, session_id) else {
                            cancellation.cancel();
                            break;
                        };
                        if !session.is_working() {
                            break;
                        }
                        if runtime.publish_native_status(&session).await.is_err() {
                            cancellation.cancel();
                            if !session.source_degraded {
                                let expected = session.revision;
                                session.source_degraded = true;
                                session.updated_at = runtime.clock.now_utc();
                                session.revision = session.revision.saturating_add(1);
                                let _ = runtime.commit(runtime.daemon_context(), |events| {
                                    runtime
                                        .repository
                                        .save_focus_session(&session, Some(expected))?;
                                    events.push(CoreEvent::CaptureStateChanged {
                                        capture: runtime.capture_projection(&session),
                                    });
                                    events.push(CoreEvent::CapabilityHealthChanged {
                                        capability: CapabilityHealth {
                                            id: "platform.native_status",
                                            state: CapabilityState::Unavailable,
                                            detail: "Native capture status heartbeat was lost.",
                                        },
                                    });
                                    Ok(())
                                });
                            }
                            break;
                        }
                    }
                }
            }
        });
    }

    fn spawn_native_status_monitor(
        &self,
        session_id: FocusSessionId,
        cancellation: CancellationToken,
    ) {
        let runtime = self.clone();
        tokio::spawn(async move {
            loop {
                let heartbeat = tokio::select! {
                    () = cancellation.cancelled() => break,
                    result = tokio::time::timeout(
                        runtime.config.native_status_heartbeat_timeout,
                        runtime.native_status.next_heartbeat(session_id),
                    ) => result,
                };
                let failure = match heartbeat {
                    Ok(Ok(heartbeat)) => runtime
                        .validate_native_status_heartbeat(session_id, &heartbeat)
                        .err()
                        .map(|_| "Native capture status heartbeat identity was invalid."),
                    Ok(Err(_)) => Some("Native capture status heartbeat stream was lost."),
                    Err(_) => Some("Native capture status heartbeat timed out."),
                };
                let Some(detail) = failure else {
                    continue;
                };
                let _ = runtime
                    .pause_capture_for_native_status_loss(session_id, detail)
                    .await;
                break;
            }
        });
    }

    fn validate_native_status_heartbeat(
        &self,
        session_id: FocusSessionId,
        heartbeat: &NativeStatusHeartbeat,
    ) -> Result<(), SecondMindError> {
        let now = self.clock.now_utc();
        let age = now - heartbeat.emitted_at;
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
            SecondMindError::permission("The native status session is no longer active.")
        })?;
        let timestamp_is_monotonic = session
            .last_native_status_heartbeat_at
            .is_none_or(|previous| heartbeat.emitted_at >= previous);
        if heartbeat.session_id != session_id
            || session.native_status_revision != Some(heartbeat.revision)
            || age.is_negative()
            || age
                > time::Duration::try_from(self.config.native_status_heartbeat_timeout)
                    .unwrap_or(time::Duration::MAX)
            || !timestamp_is_monotonic
        {
            return Err(SecondMindError::permission(
                "The native status heartbeat does not match current capture authority.",
            ));
        }
        session.last_native_status_heartbeat_at = Some(heartbeat.emitted_at);
        Ok(())
    }

    async fn pause_capture_for_native_status_loss(
        &self,
        session_id: FocusSessionId,
        detail: &'static str,
    ) -> Result<(), SecondMindError> {
        let mut session = find_session(&*self.repository, session_id)?;
        if !session.is_working() {
            return Ok(());
        }
        let observation_grants: Vec<_> = self
            .repository
            .load_grants(session.owner)?
            .into_iter()
            .filter(|grant| {
                session.permission_grant_ids.contains(&grant.id) && grant.scope.is_observation()
            })
            .map(|grant| grant.id)
            .collect();
        let now = self.clock.now_utc();
        let expected = session.revision;
        let save_session = !session.source_degraded;
        if save_session {
            session.source_degraded = true;
            session.updated_at = now;
            session.revision = session.revision.saturating_add(1);
        }
        self.commit(self.daemon_context(), |events| {
            {
                let mut state = self.ephemeral.lock().map_err(|_| {
                    SecondMindError::unavailable("Ephemeral context is unavailable.")
                })?;
                let ephemeral = state.sessions.get_mut(&session_id).ok_or_else(|| {
                    SecondMindError::unavailable("The session has no live ephemeral context.")
                })?;
                ephemeral.cancellation.cancel();
                ephemeral.observations.clear();
                for status in ephemeral.source_health.values_mut() {
                    status.health = crate::SourceHealth::Paused;
                    status.detail = "Capture is paused because native status control was lost.";
                    status.observed_at = now;
                }
            }
            if save_session {
                self.repository
                    .save_focus_session(&session, Some(expected))?;
            }
            events.push(CoreEvent::CaptureStateChanged {
                capture: self.capture_projection(&session),
            });
            events.push(CoreEvent::CapabilityHealthChanged {
                capability: CapabilityHealth {
                    id: "platform.native_status",
                    state: CapabilityState::Unavailable,
                    detail,
                },
            });
            Ok(())
        })?;
        for grant_id in observation_grants {
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                self.observation.stop(session_id, grant_id),
            )
            .await;
        }
        Ok(())
    }

    pub fn accept_observation(
        &self,
        observation: NormalizedObservation,
    ) -> Result<(), SecondMindError> {
        let now = self.clock.now_utc();
        let session = find_session(&*self.repository, observation.session_id)?;
        if session.state != FocusSessionState::Active {
            return Err(SecondMindError::permission(
                "Late observation for an inactive session was rejected.",
            ));
        }
        let grant = self
            .repository
            .load_grants(session.owner)?
            .into_iter()
            .find(|grant| grant.id == observation.grant_id)
            .ok_or_else(|| SecondMindError::permission("The observation grant is missing."))?;
        if !grant.is_current_at(now)
            || grant.focus_session_id != Some(session.id)
            || grant.revision != observation.grant_revision
            || grant.device_id != observation.device_id
            || grant.scope != observation.value.required_scope()
            || grant.selected_resource_id != observation.provenance.selected_resource_id
        {
            return Err(SecondMindError::permission(
                "The observation is outside its current grant.",
            ));
        }
        let source_status = self
            .ephemeral
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .sessions
                    .get(&session.id)
                    .and_then(|value| value.source_health.get(&observation.grant_id))
                    .cloned()
            })
            .ok_or_else(|| SecondMindError::permission("The observation source is unknown."))?;
        if source_status.source_id != observation.provenance.source_id
            || observation.observation_id.get_version_num() != 7
            || observation.provenance.source_event_id.get_version_num() != 7
        {
            return Err(SecondMindError::permission(
                "The observation provenance does not match the active source.",
            ));
        }
        let age = now - observation.provenance.observed_at;
        if age.is_negative()
            || age
                > time::Duration::try_from(self.config.observation_ttl)
                    .unwrap_or(time::Duration::MAX)
            || observation.provenance.received_at < observation.provenance.observed_at
            || observation.provenance.confidence_basis_points > 10_000
        {
            return Err(SecondMindError::invalid(
                "The observation timestamp or confidence is invalid.",
            ));
        }
        if observation
            .value
            .bounded_text()
            .is_some_and(|value| value.len() > self.config.maximum_observation_bytes)
        {
            return Err(SecondMindError::invalid(
                "The normalized observation exceeds its payload bound.",
            ));
        }

        let presence_changed =
            matches!(&observation.value, NormalizedObservationValue::Presence(_));
        let significance_relevant = !matches!(
            &observation.value,
            NormalizedObservationValue::Presence(_)
                | NormalizedObservationValue::ForegroundApplication(_)
        );
        self.commit(self.daemon_context(), |events| {
            {
                let mut state = self.ephemeral.lock().map_err(|_| {
                    SecondMindError::unavailable("Ephemeral context is unavailable.")
                })?;
                let ephemeral = state.sessions.get_mut(&session.id).ok_or_else(|| {
                    SecondMindError::unavailable("The session has no live ephemeral context.")
                })?;
                let source_is_healthy = ephemeral
                    .source_health
                    .get(&observation.grant_id)
                    .is_some_and(|status| {
                        status.health == crate::SourceHealth::Healthy
                            && now - status.observed_at
                                <= time::Duration::try_from(self.config.source_freshness)
                                    .unwrap_or(time::Duration::MAX)
                    });
                if !source_is_healthy {
                    return Err(SecondMindError::permission(
                        "The observation source is not freshly healthy.",
                    ));
                }
                if let NormalizedObservationValue::Presence(presence) = &observation.value {
                    ephemeral.presence = *presence;
                    if matches!(
                        presence,
                        crate::PresenceState::Locked | crate::PresenceState::SwitchedAway
                    ) {
                        ephemeral.source_health.values_mut().for_each(|status| {
                            status.health = crate::SourceHealth::Paused;
                            status.observed_at = now;
                        });
                    }
                }
                ephemeral.observations.push_back(observation);
                if significance_relevant {
                    ephemeral.significance_generation =
                        ephemeral.significance_generation.saturating_add(1);
                }
                ephemeral
                    .observations
                    .retain(|value| observation_is_within_retention(&self.config, value, now));
            }
            if presence_changed {
                events.push(CoreEvent::CaptureStateChanged {
                    capture: self.capture_projection(&session),
                });
            }
            Ok(())
        })
    }

    pub fn run_retention_maintenance_once(
        &self,
    ) -> Result<RetentionMaintenanceResult, SecondMindError> {
        let now = self.clock.now_utc();
        let removed_observations = {
            let mut state = self
                .ephemeral
                .lock()
                .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
            let mut removed = 0usize;
            for session in state.sessions.values_mut() {
                let before = session.observations.len();
                session.observations.retain(|observation| {
                    observation_is_within_retention(&self.config, observation, now)
                });
                removed = removed.saturating_add(before.saturating_sub(session.observations.len()));
            }
            removed
        };
        let purged_audit_records = self.repository.purge_expired_audit(now)?;
        Ok(RetentionMaintenanceResult {
            removed_observations,
            purged_audit_records,
        })
    }

    pub async fn run_retention_maintenance(
        &self,
        owner: ActorId,
        shutdown: CancellationToken,
    ) -> Result<(), SecondMindError> {
        let mut interval = tokio::time::interval(self.config.retention_maintenance_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Recovery already purges durable expiry and never restores observations.
        // Wait one full cadence so startup cannot create a catch-up burst.
        interval.tick().await;

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    self.run_retention_maintenance_once()?;
                    self.recover_cleanup_obligations(owner).await?;
                }
            }
        }
    }

    pub async fn run_reasoning_scheduler(
        &self,
        owner: ActorId,
        shutdown: CancellationToken,
    ) -> Result<(), SecondMindError> {
        let mut interval = tokio::time::interval(self.config.significance_evaluation_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Tokio intervals tick immediately once. Recovery must finish and one
        // full evaluation interval must elapse before background reasoning.
        interval.tick().await;

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    self.reconcile_focus_authority(owner).await?;
                    let sessions = self.repository.load_focus_sessions(owner)?;
                    for session in sessions
                        .into_iter()
                        .filter(|session| session.state == FocusSessionState::Active)
                    {
                        tokio::select! {
                            biased;
                            () = shutdown.cancelled() => {
                                self.cancel_proactive_cancellation(session.id)?;
                                return Ok(());
                            },
                            result = self.run_reasoning_cycle(session.id) => {
                                result?;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn reconcile_focus_authority(&self, owner: ActorId) -> Result<usize, SecondMindError> {
        let now = self.clock.now_utc();
        let goals = self.repository.load_goals(owner)?;
        let grants = self.repository.load_grants(owner)?;
        let routes = self.repository.load_model_routes(owner)?;
        let sessions = self.repository.load_focus_sessions(owner)?;
        let mut ended = 0usize;

        for session in sessions {
            if session.state == FocusSessionState::Stopping {
                match self
                    .finish_end_focus_session(owner, session.id, session.revision)
                    .await
                {
                    Ok(_) => ended = ended.saturating_add(1),
                    Err(error)
                        if matches!(
                            error.code,
                            SecondMindErrorCode::Conflict | SecondMindErrorCode::NotFound
                        ) => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
            if session.state != FocusSessionState::Active {
                continue;
            }

            let grants_are_current = session.permission_grant_ids.iter().all(|grant_id| {
                grants.iter().any(|grant| {
                    grant.id == *grant_id
                        && grant.owner == owner
                        && grant.focus_session_id == Some(session.id)
                        && grant.is_current_at(now)
                })
            });
            let route_is_current = routes.iter().any(|route| {
                route.id == session.model_route_approval_id && route.is_current_at(now)
            });
            let goal_is_current = goals.iter().any(|goal| {
                goal.id == session.goal_id
                    && goal.revision.get() == session.goal_revision
                    && goal.state == GoalState::Active
                    && goal.deadline.is_none_or(|deadline| now < deadline)
            });
            if grants_are_current && route_is_current && goal_is_current {
                continue;
            }

            let stopping = match self.end_focus_session(
                ClientAssurance::NativeEmergencyControl,
                owner,
                session.id,
                session.revision,
                EndFocusReason::Expired,
            ) {
                Ok(stopping) if stopping.state == FocusSessionState::Stopping => stopping,
                Ok(_) => continue,
                Err(error)
                    if matches!(
                        error.code,
                        SecondMindErrorCode::Conflict | SecondMindErrorCode::NotFound
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            match self
                .finish_end_focus_session(owner, stopping.id, stopping.revision)
                .await
            {
                Ok(_) => ended = ended.saturating_add(1),
                Err(error)
                    if matches!(
                        error.code,
                        SecondMindErrorCode::Conflict | SecondMindErrorCode::NotFound
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(ended)
    }

    pub async fn run_reasoning_cycle(
        &self,
        session_id: FocusSessionId,
    ) -> Result<ReasoningCycleResult, SecondMindError> {
        let now = self.clock.now_utc();
        let session = find_session(&*self.repository, session_id)?;
        if session.state != FocusSessionState::Active {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "session_not_active".to_owned(),
            });
        }
        let goal = self.get_goal(session.owner, session.goal_id)?;
        if goal.state != GoalState::Active
            || goal.revision.get() != session.goal_revision
            || goal.deadline.is_some_and(|deadline| now >= deadline)
        {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "reasoning_authority_unavailable".to_owned(),
            });
        }
        let preferences = self.effective_preferences(session.owner)?;
        if !preferences.proactive_interventions_enabled {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_interventions_disabled".to_owned(),
            });
        }
        if session.muted || preferences.proactive_interventions_muted {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "interventions_muted".to_owned(),
            });
        }
        if preferences.is_do_not_disturb(now) {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "do_not_disturb".to_owned(),
            });
        }
        if !preferences.permits_native_notification() {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "delivery_channel_not_allowed".to_owned(),
            });
        }
        let route = match find_route(
            &*self.repository,
            session.owner,
            session.model_route_approval_id,
        ) {
            Ok(route) => route,
            Err(error) if error.code == SecondMindErrorCode::NotFound => {
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_authority_unavailable".to_owned(),
                });
            }
            Err(error) => return Err(error),
        };
        if route.placement == crate::ModelPlacement::Remote
            && !preferences.remote_processing_enabled
        {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "remote_processing_disabled".to_owned(),
            });
        }
        if !route.is_current_at(now) || !self.model.availability().is_available() {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "reasoning_route_unavailable".to_owned(),
            });
        }
        let grants = match resolve_grants(
            &*self.repository,
            session.owner,
            session.id,
            &session.permission_grant_ids,
            now,
        ) {
            Ok(grants) => grants,
            Err(error)
                if matches!(
                    error.code,
                    SecondMindErrorCode::NotFound | SecondMindErrorCode::PermissionDenied
                ) =>
            {
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_authority_unavailable".to_owned(),
                });
            }
            Err(error) => return Err(error),
        };
        let (context, presence, cancellation) = self.assemble_context(&session, &route, &grants)?;
        if cancellation.is_cancelled() {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_authority_cancelled".to_owned(),
            });
        }
        if presence != crate::PresenceState::Active {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "presence_not_active".to_owned(),
            });
        }
        if context.is_empty() {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "no_fresh_significant_evidence".to_owned(),
            });
        }
        match self.significance_gate(&session, &goal, &context, &preferences)? {
            SignificanceGateResult::Skipped(reason_code) => {
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: reason_code.to_owned(),
                });
            }
            SignificanceGateResult::Evaluated {
                reason_code,
                policy_trace,
            } => {
                let audit_reason = reason_code.unwrap_or("significance_policy_passed");
                self.append_audit(
                    session.owner,
                    AuditKind::SignificanceDecision,
                    session.id.as_uuid(),
                    AuditDetails::new(
                        vec![audit_reason.to_owned()],
                        context.iter().map(|item| item.category).collect(),
                    )
                    .with_policy_trace(policy_trace),
                )?;
                if let Some(reason_code) = reason_code {
                    return Ok(ReasoningCycleResult::Silence {
                        reason_code: reason_code.to_owned(),
                    });
                }
            }
        }
        if let Some(reason_code) = self.pre_model_delivery_gate(&session, &preferences)? {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: reason_code.to_owned(),
            });
        }
        if cancellation.is_cancelled() {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_authority_cancelled".to_owned(),
            });
        }
        let model_permit = match self
            .begin_model_request(session.id, preferences.maximum_model_requests_per_hour)?
        {
            Ok(permit) => permit,
            Err(reason_code) => {
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: reason_code.to_owned(),
                });
            }
        };
        let deadline_at = now
            + time::Duration::try_from(self.config.model_deadline).unwrap_or(time::Duration::MAX);
        let mut permitted_categories: BTreeSet<_> =
            context.iter().map(|item| item.category).collect();
        permitted_categories.insert(DataCategory::Goal);
        let request = ModelReasoningRequest {
            request_id: Uuid::now_v7(),
            session_id,
            route: route.clone(),
            goal_title: SensitiveText::new(goal.title.clone()),
            success_statement: SensitiveText::new(goal.success_statement.clone()),
            deadline: goal.deadline,
            context,
            permitted_categories,
            issued_at: now,
            deadline_at,
        };
        if !self.record_model_request_started(ModelRequestReceipt {
            request_id: request.request_id,
            focus_session_id: session.id,
            model_route_approval_id: route.id,
            model_route_revision: route.revision,
            started_at: self.clock.now_utc(),
            completed_at: None,
            outcome: ModelRequestReceiptOutcome::InFlight,
        })? {
            drop(model_permit);
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_authority_cancelled".to_owned(),
            });
        }
        if cancellation.is_cancelled() {
            self.record_model_request_completed(
                session.id,
                request.request_id,
                ModelRequestReceiptOutcome::Cancelled,
            )?;
            drop(model_permit);
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_authority_cancelled".to_owned(),
            });
        }
        let output = match tokio::time::timeout(
            self.config.model_deadline,
            self.model.reason(&request, cancellation.clone()),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) if error.kind == ModelGatewayErrorKind::Cancelled => {
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::Cancelled,
                )?;
                drop(model_permit);
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_cancelled_or_timed_out".to_owned(),
                });
            }
            Ok(Err(error)) if error.kind == ModelGatewayErrorKind::DeadlineExceeded => {
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::DeadlineExceeded,
                )?;
                drop(model_permit);
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_cancelled_or_timed_out".to_owned(),
                });
            }
            Ok(Err(_)) => {
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::Failed,
                )?;
                drop(model_permit);
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_failed".to_owned(),
                });
            }
            Err(_) => {
                cancellation.cancel();
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::DeadlineExceeded,
                )?;
                drop(model_permit);
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "reasoning_cancelled_or_timed_out".to_owned(),
                });
            }
        };
        if cancellation.is_cancelled() {
            self.record_model_request_completed(
                session.id,
                request.request_id,
                ModelRequestReceiptOutcome::Cancelled,
            )?;
            drop(model_permit);
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "proactive_authority_cancelled".to_owned(),
            });
        }
        match output {
            ModelReasoningOutput::Silence { reason_code } => {
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::CompletedStrictSilence,
                )?;
                drop(model_permit);
                Ok(ReasoningCycleResult::Silence { reason_code })
            }
            ModelReasoningOutput::Candidate {
                candidate_id,
                user_visible_text,
                reason_code,
                evidence_summary,
                urgency,
                confidence_basis_points,
            } => {
                if let Err(error) = validate_candidate(
                    &user_visible_text,
                    &reason_code,
                    &evidence_summary,
                    confidence_basis_points,
                ) {
                    self.record_model_request_completed(
                        session.id,
                        request.request_id,
                        ModelRequestReceiptOutcome::Failed,
                    )?;
                    drop(model_permit);
                    return Err(error);
                }
                self.record_model_request_completed(
                    session.id,
                    request.request_id,
                    ModelRequestReceiptOutcome::CompletedStrictCandidate,
                )?;
                drop(model_permit);
                self.evaluate_and_deliver(
                    &session,
                    &route,
                    &grants,
                    &request.context,
                    candidate_id,
                    user_visible_text,
                    reason_code,
                    evidence_summary,
                    urgency,
                    confidence_basis_points,
                    &preferences,
                )
                .await
            }
        }
    }

    fn assemble_context(
        &self,
        session: &FocusSession,
        route: &ModelRouteApproval,
        grants: &[PermissionGrant],
    ) -> Result<
        (
            Vec<WorkingContextItem>,
            crate::PresenceState,
            CancellationToken,
        ),
        SecondMindError,
    > {
        let now = self.clock.now_utc();
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
        let ephemeral = state.sessions.get_mut(&session.id).ok_or_else(|| {
            SecondMindError::unavailable("The session has no live ephemeral context.")
        })?;
        let source_freshness =
            time::Duration::try_from(self.config.source_freshness).unwrap_or(time::Duration::MAX);
        let evidence_freshness = time::Duration::try_from(self.config.maximum_model_evidence_age)
            .unwrap_or(time::Duration::MAX);
        let mut items = Vec::new();
        for observation in &ephemeral.observations {
            let category = observation.value.category();
            let age = now - observation.provenance.observed_at;
            let source_healthy = ephemeral
                .source_health
                .get(&observation.grant_id)
                .is_some_and(|status| {
                    status.health == crate::SourceHealth::Healthy
                        && now - status.observed_at <= source_freshness
                });
            if age.is_negative()
                || age > evidence_freshness
                || !source_healthy
                || !route.allowed_categories.contains(&category)
                || !grants.iter().any(|grant| {
                    grant.scope == observation.value.required_scope()
                        && grant.id == observation.grant_id
                        && grant.is_current_at(now)
                })
            {
                continue;
            }
            let Some(value) = observation_to_context(&observation.value) else {
                continue;
            };
            items.push(WorkingContextItem {
                category,
                value,
                source_id: observation.provenance.source_id.clone(),
                resource_id: observation.provenance.selected_resource_id,
                observed_at: observation.provenance.observed_at,
                age_ms: u64::try_from(age.whole_milliseconds()).unwrap_or(u64::MAX),
                confidence_basis_points: observation.provenance.confidence_basis_points,
            });
        }
        // Single-operation evidence is handed to at most this one context
        // assembly. The returned request owns its bounded copy; the session
        // cannot replay it into a later model cycle.
        ephemeral.observations.retain(|observation| {
            observation.provenance.retention != crate::ObservationRetention::SingleOperation
        });
        if let Some(correction) = &ephemeral.correction {
            items.push(WorkingContextItem {
                category: DataCategory::Goal,
                value: correction.clone(),
                source_id: "direct_user_correction".to_owned(),
                resource_id: None,
                observed_at: now,
                age_ms: 0,
                confidence_basis_points: 10_000,
            });
        }
        Ok((
            items,
            ephemeral.presence,
            ephemeral.proactive_cancellation.child_token(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_and_deliver(
        &self,
        session: &FocusSession,
        route: &ModelRouteApproval,
        grants: &[PermissionGrant],
        context: &[WorkingContextItem],
        candidate_id: CandidateId,
        user_visible_text: String,
        reason_code: String,
        evidence_summary: String,
        urgency: Urgency,
        confidence_basis_points: u16,
        preferences: &EffectivePreferences,
    ) -> Result<ReasoningCycleResult, SecondMindError> {
        let now = self.clock.now_utc();
        let monotonic_elapsed = self.clock.monotonic_elapsed();
        let goal = self.get_goal(session.owner, session.goal_id)?;
        let notification_grant = grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .ok_or_else(|| SecondMindError::permission("Notification permission is missing."))?;
        let prior_interventions = self.repository.load_interventions(session.owner)?;
        let notification_available = self.notification.availability().is_available();
        let pending_deliveries = if notification_available {
            Vec::new()
        } else {
            self.repository.load_pending_deliveries(session.owner)?
        };
        let mut reasons = vec![format!("policy_profile:{POLICY_PROFILE_ID}")];
        let mut allow = true;
        if !preferences.proactive_interventions_enabled {
            allow = false;
            reasons.push("proactive_interventions_disabled".to_owned());
        }
        if session.muted || preferences.proactive_interventions_muted {
            allow = false;
            reasons.push("interventions_muted".to_owned());
        }
        if preferences.is_do_not_disturb(now) {
            allow = false;
            reasons.push("do_not_disturb".to_owned());
        }
        if !preferences.permits_native_notification() {
            allow = false;
            reasons.push("delivery_channel_not_allowed".to_owned());
        }
        if confidence_basis_points < self.config.minimum_candidate_confidence_basis_points {
            allow = false;
            reasons.push("candidate_confidence_too_low".to_owned());
        }
        if prior_interventions.iter().any(|intervention| {
            intervention.candidate_id == candidate_id && intervention.candidate_revision == 1
        }) {
            allow = false;
            reasons.push("candidate_revision_already_decided".to_owned());
        }
        let delivered: Vec<_> = prior_interventions
            .iter()
            .filter(|intervention| {
                intervention.focus_session_id == session.id
                    && matches!(
                        intervention.state,
                        InterventionState::AcceptedByChannel | InterventionState::DeliveryUnknown
                    )
            })
            .collect();
        if delivered.len() >= usize::from(preferences.maximum_interventions_per_session) {
            allow = false;
            reasons.push("session_intervention_cap".to_owned());
        }
        let durable_cooldown_active = prior_interventions.iter().any(|intervention| {
            let age = now - intervention.updated_at;
            intervention.focus_session_id == session.id
                && consumes_intervention_cooldown(intervention.state)
                && (age.is_negative()
                    || age
                        < time::Duration::try_from(preferences.intervention_cooldown)
                            .unwrap_or(time::Duration::MAX))
        });
        if durable_cooldown_active {
            allow = false;
            reasons.push("intervention_cooldown".to_owned());
        }
        if !notification_available {
            let queued: Vec<_> = pending_deliveries
                .iter()
                .filter(|entry| entry.state == OutboxState::Queued)
                .collect();
            let session_intervention_ids: BTreeSet<_> = prior_interventions
                .iter()
                .filter(|intervention| intervention.focus_session_id == session.id)
                .map(|intervention| intervention.id)
                .collect();
            let user_full = queued.len() >= self.config.outbox_capacity_per_user;
            let session_full = queued
                .iter()
                .filter(|entry| session_intervention_ids.contains(&entry.intervention_id))
                .count()
                >= self.config.outbox_capacity_per_session;
            if user_full || session_full {
                allow = false;
                reasons.push("outbox_capacity".to_owned());
            }
        }
        let (ephemeral_intervention_count, ephemeral_presence, ephemeral_last_delivery_elapsed) = {
            let state = self
                .ephemeral
                .lock()
                .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
            let ephemeral = state.sessions.get(&session.id).ok_or_else(|| {
                SecondMindError::unavailable("The session has no live ephemeral context.")
            })?;
            if ephemeral.intervention_count >= preferences.maximum_interventions_per_session {
                allow = false;
                if !reasons
                    .iter()
                    .any(|reason| reason == "session_intervention_cap")
                {
                    reasons.push("session_intervention_cap".to_owned());
                }
            }
            if ephemeral.last_delivery_elapsed.is_some_and(|last| {
                monotonic_elapsed.saturating_sub(last) < preferences.intervention_cooldown
            }) {
                allow = false;
                if !reasons
                    .iter()
                    .any(|reason| reason == "intervention_cooldown")
                {
                    reasons.push("intervention_cooldown".to_owned());
                }
            }
            if ephemeral.presence != crate::PresenceState::Active {
                allow = false;
                reasons.push("presence_not_active".to_owned());
            }
            (
                ephemeral.intervention_count,
                ephemeral.presence,
                ephemeral.last_delivery_elapsed,
            )
        };
        if !notification_grant.is_current_at(now) {
            allow = false;
            reasons.push("notification_grant_not_current".to_owned());
        }
        if allow {
            reasons.push("policy_checks_passed".to_owned());
        }

        let mut permission_grant_revisions: Vec<_> = grants
            .iter()
            .map(|grant| (grant.id, grant.revision))
            .collect();
        permission_grant_revisions.sort_by_key(|(id, revision)| (*id, *revision));
        let mut prior_policy_inputs: Vec<_> = prior_interventions
            .iter()
            .map(|intervention| PriorInterventionPolicyInputV1 {
                intervention_id: intervention.id.as_uuid(),
                candidate_id: intervention.candidate_id.as_uuid(),
                candidate_revision: intervention.candidate_revision,
                focus_session_id: intervention.focus_session_id.as_uuid(),
                state: intervention.state,
                updated_at: intervention.updated_at,
            })
            .collect();
        prior_policy_inputs.sort_by_key(|value| value.intervention_id);
        let mut pending_policy_inputs: Vec<_> = pending_deliveries
            .iter()
            .map(|entry| PendingDeliveryPolicyInputV1 {
                entry_id: entry.id.as_uuid(),
                intervention_id: entry.intervention_id.as_uuid(),
                state: entry.state,
            })
            .collect();
        pending_policy_inputs.sort_by_key(|value| value.entry_id);
        let policy_input = InterventionPolicyInputV1 {
            schema: "stein.intervention-policy-input.v1",
            policy_profile_id: POLICY_PROFILE_ID,
            preferences: preferences.into(),
            evaluated_at: now,
            owner: session.owner.as_uuid(),
            focus_session_id: session.id.as_uuid(),
            focus_session_revision: session.revision,
            goal_id: goal.id.as_uuid(),
            goal_revision: goal.revision.get(),
            goal_state: goal.state,
            goal_deadline: goal.deadline,
            session_muted: session.muted,
            candidate_id: candidate_id.as_uuid(),
            candidate_revision: 1,
            user_visible_text: &user_visible_text,
            reason_code: &reason_code,
            evidence_summary: &evidence_summary,
            urgency,
            confidence_basis_points,
            context: context.iter().map(PolicyContextInputV1::from).collect(),
            permission_grant_revisions: permission_grant_revisions
                .iter()
                .map(|(id, revision)| (id.as_uuid(), *revision))
                .collect(),
            model_route_approval_id: route.id.as_uuid(),
            model_route_revision: route.revision,
            channel: NATIVE_NOTIFICATION_CHANNEL,
            notification_available,
            prior_interventions: prior_policy_inputs,
            pending_deliveries: pending_policy_inputs,
            ephemeral_intervention_count,
            ephemeral_presence: presence_wire_name(ephemeral_presence),
            ephemeral_last_delivery_elapsed_ms: ephemeral_last_delivery_elapsed
                .map(duration_millis_u64),
            monotonic_elapsed_ms: duration_millis_u64(monotonic_elapsed),
        };
        let policy_trace = self.policy_trace(preferences.revision, &policy_input)?;
        let decision = PolicyDecision {
            id: PolicyDecisionId::new_v7(),
            candidate_id,
            candidate_revision: 1,
            owner: session.owner,
            focus_session_id: session.id,
            outcome: if allow {
                PolicyOutcome::Allow
            } else {
                PolicyOutcome::Deny
            },
            reason_codes: reasons.clone(),
            permission_grant_revisions,
            model_route_revision: route.revision,
            channel: NATIVE_NOTIFICATION_CHANNEL.to_owned(),
            policy_version: POLICY_PROFILE_ID.to_owned(),
            policy_trace: policy_trace.clone(),
            issued_at: now,
            expires_at: now
                + time::Duration::try_from(self.config.policy_validity)
                    .unwrap_or(time::Duration::MAX),
        };
        let evidence_categories = context.iter().map(|item| item.category).collect();
        let evidence_age_ms = context.iter().map(|item| item.age_ms).max().unwrap_or(0);
        let audit = self.build_audit_record(
            session.owner,
            AuditKind::InterventionDecision,
            candidate_id.as_uuid(),
            AuditDetails::new(reasons, evidence_categories)
                .with_candidate_evidence(evidence_age_ms, confidence_basis_points)
                .with_policy_trace(policy_trace),
        );
        let mut expiry = (now
            + time::Duration::try_from(self.config.outbox_entry_ttl)
                .unwrap_or(time::Duration::MAX))
        .min(decision.expires_at)
        .min(notification_grant.expires_at);
        if let Some(deadline) = goal.deadline {
            expiry = expiry.min(deadline);
        }
        if let Some(route_expiry) = route.expires_at {
            expiry = expiry.min(route_expiry);
        }
        let mut intervention = allow.then(|| Intervention {
            id: InterventionId::new_v7(),
            candidate_id,
            candidate_revision: 1,
            policy_decision_id: decision.id,
            revision: 1,
            owner: session.owner,
            focus_session_id: session.id,
            goal_id: session.goal_id,
            state: InterventionState::Allowed,
            outcome: InterventionOutcome::Unacknowledged,
            user_visible_text: user_visible_text.clone(),
            reason_code: reason_code.clone(),
            evidence_summary,
            evidence: summarize_evidence(context, &reason_code),
            urgency,
            created_at: now,
            expires_at: expiry,
            updated_at: now,
            delivery_channel: Some(NATIVE_NOTIFICATION_CHANNEL.to_owned()),
            delivered_at: None,
            outcome_at: None,
            correction_summary: None,
        });
        let write = InterventionDecisionWrite {
            decision: decision.clone(),
            audit,
            intervention: intervention.clone(),
            expected_intervention_revision: None,
        };
        let publication_fence = self
            .publication
            .get()
            .map(|publication| publication.begin_deferred(self.daemon_context()));
        let acknowledgement = tokio::time::timeout(
            self.config.audit_append_deadline,
            self.repository.commit_intervention_decision(&write),
        )
        .await;
        if !matches!(acknowledgement, Ok(Ok(()))) {
            drop(publication_fence);
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "audit_acknowledgement_unavailable".to_owned(),
            });
        }
        if let Some(publication) = publication_fence {
            publication.publish(
                intervention
                    .iter()
                    .map(|intervention| CoreEvent::InterventionHistoryChanged {
                        change: InterventionHistoryViewChange::Added,
                        owner: intervention.owner,
                        intervention_id: intervention.id,
                        entry: Some(intervention.clone()),
                    })
                    .collect(),
            );
        }
        let Some(mut intervention) = intervention.take() else {
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "deterministic_policy_denied".to_owned(),
            });
        };

        // Delivery-time revalidation intentionally happens after the durable
        // audit acknowledgement and immediately before invoking the adapter.
        let current_now = self.clock.now_utc();
        if !self.delivery_authority_is_current(&decision, session.goal_id, intervention.id) {
            cancel_intervention_without_delivery(
                &mut intervention,
                current_now,
                "authority_changed_before_delivery",
            );
            intervention.revision += 1;
            intervention.updated_at = current_now;
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    1,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(
                        vec!["authority_changed_before_delivery".to_owned()],
                        BTreeSet::new(),
                    )
                    .with_policy_trace(decision.policy_trace.clone()),
                    None,
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "authority_changed_before_delivery".to_owned(),
            });
        }

        let delivery = NotificationDelivery {
            intervention_id: intervention.id,
            policy_decision_id: decision.id,
            title: "STEIN focus note".to_owned(),
            body: user_visible_text,
            urgency,
            deduplication_key: delivery_deduplication_key(
                candidate_id,
                decision.candidate_revision,
                NATIVE_NOTIFICATION_CHANNEL,
            ),
            expires_at: intervention.expires_at,
        };
        let delivery_cancellation = match self.proactive_cancellation(session.id) {
            Ok(cancellation) => cancellation,
            Err(_) => {
                let cancelled_at = self.clock.now_utc();
                cancel_intervention_without_delivery(
                    &mut intervention,
                    cancelled_at,
                    "delivery_cancellation_authority_unavailable",
                );
                intervention.revision += 1;
                intervention.updated_at = cancelled_at;
                self.commit(self.daemon_context(), |events| {
                    self.persist_intervention_transition(
                        &intervention,
                        1,
                        AuditKind::InterventionDelivery,
                        AuditDetails::new(
                            vec!["delivery_cancellation_authority_unavailable".to_owned()],
                            BTreeSet::new(),
                        )
                        .with_policy_trace(decision.policy_trace.clone()),
                        None,
                    )?;
                    Self::push_intervention_update(
                        events,
                        &intervention,
                        InterventionHistoryViewChange::Updated,
                    );
                    Ok(())
                })?;
                return Ok(ReasoningCycleResult::Silence {
                    reason_code: "delivery_cancellation_authority_unavailable".to_owned(),
                });
            }
        };
        let mut cancelled_before_submission = false;
        if notification_available {
            // `Delivering` is the durable pre-attempt marker. No notification
            // port call is permitted until this intervention revision and its
            // content-free delivery audit commit together.
            let expected = intervention.revision;
            intervention.state = InterventionState::Delivering;
            intervention.revision += 1;
            intervention.updated_at = self.clock.now_utc();
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(vec!["delivery_attempt_started".to_owned()], BTreeSet::new())
                        .with_policy_trace(decision.policy_trace.clone()),
                    None,
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            cancelled_before_submission = delivery_cancellation.is_cancelled()
                || !self.delivery_authority_is_current(&decision, session.goal_id, intervention.id);
        }
        let acknowledgement = if notification_available && !cancelled_before_submission {
            Some(
                tokio::time::timeout(
                    self.config.notification_attempt_deadline,
                    self.notification
                        .deliver(&delivery, delivery_cancellation.child_token()),
                )
                .await,
            )
        } else {
            None
        };
        if acknowledgement.as_ref().is_some_and(Result::is_err) {
            delivery_cancellation.cancel();
        }
        let authority_after_attempt = !delivery_cancellation.is_cancelled()
            && self.delivery_authority_is_current(&decision, session.goal_id, intervention.id);
        let expected_delivery_revision = intervention.revision;
        let delivery_transition = match acknowledgement {
            Some(Ok(Ok(ChannelAcknowledgement::AcceptedByChannel))) => {
                intervention.state = InterventionState::AcceptedByChannel;
                intervention.delivered_at = Some(self.clock.now_utc());
                intervention.revision += 1;
                intervention.updated_at = self.clock.now_utc();
                None
            }
            Some(Ok(Ok(ChannelAcknowledgement::DeliveryUnknown))) | Some(Err(_)) => {
                intervention.state = InterventionState::DeliveryUnknown;
                intervention.revision += 1;
                intervention.updated_at = self.clock.now_utc();
                None
            }
            Some(Ok(Ok(ChannelAcknowledgement::DeliveryFailed))) | Some(Ok(Err(_))) => {
                if !authority_after_attempt {
                    cancel_intervention_without_delivery(
                        &mut intervention,
                        self.clock.now_utc(),
                        "authority_changed_during_failed_delivery",
                    );
                } else {
                    intervention.state = InterventionState::DeliveryFailed;
                }
                intervention.revision += 1;
                intervention.updated_at = self.clock.now_utc();
                None
            }
            None if cancelled_before_submission => {
                cancel_intervention_without_delivery(
                    &mut intervention,
                    self.clock.now_utc(),
                    "authority_changed_before_submission",
                );
                intervention.revision += 1;
                intervention.updated_at = self.clock.now_utc();
                None
            }
            None if !notification_available && authority_after_attempt => self
                .queue_intervention(&mut intervention, &decision, notification_grant, &delivery)?
                .map(PendingDeliveryTransition::Enqueue),
            None => {
                cancel_intervention_without_delivery(
                    &mut intervention,
                    self.clock.now_utc(),
                    "authority_unavailable_before_queue",
                );
                intervention.revision += 1;
                intervention.updated_at = self.clock.now_utc();
                None
            }
        };
        let consumes_delivery_cap = matches!(
            intervention.state,
            InterventionState::AcceptedByChannel | InterventionState::DeliveryUnknown
        );
        let queued_delivery =
            delivery_transition
                .as_ref()
                .and_then(|transition| match transition {
                    PendingDeliveryTransition::Enqueue(delivery) => Some(delivery.clone()),
                    PendingDeliveryTransition::Update { .. }
                    | PendingDeliveryTransition::ReconcileLegacy { .. } => None,
                });
        #[cfg(test)]
        if queued_delivery.is_some() {
            self.run_before_queue_commit_hook();
        }
        self.commit(self.daemon_context(), |events| {
            self.persist_intervention_transition(
                &intervention,
                expected_delivery_revision,
                AuditKind::InterventionDelivery,
                AuditDetails::new(
                    vec![format!("delivery_{:?}", intervention.state).to_lowercase()],
                    BTreeSet::new(),
                )
                .with_policy_trace(decision.policy_trace.clone()),
                delivery_transition,
            )?;
            if consumes_delivery_cap {
                let mut state = self.ephemeral.lock().map_err(|_| {
                    SecondMindError::unavailable("Ephemeral context is unavailable.")
                })?;
                if let Some(ephemeral) = state.sessions.get_mut(&session.id) {
                    ephemeral.last_delivery_elapsed = Some(self.clock.monotonic_elapsed());
                    ephemeral.intervention_count = ephemeral.intervention_count.saturating_add(1);
                }
            }
            events.push(CoreEvent::InterventionAvailable {
                intervention: intervention.clone(),
            });
            events.push(CoreEvent::InterventionHistoryChanged {
                change: InterventionHistoryViewChange::Updated,
                owner: intervention.owner,
                intervention_id: intervention.id,
                entry: Some(intervention.clone()),
            });
            Ok(())
        })?;
        if let Some(mut queued_delivery) = queued_delivery
            && (delivery_cancellation.is_cancelled()
                || !self.delivery_authority_is_current(&decision, session.goal_id, intervention.id))
        {
            let expected_delivery_state = queued_delivery.state;
            queued_delivery.state = OutboxState::Cancelled;
            queued_delivery.user_visible_text.clear();
            let expected = intervention.revision;
            intervention.state = InterventionState::Cancelled;
            intervention.outcome = InterventionOutcome::Expired;
            intervention.outcome_at = Some(self.clock.now_utc());
            intervention.reason_code = "authority_changed_after_enqueue".to_owned();
            scrub_intervention(&mut intervention);
            intervention.revision = intervention.revision.saturating_add(1);
            intervention.updated_at = self.clock.now_utc();
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(
                        vec!["authority_changed_after_enqueue".to_owned()],
                        BTreeSet::new(),
                    )
                    .with_policy_trace(decision.policy_trace.clone()),
                    Some(PendingDeliveryTransition::Update {
                        delivery: queued_delivery.clone(),
                        expected_state: expected_delivery_state,
                    }),
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            return Ok(ReasoningCycleResult::Silence {
                reason_code: "authority_changed_after_enqueue".to_owned(),
            });
        }
        let channel_status = tokio::time::timeout(
            self.config.notification_attempt_deadline,
            self.notification.status(),
        )
        .await
        .unwrap_or_else(|_| delivery_status_timeout(self.clock.now_utc()));
        self.commit(self.daemon_context(), |events| {
            events.push(CoreEvent::DeliveryChannelViewChanged {
                owner: intervention.owner,
                channel: channel_status,
            });
            Ok(())
        })?;
        Ok(ReasoningCycleResult::Intervention(Box::new(intervention)))
    }

    fn queue_intervention(
        &self,
        intervention: &mut Intervention,
        decision: &PolicyDecision,
        notification_grant: &PermissionGrant,
        delivery: &NotificationDelivery,
    ) -> Result<Option<PendingInterventionDelivery>, SecondMindError> {
        let pending = self
            .repository
            .load_pending_deliveries(intervention.owner)?;
        let queued: Vec<_> = pending
            .iter()
            .filter(|entry| entry.state == OutboxState::Queued)
            .collect();
        let intervention_ids: BTreeSet<_> = self
            .repository
            .load_interventions(intervention.owner)?
            .into_iter()
            .filter(|value| value.focus_session_id == intervention.focus_session_id)
            .map(|value| value.id)
            .collect();
        let duplicate_exists = pending.iter().any(|entry| {
            entry.deduplication_key == delivery.deduplication_key
                && !matches!(entry.state, OutboxState::Expired | OutboxState::Cancelled)
        });
        let user_full = queued.len() >= self.config.outbox_capacity_per_user;
        let session_full = queued
            .iter()
            .filter(|entry| intervention_ids.contains(&entry.intervention_id))
            .count()
            >= self.config.outbox_capacity_per_session;
        if duplicate_exists || user_full || session_full {
            let reason_code = if duplicate_exists {
                "delivery_deduplicated"
            } else {
                "outbox_capacity"
            };
            cancel_intervention_without_delivery(intervention, self.clock.now_utc(), reason_code);
            intervention.revision += 1;
            intervention.updated_at = self.clock.now_utc();
            return Ok(None);
        }
        let now = self.clock.now_utc();
        let pending = PendingInterventionDelivery {
            id: OutboxEntryId::new_v7(),
            owner: intervention.owner,
            intervention_id: intervention.id,
            candidate_revision: decision.candidate_revision,
            policy_decision_id: decision.id,
            permission_grant_ids: BTreeSet::from([notification_grant.id]),
            user_visible_text: delivery.body.clone(),
            reason_code: intervention.reason_code.clone(),
            urgency: delivery.urgency,
            sensitivity: "personal".to_owned(),
            permitted_channels: BTreeSet::from([NATIVE_NOTIFICATION_CHANNEL.to_owned()]),
            deduplication_key: delivery.deduplication_key,
            state: OutboxState::Queued,
            attempt_count: 0,
            created_at: now,
            not_before: now,
            expires_at: delivery.expires_at,
            last_attempt_at: None,
        };
        intervention.state = InterventionState::Queued;
        intervention.revision += 1;
        intervention.updated_at = self.clock.now_utc();
        Ok(Some(pending))
    }

    pub async fn revalidate_pending_deliveries(
        &self,
        owner: ActorId,
    ) -> Result<Vec<Intervention>, SecondMindError> {
        let now = self.clock.now_utc();
        let elapsed = self.clock.monotonic_elapsed();
        {
            let mut state = self
                .ephemeral
                .lock()
                .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?;
            if state
                .last_recovery_batch_elapsed
                .get(&owner)
                .is_some_and(|last| {
                    elapsed.saturating_sub(*last) < self.config.recovery_batch_interval
                })
            {
                return Ok(Vec::new());
            }
            state.last_recovery_batch_elapsed.insert(owner, elapsed);
        }

        let mut changed = Vec::new();
        let mut pending = self.repository.load_pending_deliveries(owner)?;
        pending.sort_by_key(|entry| (entry.created_at, entry.id));
        let recovery_entries: Vec<_> = pending
            .iter()
            .filter(|entry| matches!(entry.state, OutboxState::Queued | OutboxState::Delivering))
            .take(self.config.recovery_batch_size)
            .cloned()
            .collect();
        for mut entry in recovery_entries {
            let mut intervention = self
                .repository
                .load_interventions(owner)?
                .into_iter()
                .find(|value| value.id == entry.intervention_id)
                .ok_or_else(|| SecondMindError::unavailable("Queued intervention is missing."))?;
            if entry.state == OutboxState::Delivering || entry.attempt_count > 0 {
                let policy_trace = self.persisted_policy_trace(entry.policy_decision_id)?;
                let expected_delivery_state = entry.state;
                entry.state = OutboxState::DeliveryUnknown;
                entry.user_visible_text.clear();
                intervention.state = InterventionState::DeliveryUnknown;
                let expected = intervention.revision;
                intervention.revision = intervention.revision.saturating_add(1);
                intervention.updated_at = now;
                self.commit(self.daemon_context(), |events| {
                    self.persist_intervention_transition(
                        &intervention,
                        expected,
                        AuditKind::InterventionDelivery,
                        AuditDetails::new(
                            vec!["delivery_unknown_after_restart".to_owned()],
                            BTreeSet::new(),
                        )
                        .with_optional_policy_trace(policy_trace),
                        Some(PendingDeliveryTransition::Update {
                            delivery: entry.clone(),
                            expected_state: expected_delivery_state,
                        }),
                    )?;
                    Self::push_intervention_update(
                        events,
                        &intervention,
                        InterventionHistoryViewChange::Updated,
                    );
                    Ok(())
                })?;
                changed.push(intervention);
                continue;
            }

            if entry.not_before > now {
                continue;
            }
            let session = find_session(&*self.repository, intervention.focus_session_id)?;
            let grants = self.repository.load_grants(owner)?;
            let prior_decision = self
                .repository
                .find_policy_decision(entry.policy_decision_id)?;
            let preferences = self.effective_preferences(owner)?;
            let goal = self.get_goal(owner, intervention.goal_id).ok();
            let route = find_route(&*self.repository, owner, session.model_route_approval_id).ok();
            let entry_grants_current = entry.permission_grant_ids.iter().all(|id| {
                grants
                    .iter()
                    .any(|grant| grant.id == *id && grant.is_current_at(now))
            });
            let decision_grants_current = prior_decision.as_ref().is_some_and(|decision| {
                decision
                    .permission_grant_revisions
                    .iter()
                    .all(|(id, revision)| {
                        grants.iter().any(|grant| {
                            grant.id == *id
                                && grant.revision == *revision
                                && grant.is_current_at(now)
                        })
                    })
            });
            let (presence_active, sources_healthy) = self
                .ephemeral
                .lock()
                .ok()
                .and_then(|state| {
                    state.sessions.get(&session.id).map(|value| {
                        let healthy = grants
                            .iter()
                            .filter(|grant| {
                                grant.scope.is_observation()
                                    && prior_decision.as_ref().is_some_and(|decision| {
                                        decision
                                            .permission_grant_revisions
                                            .iter()
                                            .any(|(id, _)| *id == grant.id)
                                    })
                            })
                            .all(|grant| {
                                value.source_health.get(&grant.id).is_some_and(|status| {
                                    status.health == crate::SourceHealth::Healthy
                                        && now - status.observed_at
                                            <= time::Duration::try_from(
                                                self.config.source_freshness,
                                            )
                                            .unwrap_or(time::Duration::MAX)
                                })
                            });
                        (value.presence == crate::PresenceState::Active, healthy)
                    })
                })
                .unwrap_or((false, false));
            let decision_matches = prior_decision.as_ref().is_some_and(|decision| {
                decision.id == entry.policy_decision_id
                    && decision.candidate_id == intervention.candidate_id
                    && decision.candidate_revision == entry.candidate_revision
                    && decision.focus_session_id == session.id
                    && decision.outcome == PolicyOutcome::Allow
                    && decision.policy_trace.is_complete()
                    && decision.policy_version == POLICY_PROFILE_ID
                    && decision.policy_trace.policy_profile_id == POLICY_PROFILE_ID
                    && decision.policy_trace.user_preferences_revision == preferences.revision
                    && now < decision.expires_at
            });
            let route_current = route.as_ref().is_some_and(|route| {
                prior_decision.as_ref().is_some_and(|decision| {
                    route.revision == decision.model_route_revision
                        && route.is_current_at(now)
                        && (route.placement != crate::ModelPlacement::Remote
                            || preferences.remote_processing_enabled)
                })
            });
            let goal_current = goal.as_ref().is_some_and(|goal| {
                goal.state == GoalState::Active
                    && goal.deadline.is_none_or(|deadline| now < deadline)
            });
            let duplicate_terminal = pending.iter().any(|other| {
                other.id != entry.id
                    && other.deduplication_key == entry.deduplication_key
                    && matches!(
                        other.state,
                        OutboxState::AcceptedByChannel | OutboxState::DeliveryUnknown
                    )
            });
            let delivered = self.repository.load_interventions(owner)?;
            let delivered_count = delivered
                .iter()
                .filter(|other| {
                    other.id != intervention.id
                        && other.focus_session_id == session.id
                        && matches!(
                            other.state,
                            InterventionState::AcceptedByChannel
                                | InterventionState::DeliveryUnknown
                        )
                })
                .count();
            let cooldown_active = delivered.iter().any(|other| {
                let age = now - other.updated_at;
                other.id != intervention.id
                    && other.focus_session_id == session.id
                    && consumes_intervention_cooldown(other.state)
                    && (age.is_negative()
                        || age
                            < time::Duration::try_from(preferences.intervention_cooldown)
                                .unwrap_or(time::Duration::MAX))
            });
            let preferences_allow = preferences.proactive_interventions_enabled
                && !preferences.proactive_interventions_muted
                && !preferences.is_do_not_disturb(now)
                && preferences.permits_native_notification()
                && delivered_count < usize::from(preferences.maximum_interventions_per_session)
                && !cooldown_active;
            if now >= entry.expires_at
                || session.state != FocusSessionState::Active
                || session.muted
                || !entry_grants_current
                || !decision_grants_current
                || !decision_matches
                || !route_current
                || !goal_current
                || !presence_active
                || !sources_healthy
                || !preferences_allow
                || duplicate_terminal
            {
                let policy_trace = prior_decision
                    .as_ref()
                    .map(|decision| decision.policy_trace.clone())
                    .filter(PolicyTrace::is_complete);
                let expected_delivery_state = entry.state;
                entry.state = OutboxState::Expired;
                entry.user_visible_text.clear();
                intervention.state = InterventionState::Expired;
                intervention.outcome = InterventionOutcome::Expired;
                intervention.outcome_at = Some(now);
                intervention.reason_code = "missed_intervention".to_owned();
                scrub_intervention(&mut intervention);
                let expected = intervention.revision;
                intervention.revision = intervention.revision.saturating_add(1);
                intervention.updated_at = now;
                self.commit(self.daemon_context(), |events| {
                    self.persist_intervention_transition(
                        &intervention,
                        expected,
                        AuditKind::InterventionDelivery,
                        AuditDetails::new(vec!["missed_intervention".to_owned()], BTreeSet::new())
                            .with_optional_policy_trace(policy_trace),
                        Some(PendingDeliveryTransition::Update {
                            delivery: entry.clone(),
                            expected_state: expected_delivery_state,
                        }),
                    )?;
                    Self::push_intervention_update(
                        events,
                        &intervention,
                        InterventionHistoryViewChange::Updated,
                    );
                    Ok(())
                })?;
                changed.push(intervention);
                continue;
            }
            let notification_available = self.notification.availability().is_available();
            if !notification_available {
                continue;
            }

            let Some(route) = route else {
                continue;
            };
            let (Some(goal), Some(prior_decision)) = (goal, prior_decision) else {
                continue;
            };
            let mut permission_grant_revisions = prior_decision.permission_grant_revisions.clone();
            permission_grant_revisions.sort_by_key(|(id, revision)| (*id, *revision));
            let recovery_input = RecoveryPolicyInputV1 {
                schema: "stein.intervention-recovery-policy-input.v1",
                policy_profile_id: POLICY_PROFILE_ID,
                preferences: (&preferences).into(),
                evaluated_at: now,
                owner: owner.as_uuid(),
                focus_session_id: session.id.as_uuid(),
                focus_session_revision: session.revision,
                focus_session_state: session.state,
                focus_session_muted: session.muted,
                goal_id: goal.id.as_uuid(),
                goal_revision: goal.revision.get(),
                goal_state: goal.state,
                goal_deadline: goal.deadline,
                model_route_approval_id: route.id.as_uuid(),
                model_route_revision: route.revision,
                permission_grant_revisions: permission_grant_revisions
                    .iter()
                    .map(|(id, revision)| (id.as_uuid(), *revision))
                    .collect(),
                intervention_id: intervention.id.as_uuid(),
                intervention_revision: intervention.revision,
                candidate_id: intervention.candidate_id.as_uuid(),
                candidate_revision: intervention.candidate_revision,
                prior_policy_decision_id: prior_decision.id.as_uuid(),
                prior_policy_trace_digest: prior_decision.policy_trace.proposed_input_digest,
                outbox_entry_id: entry.id.as_uuid(),
                queued_text: &entry.user_visible_text,
                reason_code: &entry.reason_code,
                urgency: entry.urgency,
                sensitivity: &entry.sensitivity,
                permitted_channels: &entry.permitted_channels,
                deduplication_key: entry.deduplication_key,
                created_at: entry.created_at,
                not_before: entry.not_before,
                expires_at: entry.expires_at,
                channel: NATIVE_NOTIFICATION_CHANNEL,
                presence_active,
                sources_healthy,
                entry_grants_current,
                decision_grants_current,
                decision_matches,
                route_current,
                goal_current,
                preferences_allow,
                duplicate_terminal,
                delivered_count,
                cooldown_active,
                notification_available,
            };
            let policy_trace = self.policy_trace(preferences.revision, &recovery_input)?;
            let new_decision = PolicyDecision {
                id: PolicyDecisionId::new_v7(),
                candidate_id: intervention.candidate_id,
                candidate_revision: intervention.candidate_revision,
                owner,
                focus_session_id: session.id,
                outcome: PolicyOutcome::Allow,
                reason_codes: vec![
                    format!("policy_profile:{POLICY_PROFILE_ID}"),
                    "recovery_revalidation_passed".to_owned(),
                ],
                permission_grant_revisions,
                model_route_revision: route.revision,
                channel: NATIVE_NOTIFICATION_CHANNEL.to_owned(),
                policy_version: POLICY_PROFILE_ID.to_owned(),
                policy_trace: policy_trace.clone(),
                issued_at: now,
                expires_at: (now
                    + time::Duration::try_from(self.config.policy_validity)
                        .unwrap_or(time::Duration::MAX))
                .min(entry.expires_at),
            };
            let expected = intervention.revision;
            intervention.policy_decision_id = new_decision.id;
            // Revalidation and its audit commit before an attempt marker. A
            // crash here is still a queued, definitely unattempted delivery.
            intervention.state = InterventionState::Queued;
            intervention.revision = intervention.revision.saturating_add(1);
            intervention.updated_at = now;
            let evidence_categories = intervention
                .evidence
                .iter()
                .map(|evidence| evidence.category)
                .collect();
            let audit = self.build_audit_record(
                owner,
                AuditKind::InterventionDecision,
                intervention.candidate_id.as_uuid(),
                AuditDetails::new(new_decision.reason_codes.clone(), evidence_categories)
                    .with_policy_trace(policy_trace),
            );
            let write = InterventionDecisionWrite {
                decision: new_decision.clone(),
                audit,
                intervention: Some(intervention.clone()),
                expected_intervention_revision: Some(expected),
            };
            let publication_fence = self
                .publication
                .get()
                .map(|publication| publication.begin_deferred(self.daemon_context()));
            let acknowledgement = tokio::time::timeout(
                self.config.audit_append_deadline,
                self.repository.commit_intervention_decision(&write),
            )
            .await;
            if !matches!(acknowledgement, Ok(Ok(()))) {
                drop(publication_fence);
                continue;
            }
            #[cfg(test)]
            self.run_after_recovery_revalidation_commit_hook();
            if !self.delivery_authority_is_current(
                &new_decision,
                intervention.goal_id,
                intervention.id,
            ) {
                let expected_delivery_state = entry.state;
                entry.state = OutboxState::Cancelled;
                entry.user_visible_text.clear();
                let expected = intervention.revision;
                intervention.state = InterventionState::Cancelled;
                intervention.outcome = InterventionOutcome::Expired;
                intervention.outcome_at = Some(self.clock.now_utc());
                intervention.reason_code = "missed_intervention".to_owned();
                scrub_intervention(&mut intervention);
                intervention.revision = intervention.revision.saturating_add(1);
                intervention.updated_at = self.clock.now_utc();
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(
                        vec!["authority_changed_before_recovery_delivery".to_owned()],
                        BTreeSet::new(),
                    )
                    .with_policy_trace(new_decision.policy_trace.clone()),
                    Some(PendingDeliveryTransition::Update {
                        delivery: entry.clone(),
                        expected_state: expected_delivery_state,
                    }),
                )?;
                if let Some(publication) = publication_fence {
                    publication.publish(vec![CoreEvent::InterventionHistoryChanged {
                        change: InterventionHistoryViewChange::Updated,
                        owner,
                        intervention_id: intervention.id,
                        entry: Some(intervention.clone()),
                    }]);
                }
                changed.push(intervention);
                continue;
            }
            if let Some(publication) = publication_fence {
                publication.publish(vec![CoreEvent::InterventionHistoryChanged {
                    change: InterventionHistoryViewChange::Updated,
                    owner,
                    intervention_id: intervention.id,
                    entry: Some(intervention.clone()),
                }]);
            }
            let delivery_cancellation = self.proactive_cancellation(session.id)?;
            entry.state = OutboxState::Delivering;
            entry.attempt_count = entry.attempt_count.saturating_add(1);
            entry.last_attempt_at = Some(now);
            entry.policy_decision_id = new_decision.id;
            let expected_intervention_revision = intervention.revision;
            intervention.state = InterventionState::Delivering;
            intervention.revision = intervention.revision.saturating_add(1);
            intervention.updated_at = self.clock.now_utc();
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected_intervention_revision,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(
                        vec!["recovery_delivery_attempt_started".to_owned()],
                        BTreeSet::new(),
                    )
                    .with_policy_trace(new_decision.policy_trace.clone()),
                    Some(PendingDeliveryTransition::Update {
                        delivery: entry.clone(),
                        expected_state: OutboxState::Queued,
                    }),
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            if delivery_cancellation.is_cancelled()
                || !self.delivery_authority_is_current(
                    &new_decision,
                    intervention.goal_id,
                    intervention.id,
                )
            {
                let expected_delivery_state = entry.state;
                entry.state = OutboxState::Cancelled;
                entry.user_visible_text.clear();
                let expected = intervention.revision;
                intervention.state = InterventionState::Cancelled;
                intervention.outcome = InterventionOutcome::Expired;
                intervention.outcome_at = Some(self.clock.now_utc());
                intervention.reason_code = "authority_changed_before_recovery_delivery".to_owned();
                scrub_intervention(&mut intervention);
                intervention.revision = intervention.revision.saturating_add(1);
                intervention.updated_at = self.clock.now_utc();
                self.commit(self.daemon_context(), |events| {
                    self.persist_intervention_transition(
                        &intervention,
                        expected,
                        AuditKind::InterventionDelivery,
                        AuditDetails::new(
                            vec!["authority_changed_after_delivery_marker".to_owned()],
                            BTreeSet::new(),
                        )
                        .with_policy_trace(new_decision.policy_trace.clone()),
                        Some(PendingDeliveryTransition::Update {
                            delivery: entry.clone(),
                            expected_state: expected_delivery_state,
                        }),
                    )?;
                    Self::push_intervention_update(
                        events,
                        &intervention,
                        InterventionHistoryViewChange::Updated,
                    );
                    Ok(())
                })?;
                changed.push(intervention);
                continue;
            }
            let result = tokio::time::timeout(
                self.config.notification_attempt_deadline,
                self.notification.deliver(
                    &NotificationDelivery {
                        intervention_id: intervention.id,
                        policy_decision_id: new_decision.id,
                        title: "STEIN focus note".to_owned(),
                        body: entry.user_visible_text.clone(),
                        urgency: entry.urgency,
                        deduplication_key: entry.deduplication_key,
                        expires_at: entry.expires_at,
                    },
                    delivery_cancellation.child_token(),
                ),
            )
            .await;
            if result.is_err() {
                delivery_cancellation.cancel();
            }
            let authority_after_attempt = !delivery_cancellation.is_cancelled()
                && self.delivery_authority_is_current(
                    &new_decision,
                    intervention.goal_id,
                    intervention.id,
                );
            let expected_delivery_state = entry.state;
            entry.state = match result {
                Ok(Ok(ChannelAcknowledgement::AcceptedByChannel)) => OutboxState::AcceptedByChannel,
                Ok(Ok(ChannelAcknowledgement::DeliveryUnknown)) | Err(_) => {
                    OutboxState::DeliveryUnknown
                }
                Ok(Ok(ChannelAcknowledgement::DeliveryFailed)) | Ok(Err(_))
                    if !authority_after_attempt =>
                {
                    OutboxState::Cancelled
                }
                Ok(Ok(ChannelAcknowledgement::DeliveryFailed)) | Ok(Err(_)) => {
                    OutboxState::DeliveryFailed
                }
            };
            entry.user_visible_text.clear();
            let terminal_at = self.clock.now_utc();
            match entry.state {
                OutboxState::AcceptedByChannel => {
                    intervention.state = InterventionState::AcceptedByChannel;
                    intervention.delivered_at = Some(terminal_at);
                }
                OutboxState::DeliveryUnknown => {
                    intervention.state = InterventionState::DeliveryUnknown;
                }
                OutboxState::Cancelled => cancel_intervention_without_delivery(
                    &mut intervention,
                    terminal_at,
                    "authority_changed_during_failed_delivery",
                ),
                _ => {
                    intervention.state = InterventionState::DeliveryFailed;
                }
            }
            let expected = intervention.revision;
            intervention.revision += 1;
            intervention.updated_at = terminal_at;
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(
                        vec![format!("delivery_{:?}", intervention.state).to_lowercase()],
                        BTreeSet::new(),
                    )
                    .with_policy_trace(new_decision.policy_trace.clone()),
                    Some(PendingDeliveryTransition::Update {
                        delivery: entry.clone(),
                        expected_state: expected_delivery_state,
                    }),
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            let channel_status = tokio::time::timeout(
                self.config.notification_attempt_deadline,
                self.notification.status(),
            )
            .await
            .unwrap_or_else(|_| delivery_status_timeout(now));
            self.commit(self.daemon_context(), |events| {
                events.push(CoreEvent::DeliveryChannelViewChanged {
                    owner,
                    channel: channel_status,
                });
                Ok(())
            })?;
            if matches!(
                intervention.state,
                InterventionState::AcceptedByChannel | InterventionState::DeliveryUnknown
            ) && let Ok(mut state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.get_mut(&session.id)
            {
                ephemeral.last_delivery_elapsed = Some(self.clock.monotonic_elapsed());
                ephemeral.intervention_count = ephemeral.intervention_count.saturating_add(1);
            }
            changed.push(intervention);
        }
        Ok(changed)
    }

    pub async fn revoke_permission(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        grant_id: PermissionGrantId,
        expected_revision: u64,
        reason: String,
    ) -> Result<PermissionGrant, SecondMindError> {
        require_private(assurance)?;
        let mut grant = self
            .repository
            .load_grants(owner)?
            .into_iter()
            .find(|grant| grant.id == grant_id)
            .ok_or(SecondMindError {
                code: SecondMindErrorCode::NotFound,
                summary: "The permission grant was not found.",
                retryable: false,
                current_revision: None,
            })?;
        if grant.revision != expected_revision {
            return Err(SecondMindError::conflict(grant.revision));
        }
        let expected = grant.revision;
        grant.state = GrantState::Revoked;
        grant.revoked_at = Some(self.clock.now_utc());
        grant.revocation_reason = Some(bound_text(reason, 120));
        grant.revision += 1;
        let focus_session_id = grant.focus_session_id;
        // Fence fresh model and delivery submissions before the durable
        // transition. The root observation/status token stays live until the
        // revocation commits, so a failed repository write cannot strand an
        // Active session behind an irrearmable cancelled lifecycle token.
        if let Some(session_id) = focus_session_id {
            self.cancel_proactive_cancellation(session_id)?;
        }
        #[cfg(test)]
        self.run_before_permission_revocation_commit_hook();
        let save_result = self.commit(self.daemon_context(), |events| {
            self.persist_permission_revocation(
                &grant,
                expected,
                AuditDetails::new(
                    vec!["permission_revoked".to_owned()],
                    BTreeSet::from([category_for_scope(grant.scope)]),
                ),
            )?;
            events.push(CoreEvent::PermissionViewChanged {
                change: PermissionViewChange::Revoked,
                permission: PermissionRecord::SessionGrant(grant.clone()),
            });
            Ok(())
        });
        if let Err(error) = save_result {
            if let Some(session_id) = focus_session_id
                && let (Ok(session), Ok(preferences)) = (
                    find_session(&*self.repository, session_id),
                    self.effective_preferences(owner),
                )
            {
                let _ = self.reconcile_proactive_cancellation_for_session(&session, &preferences);
            }
            return Err(error);
        }

        // Durable revocation now owns the fail-closed authority boundary. Stop
        // every raw observation/status producer and discard the revoked
        // grant's transient observations before any fallible cleanup follows.
        if let Some(session_id) = focus_session_id
            && let Ok(mut state) = self.ephemeral.lock()
            && let Some(ephemeral) = state.sessions.get_mut(&session_id)
        {
            ephemeral.cancellation.cancel();
            ephemeral
                .observations
                .retain(|observation| observation.grant_id != grant_id);
        }

        if let Some(session_id) = focus_session_id {
            // Every ID bound into a focus session is required authority, not a
            // best-effort source. Revoking any one ends the session now; it is
            // never left Active because another observation grant remains.
            // The durable Stopping transition precedes fallible queue scrub,
            // so a scrub failure is restart-recoverable rather than leaving an
            // Active session behind a revoked required grant.
            let session = find_session(&*self.repository, session_id)?;
            let stopping = if session.state == FocusSessionState::Stopping {
                session
            } else {
                self.end_focus_session(
                    ClientAssurance::NativeEmergencyControl,
                    owner,
                    session_id,
                    session.revision,
                    EndFocusReason::RequiredPermissionRevoked,
                )?
            };
            if stopping.state == FocusSessionState::Stopping {
                self.finish_end_focus_session(owner, session_id, stopping.revision)
                    .await?;
            }
        } else {
            self.cancel_queued_interventions(
                owner,
                None,
                Some(grant_id),
                "permission_revoked",
                self.daemon_context(),
            )?;
        }
        Ok(grant)
    }

    pub async fn set_interventions_muted(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        session_id: FocusSessionId,
        expected_revision: u64,
        muted: bool,
    ) -> Result<FocusSession, SecondMindError> {
        require_private(assurance)?;
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner || !session.is_working() {
            return Err(SecondMindError::permission(
                "The focus session cannot be muted by this actor.",
            ));
        }
        if session.revision != expected_revision {
            return Err(SecondMindError::conflict(session.revision));
        }
        let preferences = self.effective_preferences(owner)?;
        let context = self.daemon_context();
        let expected = session.revision;
        session.muted = muted;
        session.updated_at = self.clock.now_utc();
        session.revision += 1;
        self.reconcile_proactive_cancellation_for_session(&session, &preferences)?;
        let save_result = self.commit(context, |events| {
            self.repository
                .save_focus_session(&session, Some(expected))?;
            self.push_focus_and_capture(
                events,
                if muted {
                    FocusSessionViewChange::Muted
                } else {
                    FocusSessionViewChange::Unmuted
                },
                &session,
            );
            Ok(())
        });
        if let Err(error) = save_result {
            if let (Ok(current_session), Ok(current_preferences)) = (
                find_session(&*self.repository, session_id),
                self.effective_preferences(owner),
            ) {
                let _ = self.reconcile_proactive_cancellation_for_session(
                    &current_session,
                    &current_preferences,
                );
            }
            return Err(error);
        }
        self.reconcile_proactive_cancellation_for_session(&session, &preferences)?;
        if muted {
            self.cancel_queued_interventions(
                owner,
                Some(session_id),
                None,
                "interventions_muted",
                context,
            )?;
        }
        if self.publish_native_status(&session).await.is_err() {
            if let Ok(state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.get(&session_id)
            {
                ephemeral.cancellation.cancel();
            }
            let expected = session.revision;
            session.source_degraded = true;
            session.updated_at = self.clock.now_utc();
            session.revision = session.revision.saturating_add(1);
            self.commit(self.daemon_context(), |events| {
                self.repository
                    .save_focus_session(&session, Some(expected))?;
                events.push(CoreEvent::CaptureStateChanged {
                    capture: self.capture_projection(&session),
                });
                events.push(CoreEvent::CapabilityHealthChanged {
                    capability: CapabilityHealth {
                        id: "platform.native_status",
                        state: CapabilityState::Unavailable,
                        detail: "Native capture status acknowledgement was lost.",
                    },
                });
                Ok(())
            })?;
        }
        Ok(session)
    }

    async fn publish_native_status(
        &self,
        session: &FocusSession,
    ) -> Result<NativeStatusAcknowledgement, SecondMindError> {
        let grants: Vec<_> = self
            .repository
            .load_grants(session.owner)?
            .into_iter()
            .filter(|grant| {
                session.permission_grant_ids.contains(&grant.id) && grant.scope.is_observation()
            })
            .collect();
        let hide_private_labels = self
            .ephemeral
            .lock()
            .ok()
            .and_then(|state| state.sessions.get(&session.id).map(|value| value.presence))
            .is_some_and(|presence| {
                matches!(
                    presence,
                    crate::PresenceState::Locked | crate::PresenceState::SwitchedAway
                )
            });
        let published_at = self.clock.now_utc();
        let status = NativeCaptureStatus {
            revision: session.revision,
            session_id: session.id,
            active_scopes: grants.iter().map(|grant| grant.scope).collect(),
            resources: if hide_private_labels {
                Vec::new()
            } else {
                resource_statuses(&*self.repository, session.owner, &grants)?
            },
            muted: session.muted,
            source_degraded: session.source_degraded,
            published_at,
            heartbeat_deadline: published_at + time::Duration::seconds(10),
        };
        let acknowledgement = tokio::time::timeout(
            self.config.native_status_heartbeat_timeout,
            self.native_status.publish(&status),
        )
        .await
        .map_err(|_| SecondMindError::deadline_exceeded("Native capture status timed out."))?
        .map_err(|_| SecondMindError::unavailable("Native capture status is unavailable."))?;
        if !valid_status_acknowledgement(&status, &acknowledgement) {
            return Err(SecondMindError::unavailable(
                "Native capture status acknowledgement is invalid.",
            ));
        }
        if let Ok(mut state) = self.ephemeral.lock()
            && let Some(ephemeral) = state.sessions.get_mut(&session.id)
        {
            ephemeral.native_status_revision = Some(status.revision);
        }
        Ok(acknowledgement)
    }

    pub fn end_focus_session(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        session_id: FocusSessionId,
        expected_revision: u64,
        reason: EndFocusReason,
    ) -> Result<FocusSession, SecondMindError> {
        require_private(assurance)?;
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError::permission(
                "The focus session belongs to another actor.",
            ));
        }
        if matches!(
            session.state,
            FocusSessionState::Ended | FocusSessionState::Failed
        ) {
            return Ok(session);
        }
        if session.revision != expected_revision {
            return Err(SecondMindError::conflict(session.revision));
        }
        let expected = session.revision;
        session.state = FocusSessionState::Stopping;
        session.failure_reason = Some(format!("ending_{reason:?}").to_lowercase());
        session.updated_at = self.clock.now_utc();
        session.revision += 1;
        // Fence model and delivery submission before the durable lifecycle
        // transition, but do not cancel the irrearmable observation/status
        // root until Stopping commits. A failed repository write can therefore
        // restore proactive authority without stranding an Active session.
        self.cancel_proactive_cancellation(session_id)?;
        let save_result = self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                &session,
                expected,
                AuditDetails::new(vec!["focus_session_stopping".to_owned()], BTreeSet::new()),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::Stopping, &session);
            Ok(())
        });
        if let Err(error) = save_result {
            if let (Ok(current), Ok(preferences)) = (
                find_session(&*self.repository, session_id),
                self.effective_preferences(owner),
            ) {
                let _ = self.reconcile_proactive_cancellation_for_session(&current, &preferences);
            }
            return Err(error);
        }

        // Stopping is now the durable authority boundary. Cancel all raw
        // producers and erase transient observations before fallible cleanup.
        if let Ok(mut state) = self.ephemeral.lock()
            && let Some(ephemeral) = state.sessions.get_mut(&session_id)
        {
            ephemeral.cancellation.cancel();
            ephemeral.observations.clear();
            let now = self.clock.now_utc();
            for status in ephemeral.source_health.values_mut() {
                status.health = crate::SourceHealth::Paused;
                status.detail = "Capture authority was revoked before adapter cleanup.";
                status.observed_at = now;
            }
        }
        self.cancel_queued_interventions(
            owner,
            Some(session_id),
            None,
            if reason == EndFocusReason::RequiredPermissionRevoked {
                "permission_revoked"
            } else {
                "focus_session_stopping"
            },
            self.daemon_context(),
        )?;
        Ok(session)
    }

    pub async fn finish_end_focus_session(
        &self,
        owner: ActorId,
        session_id: FocusSessionId,
        expected_revision: u64,
    ) -> Result<FocusSession, SecondMindError> {
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner {
            return Err(SecondMindError::permission(
                "The focus session belongs to another actor.",
            ));
        }
        if session.state == FocusSessionState::Ended {
            return Ok(session);
        }
        if session.state != FocusSessionState::Stopping {
            return Err(SecondMindError::invalid(
                "The focus session is not awaiting adapter cleanup.",
            ));
        }
        if session.revision != expected_revision {
            return Err(SecondMindError::conflict(session.revision));
        }

        // This is idempotent and intentionally repeated during restart
        // recovery: a crash after Stopping committed but before the original
        // caller scrubbed the outbox must not preserve actionable text.
        self.cancel_queued_interventions(
            owner,
            Some(session_id),
            None,
            "focus_session_stopping",
            self.daemon_context(),
        )?;
        let grants = self.repository.load_grants(owner)?;
        let mut cleanup_incomplete = false;
        for grant_id in &session.permission_grant_ids {
            let grant = grants.iter().find(|grant| grant.id == *grant_id);
            if grant.is_none() {
                cleanup_incomplete = true;
            };
            if grant.is_some_and(|grant| !grant.scope.is_observation()) {
                continue;
            }
            let stopped = tokio::time::timeout(
                Duration::from_secs(5),
                self.observation.stop(session_id, *grant_id),
            )
            .await;
            if !matches!(stopped, Ok(Ok(()))) {
                cleanup_incomplete = true;
            }
        }
        let clear = tokio::time::timeout(
            Duration::from_secs(5),
            self.native_status.clear(session_id, session.revision),
        )
        .await;
        if !matches!(
            clear,
            Ok(Ok(NativeStatusAcknowledgement {
                session_id: acknowledged_session,
                revision: acknowledged_revision,
                ..
            })) if acknowledged_session == session_id && acknowledged_revision == session.revision
        ) {
            cleanup_incomplete = true;
        }
        if let Ok(mut state) = self.ephemeral.lock() {
            state.sessions.remove(&session_id);
        }
        let expected = session.revision;
        session.state = FocusSessionState::Ended;
        session.ended_at = Some(self.clock.now_utc());
        session.updated_at = self.clock.now_utc();
        session.source_degraded = cleanup_incomplete;
        if cleanup_incomplete {
            session.failure_reason = Some("ended_cleanup_incomplete".to_owned());
        }
        session.revision += 1;
        self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                &session,
                expected,
                AuditDetails::new(
                    vec![if cleanup_incomplete {
                        "focus_session_ended_cleanup_incomplete".to_owned()
                    } else {
                        "focus_session_ended".to_owned()
                    }],
                    BTreeSet::new(),
                ),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::Ended, &session);
            Ok(())
        })?;
        Ok(session)
    }

    pub fn record_feedback(
        &self,
        assurance: ClientAssurance,
        owner: ActorId,
        intervention_id: InterventionId,
        expected_revision: u64,
        outcome: InterventionOutcome,
        correction: Option<SensitiveText>,
    ) -> Result<Intervention, SecondMindError> {
        require_private(assurance)?;
        if outcome == InterventionOutcome::Corrected
            && correction.as_ref().is_none_or(|v| v.is_empty())
        {
            return Err(SecondMindError::invalid(
                "Corrected feedback requires a current-context correction.",
            ));
        }
        let mut intervention = self
            .repository
            .load_interventions(owner)?
            .into_iter()
            .find(|value| value.id == intervention_id)
            .ok_or(SecondMindError {
                code: SecondMindErrorCode::NotFound,
                summary: "The intervention was not found.",
                retryable: false,
                current_revision: None,
            })?;
        if intervention.revision != expected_revision {
            return Err(SecondMindError::conflict(intervention.revision));
        }
        let eligible_delivery_state = match intervention.state {
            InterventionState::AcceptedByChannel => intervention.delivered_at.is_some(),
            // A capability-bound user action on an ambiguous/history record is
            // stronger evidence than the lost channel acknowledgement (for
            // example, a crash-recovered toast activation).
            InterventionState::DeliveryUnknown => true,
            _ => false,
        };
        if !eligible_delivery_state
            || intervention.outcome != InterventionOutcome::Unacknowledged
            || intervention.outcome_at.is_some()
            || !matches!(
                outcome,
                InterventionOutcome::Accepted
                    | InterventionOutcome::Dismissed
                    | InterventionOutcome::Corrected
            )
        {
            return Err(SecondMindError::invalid(
                "Feedback requires an accepted or delivery-unknown intervention with no prior outcome.",
            ));
        }
        let policy_trace = self.persisted_policy_trace(intervention.policy_decision_id)?;
        intervention.outcome = outcome;
        intervention.outcome_at = Some(self.clock.now_utc());
        intervention.correction_summary = (outcome == InterventionOutcome::Corrected)
            .then(|| "current_context_corrected".to_owned());
        intervention.revision += 1;
        intervention.updated_at = self.clock.now_utc();
        self.commit(self.daemon_context(), |events| {
            self.persist_intervention_transition(
                &intervention,
                expected_revision,
                AuditKind::InterventionOutcome,
                AuditDetails::new(
                    vec![format!("outcome_{outcome:?}").to_lowercase()],
                    BTreeSet::new(),
                )
                .with_optional_policy_trace(policy_trace),
                None,
            )?;
            if let Some(correction) = correction
                && let Ok(mut state) = self.ephemeral.lock()
                && let Some(ephemeral) = state.sessions.get_mut(&intervention.focus_session_id)
            {
                ephemeral.correction = Some(correction);
                ephemeral.significance_generation =
                    ephemeral.significance_generation.saturating_add(1);
            }
            Self::push_intervention_update(
                events,
                &intervention,
                InterventionHistoryViewChange::Updated,
            );
            Ok(())
        })?;
        Ok(intervention)
    }

    /// Closes delivery records whose process died before their terminal outcome
    /// could be committed. This method never calls a notification adapter:
    /// once a durable attempt marker exists, losing the native result can only
    /// be reported as unknown, never retried.
    pub fn reconcile_interrupted_deliveries(
        &self,
        owner: ActorId,
    ) -> Result<Vec<Intervention>, SecondMindError> {
        let now = self.clock.now_utc();
        let mut interventions = self.repository.load_interventions(owner)?;
        interventions.sort_by_key(|intervention| (intervention.updated_at, intervention.id));
        let deliveries = self.repository.load_pending_deliveries(owner)?;
        let mut changed = Vec::new();

        for mut intervention in interventions.into_iter().filter(|intervention| {
            matches!(
                intervention.state,
                InterventionState::Allowed
                    | InterventionState::Queued
                    | InterventionState::Delivering
            )
        }) {
            let mut matching = deliveries
                .iter()
                .filter(|delivery| delivery.intervention_id == intervention.id);
            let delivery = matching.next().cloned();
            if matching.next().is_some() {
                return Err(SecondMindError::unavailable(
                    "An interrupted intervention has multiple delivery records.",
                ));
            }

            let expected = intervention.revision;
            let policy_trace = self.persisted_policy_trace(intervention.policy_decision_id)?;
            let (reason_code, delivery_transition) = match (intervention.state, delivery) {
                (InterventionState::Allowed, None) => {
                    intervention.state = InterventionState::Cancelled;
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "delivery_not_started_after_restart".to_owned();
                    scrub_intervention(&mut intervention);
                    ("delivery_not_started_after_restart", None)
                }
                (InterventionState::Allowed, Some(mut delivery))
                    if delivery.state == OutboxState::Queued =>
                {
                    let expected_state = delivery.state;
                    delivery.state = OutboxState::Cancelled;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::Cancelled;
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "delivery_not_started_after_restart".to_owned();
                    scrub_intervention(&mut intervention);
                    (
                        "delivery_not_started_after_restart",
                        Some(PendingDeliveryTransition::Update {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Queued, None) => {
                    intervention.state = InterventionState::Cancelled;
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "delivery_not_started_after_restart".to_owned();
                    scrub_intervention(&mut intervention);
                    ("delivery_not_started_after_restart", None)
                }
                (InterventionState::Queued, Some(mut delivery))
                    if delivery.state == OutboxState::Queued =>
                {
                    let authority_is_current = self
                        .repository
                        .find_policy_decision(delivery.policy_decision_id)?
                        .as_ref()
                        .is_some_and(|decision| {
                            decision.id == intervention.policy_decision_id
                                && self.durable_delivery_authority_is_current(
                                    decision,
                                    intervention.goal_id,
                                    intervention.id,
                                )
                        });
                    if authority_is_current {
                        // This is the only restart state that remains eligible
                        // for fresh policy revalidation and a later marker.
                        continue;
                    }
                    let expected_state = delivery.state;
                    delivery.state = OutboxState::Cancelled;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::Cancelled;
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "queued_authority_invalid_after_restart".to_owned();
                    scrub_intervention(&mut intervention);
                    (
                        "queued_authority_invalid_after_restart",
                        Some(PendingDeliveryTransition::Update {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Queued, Some(mut delivery))
                    if matches!(
                        delivery.state,
                        OutboxState::Delivering | OutboxState::DeliveryUnknown
                    ) =>
                {
                    // An outbox attempt marker is authoritative even if an
                    // older implementation failed to update the intervention.
                    let expected_state = delivery.state;
                    delivery.state = OutboxState::DeliveryUnknown;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::DeliveryUnknown;
                    (
                        "delivery_unknown_after_restart",
                        Some(PendingDeliveryTransition::ReconcileLegacy {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Queued, Some(mut delivery))
                    if delivery.state == OutboxState::AcceptedByChannel =>
                {
                    let expected_state = delivery.state;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::AcceptedByChannel;
                    intervention.delivered_at = Some(now);
                    (
                        "delivery_state_reconciled_after_restart",
                        Some(PendingDeliveryTransition::ReconcileLegacy {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Queued, Some(mut delivery))
                    if delivery.state == OutboxState::DeliveryFailed =>
                {
                    let expected_state = delivery.state;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::DeliveryFailed;
                    (
                        "delivery_state_reconciled_after_restart",
                        Some(PendingDeliveryTransition::ReconcileLegacy {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Queued, Some(mut delivery))
                    if matches!(
                        delivery.state,
                        OutboxState::Expired | OutboxState::Cancelled
                    ) =>
                {
                    let expected_state = delivery.state;
                    delivery.user_visible_text.clear();
                    intervention.state = match delivery.state {
                        OutboxState::Expired => InterventionState::Expired,
                        OutboxState::Cancelled => InterventionState::Cancelled,
                        _ => unreachable!("matched terminal non-delivery state"),
                    };
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "missed_intervention".to_owned();
                    scrub_intervention(&mut intervention);
                    (
                        "delivery_state_reconciled_after_restart",
                        Some(PendingDeliveryTransition::ReconcileLegacy {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Delivering, None) => {
                    intervention.state = InterventionState::DeliveryUnknown;
                    ("delivery_unknown_after_restart", None)
                }
                (InterventionState::Delivering, Some(mut delivery))
                    if matches!(
                        delivery.state,
                        OutboxState::Delivering | OutboxState::DeliveryUnknown
                    ) =>
                {
                    let expected_state = delivery.state;
                    delivery.state = OutboxState::DeliveryUnknown;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::DeliveryUnknown;
                    (
                        "delivery_unknown_after_restart",
                        Some(PendingDeliveryTransition::Update {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                (InterventionState::Delivering, Some(mut delivery))
                    if delivery.state == OutboxState::Queued =>
                {
                    // The recovery decision committed, but the atomic attempt
                    // marker did not. No adapter call was possible.
                    let expected_state = delivery.state;
                    delivery.state = OutboxState::Cancelled;
                    delivery.user_visible_text.clear();
                    intervention.state = InterventionState::Cancelled;
                    intervention.outcome = InterventionOutcome::Expired;
                    intervention.outcome_at = Some(now);
                    intervention.reason_code = "delivery_not_started_after_restart".to_owned();
                    scrub_intervention(&mut intervention);
                    (
                        "delivery_not_started_after_restart",
                        Some(PendingDeliveryTransition::Update {
                            delivery,
                            expected_state,
                        }),
                    )
                }
                _ => {
                    return Err(SecondMindError::unavailable(
                        "An interrupted intervention and delivery record disagree.",
                    ));
                }
            };
            intervention.revision = intervention.revision.saturating_add(1);
            intervention.updated_at = now;
            self.commit(self.daemon_context(), |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(vec![reason_code.to_owned()], BTreeSet::new())
                        .with_optional_policy_trace(policy_trace),
                    delivery_transition,
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
            changed.push(intervention);
        }
        Ok(changed)
    }

    pub fn recover_owner(&self, owner: ActorId) -> Result<Vec<FocusSession>, SecondMindError> {
        let now = self.clock.now_utc();
        self.repository.purge_expired_audit(now)?;
        let goals = self.repository.load_goals(owner)?;
        let grants = self.repository.load_grants(owner)?;
        let resources = self.repository.load_resources(owner)?;
        let routes = self.repository.load_model_routes(owner)?;
        let mut recovered = Vec::new();
        for mut session in self.repository.load_focus_sessions(owner)? {
            if session.state == FocusSessionState::Stopping {
                // Authority was revoked before the durable Stopping transition
                // committed. Return it to the daemon recovery coordinator so
                // bounded adapter/native-status cleanup can resume.
                recovered.push(session);
                continue;
            }
            if !session.is_working() {
                continue;
            }
            if self
                .ephemeral
                .lock()
                .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?
                .activations
                .contains(&session.id)
            {
                return Err(SecondMindError::unavailable(
                    "A focus-session activation is already in progress.",
                ));
            }
            let can_recover = goals.iter().any(|goal| {
                goal.id == session.goal_id
                    && goal.revision.get() == session.goal_revision
                    && goal.state == GoalState::Active
                    && goal.deadline.is_none_or(|deadline| now < deadline)
            }) && session.daemon_restart_allowed
                && session.permission_grant_ids.iter().all(|id| {
                    grants.iter().any(|grant| {
                        grant.id == *id
                            && grant.daemon_restart_allowed
                            && grant.is_current_at(now)
                            && grant.selected_resource_id.is_none_or(|resource_id| {
                                resources.iter().any(|resource| {
                                    resource.id == resource_id
                                        && resource_kind_allows_restart(resource.kind)
                                })
                            })
                    })
                })
                && routes.iter().any(|route| {
                    route.id == session.model_route_approval_id && route.is_current_at(now)
                });
            if can_recover && session.state == FocusSessionState::Recovering {
                recovered.push(session);
                continue;
            }
            self.remove_focus_ephemeral(session.id);
            let expected = session.revision;
            if can_recover {
                session.state = FocusSessionState::Recovering;
                session.source_degraded = true;
                session.updated_at = now;
                session.revision += 1;
                self.commit(self.daemon_context(), |events| {
                    self.persist_focus_lifecycle_transition(
                        &session,
                        expected,
                        AuditDetails::new(
                            vec!["focus_session_recovery_started".to_owned()],
                            BTreeSet::new(),
                        ),
                    )?;
                    self.push_focus_and_capture(
                        events,
                        FocusSessionViewChange::RecoveryStarted,
                        &session,
                    );
                    Ok(())
                })?;
            } else {
                session.state = FocusSessionState::Ended;
                session.ended_at = Some(now);
                session.updated_at = now;
                session.failure_reason = Some("restart_continuity_not_authorized".to_owned());
                session.revision += 1;
                self.commit(self.daemon_context(), |events| {
                    self.persist_focus_lifecycle_transition(
                        &session,
                        expected,
                        AuditDetails::new(
                            vec!["restart_continuity_not_authorized".to_owned()],
                            BTreeSet::new(),
                        ),
                    )?;
                    self.push_focus_and_capture(events, FocusSessionViewChange::Ended, &session);
                    Ok(())
                })?;
            }
            recovered.push(session);
        }
        Ok(recovered)
    }

    /// Revalidates and restarts every adapter required by a durable recovering
    /// session. Recovery is not complete merely because records survived a
    /// restart: native status must acknowledge first, every grant/resource and
    /// route must still be current, and each observation source must return a
    /// fresh healthy initial status before the session becomes active.
    pub async fn reactivate_recovered_focus_session(
        &self,
        owner: ActorId,
        session_id: FocusSessionId,
    ) -> Result<FocusSession, SecondMindError> {
        let now = self.clock.now_utc();
        let mut session = find_session(&*self.repository, session_id)?;
        if session.owner != owner || session.state != FocusSessionState::Recovering {
            return Err(SecondMindError::invalid(
                "The focus session is not awaiting adapter recovery.",
            ));
        }
        let _activation = self.acquire_focus_activation(session.id, session.revision)?;
        let goal = self.get_goal(owner, session.goal_id)?;
        if goal.state != GoalState::Active
            || goal.revision.get() != session.goal_revision
            || goal.deadline.is_some_and(|deadline| now >= deadline)
        {
            return Err(SecondMindError::permission(
                "The recovering focus session no longer matches its goal.",
            ));
        }
        let route = find_route(&*self.repository, owner, session.model_route_approval_id)?;
        validate_model_route(&route, now)?;
        let grants = resolve_grants(
            &*self.repository,
            owner,
            session.id,
            &session.permission_grant_ids,
            now,
        )?;
        let selected_resources: BTreeSet<_> = grants
            .iter()
            .filter_map(|grant| grant.selected_resource_id)
            .collect();
        if selected_resources != session.selected_resource_ids {
            return Err(SecondMindError::permission(
                "The recovering focus session resource bindings changed.",
            ));
        }
        let resources = self.repository.load_resources(owner)?;
        let preferences = self.effective_preferences(session.owner)?;
        let cancellation = CancellationToken::new();
        if !self.emergency_control.availability().is_available()
            || self.publish_native_status(&session).await.is_err()
        {
            self.cleanup_focus_activation(session.id, session.revision, &cancellation, &[])
                .await;
            return Err(SecondMindError::unavailable(
                "Independent native status and stop control are required for recovery.",
            ));
        }

        let mut observation_grants: Vec<_> = grants
            .into_iter()
            .filter(|grant| grant.scope.is_observation())
            .collect();
        observation_grants.sort_by_key(|grant| observation_start_tier(grant.scope));
        let mut started = Vec::new();
        let mut source_health = BTreeMap::new();
        let mut subscriptions = Vec::new();
        for grant in &observation_grants {
            if !self.observation.availability(grant.scope).is_available() {
                self.cleanup_focus_activation(
                    session.id,
                    session.revision,
                    &cancellation,
                    &started,
                )
                .await;
                return Err(SecondMindError::unavailable(
                    "A required recovering observation source is unavailable.",
                ));
            }
            let resource = grant
                .selected_resource_id
                .and_then(|id| resources.iter().find(|resource| resource.id == id).cloned());
            let request = ObservationStartRequest {
                grant: grant.clone(),
                resource,
                limits: observation_limits(&self.config, grant.scope),
            };
            let subscription = match tokio::time::timeout(
                self.config.native_status_heartbeat_timeout,
                self.observation.start(&request, cancellation.child_token()),
            )
            .await
            {
                Ok(Ok(subscription)) => subscription,
                Ok(Err(_)) | Err(_) => {
                    started.push(grant.id);
                    self.cleanup_focus_activation(
                        session.id,
                        session.revision,
                        &cancellation,
                        &started,
                    )
                    .await;
                    return Err(SecondMindError::unavailable(
                        "A recovering observation source failed to restart.",
                    ));
                }
            };
            started.push(grant.id);
            let age = now - subscription.initial_status.observed_at;
            if validate_source_status(grant, &subscription.initial_status).is_err()
                || subscription.initial_status.health != crate::SourceHealth::Healthy
                || age.is_negative()
                || age
                    > time::Duration::try_from(self.config.source_freshness)
                        .unwrap_or(time::Duration::MAX)
            {
                self.cleanup_focus_activation(
                    session.id,
                    session.revision,
                    &cancellation,
                    &started,
                )
                .await;
                return Err(SecondMindError::unavailable(
                    "A recovering observation source is not freshly healthy.",
                ));
            }
            source_health.insert(grant.id, subscription.initial_status.clone());
            subscriptions.push((grant.id, subscription));
        }

        let expected = session.revision;
        let active_revision = session.revision.saturating_add(1);
        let mut ephemeral = EphemeralSession {
            source_health,
            native_status_revision: Some(active_revision),
            ..EphemeralSession::with_cancellation(cancellation.clone())
        };
        reconcile_proactive_cancellation(
            &mut ephemeral,
            !session.muted
                && preferences.proactive_interventions_enabled
                && !preferences.proactive_interventions_muted,
        );
        let install_result = self
            .ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))
            .map(|mut state| {
                if let Some(previous) = state.sessions.insert(session.id, ephemeral) {
                    previous.cancellation.cancel();
                }
            });
        if let Err(error) = install_result {
            self.cleanup_focus_activation(session.id, session.revision, &cancellation, &started)
                .await;
            return Err(error);
        }
        session.state = FocusSessionState::Active;
        session.source_degraded = false;
        session.failure_reason = None;
        session.updated_at = self.clock.now_utc();
        session.revision = active_revision;
        if let Err(error) = self.commit(self.daemon_context(), |events| {
            self.persist_focus_lifecycle_transition(
                &session,
                expected,
                AuditDetails::new(vec!["focus_session_recovered".to_owned()], BTreeSet::new()),
            )?;
            self.push_focus_and_capture(events, FocusSessionViewChange::Recovered, &session);
            Ok(())
        }) {
            self.cleanup_focus_activation(session.id, expected, &cancellation, &started)
                .await;
            return Err(error);
        }
        if self.publish_native_status(&session).await.is_err() {
            self.cleanup_focus_activation(session.id, session.revision, &cancellation, &started)
                .await;
            let _ = self.mark_focus_recovery_pending(
                &mut session,
                "native_status_acknowledgement_lost_during_recovery",
            );
            return Err(SecondMindError::unavailable(
                "Native capture status acknowledgement was lost during recovery.",
            ));
        }
        let _ = self.commit(self.daemon_context(), |events| {
            events.push(CoreEvent::CapabilityHealthChanged {
                capability: CapabilityHealth {
                    id: "platform.native_status",
                    state: CapabilityState::Available,
                    detail: "Native capture status was freshly revalidated.",
                },
            });
            Ok(())
        });
        for (grant_id, subscription) in subscriptions {
            self.spawn_observation_subscription(
                session.id,
                grant_id,
                cancellation.child_token(),
                subscription,
            );
        }
        self.spawn_native_status_monitor(session.id, cancellation.child_token());
        self.spawn_native_status_heartbeat(session.id, cancellation.child_token());
        Ok(session)
    }

    fn cancel_queued_interventions(
        &self,
        owner: ActorId,
        session_filter: Option<FocusSessionId>,
        grant_filter: Option<PermissionGrantId>,
        reason_code: &'static str,
        context: EventContext,
    ) -> Result<(), SecondMindError> {
        let now = self.clock.now_utc();
        let interventions = self.repository.load_interventions(owner)?;
        for mut entry in self.repository.load_pending_deliveries(owner)? {
            if entry.state != OutboxState::Queued {
                continue;
            }
            if grant_filter.is_some_and(|grant_id| !entry.permission_grant_ids.contains(&grant_id))
            {
                continue;
            }
            let Some(mut intervention) = interventions
                .iter()
                .find(|intervention| intervention.id == entry.intervention_id)
                .cloned()
            else {
                return Err(SecondMindError::unavailable(
                    "A queued intervention is unavailable.",
                ));
            };
            if session_filter.is_some_and(|session_id| intervention.focus_session_id != session_id)
            {
                continue;
            }
            let policy_trace = self.persisted_policy_trace(intervention.policy_decision_id)?;
            let expected_delivery_state = entry.state;
            entry.state = OutboxState::Cancelled;
            entry.user_visible_text.clear();
            let expected = intervention.revision;
            intervention.state = InterventionState::Cancelled;
            intervention.outcome = InterventionOutcome::Expired;
            intervention.outcome_at = Some(now);
            intervention.reason_code = reason_code.to_owned();
            scrub_intervention(&mut intervention);
            intervention.revision = intervention.revision.saturating_add(1);
            intervention.updated_at = now;
            self.commit(context, |events| {
                self.persist_intervention_transition(
                    &intervention,
                    expected,
                    AuditKind::InterventionDelivery,
                    AuditDetails::new(vec![reason_code.to_owned()], BTreeSet::new())
                        .with_optional_policy_trace(policy_trace.clone()),
                    Some(PendingDeliveryTransition::Update {
                        delivery: entry.clone(),
                        expected_state: expected_delivery_state,
                    }),
                )?;
                Self::push_intervention_update(
                    events,
                    &intervention,
                    InterventionHistoryViewChange::Updated,
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    fn proactive_cancellation(
        &self,
        session_id: FocusSessionId,
    ) -> Result<CancellationToken, SecondMindError> {
        self.ephemeral
            .lock()
            .map_err(|_| SecondMindError::unavailable("Ephemeral context is unavailable."))?
            .sessions
            .get(&session_id)
            .map(|session| session.proactive_cancellation.child_token())
            .ok_or_else(|| {
                SecondMindError::unavailable("The session has no live cancellation authority.")
            })
    }

    fn replayed_result(
        &self,
        owner: ActorId,
        kind: OperationKind,
        idempotency: IdempotencyContext,
    ) -> Result<Option<Uuid>, SecondMindError> {
        let Some(receipt) = self
            .repository
            .find_operation_receipt(owner, kind, idempotency.key)?
        else {
            return Ok(None);
        };
        if receipt.request_digest != idempotency.request_digest {
            return Err(SecondMindError::idempotency_conflict());
        }
        Ok(Some(receipt.result_id))
    }

    fn build_audit_record(
        &self,
        owner: ActorId,
        kind: AuditKind,
        subject_id: Uuid,
        details: AuditDetails,
    ) -> AuditRecord {
        let now = self.clock.now_utc();
        AuditRecord {
            id: AuditRecordId::new_v7(),
            owner,
            kind,
            subject_id,
            correlation_id: Uuid::now_v7(),
            reason_codes: details.reason_codes,
            evidence_categories: details.evidence_categories,
            evidence_age_ms: details.evidence_age_ms,
            confidence_basis_points: details.confidence_basis_points,
            policy_trace: details.policy_trace,
            occurred_at: now,
            expires_at: now
                + time::Duration::try_from(self.config.audit_ttl).unwrap_or(time::Duration::MAX),
        }
    }

    fn persist_focus_lifecycle_transition(
        &self,
        session: &FocusSession,
        expected_revision: u64,
        details: AuditDetails,
    ) -> Result<(), SecondMindError> {
        let audit = self.build_audit_record(
            session.owner,
            AuditKind::FocusSessionStateChanged,
            session.id.as_uuid(),
            details,
        );
        self.repository
            .save_focus_session_transition(&FocusSessionLifecycleWrite {
                session: session.clone(),
                expected_revision,
                audit,
            })?;
        Ok(())
    }

    fn persist_permission_revocation(
        &self,
        grant: &PermissionGrant,
        expected_revision: u64,
        details: AuditDetails,
    ) -> Result<(), SecondMindError> {
        let audit = self.build_audit_record(
            grant.owner,
            AuditKind::PermissionRevoked,
            grant.id.as_uuid(),
            details,
        );
        self.repository
            .save_permission_grant_revocation(&PermissionGrantRevocationWrite {
                grant: grant.clone(),
                expected_revision,
                audit,
            })?;
        Ok(())
    }

    fn persist_intervention_transition(
        &self,
        intervention: &Intervention,
        expected_revision: u64,
        kind: AuditKind,
        details: AuditDetails,
        delivery: Option<PendingDeliveryTransition>,
    ) -> Result<(), SecondMindError> {
        let audit =
            self.build_audit_record(intervention.owner, kind, intervention.id.as_uuid(), details);
        self.repository
            .save_intervention_transition(&InterventionTransitionWrite {
                intervention: intervention.clone(),
                expected_revision,
                audit,
                delivery,
            })?;
        Ok(())
    }

    fn append_audit(
        &self,
        owner: ActorId,
        kind: AuditKind,
        subject_id: Uuid,
        details: AuditDetails,
    ) -> Result<AuditRecord, SecondMindError> {
        let record = self.build_audit_record(owner, kind, subject_id, details);
        self.repository.append_audit(&record)?;
        Ok(record)
    }
}

fn observation_is_within_retention(
    config: &SecondMindConfig,
    observation: &NormalizedObservation,
    now: OffsetDateTime,
) -> bool {
    let configured_ttl = match observation.provenance.retention {
        crate::ObservationRetention::EphemeralSession => config.observation_ttl,
        crate::ObservationRetention::SingleOperation => config
            .observation_ttl
            .min(config.maximum_model_evidence_age),
    };
    let ttl = time::Duration::try_from(configured_ttl).unwrap_or(time::Duration::MAX);
    let age = now - observation.provenance.observed_at;
    !age.is_negative() && age < ttl
}

fn duration_millis_u64(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

const fn presence_wire_name(value: crate::PresenceState) -> &'static str {
    match value {
        crate::PresenceState::Active => "active",
        crate::PresenceState::Idle => "idle",
        crate::PresenceState::Locked => "locked",
        crate::PresenceState::SwitchedAway => "switched_away",
        crate::PresenceState::Unknown => "unknown",
    }
}

fn validate_config(config: &SecondMindConfig) -> Result<(), SecondMindError> {
    if config.observation_ttl.is_zero()
        || config.observation_ttl > Duration::from_secs(10 * 60)
        || config.retention_maintenance_interval.is_zero()
        || config.retention_maintenance_interval > Duration::from_secs(60)
        || config.source_freshness.is_zero()
        || config.source_freshness > Duration::from_secs(30)
        || config.source_freshness > config.observation_ttl
        || config.native_status_heartbeat_timeout.is_zero()
        || config.native_status_heartbeat_timeout > Duration::from_secs(10)
        || config.maximum_observation_bytes == 0
        || config.maximum_observation_bytes > 16 * 1024
        || config.model_deadline.is_zero()
        || config.model_deadline > Duration::from_secs(30)
        || config.significance_evaluation_interval.is_zero()
        || config.significance_evaluation_interval < Duration::from_secs(60)
        || config.model_request_cooldown.is_zero()
        || config.model_request_cooldown < Duration::from_secs(5 * 60)
        || config.maximum_model_requests_per_hour == 0
        || config.maximum_model_requests_per_hour > 12
        || config.deadline_risk_horizon.is_zero()
        || config.deadline_risk_horizon > Duration::from_secs(30 * 60)
        || config.maximum_model_evidence_age.is_zero()
        || config.maximum_model_evidence_age > Duration::from_secs(2 * 60)
        || config.maximum_model_evidence_age > config.observation_ttl
        || config.policy_validity.is_zero()
        || config.policy_validity > Duration::from_secs(30)
        || config.intervention_cooldown.is_zero()
        || config.intervention_cooldown < Duration::from_secs(15 * 60)
        || config.maximum_interventions_per_session == 0
        || config.maximum_interventions_per_session > 3
        || config.outbox_capacity_per_user == 0
        || config.outbox_capacity_per_user > 20
        || config.outbox_capacity_per_session == 0
        || config.outbox_capacity_per_session > 5
        || config.outbox_capacity_per_session > config.outbox_capacity_per_user
        || config.outbox_entry_ttl.is_zero()
        || config.outbox_entry_ttl > Duration::from_secs(15 * 60)
        || config.recovery_batch_size == 0
        || config.recovery_batch_size > 3
        || config.recovery_batch_interval.is_zero()
        || config.recovery_batch_interval < Duration::from_secs(10)
        || config.audit_append_deadline.is_zero()
        || config.audit_append_deadline > Duration::from_secs(2)
        || config.notification_attempt_deadline.is_zero()
        || config.notification_attempt_deadline > Duration::from_secs(5)
        || config.resource_selection_deadline.is_zero()
        || config.resource_selection_deadline > Duration::from_secs(2 * 60)
        || config.resource_release_deadline.is_zero()
        || config.resource_release_deadline > Duration::from_secs(10)
        || config.audit_ttl.is_zero()
        || config.audit_ttl > Duration::from_secs(30 * 24 * 60 * 60)
        || config.minimum_candidate_confidence_basis_points > 10_000
    {
        return Err(SecondMindError::invalid(
            "The second-mind policy configuration is invalid.",
        ));
    }
    Ok(())
}

fn valid_do_not_disturb_window(window: DoNotDisturbWindow) -> bool {
    window.start_minute_local < 24 * 60
        && window.end_minute_local < 24 * 60
        && window.start_minute_local != window.end_minute_local
        && (-1_439..=1_439).contains(&window.utc_offset_minutes)
}

fn do_not_disturb_contains(window: DoNotDisturbWindow, now: OffsetDateTime) -> bool {
    let offset_seconds = i32::from(window.utc_offset_minutes).saturating_mul(60);
    let Ok(offset) = time::UtcOffset::from_whole_seconds(offset_seconds) else {
        return true;
    };
    let local = now.to_offset(offset);
    let minute = u16::from(local.hour()) * 60 + u16::from(local.minute());
    if window.start_minute_local < window.end_minute_local {
        (window.start_minute_local..window.end_minute_local).contains(&minute)
    } else {
        minute >= window.start_minute_local || minute < window.end_minute_local
    }
}

fn delivery_deduplication_key(
    candidate_id: CandidateId,
    candidate_revision: u64,
    channel: &str,
) -> Uuid {
    let name = format!("{}:{candidate_revision}:{channel}", candidate_id.as_uuid());
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}

fn delivery_status_timeout(now: OffsetDateTime) -> crate::DeliveryChannelStatus {
    crate::DeliveryChannelStatus {
        channel_id: NATIVE_NOTIFICATION_CHANNEL.to_owned(),
        health: crate::DeliveryChannelHealth::Degraded,
        detail: "Native notification status acknowledgement timed out.",
        observed_at: now,
    }
}

fn scrub_intervention(intervention: &mut Intervention) {
    intervention.user_visible_text.clear();
    intervention.evidence_summary.clear();
    intervention.evidence.clear();
}

fn cancel_intervention_without_delivery(
    intervention: &mut Intervention,
    cancelled_at: OffsetDateTime,
    reason_code: &str,
) {
    intervention.state = InterventionState::Cancelled;
    intervention.outcome = InterventionOutcome::Expired;
    intervention.outcome_at = Some(cancelled_at);
    intervention.reason_code = reason_code.to_owned();
    scrub_intervention(intervention);
}

fn reconcile_proactive_cancellation(ephemeral: &mut EphemeralSession, allowed: bool) {
    if allowed {
        if ephemeral.proactive_cancellation.is_cancelled() && !ephemeral.cancellation.is_cancelled()
        {
            ephemeral.proactive_cancellation = ephemeral.cancellation.child_token();
        }
    } else {
        ephemeral.proactive_cancellation.cancel();
    }
}

const fn consumes_intervention_cooldown(state: InterventionState) -> bool {
    matches!(
        state,
        InterventionState::Queued
            | InterventionState::Delivering
            | InterventionState::AcceptedByChannel
            | InterventionState::DeliveryUnknown
    )
}

fn require_private(assurance: ClientAssurance) -> Result<(), SecondMindError> {
    if assurance.permits_private() {
        Ok(())
    } else {
        Err(SecondMindError::permission(
            "This operation requires an OS capability-bound client.",
        ))
    }
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    summary: &'static str,
) -> Result<(), SecondMindError> {
    let length = value.trim().chars().count();
    if length < minimum || length > maximum || value.chars().any(char::is_control) {
        Err(SecondMindError::invalid(summary))
    } else {
        Ok(())
    }
}

fn bound_text(value: String, maximum: usize) -> String {
    value.trim().chars().take(maximum).collect()
}

fn apply_goal_patch(goal: &mut Goal, patch: GoalPatch) {
    if let Some(value) = patch.title {
        goal.title = value;
    }
    if let Some(value) = patch.success_statement {
        goal.success_statement = value;
    }
    if let Some(value) = patch.deadline {
        goal.deadline = value;
    }
}

fn validate_model_route(
    route: &ModelRouteApproval,
    now: OffsetDateTime,
) -> Result<(), SecondMindError> {
    if route.provider.trim().is_empty()
        || route.model.trim().is_empty()
        || !route.has_approval_scoped_secret_ref()
        || route.purpose != "reason.focus_context"
        || route.maximum_input_tokens == 0
        || route.maximum_input_tokens > 8_000
        || route.maximum_output_tokens == 0
        || route.maximum_output_tokens > 512
        || route.allowed_categories.is_empty()
        || route.handling.tools_enabled
        || route.handling.core_persists_prompt_or_response
        || route.fallback_allowed != route.fallback.is_some()
        || route.expires_at.is_some_and(|expiry| expiry <= now)
    {
        return Err(SecondMindError::invalid(
            "The model route approval is invalid or unsafe.",
        ));
    }
    Ok(())
}

fn validate_grant_input(
    command: &GrantPermission,
    now: OffsetDateTime,
) -> Result<(), SecondMindError> {
    validate_text(&command.purpose, 1, 240, "Permission purpose is invalid.")?;
    validate_text(
        &command.consent_copy_version,
        1,
        64,
        "Consent copy version is invalid.",
    )?;
    if command.effective_at < now - time::Duration::minutes(1)
        || command.expires_at <= command.effective_at
        || command.expires_at > command.effective_at + time::Duration::hours(8)
    {
        return Err(SecondMindError::invalid(
            "Permission effective and expiry times are invalid or exceed the eight-hour maximum.",
        ));
    }
    if command.scope == PermissionScope::ObserveScreenPixels && command.daemon_restart_allowed {
        return Err(SecondMindError::invalid(
            "Screen-pixel permission cannot continue after a daemon restart; select the source again.",
        ));
    }
    let needs_resource = scope_requires_resource(command.scope);
    if needs_resource != command.selected_resource_id.is_some() {
        return Err(SecondMindError::invalid(
            "The permission resource binding does not match its scope.",
        ));
    }
    Ok(())
}

const fn scope_requires_resource(scope: PermissionScope) -> bool {
    matches!(
        scope,
        PermissionScope::ObserveDesktopForegroundApplication
            | PermissionScope::ObserveDesktopWindowMetadata
            | PermissionScope::ObserveBrowserLocation
            | PermissionScope::ObserveContentVisibleText
            | PermissionScope::ObserveContentSelectedDocument
            | PermissionScope::ObserveScreenPixels
            | PermissionScope::ObserveWorkspaceActivity
    )
}

const fn resource_kind_matches_scope(scope: PermissionScope, kind: ResourceKind) -> bool {
    matches!(
        (scope, kind),
        (
            PermissionScope::ObserveDesktopForegroundApplication,
            ResourceKind::Application
        ) | (
            PermissionScope::ObserveDesktopWindowMetadata,
            ResourceKind::Window
        ) | (
            PermissionScope::ObserveBrowserLocation,
            ResourceKind::BrowserSurface
        ) | (
            PermissionScope::ObserveContentVisibleText,
            ResourceKind::Window | ResourceKind::BrowserSurface
        ) | (
            PermissionScope::ObserveContentSelectedDocument,
            ResourceKind::Document
        ) | (
            PermissionScope::ObserveScreenPixels,
            ResourceKind::ScreenRegion
        ) | (
            PermissionScope::ObserveWorkspaceActivity,
            ResourceKind::Workspace
        )
    )
}

const fn resource_kind_allows_restart(kind: ResourceKind) -> bool {
    !matches!(
        kind,
        ResourceKind::BrowserSurface | ResourceKind::ScreenRegion
    )
}

fn validate_candidate(
    text: &str,
    reason: &str,
    evidence: &str,
    confidence: u16,
) -> Result<(), SecondMindError> {
    validate_text(text, 1, 512, "Candidate intervention text is invalid.")?;
    validate_text(reason, 1, 80, "Candidate reason code is invalid.")?;
    validate_text(evidence, 1, 240, "Candidate evidence summary is invalid.")?;
    let lower = text.to_ascii_lowercase();
    if confidence > 10_000
        || lower.contains("\"tool\"")
        || lower.contains("function_call")
        || lower.contains("<tool_call")
    {
        return Err(SecondMindError::permission(
            "Tool-shaped or invalid model output was rejected.",
        ));
    }
    Ok(())
}

fn summarize_evidence(
    context: &[WorkingContextItem],
    reason_code: &str,
) -> Vec<crate::EvidenceSummary> {
    let role = match reason_code {
        "recent_relevant_progress" => crate::EvidenceRole::SupportsProgress,
        "deadline_near" | "success_condition_unobserved" => {
            crate::EvidenceRole::SupportsDeadlineRisk
        }
        _ => crate::EvidenceRole::Uncertain,
    };
    let mut summaries: BTreeMap<DataCategory, (OffsetDateTime, OffsetDateTime, u16)> =
        BTreeMap::new();
    for item in context {
        summaries
            .entry(item.category)
            .and_modify(|(from, until, confidence)| {
                *from = (*from).min(item.observed_at);
                *until = (*until).max(item.observed_at);
                *confidence = (*confidence).min(item.confidence_basis_points);
            })
            .or_insert((
                item.observed_at,
                item.observed_at,
                item.confidence_basis_points,
            ));
    }
    summaries
        .into_iter()
        .map(
            |(category, (observed_from, observed_until, confidence_basis_points))| {
                crate::EvidenceSummary {
                    category,
                    observed_from,
                    observed_until,
                    confidence_basis_points,
                    role,
                }
            },
        )
        .collect()
}

fn find_route(
    repository: &dyn DurableRepository,
    owner: ActorId,
    id: ModelRouteApprovalId,
) -> Result<ModelRouteApproval, SecondMindError> {
    repository
        .load_model_routes(owner)?
        .into_iter()
        .find(|route| route.id == id)
        .ok_or(SecondMindError {
            code: SecondMindErrorCode::NotFound,
            summary: "The model route approval was not found.",
            retryable: false,
            current_revision: None,
        })
}

fn find_resource(
    repository: &dyn DurableRepository,
    owner: ActorId,
    id: ResourceId,
) -> Result<ResourceBinding, SecondMindError> {
    repository
        .load_resources(owner)?
        .into_iter()
        .find(|resource| resource.id == id)
        .ok_or(SecondMindError {
            code: SecondMindErrorCode::NotFound,
            summary: "The selected resource was not found.",
            retryable: false,
            current_revision: None,
        })
}

fn find_grant(
    repository: &dyn DurableRepository,
    owner: ActorId,
    id: PermissionGrantId,
) -> Result<PermissionGrant, SecondMindError> {
    repository
        .load_grants(owner)?
        .into_iter()
        .find(|grant| grant.id == id)
        .ok_or(SecondMindError {
            code: SecondMindErrorCode::NotFound,
            summary: "The permission grant was not found.",
            retryable: false,
            current_revision: None,
        })
}

fn find_session(
    repository: &dyn DurableRepository,
    id: FocusSessionId,
) -> Result<FocusSession, SecondMindError> {
    repository.find_focus_session(id)?.ok_or(SecondMindError {
        code: SecondMindErrorCode::NotFound,
        summary: "The focus session was not found.",
        retryable: false,
        current_revision: None,
    })
}

fn find_owned_session(
    repository: &dyn DurableRepository,
    owner: ActorId,
    id: FocusSessionId,
) -> Result<FocusSession, SecondMindError> {
    let session = find_session(repository, id)?;
    if session.owner != owner {
        return Err(SecondMindError {
            code: SecondMindErrorCode::NotFound,
            summary: "The focus session was not found.",
            retryable: false,
            current_revision: None,
        });
    }
    Ok(session)
}

fn resolve_grants(
    repository: &dyn DurableRepository,
    owner: ActorId,
    session_id: FocusSessionId,
    ids: &BTreeSet<PermissionGrantId>,
    now: OffsetDateTime,
) -> Result<Vec<PermissionGrant>, SecondMindError> {
    let all = repository.load_grants(owner)?;
    let mut grants = Vec::new();
    for id in ids {
        let grant = all
            .iter()
            .find(|grant| grant.id == *id)
            .cloned()
            .ok_or_else(|| SecondMindError::permission("A referenced permission is missing."))?;
        if grant.focus_session_id != Some(session_id) || !grant.is_current_at(now) {
            return Err(SecondMindError::permission(
                "A referenced permission is not current for this session.",
            ));
        }
        grants.push(grant);
    }
    Ok(grants)
}

fn resolve_grants_for_start(
    repository: &dyn DurableRepository,
    owner: ActorId,
    goal_id: GoalId,
    session_id: FocusSessionId,
    ids: &BTreeSet<PermissionGrantId>,
    now: OffsetDateTime,
) -> Result<Vec<PermissionGrant>, SecondMindError> {
    let all = repository.load_grants(owner)?;
    let mut grants = Vec::new();
    for id in ids {
        let grant = all
            .iter()
            .find(|grant| grant.id == *id)
            .cloned()
            .ok_or_else(|| SecondMindError::permission("A referenced permission is missing."))?;
        if grant.goal_id != goal_id
            || grant
                .focus_session_id
                .is_some_and(|bound| bound != session_id)
            || !grant.is_current_at(now)
        {
            return Err(SecondMindError::permission(
                "A referenced permission is not current for this goal and session.",
            ));
        }
        grants.push(grant);
    }
    Ok(grants)
}

fn category_for_scope(scope: PermissionScope) -> DataCategory {
    match scope {
        PermissionScope::ObserveDesktopPresence
        | PermissionScope::ObserveDesktopForegroundApplication => DataCategory::EvidenceAggregates,
        PermissionScope::ObserveDesktopWindowMetadata => DataCategory::WindowMetadata,
        PermissionScope::ObserveBrowserLocation => DataCategory::BrowserLocation,
        PermissionScope::ObserveContentVisibleText => DataCategory::VisibleText,
        PermissionScope::ObserveContentSelectedDocument => DataCategory::SelectedDocument,
        PermissionScope::ObserveScreenPixels => DataCategory::ScreenPixels,
        PermissionScope::ObserveWorkspaceActivity => DataCategory::WorkspaceActivity,
        PermissionScope::ReasonFocusContext => DataCategory::Goal,
        PermissionScope::InterveneDesktopNotification => DataCategory::DeliveryConstraints,
    }
}

fn resource_statuses(
    repository: &dyn DurableRepository,
    owner: ActorId,
    grants: &[PermissionGrant],
) -> Result<Vec<NativeResourceStatus>, SecondMindError> {
    let resources = repository.load_resources(owner)?;
    Ok(grants
        .iter()
        .filter_map(|grant| {
            let id = grant.selected_resource_id?;
            resources
                .iter()
                .find(|resource| resource.id == id)
                .map(|resource| NativeResourceStatus {
                    grant_id: grant.id,
                    scope: grant.scope,
                    display_label: resource.display_label.clone(),
                })
        })
        .collect())
}

fn valid_status_acknowledgement(
    status: &NativeCaptureStatus,
    acknowledgement: &NativeStatusAcknowledgement,
) -> bool {
    acknowledgement.session_id == status.session_id
        && acknowledgement.revision == status.revision
        && acknowledgement.acknowledged_at >= status.published_at
        && acknowledgement.acknowledged_at <= status.heartbeat_deadline
        && acknowledgement.heartbeat_deadline >= status.heartbeat_deadline
}

fn observation_to_context(value: &NormalizedObservationValue) -> Option<SensitiveText> {
    match value {
        NormalizedObservationValue::Presence(_) => None,
        NormalizedObservationValue::ForegroundApplication(
            crate::ForegroundApplicationState::Selected { application_id },
        ) => Some(SensitiveText::new(application_id.clone())),
        NormalizedObservationValue::ForegroundApplication(
            crate::ForegroundApplicationState::OutsideSelectedScope,
        ) => None,
        NormalizedObservationValue::BrowserLocation { origin, path, .. } => {
            let mut value = origin.as_ref()?.expose().to_owned();
            if let Some(path) = path {
                value.push_str(path.expose());
            }
            Some(SensitiveText::new(value))
        }
        NormalizedObservationValue::WorkspaceActivity { activity } => {
            Some(SensitiveText::new(match activity {
                crate::WorkspaceActivityKind::Created => "created",
                crate::WorkspaceActivityKind::Modified => "modified",
                crate::WorkspaceActivityKind::Renamed => "renamed",
                crate::WorkspaceActivityKind::Deleted => "deleted",
            }))
        }
        _ => value.bounded_text().cloned(),
    }
}

const fn observation_start_tier(scope: PermissionScope) -> u8 {
    match scope {
        PermissionScope::ObserveBrowserLocation
        | PermissionScope::ObserveContentSelectedDocument
        | PermissionScope::ObserveContentVisibleText
        | PermissionScope::ObserveDesktopWindowMetadata => 0,
        PermissionScope::ObserveScreenPixels => 2,
        _ => 1,
    }
}

fn observation_limits(config: &SecondMindConfig, scope: PermissionScope) -> ObservationLimits {
    let minimum_interval = match scope {
        PermissionScope::ObserveDesktopPresence
        | PermissionScope::ObserveDesktopForegroundApplication => Duration::from_secs(1),
        PermissionScope::ObserveScreenPixels => Duration::from_secs(10),
        _ => Duration::from_secs(5),
    };
    let maximum_payload_bytes = if scope == PermissionScope::ObserveBrowserLocation {
        2 * 1024
    } else {
        config.maximum_observation_bytes
    };
    ObservationLimits {
        maximum_payload_bytes,
        minimum_interval,
        heartbeat_interval: Duration::from_secs(10),
        stale_after: config.source_freshness,
    }
}

fn validate_source_status(
    grant: &PermissionGrant,
    status: &ObservationSourceStatus,
) -> Result<(), SecondMindError> {
    if status.source_id.trim().is_empty()
        || status.grant_id != grant.id
        || status.scope != grant.scope
        || status.resource_id != grant.selected_resource_id
    {
        return Err(SecondMindError::permission(
            "The observation source status is outside its grant.",
        ));
    }
    Ok(())
}

async fn stop_started(
    observation: &dyn ObservationPort,
    session_id: FocusSessionId,
    grants: &[PermissionGrantId],
) {
    for grant_id in grants {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            observation.stop(session_id, *grant_id),
        )
        .await;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableObservationPort;

impl ObservationPort for UnavailableObservationPort {
    fn availability(&self, _scope: PermissionScope) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "No observation adapter is configured.",
        }
    }

    fn start<'a>(
        &'a self,
        _request: &'a ObservationStartRequest,
        _cancellation: CancellationToken,
    ) -> crate::PortFuture<'a, Result<ObservationSubscription, crate::ObservationPortError>> {
        Box::pin(async {
            Err(crate::ObservationPortError {
                kind: crate::ObservationPortErrorKind::Unavailable,
                summary: "No observation adapter is configured.",
            })
        })
    }

    fn stop<'a>(
        &'a self,
        _session_id: FocusSessionId,
        _grant_id: PermissionGrantId,
    ) -> crate::PortFuture<'a, Result<(), crate::ObservationPortError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableModelGateway;

impl ModelGateway for UnavailableModelGateway {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Unavailable {
            reason: "No model route adapter is configured.",
        }
    }

    fn reason<'a>(
        &'a self,
        _request: &'a ModelReasoningRequest,
        _cancellation: CancellationToken,
    ) -> crate::PortFuture<'a, Result<ModelReasoningOutput, crate::ModelGatewayError>> {
        Box::pin(async {
            Err(crate::ModelGatewayError {
                kind: ModelGatewayErrorKind::Unavailable,
                summary: "No model route adapter is configured.",
                retryable: true,
            })
        })
    }
}

impl Default for SecondMindRuntime {
    fn default() -> Self {
        Self::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(crate::MemoryRepository::default()),
                clock: Arc::new(SystemClock::default()),
                observation: Arc::new(UnavailableObservationPort),
                model: Arc::new(UnavailableModelGateway),
                notification: Arc::new(crate::UnavailableNotificationPort),
                native_status: Arc::new(crate::UnavailableNativeStatusPort),
                emergency_control: Arc::new(crate::UnavailableEmergencyControlPort),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .expect("default second-mind configuration is valid")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use time::macros::datetime;

    use super::*;
    use crate::{
        EmergencyControlPort, IdempotencyKey, InterventionTone, ManualClock, MemoryRepository,
        ModelHandlingProfile, ModelPlacement, ObservationPortError, ObservationSourceStatus,
        PlatformPortAvailability, ResourceId, SourceHealth, UnavailableEmergencyControlPort,
        UnavailableNativeStatusPort, UnavailableNotificationPort,
    };

    fn idempotency(seed: u8) -> IdempotencyContext {
        IdempotencyContext {
            key: IdempotencyKey::new_v7(),
            request_digest: [seed; 32],
        }
    }

    #[test]
    fn observation_start_order_is_stable_and_places_structured_sources_before_pixels() {
        let mut scopes = vec![
            PermissionScope::ObserveScreenPixels,
            PermissionScope::ObserveDesktopPresence,
            PermissionScope::ObserveContentSelectedDocument,
            PermissionScope::ObserveWorkspaceActivity,
            PermissionScope::ObserveBrowserLocation,
            PermissionScope::ObserveContentVisibleText,
            PermissionScope::ObserveDesktopWindowMetadata,
            PermissionScope::ObserveDesktopForegroundApplication,
        ];
        scopes.sort_by_key(|scope| observation_start_tier(*scope));
        assert_eq!(
            scopes,
            vec![
                PermissionScope::ObserveContentSelectedDocument,
                PermissionScope::ObserveBrowserLocation,
                PermissionScope::ObserveContentVisibleText,
                PermissionScope::ObserveDesktopWindowMetadata,
                PermissionScope::ObserveDesktopPresence,
                PermissionScope::ObserveWorkspaceActivity,
                PermissionScope::ObserveDesktopForegroundApplication,
                PermissionScope::ObserveScreenPixels,
            ]
        );
    }

    #[test]
    fn screen_pixel_grant_cannot_claim_daemon_restart_continuity() {
        let now = datetime!(2026-08-20 12:00 UTC);
        let command = GrantPermission {
            idempotency: idempotency(1),
            owner: ActorId::new_v7(),
            goal_id: GoalId::new_v7(),
            client_id: ClientId::new_v7(),
            device_id: crate::DeviceId::new_v7(),
            scope: PermissionScope::ObserveScreenPixels,
            selected_resource_id: Some(ResourceId::new_v7()),
            purpose: "Synthetic bounded pixel fixture".to_owned(),
            client_disconnect_allowed: true,
            daemon_restart_allowed: true,
            effective_at: now,
            expires_at: now + time::Duration::minutes(5),
            consent_copy_version: "phase2-consent-v1".to_owned(),
        };

        let error = validate_grant_input(&command, now).unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "Screen-pixel permission cannot continue after a daemon restart; select the source again."
        );

        let mut process_lifetime_only = command;
        process_lifetime_only.daemon_restart_allowed = false;
        assert!(validate_grant_input(&process_lifetime_only, now).is_ok());

        process_lifetime_only.expires_at =
            process_lifetime_only.effective_at + time::Duration::hours(8);
        assert!(validate_grant_input(&process_lifetime_only, now).is_ok());
        process_lifetime_only.expires_at += time::Duration::nanoseconds(1);
        let error = validate_grant_input(&process_lifetime_only, now).unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "Permission effective and expiry times are invalid or exceed the eight-hour maximum."
        );
    }

    #[test]
    fn grant_permission_rejects_a_resource_kind_that_does_not_match_the_scope() {
        assert!(resource_kind_matches_scope(
            PermissionScope::ObserveContentVisibleText,
            ResourceKind::Window
        ));
        assert!(resource_kind_matches_scope(
            PermissionScope::ObserveContentVisibleText,
            ResourceKind::BrowserSurface
        ));
        let fixture = fixture(Vec::new(), true);
        let now = fixture.clock.now_utc();
        let goal = fixture
            .runtime
            .create_goal(
                ClientAssurance::PrivateCapabilityBound,
                CreateGoal {
                    actor: fixture.owner,
                    idempotency_key: IdempotencyKey::new_v7(),
                    title: "Synthetic resource authority".to_owned(),
                    success_statement: "Mismatched resource kinds are rejected.".to_owned(),
                    deadline: None,
                },
            )
            .unwrap();
        fixture
            .runtime
            .save_resource_binding(
                ClientAssurance::PrivateCapabilityBound,
                ResourceBinding {
                    id: fixture.resource,
                    owner: fixture.owner,
                    kind: ResourceKind::Workspace,
                    opaque_reference: "synthetic-workspace-token".to_owned(),
                    display_label: "Synthetic workspace".to_owned(),
                    revision: 1,
                    created_at: now,
                },
            )
            .unwrap();
        let command = GrantPermission {
            idempotency: idempotency(2),
            owner: fixture.owner,
            goal_id: goal.id,
            client_id: fixture.client,
            device_id: fixture.device,
            scope: PermissionScope::ObserveContentVisibleText,
            selected_resource_id: Some(fixture.resource),
            purpose: "Synthetic exact-resource fixture".to_owned(),
            client_disconnect_allowed: true,
            daemon_restart_allowed: false,
            effective_at: now,
            expires_at: now + time::Duration::minutes(5),
            consent_copy_version: "phase2-consent-v1".to_owned(),
        };

        let error = fixture
            .runtime
            .grant_permission(ClientAssurance::PrivateCapabilityBound, command)
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "The selected resource kind does not match the permission scope."
        );
        assert!(
            fixture
                .repository
                .load_grants(fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn browser_surface_grant_cannot_claim_daemon_restart_continuity() {
        assert!(!resource_kind_allows_restart(ResourceKind::BrowserSurface));
        assert!(!resource_kind_allows_restart(ResourceKind::ScreenRegion));
        assert!(resource_kind_allows_restart(ResourceKind::Window));
        let fixture = fixture(Vec::new(), true);
        let now = fixture.clock.now_utc();
        let goal = fixture
            .runtime
            .create_goal(
                ClientAssurance::PrivateCapabilityBound,
                CreateGoal {
                    actor: fixture.owner,
                    idempotency_key: IdempotencyKey::new_v7(),
                    title: "Synthetic browser continuity".to_owned(),
                    success_statement: "Connection-bound authority is explicit.".to_owned(),
                    deadline: None,
                },
            )
            .unwrap();
        fixture
            .runtime
            .save_resource_binding(
                ClientAssurance::PrivateCapabilityBound,
                ResourceBinding {
                    id: fixture.resource,
                    owner: fixture.owner,
                    kind: ResourceKind::BrowserSurface,
                    opaque_reference: "synthetic-browser-binding".to_owned(),
                    display_label: "Synthetic selected Edge tab".to_owned(),
                    revision: 1,
                    created_at: now,
                },
            )
            .unwrap();
        let command = GrantPermission {
            idempotency: idempotency(3),
            owner: fixture.owner,
            goal_id: goal.id,
            client_id: fixture.client,
            device_id: fixture.device,
            scope: PermissionScope::ObserveBrowserLocation,
            selected_resource_id: Some(fixture.resource),
            purpose: "Synthetic connection-bound browser fixture".to_owned(),
            client_disconnect_allowed: true,
            daemon_restart_allowed: true,
            effective_at: now,
            expires_at: now + time::Duration::minutes(5),
            consent_copy_version: "phase2-consent-v1".to_owned(),
        };

        let error = fixture
            .runtime
            .grant_permission(ClientAssurance::PrivateCapabilityBound, command)
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "Browser permission cannot continue after a daemon restart; select the tab again."
        );
        assert!(
            fixture
                .repository
                .load_grants(fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn grant_permission_cannot_outlive_its_goal_deadline() {
        let fixture = fixture(Vec::new(), true);
        let now = fixture.clock.now_utc();
        let deadline = now + time::Duration::minutes(30);
        let goal = fixture
            .runtime
            .create_goal(
                ClientAssurance::PrivateCapabilityBound,
                CreateGoal {
                    actor: fixture.owner,
                    idempotency_key: IdempotencyKey::new_v7(),
                    title: "Synthetic bounded permission".to_owned(),
                    success_statement: "The permission ends with its goal.".to_owned(),
                    deadline: Some(deadline),
                },
            )
            .unwrap();
        let mut command = GrantPermission {
            idempotency: idempotency(92),
            owner: fixture.owner,
            goal_id: goal.id,
            client_id: fixture.client,
            device_id: fixture.device,
            scope: PermissionScope::ObserveDesktopPresence,
            selected_resource_id: None,
            purpose: "Synthetic goal-bounded permission".to_owned(),
            client_disconnect_allowed: true,
            daemon_restart_allowed: false,
            effective_at: now,
            expires_at: deadline + time::Duration::nanoseconds(1),
            consent_copy_version: "phase2-consent-v1".to_owned(),
        };

        let error = fixture
            .runtime
            .grant_permission(ClientAssurance::PrivateCapabilityBound, command.clone())
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "Permission expiry cannot extend beyond the goal deadline."
        );

        command.idempotency = idempotency(93);
        command.expires_at = deadline;
        assert!(
            fixture
                .runtime
                .grant_permission(ClientAssurance::PrivateCapabilityBound, command)
                .is_ok()
        );
    }

    #[derive(Default)]
    struct AvailableObservation {
        repository: Option<MemoryRepository>,
        cleanup_states: Mutex<Vec<FocusSessionState>>,
        corrupt_next_initial_status: AtomicBool,
        bump_session_revision_on_next_start: AtomicBool,
        hang_next_start: AtomicBool,
        start_calls: AtomicUsize,
    }

    impl AvailableObservation {
        fn tracking(repository: MemoryRepository) -> Self {
            Self {
                repository: Some(repository),
                cleanup_states: Mutex::new(Vec::new()),
                corrupt_next_initial_status: AtomicBool::new(false),
                bump_session_revision_on_next_start: AtomicBool::new(false),
                hang_next_start: AtomicBool::new(false),
                start_calls: AtomicUsize::new(0),
            }
        }

        fn corrupt_next_initial_status(&self) {
            self.corrupt_next_initial_status
                .store(true, Ordering::SeqCst);
        }

        fn bump_session_revision_on_next_start(&self) {
            self.bump_session_revision_on_next_start
                .store(true, Ordering::SeqCst);
        }

        fn hang_next_start(&self) {
            self.hang_next_start.store(true, Ordering::SeqCst);
        }
    }

    impl ObservationPort for AvailableObservation {
        fn availability(&self, _scope: PermissionScope) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn start<'a>(
            &'a self,
            request: &'a ObservationStartRequest,
            cancellation: CancellationToken,
        ) -> crate::PortFuture<'a, Result<ObservationSubscription, ObservationPortError>> {
            Box::pin(async move {
                self.start_calls.fetch_add(1, Ordering::SeqCst);
                if self.hang_next_start.swap(false, Ordering::SeqCst) {
                    cancellation.cancelled().await;
                    return Err(ObservationPortError {
                        kind: crate::ObservationPortErrorKind::Cancelled,
                        summary: "Synthetic source start was cancelled.",
                    });
                }
                if self
                    .bump_session_revision_on_next_start
                    .swap(false, Ordering::SeqCst)
                    && let (Some(repository), Some(session_id)) =
                        (&self.repository, request.grant.focus_session_id)
                {
                    let mut session = repository
                        .find_focus_session(session_id)
                        .expect("synthetic repository is available")
                        .expect("synthetic focus session exists");
                    let expected = session.revision;
                    session.revision = session.revision.saturating_add(1);
                    repository
                        .save_focus_session(&session, Some(expected))
                        .expect("synthetic revision race is installed");
                }
                let (events, receiver) = tokio::sync::mpsc::channel(8);
                tokio::spawn(async move {
                    cancellation.cancelled().await;
                    drop(events);
                });
                let mut initial_status = ObservationSourceStatus {
                    source_id: format!("synthetic:{}", request.grant.id),
                    grant_id: request.grant.id,
                    scope: request.grant.scope,
                    resource_id: request.grant.selected_resource_id,
                    health: SourceHealth::Healthy,
                    detail: "Synthetic source is healthy.",
                    observed_at: request.grant.effective_at,
                };
                if self
                    .corrupt_next_initial_status
                    .swap(false, Ordering::SeqCst)
                {
                    initial_status.grant_id = PermissionGrantId::new_v7();
                }
                Ok(ObservationSubscription {
                    initial_status,
                    events: receiver,
                })
            })
        }

        fn stop<'a>(
            &'a self,
            session_id: FocusSessionId,
            _grant_id: PermissionGrantId,
        ) -> crate::PortFuture<'a, Result<(), ObservationPortError>> {
            if let Some(repository) = &self.repository
                && let Ok(Some(session)) = repository.find_focus_session(session_id)
            {
                self.cleanup_states
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(session.state);
            }
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct ScriptedCleanupSecretStore {
        failures_remaining: AtomicUsize,
        delete_calls: AtomicUsize,
    }

    impl ScriptedCleanupSecretStore {
        fn fail_next_delete(&self) {
            self.failures_remaining.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl SecretStore for ScriptedCleanupSecretStore {
        fn is_available(&self) -> bool {
            true
        }

        fn read(
            &self,
            _key: &crate::SecretKey,
        ) -> Result<Option<crate::SecretValue>, crate::SecretStoreError> {
            Ok(None)
        }

        fn delete(&self, _key: &crate::SecretKey) -> Result<bool, crate::SecretStoreError> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            if self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                Err(crate::SecretStoreError {
                    kind: crate::SecretStoreErrorKind::Unavailable,
                    summary: "Synthetic adapter diagnostic must not cross the cleanup boundary.",
                })
            } else {
                Ok(false)
            }
        }
    }

    #[derive(Default)]
    struct ScriptedResourceCleanup {
        failures_remaining: AtomicUsize,
        release_calls: AtomicUsize,
    }

    impl ScriptedResourceCleanup {
        fn fail_next_release(&self) {
            self.failures_remaining.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ResourceSelectionPort for ScriptedResourceCleanup {
        fn availability(&self) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn release<'a>(
            &'a self,
            _binding: NativeResourceBinding,
            _cancellation: CancellationToken,
        ) -> crate::PortFuture<'a, Result<(), crate::ResourceSelectionError>> {
            self.release_calls.fetch_add(1, Ordering::SeqCst);
            let fail = self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            Box::pin(async move {
                if fail {
                    Err(crate::ResourceSelectionError {
                        kind: ResourceSelectionErrorKind::Unavailable,
                        summary: "Synthetic native cleanup exposed private diagnostic text.",
                        retryable: true,
                    })
                } else {
                    Ok(())
                }
            })
        }
    }

    struct ScriptedModel {
        outputs: Mutex<VecDeque<ModelReasoningOutput>>,
        calls: AtomicUsize,
        hang: AtomicBool,
        cancellation_observed: Arc<AtomicBool>,
    }

    impl ScriptedModel {
        fn new(outputs: impl IntoIterator<Item = ModelReasoningOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: AtomicUsize::new(0),
                hang: AtomicBool::new(false),
                cancellation_observed: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl ModelGateway for ScriptedModel {
        fn availability(&self) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn reason<'a>(
            &'a self,
            request: &'a ModelReasoningRequest,
            cancellation: CancellationToken,
        ) -> crate::PortFuture<'a, Result<ModelReasoningOutput, crate::ModelGatewayError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let hang = self.hang.load(Ordering::SeqCst);
            if hang {
                let watcher_cancellation = cancellation.clone();
                let cancellation_observed = self.cancellation_observed.clone();
                tokio::spawn(async move {
                    watcher_cancellation.cancelled().await;
                    cancellation_observed.store(true, Ordering::SeqCst);
                });
            }
            Box::pin(async move {
                if hang {
                    cancellation.cancelled().await;
                    return Err(crate::ModelGatewayError {
                        kind: ModelGatewayErrorKind::Cancelled,
                        summary: "Synthetic model cancellation was observed.",
                        retryable: false,
                    });
                }
                assert!(request.permitted_categories.contains(&DataCategory::Goal));
                assert!(
                    request
                        .permitted_categories
                        .contains(&DataCategory::WorkspaceActivity)
                );
                self.outputs
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or(crate::ModelGatewayError {
                        kind: ModelGatewayErrorKind::Unavailable,
                        summary: "Synthetic model script is empty.",
                        retryable: false,
                    })
            })
        }
    }

    struct TestNotification {
        available: AtomicBool,
        hang: AtomicBool,
        calls: AtomicUsize,
        cancellation_observed: Arc<AtomicBool>,
        audit_seen_before_delivery: AtomicBool,
        attempt_marker_seen_before_delivery: AtomicBool,
        repository: MemoryRepository,
        owner: ActorId,
        revoke_on_delivery: Mutex<Option<PermissionGrant>>,
        acknowledgement: Mutex<ChannelAcknowledgement>,
    }

    impl NotificationPort for TestNotification {
        fn availability(&self) -> PlatformPortAvailability {
            if self.available.load(Ordering::SeqCst) {
                PlatformPortAvailability::Available
            } else {
                PlatformPortAvailability::Unavailable {
                    reason: "Synthetic channel is offline.",
                }
            }
        }

        fn deliver<'a>(
            &'a self,
            delivery: &'a NotificationDelivery,
            cancellation: CancellationToken,
        ) -> crate::PortFuture<'a, Result<ChannelAcknowledgement, crate::NotificationPortError>>
        {
            let hang = self.hang.load(Ordering::SeqCst);
            if hang {
                let watcher_cancellation = cancellation.clone();
                let cancellation_observed = self.cancellation_observed.clone();
                tokio::spawn(async move {
                    watcher_cancellation.cancelled().await;
                    cancellation_observed.store(true, Ordering::SeqCst);
                });
            }
            let acknowledgement = *self
                .acknowledgement
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let persisted_intervention = self
                .repository
                .load_interventions(self.owner)
                .unwrap()
                .into_iter()
                .find(|intervention| intervention.id == delivery.intervention_id);
            let persisted_decision = self
                .repository
                .find_policy_decision(delivery.policy_decision_id)
                .unwrap();
            let audit_exists = persisted_intervention
                .as_ref()
                .zip(persisted_decision.as_ref())
                .is_some_and(|(intervention, decision)| {
                    intervention.policy_decision_id == decision.id
                        && intervention.candidate_id == decision.candidate_id
                        && decision.outcome == PolicyOutcome::Allow
                        && decision.policy_trace.is_complete()
                        && self
                            .repository
                            .load_audit(self.owner, OffsetDateTime::UNIX_EPOCH, 100)
                            .unwrap()
                            .iter()
                            .any(|record| {
                                record.kind == AuditKind::InterventionDecision
                                    && record.subject_id == decision.candidate_id.as_uuid()
                                    && record.reason_codes == decision.reason_codes
                                    && record.policy_trace.as_ref() == Some(&decision.policy_trace)
                            })
                });
            self.audit_seen_before_delivery
                .store(audit_exists, Ordering::SeqCst);
            let attempt_audit_exists = self
                .repository
                .load_audit(self.owner, OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .iter()
                .any(|record| {
                    record.kind == AuditKind::InterventionDelivery
                        && record.subject_id == delivery.intervention_id.as_uuid()
                        && persisted_decision.as_ref().is_some_and(|decision| {
                            record.policy_trace.as_ref() == Some(&decision.policy_trace)
                        })
                        && record
                            .reason_codes
                            .iter()
                            .any(|reason| reason == "delivery_attempt_started")
                });
            let delivering_is_durable = self
                .repository
                .load_interventions(self.owner)
                .unwrap()
                .iter()
                .any(|intervention| {
                    intervention.id == delivery.intervention_id
                        && intervention.policy_decision_id == delivery.policy_decision_id
                        && intervention.state == InterventionState::Delivering
                });
            self.attempt_marker_seen_before_delivery.store(
                attempt_audit_exists && delivering_is_durable,
                Ordering::SeqCst,
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(mut grant) = self
                .revoke_on_delivery
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let expected = grant.revision;
                grant.revision = grant.revision.saturating_add(1);
                grant.state = GrantState::Revoked;
                grant.revoked_at = Some(grant.effective_at);
                grant.revocation_reason = Some("synthetic_delivery_race".to_owned());
                self.repository.save_grant(&grant, Some(expected)).unwrap();
            }
            Box::pin(async move {
                if hang {
                    cancellation.cancelled().await;
                    return Err(crate::NotificationPortError {
                        summary: "Synthetic delivery cancellation was observed.",
                        retryable: false,
                    });
                }
                if cancellation.is_cancelled() {
                    Err(crate::NotificationPortError {
                        summary: "Synthetic delivery was cancelled.",
                        retryable: false,
                    })
                } else {
                    Ok(acknowledgement)
                }
            })
        }
    }

    #[derive(Default)]
    struct TestStatus {
        publishes: AtomicUsize,
        fail_publish_on_call: AtomicUsize,
        clears: Mutex<Vec<(FocusSessionId, u64)>>,
        heartbeats: Mutex<VecDeque<Result<NativeStatusHeartbeat, crate::NativeStatusError>>>,
        heartbeat_notify: tokio::sync::Notify,
    }

    impl TestStatus {
        fn emit_heartbeat(
            &self,
            heartbeat: Result<NativeStatusHeartbeat, crate::NativeStatusError>,
        ) {
            self.heartbeats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(heartbeat);
            self.heartbeat_notify.notify_one();
        }

        fn fail_publish_on_call(&self, call: usize) {
            self.fail_publish_on_call.store(call, Ordering::SeqCst);
        }
    }

    impl NativeStatusPort for TestStatus {
        fn availability(&self) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn publish<'a>(
            &'a self,
            status: &'a NativeCaptureStatus,
        ) -> crate::PortFuture<'a, Result<NativeStatusAcknowledgement, crate::NativeStatusError>>
        {
            let call = self.publishes.fetch_add(1, Ordering::SeqCst) + 1;
            let fail = self.fail_publish_on_call.load(Ordering::SeqCst) == call;
            Box::pin(async move {
                assert!(
                    status
                        .active_scopes
                        .contains(&PermissionScope::ObserveDesktopPresence)
                );
                if fail {
                    return Err(crate::NativeStatusError {
                        summary: "Synthetic native status acknowledgement was lost.",
                        retryable: true,
                    });
                }
                Ok(NativeStatusAcknowledgement {
                    session_id: status.session_id,
                    revision: status.revision,
                    acknowledged_at: status.published_at,
                    heartbeat_deadline: status.heartbeat_deadline,
                })
            })
        }

        fn clear<'a>(
            &'a self,
            session_id: FocusSessionId,
            revision: u64,
        ) -> crate::PortFuture<'a, Result<NativeStatusAcknowledgement, crate::NativeStatusError>>
        {
            self.clears
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((session_id, revision));
            Box::pin(async move {
                let now = OffsetDateTime::now_utc();
                Ok(NativeStatusAcknowledgement {
                    session_id,
                    revision,
                    acknowledged_at: now,
                    heartbeat_deadline: now + time::Duration::seconds(10),
                })
            })
        }

        fn next_heartbeat<'a>(
            &'a self,
            _session_id: FocusSessionId,
        ) -> crate::PortFuture<'a, Result<NativeStatusHeartbeat, crate::NativeStatusError>>
        {
            Box::pin(async move {
                loop {
                    let notified = self.heartbeat_notify.notified();
                    if let Some(heartbeat) = self
                        .heartbeats
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop_front()
                    {
                        return heartbeat;
                    }
                    notified.await;
                }
            })
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum EmergencyAckMode {
        #[default]
        Exact,
        Missing,
        WrongRevision,
    }

    #[derive(Default)]
    struct TestEmergency {
        commands: Mutex<VecDeque<Result<crate::EmergencyCommandEnvelope, &'static str>>>,
        command_notify: tokio::sync::Notify,
        acknowledgements: Mutex<Vec<crate::EmergencyCommandAcknowledgement>>,
        acknowledgement_notify: tokio::sync::Notify,
        acknowledgement_mode: Mutex<EmergencyAckMode>,
    }

    impl TestEmergency {
        fn push(&self, envelope: crate::EmergencyCommandEnvelope) {
            self.commands
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(Ok(envelope));
            self.command_notify.notify_one();
        }

        fn set_acknowledgement_mode(&self, mode: EmergencyAckMode) {
            *self
                .acknowledgement_mode
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = mode;
        }
    }

    impl EmergencyControlPort for TestEmergency {
        fn availability(&self) -> PlatformPortAvailability {
            PlatformPortAvailability::Available
        }

        fn next_command<'a>(
            &'a self,
        ) -> crate::PortFuture<'a, Result<crate::EmergencyCommandEnvelope, &'static str>> {
            Box::pin(async move {
                loop {
                    let notified = self.command_notify.notified();
                    if let Some(command) = self
                        .commands
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop_front()
                    {
                        return command;
                    }
                    notified.await;
                }
            })
        }

        fn acknowledge<'a>(
            &'a self,
            acknowledgement: crate::EmergencyCommandAcknowledgement,
        ) -> crate::PortFuture<'a, Result<crate::EmergencyCommandAcknowledgement, &'static str>>
        {
            self.acknowledgements
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(acknowledgement.clone());
            self.acknowledgement_notify.notify_waiters();
            let mode = *self
                .acknowledgement_mode
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Box::pin(async move {
                match mode {
                    EmergencyAckMode::Exact => Ok(acknowledgement),
                    EmergencyAckMode::Missing => Err("Synthetic acknowledgement was lost."),
                    EmergencyAckMode::WrongRevision => {
                        let mut wrong = acknowledgement;
                        wrong.revision = wrong.revision.saturating_add(1);
                        Ok(wrong)
                    }
                }
            })
        }
    }

    struct Fixture {
        runtime: SecondMindRuntime,
        repository: MemoryRepository,
        clock: Arc<ManualClock>,
        model: Arc<ScriptedModel>,
        notification: Arc<TestNotification>,
        status: Arc<TestStatus>,
        observation: Arc<AvailableObservation>,
        emergency: Arc<TestEmergency>,
        owner: ActorId,
        client: ClientId,
        device: crate::DeviceId,
        session: FocusSessionId,
        resource: ResourceId,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct DurableIdentityPreferencesSnapshot {
        identity_revision: u64,
        preferences_revision: u64,
        canonical_json: Vec<u8>,
    }

    fn identity_preferences_snapshot(
        repository: &MemoryRepository,
        owner: ActorId,
    ) -> DurableIdentityPreferencesSnapshot {
        let identity = repository.load_identity(owner).unwrap().unwrap();
        let preferences = repository.load_preferences(owner).unwrap().unwrap();
        DurableIdentityPreferencesSnapshot {
            identity_revision: identity.revision,
            preferences_revision: preferences.revision,
            canonical_json: serde_json::to_vec(&(identity, preferences)).unwrap(),
        }
    }

    fn candidate() -> ModelReasoningOutput {
        ModelReasoningOutput::Candidate {
            candidate_id: CandidateId::new_v7(),
            user_visible_text:
                "You have fresh synthetic progress; consider validating the release ledger now."
                    .to_owned(),
            reason_code: "recent_relevant_progress".to_owned(),
            evidence_summary: "Fresh selected-workspace activity aligns with the active goal."
                .to_owned(),
            urgency: Urgency::Normal,
            confidence_basis_points: 8_000,
        }
    }

    const NEAR_DEADLINE_QUALIFIED_TEXT: &str = "The deadline is near, but I have not observed a success-confirmation signal; consider checking the synthetic release ledger.";
    const NEAR_DEADLINE_EVIDENCE_SUMMARY: &str = "Fresh selected-workspace activity exists, but it does not confirm the goal's success condition.";

    fn near_deadline_uncertainty_candidate(candidate_id: CandidateId) -> ModelReasoningOutput {
        ModelReasoningOutput::Candidate {
            candidate_id,
            user_visible_text: NEAR_DEADLINE_QUALIFIED_TEXT.to_owned(),
            reason_code: "success_condition_unobserved".to_owned(),
            evidence_summary: NEAR_DEADLINE_EVIDENCE_SUMMARY.to_owned(),
            urgency: Urgency::Normal,
            confidence_basis_points: 8_000,
        }
    }

    fn fixture(model_outputs: Vec<ModelReasoningOutput>, notification_available: bool) -> Fixture {
        fixture_with_config(
            model_outputs,
            notification_available,
            SecondMindConfig::default(),
        )
    }

    fn fixture_with_config(
        model_outputs: Vec<ModelReasoningOutput>,
        notification_available: bool,
        config: SecondMindConfig,
    ) -> Fixture {
        let owner = ActorId::new_v7();
        let repository = MemoryRepository::default();
        let clock = Arc::new(ManualClock::new(datetime!(2026-08-19 10:00 UTC)));
        let model = Arc::new(ScriptedModel::new(model_outputs));
        let notification = Arc::new(TestNotification {
            available: AtomicBool::new(notification_available),
            hang: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            cancellation_observed: Arc::new(AtomicBool::new(false)),
            audit_seen_before_delivery: AtomicBool::new(false),
            attempt_marker_seen_before_delivery: AtomicBool::new(false),
            repository: repository.clone(),
            owner,
            revoke_on_delivery: Mutex::new(None),
            acknowledgement: Mutex::new(ChannelAcknowledgement::AcceptedByChannel),
        });
        let status = Arc::new(TestStatus::default());
        let observation = Arc::new(AvailableObservation::tracking(repository.clone()));
        let emergency = Arc::new(TestEmergency::default());
        let runtime = SecondMindRuntime::new(
            config,
            SecondMindPorts {
                repository: Arc::new(repository.clone()),
                clock: clock.clone(),
                observation: observation.clone(),
                model: model.clone(),
                notification: notification.clone(),
                native_status: status.clone(),
                emergency_control: emergency.clone(),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        Fixture {
            runtime,
            repository,
            clock,
            model,
            notification,
            status,
            observation,
            emergency,
            owner,
            client: ClientId::new_v7(),
            device: crate::DeviceId::new_v7(),
            session: FocusSessionId::new_v7(),
            resource: ResourceId::new_v7(),
        }
    }

    fn cleanup_runtime(
        config: SecondMindConfig,
        repository: &MemoryRepository,
        clock: Arc<ManualClock>,
        secret_store: Arc<ScriptedCleanupSecretStore>,
        resource_selection: Arc<ScriptedResourceCleanup>,
    ) -> SecondMindRuntime {
        SecondMindRuntime::new(
            config,
            SecondMindPorts {
                repository: Arc::new(repository.clone()),
                clock,
                observation: Arc::new(UnavailableObservationPort),
                model: Arc::new(UnavailableModelGateway),
                notification: Arc::new(crate::UnavailableNotificationPort),
                native_status: Arc::new(crate::UnavailableNativeStatusPort),
                emergency_control: Arc::new(crate::UnavailableEmergencyControlPort),
                secret_store,
                resource_selection,
            },
        )
        .unwrap()
    }

    fn cleanup_route(owner: ActorId, now: OffsetDateTime) -> ModelRouteApproval {
        let id = ModelRouteApprovalId::new_v7();
        ModelRouteApproval {
            id,
            revision: 1,
            owner,
            authenticated_client: ClientId::new_v7(),
            provider: "synthetic".to_owned(),
            account_profile: "cleanup-fixture".to_owned(),
            model: "deterministic-v1".to_owned(),
            secret_ref: ModelRouteApproval::approval_scoped_secret_ref(id),
            placement: ModelPlacement::Local,
            allowed_categories: BTreeSet::from([DataCategory::Goal]),
            handling: ModelHandlingProfile {
                profile_id: "synthetic-no-retention-v1".to_owned(),
                retention: crate::ProviderRetentionPolicy::None,
                training_use: crate::ProviderTrainingUse::Excluded,
                data_residency: None,
                core_persists_prompt_or_response: false,
                tools_enabled: false,
            },
            purpose: "reason.focus_context".to_owned(),
            maximum_input_tokens: 1_200,
            maximum_output_tokens: 220,
            fallback: None,
            fallback_allowed: false,
            effective_at: now,
            expires_at: Some(now + time::Duration::hours(3)),
            revoked_at: None,
            disclosure_version: "synthetic-v1".to_owned(),
        }
    }

    struct ActiveFixture {
        fixture: Fixture,
        grants: Vec<PermissionGrant>,
    }

    async fn start(fixture: Fixture) -> ActiveFixture {
        try_start(fixture).await.unwrap()
    }

    async fn try_start(fixture: Fixture) -> Result<ActiveFixture, SecondMindError> {
        let now = fixture.clock.now_utc();
        let mut preferences = fixture
            .runtime
            .user_preferences(ClientAssurance::PrivateCapabilityBound, fixture.owner)
            .unwrap();
        let expected_preferences_revision = preferences.revision;
        preferences.proactive_interventions_enabled = true;
        fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected_preferences_revision),
            )
            .unwrap();
        let goal = fixture
            .runtime
            .create_goal(
                ClientAssurance::PrivateCapabilityBound,
                CreateGoal {
                    actor: fixture.owner,
                    idempotency_key: IdempotencyKey::new_v7(),
                    title: "Validate the synthetic Phase 2 release".to_owned(),
                    success_statement: "Every synthetic trust gate is green.".to_owned(),
                    deadline: Some(now + time::Duration::minutes(20)),
                },
            )
            .unwrap();
        fixture
            .runtime
            .save_resource_binding(
                ClientAssurance::PrivateCapabilityBound,
                ResourceBinding {
                    id: fixture.resource,
                    owner: fixture.owner,
                    kind: ResourceKind::Workspace,
                    opaque_reference: "synthetic-resource-token".to_owned(),
                    display_label: "Synthetic release workspace".to_owned(),
                    revision: 1,
                    created_at: now,
                },
            )
            .unwrap();
        let route_idempotency = idempotency(1);
        let route_approval_id = ModelRouteApprovalId::new_v7();
        let route_input = ModelRouteApproval {
            id: route_approval_id,
            revision: 1,
            owner: fixture.owner,
            authenticated_client: fixture.client,
            provider: "synthetic".to_owned(),
            account_profile: "fixture".to_owned(),
            model: "deterministic-v1".to_owned(),
            secret_ref: ModelRouteApproval::approval_scoped_secret_ref(route_approval_id),
            placement: ModelPlacement::Local,
            allowed_categories: BTreeSet::from([
                DataCategory::Goal,
                DataCategory::EvidenceAggregates,
                DataCategory::WorkspaceActivity,
            ]),
            handling: ModelHandlingProfile {
                profile_id: "synthetic-no-retention-v1".to_owned(),
                retention: crate::ProviderRetentionPolicy::None,
                training_use: crate::ProviderTrainingUse::Excluded,
                data_residency: None,
                core_persists_prompt_or_response: false,
                tools_enabled: false,
            },
            purpose: "reason.focus_context".to_owned(),
            maximum_input_tokens: 1_200,
            maximum_output_tokens: 220,
            fallback: None,
            fallback_allowed: false,
            effective_at: now,
            expires_at: Some(now + time::Duration::hours(3)),
            revoked_at: None,
            disclosure_version: "synthetic-v1".to_owned(),
        };
        let route = fixture
            .runtime
            .approve_model_route(
                ClientAssurance::PrivateCapabilityBound,
                route_idempotency,
                route_input.clone(),
            )
            .unwrap();
        let mut route_retry = route_input;
        route_retry.id = ModelRouteApprovalId::new_v7();
        assert_eq!(
            fixture
                .runtime
                .approve_model_route(
                    ClientAssurance::PrivateCapabilityBound,
                    route_idempotency,
                    route_retry,
                )
                .unwrap()
                .id,
            route.id
        );
        let conflict = fixture
            .runtime
            .approve_model_route(
                ClientAssurance::PrivateCapabilityBound,
                IdempotencyContext {
                    key: route_idempotency.key,
                    request_digest: [99; 32],
                },
                route.clone(),
            )
            .unwrap_err();
        assert_eq!(conflict.code, SecondMindErrorCode::Conflict);
        assert_eq!(
            conflict.summary,
            "The idempotency key was already used for different input."
        );

        let mut grants = Vec::new();
        for (index, (scope, resource)) in [
            (PermissionScope::ObserveDesktopPresence, None),
            (
                PermissionScope::ObserveWorkspaceActivity,
                Some(fixture.resource),
            ),
            (PermissionScope::ReasonFocusContext, None),
            (PermissionScope::InterveneDesktopNotification, None),
        ]
        .into_iter()
        .enumerate()
        {
            let command = GrantPermission {
                idempotency: idempotency(u8::try_from(index + 2).unwrap()),
                owner: fixture.owner,
                goal_id: goal.id,
                client_id: fixture.client,
                device_id: fixture.device,
                scope,
                selected_resource_id: resource,
                purpose: "Synthetic deadline-aware focus fixture".to_owned(),
                client_disconnect_allowed: true,
                daemon_restart_allowed: true,
                effective_at: now,
                expires_at: goal.deadline.expect("synthetic goal has a deadline"),
                consent_copy_version: "phase2-consent-v1".to_owned(),
            };
            let grant = fixture
                .runtime
                .grant_permission(ClientAssurance::PrivateCapabilityBound, command.clone())
                .unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .grant_permission(ClientAssurance::PrivateCapabilityBound, command)
                    .unwrap()
                    .id,
                grant.id
            );
            grants.push(grant);
        }
        let start_command = StartFocusSession {
            idempotency: idempotency(10),
            owner: fixture.owner,
            session_id: fixture.session,
            goal_id: goal.id,
            expected_goal_revision: goal.revision.get(),
            selected_resource_ids: BTreeSet::from([fixture.resource]),
            grant_ids: grants.iter().map(|grant| grant.id).collect(),
            model_route_approval_id: route.id,
            client_disconnect_allowed: true,
            daemon_restart_allowed: true,
        };
        let starting = fixture
            .runtime
            .request_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                start_command.clone(),
            )
            .unwrap();
        let mut retry_start = start_command;
        retry_start.session_id = FocusSessionId::new_v7();
        assert_eq!(
            fixture
                .runtime
                .request_focus_session(ClientAssurance::PrivateCapabilityBound, retry_start)
                .unwrap()
                .id,
            starting.id
        );
        assert_eq!(starting.state, FocusSessionState::Starting);
        assert_eq!(
            starting.selected_resource_ids,
            BTreeSet::from([fixture.resource])
        );
        assert_eq!(
            fixture
                .repository
                .find_focus_session(fixture.session)
                .unwrap()
                .unwrap()
                .state,
            FocusSessionState::Starting
        );
        let active = fixture
            .runtime
            .activate_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                fixture.owner,
                fixture.session,
                starting.revision,
            )
            .await?;
        assert_eq!(active.state, FocusSessionState::Active);
        let grants = fixture.repository.load_grants(fixture.owner).unwrap();
        Ok(ActiveFixture { fixture, grants })
    }

    #[tokio::test]
    async fn invalid_initial_source_status_fails_the_session_and_stops_the_source() {
        let fixture = fixture(Vec::new(), true);
        let repository = fixture.repository.clone();
        let observation = fixture.observation.clone();
        let status = fixture.status.clone();
        let runtime = fixture.runtime.clone();
        let session_id = fixture.session;
        observation.corrupt_next_initial_status();

        let error = try_start(fixture)
            .await
            .err()
            .expect("activation must fail");

        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        let failed = repository
            .find_focus_session(session_id)
            .unwrap()
            .expect("failed focus session remains durable");
        assert_eq!(failed.state, FocusSessionState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("observation_source_status_invalid")
        );
        assert_eq!(
            observation.cleanup_states.lock().unwrap().as_slice(),
            &[FocusSessionState::Starting]
        );
        assert_eq!(status.clears.lock().unwrap().as_slice(), &[(session_id, 1)]);
        assert!(
            repository
                .load_audit(failed.owner, OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .iter()
                .any(|record| {
                    record.kind == AuditKind::FocusSessionStateChanged
                        && record.subject_id == session_id.as_uuid()
                        && record
                            .reason_codes
                            .iter()
                            .any(|reason| reason == "observation_source_status_invalid")
                })
        );
        assert!(
            !runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session_id)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hung_observation_start_is_bounded_and_clears_native_status() {
        let fixture = fixture(Vec::new(), true);
        let repository = fixture.repository.clone();
        let observation = fixture.observation.clone();
        let status = fixture.status.clone();
        let session_id = fixture.session;
        observation.hang_next_start();
        let activation = tokio::spawn(try_start(fixture));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(10)).await;
        let error = activation
            .await
            .expect("the activation task remains supervised")
            .err()
            .expect("the hung source start must fail closed");

        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        let failed = repository
            .find_focus_session(session_id)
            .unwrap()
            .expect("the failed activation remains durable");
        assert_eq!(failed.state, FocusSessionState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("observation_source_start_failed")
        );
        assert_eq!(
            observation.cleanup_states.lock().unwrap().as_slice(),
            &[FocusSessionState::Starting]
        );
        assert_eq!(status.clears.lock().unwrap().as_slice(), &[(session_id, 1)]);
    }

    #[tokio::test]
    async fn activation_revision_conflict_cleans_every_started_source_and_native_status() {
        let fixture = fixture(Vec::new(), true);
        let repository = fixture.repository.clone();
        let observation = fixture.observation.clone();
        let status = fixture.status.clone();
        let runtime = fixture.runtime.clone();
        let session_id = fixture.session;
        observation.bump_session_revision_on_next_start();

        let error = try_start(fixture)
            .await
            .err()
            .expect("the synthetic activation commit must conflict");

        assert_eq!(error.code, SecondMindErrorCode::Conflict);
        let durable = repository
            .find_focus_session(session_id)
            .unwrap()
            .expect("the starting session remains durable");
        assert_eq!(durable.state, FocusSessionState::Starting);
        assert_eq!(durable.revision, 2);
        assert_eq!(
            observation.cleanup_states.lock().unwrap().as_slice(),
            &[FocusSessionState::Starting, FocusSessionState::Starting]
        );
        assert_eq!(status.clears.lock().unwrap().as_slice(), &[(session_id, 1)]);
        assert!(
            !runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session_id)
        );
    }

    #[tokio::test]
    async fn detached_activation_failure_supervision_does_not_leave_starting_durable() {
        let fixture = fixture(Vec::new(), true);
        let repository = fixture.repository.clone();
        let observation = fixture.observation.clone();
        let status = fixture.status.clone();
        let runtime = fixture.runtime.clone();
        let owner = fixture.owner;
        let session_id = fixture.session;
        observation.bump_session_revision_on_next_start();
        let _ = try_start(fixture)
            .await
            .err()
            .expect("the synthetic activation commit must conflict");

        runtime
            .fail_detached_focus_activation(owner, session_id, false, "detached_activation_failed")
            .await
            .unwrap();

        let failed = repository
            .find_focus_session(session_id)
            .unwrap()
            .expect("supervised activation failure remains durable");
        assert_eq!(failed.state, FocusSessionState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("detached_activation_failed")
        );
        assert_eq!(
            status.clears.lock().unwrap().as_slice(),
            &[(session_id, 1), (session_id, 2)]
        );
        assert!(
            repository
                .load_audit(owner, OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .iter()
                .any(|record| {
                    record.subject_id == session_id.as_uuid()
                        && record
                            .reason_codes
                            .iter()
                            .any(|reason| reason == "detached_activation_failed")
                })
        );
    }

    fn observe(active: &ActiveFixture) {
        let now = active.fixture.clock.now_utc();
        let presence = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::ObserveDesktopPresence)
            .unwrap();
        active
            .fixture
            .runtime
            .accept_observation(NormalizedObservation {
                observation_id: Uuid::now_v7(),
                session_id: active.fixture.session,
                grant_id: presence.id,
                grant_revision: presence.revision,
                device_id: presence.device_id,
                value: NormalizedObservationValue::Presence(crate::PresenceState::Active),
                provenance: crate::ObservationProvenance {
                    source_id: format!("synthetic:{}", presence.id),
                    source_event_id: Uuid::now_v7(),
                    selected_resource_id: None,
                    observed_at: now,
                    received_at: now,
                    extraction_version: "v1".to_owned(),
                    redaction_version: "v1".to_owned(),
                    normalization_schema_version: "v1".to_owned(),
                    confidence_basis_points: 10_000,
                    complete: true,
                    sensitivity: crate::ObservationSensitivity::Personal,
                    retention: crate::ObservationRetention::EphemeralSession,
                    browser_granularity: None,
                },
            })
            .unwrap();
        let workspace = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::ObserveWorkspaceActivity)
            .unwrap();
        active
            .fixture
            .runtime
            .accept_observation(NormalizedObservation {
                observation_id: Uuid::now_v7(),
                session_id: active.fixture.session,
                grant_id: workspace.id,
                grant_revision: workspace.revision,
                device_id: workspace.device_id,
                value: NormalizedObservationValue::WorkspaceActivity {
                    activity: crate::WorkspaceActivityKind::Modified,
                },
                provenance: crate::ObservationProvenance {
                    source_id: format!("synthetic:{}", workspace.id),
                    source_event_id: Uuid::now_v7(),
                    selected_resource_id: Some(active.fixture.resource),
                    observed_at: now,
                    received_at: now,
                    extraction_version: "v1".to_owned(),
                    redaction_version: "v1".to_owned(),
                    normalization_schema_version: "v1".to_owned(),
                    confidence_basis_points: 9_000,
                    complete: true,
                    sensitivity: crate::ObservationSensitivity::Personal,
                    retention: crate::ObservationRetention::EphemeralSession,
                    browser_granularity: None,
                },
            })
            .unwrap();
    }

    async fn refresh_workspace_and_observe(active: &ActiveFixture) {
        let now = active.fixture.clock.now_utc();
        let workspace = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::ObserveWorkspaceActivity)
            .unwrap();
        active
            .fixture
            .runtime
            .accept_source_status(
                active.fixture.session,
                workspace.id,
                ObservationSourceStatus {
                    source_id: format!("synthetic:{}", workspace.id),
                    grant_id: workspace.id,
                    scope: workspace.scope,
                    resource_id: workspace.selected_resource_id,
                    health: SourceHealth::Healthy,
                    detail: "Synthetic source heartbeat is fresh.",
                    observed_at: now,
                },
            )
            .await
            .unwrap();
        active
            .fixture
            .runtime
            .accept_observation(NormalizedObservation {
                observation_id: Uuid::now_v7(),
                session_id: active.fixture.session,
                grant_id: workspace.id,
                grant_revision: workspace.revision,
                device_id: workspace.device_id,
                value: NormalizedObservationValue::WorkspaceActivity {
                    activity: crate::WorkspaceActivityKind::Modified,
                },
                provenance: crate::ObservationProvenance {
                    source_id: format!("synthetic:{}", workspace.id),
                    source_event_id: Uuid::now_v7(),
                    selected_resource_id: workspace.selected_resource_id,
                    observed_at: now,
                    received_at: now,
                    extraction_version: "v1".to_owned(),
                    redaction_version: "v1".to_owned(),
                    normalization_schema_version: "v1".to_owned(),
                    confidence_basis_points: 9_000,
                    complete: true,
                    sensitivity: crate::ObservationSensitivity::Personal,
                    retention: crate::ObservationRetention::EphemeralSession,
                    browser_granularity: None,
                },
            })
            .unwrap();
    }

    fn stop_synthetic_background_tasks(active: &ActiveFixture) {
        let mut state = active.fixture.runtime.ephemeral.lock().unwrap();
        let ephemeral = state.sessions.get_mut(&active.fixture.session).unwrap();
        ephemeral.cancellation.cancel();
        // Tests use this helper only to stop spawned source/status tasks while
        // retaining an isolated live reasoning authority for paused-clock
        // scheduler assertions.
        ephemeral.cancellation = CancellationToken::new();
        ephemeral.proactive_cancellation = ephemeral.cancellation.child_token();
    }

    async fn wait_for_model_calls(model: &ScriptedModel, expected: usize) {
        for _ in 0..100 {
            if model.calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the synthetic model did not receive {expected} calls");
    }

    async fn wait_for_notification_calls(notification: &TestNotification, expected: usize) {
        for _ in 0..100 {
            if notification.calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the synthetic notification adapter did not receive {expected} calls");
    }

    async fn wait_for_cancellation_observation(observed: &AtomicBool) {
        for _ in 0..100 {
            if observed.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the adapter did not observe cancellation");
    }

    async fn observe_foreground_churn(active: &ActiveFixture) {
        let now = active.fixture.clock.now_utc();
        let template = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::ObserveWorkspaceActivity)
            .unwrap();
        let foreground = PermissionGrant {
            id: PermissionGrantId::new_v7(),
            scope: PermissionScope::ObserveDesktopForegroundApplication,
            purpose: "Synthetic selected-application identity only".to_owned(),
            ..template.clone()
        };
        active
            .fixture
            .repository
            .save_grant(&foreground, None)
            .unwrap();
        let mut session =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        let expected = session.revision;
        session.permission_grant_ids.insert(foreground.id);
        session.revision = session.revision.saturating_add(1);
        session.updated_at = now;
        active
            .fixture
            .repository
            .save_focus_session(&session, Some(expected))
            .unwrap();
        active
            .fixture
            .runtime
            .accept_source_status(
                active.fixture.session,
                foreground.id,
                ObservationSourceStatus {
                    source_id: format!("synthetic:{}", foreground.id),
                    grant_id: foreground.id,
                    scope: foreground.scope,
                    resource_id: foreground.selected_resource_id,
                    health: SourceHealth::Healthy,
                    detail: "Synthetic foreground identity source is healthy.",
                    observed_at: now,
                },
            )
            .await
            .unwrap();
        active
            .fixture
            .runtime
            .accept_observation(NormalizedObservation {
                observation_id: Uuid::now_v7(),
                session_id: active.fixture.session,
                grant_id: foreground.id,
                grant_revision: foreground.revision,
                device_id: foreground.device_id,
                value: NormalizedObservationValue::ForegroundApplication(
                    crate::ForegroundApplicationState::Selected {
                        application_id: "synthetic.stable.application.identity".to_owned(),
                    },
                ),
                provenance: crate::ObservationProvenance {
                    source_id: format!("synthetic:{}", foreground.id),
                    source_event_id: Uuid::now_v7(),
                    selected_resource_id: foreground.selected_resource_id,
                    observed_at: now,
                    received_at: now,
                    extraction_version: "v1".to_owned(),
                    redaction_version: "v1".to_owned(),
                    normalization_schema_version: "v1".to_owned(),
                    confidence_basis_points: 10_000,
                    complete: true,
                    sensitivity: crate::ObservationSensitivity::Personal,
                    retention: crate::ObservationRetention::EphemeralSession,
                    browser_granularity: None,
                },
            })
            .unwrap();
    }

    fn queue_synthetic_clone(
        active: &ActiveFixture,
        template: &Intervention,
        template_decision: &PolicyDecision,
        notification_grant: &PermissionGrant,
        session_id: FocusSessionId,
    ) -> Intervention {
        let candidate_id = CandidateId::new_v7();
        let mut decision = template_decision.clone();
        decision.id = PolicyDecisionId::new_v7();
        decision.candidate_id = candidate_id;
        decision.focus_session_id = session_id;
        active
            .fixture
            .repository
            .save_policy_decision(&decision)
            .unwrap();
        let mut intervention = template.clone();
        intervention.id = InterventionId::new_v7();
        intervention.candidate_id = candidate_id;
        intervention.policy_decision_id = decision.id;
        intervention.focus_session_id = session_id;
        intervention.revision = 1;
        intervention.state = InterventionState::Allowed;
        intervention.updated_at = active.fixture.clock.now_utc();
        active
            .fixture
            .repository
            .save_intervention(&intervention, None)
            .unwrap();
        let delivery = NotificationDelivery {
            intervention_id: intervention.id,
            policy_decision_id: decision.id,
            title: "STEIN focus note".to_owned(),
            body: intervention.user_visible_text.clone(),
            urgency: intervention.urgency,
            deduplication_key: delivery_deduplication_key(
                candidate_id,
                decision.candidate_revision,
                NATIVE_NOTIFICATION_CHANNEL,
            ),
            expires_at: intervention.expires_at,
        };
        let pending = active
            .fixture
            .runtime
            .queue_intervention(&mut intervention, &decision, notification_grant, &delivery)
            .unwrap();
        active
            .fixture
            .runtime
            .persist_intervention_transition(
                &intervention,
                1,
                AuditKind::InterventionDelivery,
                AuditDetails::new(vec!["synthetic_queue_seed".to_owned()], BTreeSet::new())
                    .with_policy_trace(decision.policy_trace.clone()),
                pending.map(PendingDeliveryTransition::Enqueue),
            )
            .unwrap();
        intervention
    }

    fn allowed_synthetic_clone(
        active: &ActiveFixture,
        template: &Intervention,
        template_decision: &PolicyDecision,
    ) -> Intervention {
        let candidate_id = CandidateId::new_v7();
        let mut decision = template_decision.clone();
        decision.id = PolicyDecisionId::new_v7();
        decision.candidate_id = candidate_id;
        active
            .fixture
            .repository
            .save_policy_decision(&decision)
            .unwrap();
        let mut intervention = template.clone();
        intervention.id = InterventionId::new_v7();
        intervention.candidate_id = candidate_id;
        intervention.policy_decision_id = decision.id;
        intervention.revision = 1;
        intervention.state = InterventionState::Allowed;
        intervention.updated_at = active.fixture.clock.now_utc();
        active
            .fixture
            .repository
            .save_intervention(&intervention, None)
            .unwrap();
        intervention
    }

    #[test]
    fn diagnostic_client_cannot_read_or_mutate_private_state() {
        let fixture = fixture(Vec::new(), true);
        let error = fixture
            .runtime
            .create_goal(
                ClientAssurance::Diagnostic,
                CreateGoal {
                    actor: fixture.owner,
                    idempotency_key: IdempotencyKey::new_v7(),
                    title: "Private synthetic goal".to_owned(),
                    success_statement: "This must not be accepted.".to_owned(),
                    deadline: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::PermissionDenied);
        assert!(
            fixture
                .repository
                .load_goals(fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn policy_trace_digest_is_deterministic_and_audit_keeps_only_the_digest() {
        let fixture = fixture(Vec::new(), true);
        let input = serde_json::json!({
            "schema": "synthetic.policy-input.v1",
            "candidate_revision": 7,
            "private_candidate_text": "synthetic-private-policy-input"
        });
        let first = fixture.runtime.policy_trace(3, &input).unwrap();
        let second = fixture.runtime.policy_trace(3, &input).unwrap();
        assert_eq!(first, second);
        assert!(first.is_complete());
        let mut unknown_schema = first.clone();
        unknown_schema.proposed_input_schema_version = PolicyTrace::INPUT_SCHEMA_V1 + 1;
        assert!(!unknown_schema.is_complete());

        let changed = fixture
            .runtime
            .policy_trace(
                3,
                &serde_json::json!({
                    "schema": "synthetic.policy-input.v1",
                    "candidate_revision": 8,
                    "private_candidate_text": "synthetic-private-policy-input"
                }),
            )
            .unwrap();
        assert_ne!(first.proposed_input_digest, changed.proposed_input_digest);

        let audit = fixture.runtime.build_audit_record(
            fixture.owner,
            AuditKind::SignificanceDecision,
            fixture.session.as_uuid(),
            AuditDetails::new(
                vec!["synthetic_policy_decision".to_owned()],
                BTreeSet::new(),
            )
            .with_policy_trace(first),
        );
        let encoded = serde_json::to_string(&audit).unwrap();
        assert!(encoded.contains("proposed_input_digest"));
        assert!(!encoded.contains("synthetic-private-policy-input"));
    }

    #[test]
    fn do_not_disturb_window_is_start_inclusive_end_exclusive_and_wraps_midnight() {
        let window = DoNotDisturbWindow {
            start_minute_local: 22 * 60,
            end_minute_local: 7 * 60,
            utc_offset_minutes: 60,
        };
        assert!(!do_not_disturb_contains(
            window,
            datetime!(2026-08-19 20:59 UTC)
        ));
        assert!(do_not_disturb_contains(
            window,
            datetime!(2026-08-19 21:00 UTC)
        ));
        assert!(do_not_disturb_contains(
            window,
            datetime!(2026-08-20 05:59 UTC)
        ));
        assert!(!do_not_disturb_contains(
            window,
            datetime!(2026-08-20 06:00 UTC)
        ));
    }

    fn drain_events(
        receiver: &mut tokio::sync::broadcast::Receiver<crate::CoreEventEnvelope>,
    ) -> Vec<CoreEvent> {
        let mut events = Vec::new();
        loop {
            match receiver.try_recv() {
                Ok(envelope) => events.push(envelope.event),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(missed)) => {
                    panic!("synthetic publication receiver lagged by {missed}")
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    panic!("synthetic publication receiver closed")
                }
            }
        }
        events
    }

    async fn wait_for_degraded_session(active: &ActiveFixture) -> FocusSession {
        for _ in 0..100 {
            let session =
                find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
            if session.source_degraded {
                return session;
            }
            tokio::task::yield_now().await;
        }
        panic!("native status failure did not pause capture")
    }

    async fn wait_for_emergency_acknowledgements(
        emergency: &TestEmergency,
        count: usize,
    ) -> Vec<crate::EmergencyCommandAcknowledgement> {
        for _ in 0..100 {
            let acknowledgements = emergency
                .acknowledgements
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if acknowledgements.len() >= count {
                return acknowledgements;
            }
            tokio::task::yield_now().await;
        }
        panic!("emergency acknowledgement was not emitted")
    }

    #[tokio::test]
    async fn message_loop_loss_between_publishes_pauses_capture_and_publishes_degraded_health() {
        let fixture = fixture(Vec::new(), true);
        let publication = ViewPublication::new(128, Uuid::now_v7());
        fixture
            .runtime
            .attach_publication(publication.clone())
            .unwrap();
        let mut receiver = publication
            .capture(|_, receiver| Ok::<_, ()>(receiver))
            .unwrap();
        let active = start(fixture).await;
        let _ = drain_events(&mut receiver);
        observe(&active);
        let _ = drain_events(&mut receiver);
        assert_eq!(active.fixture.status.publishes.load(Ordering::SeqCst), 2);

        active
            .fixture
            .status
            .emit_heartbeat(Err(crate::NativeStatusError {
                summary: "Synthetic native message loop was lost.",
                retryable: true,
            }));
        let degraded = wait_for_degraded_session(&active).await;
        assert_eq!(degraded.state, FocusSessionState::Active);
        assert_eq!(active.fixture.status.publishes.load(Ordering::SeqCst), 2);
        let statuses = active
            .fixture
            .runtime
            .observation_source_statuses(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap();
        assert!(
            statuses
                .iter()
                .all(|status| status.health == SourceHealth::Paused)
        );
        let state = active.fixture.runtime.ephemeral.lock().unwrap();
        let ephemeral = state.sessions.get(&active.fixture.session).unwrap();
        assert!(ephemeral.cancellation.is_cancelled());
        assert!(ephemeral.observations.is_empty());
        drop(state);
        assert!(drain_events(&mut receiver).iter().any(|event| matches!(
            event,
            CoreEvent::CapabilityHealthChanged { capability }
                if capability.id == "platform.native_status"
                    && capability.state == CapabilityState::Unavailable
        )));
        assert_eq!(
            publication.read(|state| state
                .capability_overrides
                .get("platform.native_status")
                .map(|capability| capability.state)),
            Some(CapabilityState::Unavailable)
        );
    }

    #[tokio::test]
    async fn stale_wrong_session_and_wrong_revision_native_heartbeats_fail_closed() {
        let active = start(fixture(Vec::new(), true)).await;
        let revision = find_session(&*active.fixture.runtime.repository, active.fixture.session)
            .unwrap()
            .revision;
        active
            .fixture
            .status
            .emit_heartbeat(Ok(NativeStatusHeartbeat {
                session_id: active.fixture.session,
                revision,
                emitted_at: active.fixture.clock.now_utc() - time::Duration::seconds(11),
            }));
        let _ = wait_for_degraded_session(&active).await;

        let wrong_session = start(fixture(Vec::new(), true)).await;
        let revision = find_session(
            &*wrong_session.fixture.runtime.repository,
            wrong_session.fixture.session,
        )
        .unwrap()
        .revision;
        wrong_session
            .fixture
            .status
            .emit_heartbeat(Ok(NativeStatusHeartbeat {
                session_id: FocusSessionId::new_v7(),
                revision,
                emitted_at: wrong_session.fixture.clock.now_utc(),
            }));
        let _ = wait_for_degraded_session(&wrong_session).await;

        let wrong_revision = start(fixture(Vec::new(), true)).await;
        let revision = find_session(
            &*wrong_revision.fixture.runtime.repository,
            wrong_revision.fixture.session,
        )
        .unwrap()
        .revision;
        wrong_revision
            .fixture
            .status
            .emit_heartbeat(Ok(NativeStatusHeartbeat {
                session_id: wrong_revision.fixture.session,
                revision: revision.saturating_add(1),
                emitted_at: wrong_revision.fixture.clock.now_utc(),
            }));
        let _ = wait_for_degraded_session(&wrong_revision).await;
    }

    #[tokio::test(start_paused = true)]
    async fn native_status_heartbeat_timeout_uses_a_deterministic_deadline() {
        let config = SecondMindConfig {
            native_status_heartbeat_timeout: Duration::from_secs(1),
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(Vec::new(), true, config)).await;
        tokio::task::yield_now().await;
        active.fixture.clock.advance(Duration::from_secs(2));
        tokio::time::advance(Duration::from_secs(2)).await;
        let _ = wait_for_degraded_session(&active).await;
    }

    #[tokio::test]
    async fn emergency_commands_are_monotonic_and_acknowledge_the_exact_revision() {
        let fixture = fixture(Vec::new(), true);
        let shutdown = CancellationToken::new();
        let runtime = fixture.runtime.clone();
        let owner = fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            runtime
                .run_emergency_control_loop(owner, loop_shutdown)
                .await
        });
        fixture.emergency.push(crate::EmergencyCommandEnvelope {
            command_id: Uuid::now_v7(),
            revision: 2,
            issued_at: fixture.clock.now_utc(),
            command: EmergencyCommand::OpenStein,
        });
        fixture.emergency.push(crate::EmergencyCommandEnvelope {
            command_id: Uuid::now_v7(),
            revision: 1,
            issued_at: fixture.clock.now_utc(),
            command: EmergencyCommand::OpenStein,
        });
        let acknowledgements = wait_for_emergency_acknowledgements(&fixture.emergency, 2).await;
        assert_eq!(acknowledgements[0].revision, 2);
        assert_eq!(acknowledgements[0].status, EmergencyCommandStatus::Rejected);
        assert_eq!(acknowledgements[1].revision, 1);
        assert_eq!(acknowledgements[1].status, EmergencyCommandStatus::Rejected);
        shutdown.cancel();
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn emergency_stop_revokes_authority_before_cleanup_even_when_ack_revision_is_wrong() {
        let active = start(fixture(Vec::new(), true)).await;
        active
            .fixture
            .emergency
            .set_acknowledgement_mode(EmergencyAckMode::WrongRevision);
        let command_id = Uuid::now_v7();
        active
            .fixture
            .emergency
            .push(crate::EmergencyCommandEnvelope {
                command_id,
                revision: 1,
                issued_at: active.fixture.clock.now_utc(),
                command: EmergencyCommand::StopAllObservation,
            });
        let error = active
            .fixture
            .runtime
            .run_emergency_control_loop(active.fixture.owner, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        let acknowledgement = active
            .fixture
            .emergency
            .acknowledgements
            .lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap();
        assert_eq!(
            (acknowledgement.command_id, acknowledgement.revision),
            (command_id, 1)
        );
        assert_eq!(acknowledgement.status, EmergencyCommandStatus::Accepted);
        assert_eq!(
            find_session(&*active.fixture.runtime.repository, active.fixture.session)
                .unwrap()
                .state,
            FocusSessionState::Ended
        );
        let cleanup_states = active.fixture.observation.cleanup_states.lock().unwrap();
        assert!(!cleanup_states.is_empty());
        assert!(
            cleanup_states
                .iter()
                .all(|state| *state == FocusSessionState::Stopping)
        );
    }

    #[tokio::test]
    async fn restart_recovery_resumes_stopping_adapter_and_native_status_cleanup() {
        let active = start(fixture(Vec::new(), true)).await;
        let stopping = active
            .fixture
            .runtime
            .end_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
                find_session(&*active.fixture.runtime.repository, active.fixture.session)
                    .unwrap()
                    .revision,
                EndFocusReason::UserRequested,
            )
            .unwrap();
        assert_eq!(stopping.state, FocusSessionState::Stopping);
        let restarted = SecondMindRuntime::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(active.fixture.repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: active.fixture.observation.clone(),
                model: active.fixture.model.clone(),
                notification: active.fixture.notification.clone(),
                native_status: active.fixture.status.clone(),
                emergency_control: active.fixture.emergency.clone(),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();

        let recovered = restarted.recover_owner(active.fixture.owner).unwrap();
        assert_eq!(recovered, vec![stopping.clone()]);
        let ended = restarted
            .finish_end_focus_session(active.fixture.owner, stopping.id, stopping.revision)
            .await
            .unwrap();

        assert_eq!(ended.state, FocusSessionState::Ended);
        let cleanup_states = active.fixture.observation.cleanup_states.lock().unwrap();
        assert!(!cleanup_states.is_empty());
        assert!(
            cleanup_states
                .iter()
                .all(|state| *state == FocusSessionState::Stopping)
        );
        assert_eq!(
            active.fixture.status.clears.lock().unwrap().as_slice(),
            &[(stopping.id, stopping.revision)]
        );
    }

    #[tokio::test]
    async fn missing_emergency_acknowledgement_is_a_channel_failure() {
        let fixture = fixture(Vec::new(), true);
        fixture
            .emergency
            .set_acknowledgement_mode(EmergencyAckMode::Missing);
        fixture.emergency.push(crate::EmergencyCommandEnvelope {
            command_id: Uuid::now_v7(),
            revision: 1,
            issued_at: fixture.clock.now_utc(),
            command: EmergencyCommand::OpenStein,
        });
        let error = fixture
            .runtime
            .run_emergency_control_loop(fixture.owner, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        assert_eq!(fixture.emergency.acknowledgements.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retention_sweep_removes_observations_at_and_after_ttl_without_new_ingestion() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        assert_eq!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .len(),
            2
        );

        active.fixture.clock.advance(Duration::from_secs(599));
        assert_eq!(
            active
                .fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .removed_observations,
            0
        );
        assert_eq!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .len(),
            2
        );

        active.fixture.clock.advance(Duration::from_secs(1));
        assert_eq!(
            active
                .fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .removed_observations,
            2
        );
        assert!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .is_empty()
        );

        refresh_workspace_and_observe(&active).await;
        active.fixture.clock.advance(Duration::from_secs(601));
        assert_eq!(
            active
                .fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .removed_observations,
            1
        );
        assert!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .is_empty()
        );
    }

    #[tokio::test]
    async fn single_operation_observation_is_consumed_by_one_context_assembly() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        {
            let mut state = active.fixture.runtime.ephemeral.lock().unwrap();
            let session = state.sessions.get_mut(&active.fixture.session).unwrap();
            let observation = session
                .observations
                .iter_mut()
                .find(|observation| observation.value.category() == DataCategory::WorkspaceActivity)
                .unwrap();
            observation.provenance.retention = crate::ObservationRetention::SingleOperation;
        }
        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let route = find_route(
            &active.fixture.repository,
            active.fixture.owner,
            session.model_route_approval_id,
        )
        .unwrap();

        let first = active
            .fixture
            .runtime
            .assemble_context(&session, &route, &active.grants)
            .unwrap()
            .0;
        let second = active
            .fixture
            .runtime
            .assemble_context(&session, &route, &active.grants)
            .unwrap()
            .0;

        assert_eq!(
            first
                .iter()
                .filter(|item| item.category == DataCategory::WorkspaceActivity)
                .count(),
            1
        );
        assert!(
            second
                .iter()
                .all(|item| item.category != DataCategory::WorkspaceActivity)
        );
        let state = active.fixture.runtime.ephemeral.lock().unwrap();
        assert!(
            state
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .iter()
                .all(|observation| {
                    observation.provenance.retention != crate::ObservationRetention::SingleOperation
                })
        );
    }

    #[tokio::test]
    async fn single_operation_observation_has_a_bounded_unused_retention_fallback() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        {
            let mut state = active.fixture.runtime.ephemeral.lock().unwrap();
            let session = state.sessions.get_mut(&active.fixture.session).unwrap();
            session
                .observations
                .iter_mut()
                .find(|observation| observation.value.category() == DataCategory::WorkspaceActivity)
                .unwrap()
                .provenance
                .retention = crate::ObservationRetention::SingleOperation;
        }

        active.fixture.clock.advance(Duration::from_secs(119));
        assert_eq!(
            active
                .fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .removed_observations,
            0
        );
        active.fixture.clock.advance(Duration::from_secs(1));
        assert_eq!(
            active
                .fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .removed_observations,
            1
        );
        let state = active.fixture.runtime.ephemeral.lock().unwrap();
        let observations = &state
            .sessions
            .get(&active.fixture.session)
            .unwrap()
            .observations;
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].provenance.retention,
            crate::ObservationRetention::EphemeralSession
        );
    }

    #[tokio::test]
    async fn phase2_retention_context_is_erased_at_session_end_and_restart() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let route = find_route(
            &active.fixture.repository,
            active.fixture.owner,
            session.model_route_approval_id,
        )
        .unwrap();
        let context = active
            .fixture
            .runtime
            .assemble_context(&session, &route, &active.grants)
            .unwrap()
            .0;
        assert!(!context.is_empty());
        assert!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session.id)
        );

        let stopping = active
            .fixture
            .runtime
            .end_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                session.id,
                session.revision,
                EndFocusReason::UserRequested,
            )
            .unwrap();
        let ended = active
            .fixture
            .runtime
            .finish_end_focus_session(active.fixture.owner, stopping.id, stopping.revision)
            .await
            .unwrap();
        assert_eq!(ended.state, FocusSessionState::Ended);
        assert!(
            !active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session.id)
        );
        assert!(
            active
                .fixture
                .runtime
                .assemble_context(&ended, &route, &active.grants)
                .is_err()
        );

        let restarted = SecondMindRuntime::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(active.fixture.repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: Arc::new(UnavailableObservationPort),
                model: Arc::new(UnavailableModelGateway),
                notification: Arc::new(UnavailableNotificationPort),
                native_status: Arc::new(UnavailableNativeStatusPort),
                emergency_control: Arc::new(UnavailableEmergencyControlPort),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        assert!(
            restarted
                .recover_owner(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
        assert!(restarted.ephemeral.lock().unwrap().sessions.is_empty());
        assert!(
            restarted
                .latest_model_request_receipt(
                    ClientAssurance::PrivateCapabilityBound,
                    active.fixture.owner,
                    session.id,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn retention_sweep_physically_purges_audit_at_the_expiry_boundary() {
        let fixture = fixture(Vec::new(), true);
        fixture
            .runtime
            .append_audit(
                fixture.owner,
                AuditKind::FocusSessionStateChanged,
                Uuid::now_v7(),
                AuditDetails::new(
                    vec!["synthetic_retention_boundary".to_owned()],
                    BTreeSet::new(),
                ),
            )
            .unwrap();

        fixture
            .clock
            .advance(Duration::from_secs(30 * 24 * 60 * 60 - 1));
        assert_eq!(
            fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .purged_audit_records,
            0
        );
        assert_eq!(
            fixture
                .repository
                .load_audit(fixture.owner, OffsetDateTime::UNIX_EPOCH, 10)
                .unwrap()
                .len(),
            1
        );

        fixture.clock.advance(Duration::from_secs(1));
        assert_eq!(
            fixture
                .runtime
                .run_retention_maintenance_once()
                .unwrap()
                .purged_audit_records,
            1
        );
        assert!(
            fixture
                .repository
                .load_audit(fixture.owner, OffsetDateTime::UNIX_EPOCH, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn model_route_approval_requires_an_approval_scoped_secret_reference() {
        let fixture = fixture(Vec::new(), true);
        let mut route = cleanup_route(fixture.owner, fixture.clock.now_utc());
        route.secret_ref = crate::SecretRef::new("shared-provider-route-name");

        let error = fixture
            .runtime
            .approve_model_route(
                ClientAssurance::PrivateCapabilityBound,
                idempotency(0x61),
                route,
            )
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            error.summary,
            "The model route approval is invalid or unsafe."
        );
        assert!(
            fixture
                .repository
                .load_model_routes(fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn revoked_route_retains_secret_cleanup_until_a_content_free_retry_succeeds() {
        let owner = ActorId::new_v7();
        let now = datetime!(2026-08-19 10:00 UTC);
        let repository = MemoryRepository::default();
        let clock = Arc::new(ManualClock::new(now));
        let secret_store = Arc::new(ScriptedCleanupSecretStore::default());
        secret_store.fail_next_delete();
        let runtime = cleanup_runtime(
            SecondMindConfig::default(),
            &repository,
            clock,
            secret_store.clone(),
            Arc::new(ScriptedResourceCleanup::default()),
        );
        let route = cleanup_route(owner, now);
        repository.save_model_route(&route, None).unwrap();

        let error = runtime
            .revoke_model_route(
                ClientAssurance::PrivateCapabilityBound,
                owner,
                route.id,
                route.revision,
                "Synthetic direct-user revocation".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        assert_eq!(
            error.summary,
            "The model route is revoked, but its native credential cleanup remains pending."
        );
        assert!(
            repository.load_model_routes(owner).unwrap()[0]
                .revoked_at
                .is_some()
        );
        assert_eq!(
            repository
                .load_secret_deletion_cleanups(owner)
                .unwrap()
                .len(),
            1
        );
        assert!(
            repository
                .load_audit(owner, OffsetDateTime::UNIX_EPOCH, 10)
                .unwrap()
                .iter()
                .any(|record| record.kind == AuditKind::ModelRouteRevoked)
        );

        let revoked = repository.load_model_routes(owner).unwrap()[0].clone();
        let repeated = runtime
            .revoke_model_route(
                ClientAssurance::PrivateCapabilityBound,
                owner,
                revoked.id,
                revoked.revision,
                "Synthetic repeated revocation".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(repeated.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            repeated.summary,
            "The model route approval is already revoked."
        );
        assert_eq!(repository.load_model_routes(owner).unwrap()[0], revoked);
        assert_eq!(
            repository
                .load_secret_deletion_cleanups(owner)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            repository
                .load_audit(owner, OffsetDateTime::UNIX_EPOCH, 10)
                .unwrap()
                .iter()
                .filter(|record| record.kind == AuditKind::ModelRouteRevoked)
                .count(),
            1
        );
        assert_eq!(secret_store.delete_calls.load(Ordering::SeqCst), 1);

        let retry = runtime.recover_cleanup_obligations(owner).await.unwrap();
        assert_eq!(retry.secret_deletion_attempts, 1);
        assert_eq!(retry.secret_deletion_completed, 1);
        assert_eq!(retry.secret_deletion_pending, 0);
        assert!(
            repository
                .load_secret_deletion_cleanups(owner)
                .unwrap()
                .is_empty()
        );
        assert!(
            repository.load_model_routes(owner).unwrap()[0]
                .revoked_at
                .is_some()
        );
        assert_eq!(secret_store.delete_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn native_cleanup_retry_never_restores_removed_resource_authority() {
        let owner = ActorId::new_v7();
        let repository = MemoryRepository::default();
        let resource_selection = Arc::new(ScriptedResourceCleanup::default());
        resource_selection.fail_next_release();
        let runtime = cleanup_runtime(
            SecondMindConfig::default(),
            &repository,
            Arc::new(ManualClock::new(datetime!(2026-08-19 10:00 UTC))),
            Arc::new(ScriptedCleanupSecretStore::default()),
            resource_selection.clone(),
        );
        let resource_id = ResourceId::new_v7();
        repository
            .save_native_resource_cleanup(&crate::NativeResourceCleanup {
                owner,
                resource_id,
                opaque_reference: "synthetic-native-cleanup-token".to_owned(),
                created_at: datetime!(2026-08-19 10:00 UTC),
            })
            .unwrap();
        assert!(repository.load_resources(owner).unwrap().is_empty());

        let first = runtime.recover_cleanup_obligations(owner).await.unwrap();
        assert_eq!(first.native_resource_attempts, 1);
        assert_eq!(first.native_resource_completed, 0);
        assert_eq!(first.native_resource_pending, 1);
        assert!(repository.load_resources(owner).unwrap().is_empty());

        let second = runtime.recover_cleanup_obligations(owner).await.unwrap();
        assert_eq!(second.native_resource_attempts, 1);
        assert_eq!(second.native_resource_completed, 1);
        assert_eq!(second.native_resource_pending, 0);
        assert!(repository.load_resources(owner).unwrap().is_empty());
        assert!(
            repository
                .load_native_resource_cleanups(owner)
                .unwrap()
                .is_empty()
        );
        assert_eq!(resource_selection.release_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cleanup_recovery_is_bounded_to_three_records_per_kind_per_pass() {
        let owner = ActorId::new_v7();
        let repository = MemoryRepository::default();
        let resource_selection = Arc::new(ScriptedResourceCleanup::default());
        let runtime = cleanup_runtime(
            SecondMindConfig::default(),
            &repository,
            Arc::new(ManualClock::new(datetime!(2026-08-19 10:00 UTC))),
            Arc::new(ScriptedCleanupSecretStore::default()),
            resource_selection.clone(),
        );
        for index in 0..4 {
            repository
                .save_native_resource_cleanup(&crate::NativeResourceCleanup {
                    owner,
                    resource_id: ResourceId::new_v7(),
                    opaque_reference: format!("synthetic-bounded-cleanup-{index}"),
                    created_at: datetime!(2026-08-19 10:00 UTC),
                })
                .unwrap();
        }

        let first = runtime.recover_cleanup_obligations(owner).await.unwrap();
        assert_eq!(first.native_resource_attempts, 3);
        assert_eq!(first.native_resource_completed, 3);
        assert_eq!(first.native_resource_pending, 1);
        assert_eq!(resource_selection.release_calls.load(Ordering::SeqCst), 3);

        let second = runtime.recover_cleanup_obligations(owner).await.unwrap();
        assert_eq!(second.native_resource_attempts, 1);
        assert_eq!(second.native_resource_completed, 1);
        assert_eq!(second.native_resource_pending, 0);
        assert_eq!(resource_selection.release_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_retention_maintenance_retries_private_cleanup_obligations() {
        let owner = ActorId::new_v7();
        let repository = MemoryRepository::default();
        let resource_selection = Arc::new(ScriptedResourceCleanup::default());
        let runtime = cleanup_runtime(
            SecondMindConfig {
                retention_maintenance_interval: Duration::from_secs(1),
                ..SecondMindConfig::default()
            },
            &repository,
            Arc::new(ManualClock::new(datetime!(2026-08-19 10:00 UTC))),
            Arc::new(ScriptedCleanupSecretStore::default()),
            resource_selection.clone(),
        );
        repository
            .save_native_resource_cleanup(&crate::NativeResourceCleanup {
                owner,
                resource_id: ResourceId::new_v7(),
                opaque_reference: "synthetic-periodic-cleanup-token".to_owned(),
                created_at: datetime!(2026-08-19 10:00 UTC),
            })
            .unwrap();

        let shutdown = CancellationToken::new();
        let loop_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            runtime
                .run_retention_maintenance(owner, loop_shutdown)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            repository
                .load_native_resource_cleanups(owner)
                .unwrap()
                .is_empty()
        );
        assert_eq!(resource_selection.release_calls.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn retention_maintenance_cleans_quiet_sessions_and_shutdown_is_bounded() {
        let config = SecondMindConfig {
            retention_maintenance_interval: Duration::from_secs(1),
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(Vec::new(), true, config)).await;
        observe(&active);
        active.fixture.clock.advance(Duration::from_secs(10 * 60));

        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            runtime
                .run_retention_maintenance(owner, loop_shutdown)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..10 {
            if active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .observations
                .is_empty()
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("retention-maintenance shutdown remained bounded")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reasoning_scheduler_waits_a_full_interval_before_the_first_cycle() {
        let active = start(fixture(
            vec![ModelReasoningOutput::Silence {
                reason_code: "scheduled_silence".to_owned(),
            }],
            true,
        ))
        .await;
        observe(&active);
        stop_synthetic_background_tasks(&active);
        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task =
            tokio::spawn(
                async move { runtime.run_reasoning_scheduler(owner, loop_shutdown).await },
            );
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);

        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_model_calls(&active.fixture.model, 1).await;
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reasoning_scheduler_ends_an_expired_route_even_when_the_session_is_muted() {
        let active = start(fixture(Vec::new(), true)).await;
        let current =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        active
            .fixture
            .runtime
            .set_interventions_muted(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
                current.revision,
                true,
            )
            .await
            .unwrap();
        let mut route = find_route(
            &*active.fixture.runtime.repository,
            active.fixture.owner,
            current.model_route_approval_id,
        )
        .unwrap();
        let expected_route_revision = route.revision;
        route.revision = route.revision.saturating_add(1);
        route.expires_at = Some(active.fixture.clock.now_utc() + time::Duration::seconds(30));
        active
            .fixture
            .repository
            .save_model_route(&route, Some(expected_route_revision))
            .unwrap();
        stop_synthetic_background_tasks(&active);
        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task =
            tokio::spawn(
                async move { runtime.run_reasoning_scheduler(owner, loop_shutdown).await },
            );
        tokio::task::yield_now().await;

        active.fixture.clock.advance(Duration::from_secs(60));
        tokio::time::advance(Duration::from_secs(60)).await;
        for _ in 0..100 {
            if find_session(&*active.fixture.runtime.repository, active.fixture.session)
                .unwrap()
                .state
                == FocusSessionState::Ended
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        let ended =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        assert_eq!(ended.state, FocusSessionState::Ended);
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authority_reconciliation_ends_at_the_exact_goal_and_grant_deadline() {
        let active = start(fixture(Vec::new(), true)).await;
        active.fixture.clock.advance(Duration::from_secs(20 * 60));

        let ended = active
            .fixture
            .runtime
            .reconcile_focus_authority(active.fixture.owner)
            .await
            .unwrap();

        assert_eq!(ended, 1);
        let session =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        assert_eq!(session.state, FocusSessionState::Ended);
        assert_eq!(session.failure_reason.as_deref(), Some("ending_expired"));
    }

    #[tokio::test(start_paused = true)]
    async fn reasoning_scheduler_skips_recovering_and_ended_sessions() {
        let active = start(fixture(
            vec![ModelReasoningOutput::Silence {
                reason_code: "must_not_run".to_owned(),
            }],
            true,
        ))
        .await;
        stop_synthetic_background_tasks(&active);
        let mut recovering =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        let expected = recovering.revision;
        recovering.state = FocusSessionState::Recovering;
        recovering.revision = recovering.revision.saturating_add(1);
        active
            .fixture
            .repository
            .save_focus_session(&recovering, Some(expected))
            .unwrap();
        let mut ended = recovering;
        ended.id = FocusSessionId::new_v7();
        ended.state = FocusSessionState::Ended;
        ended.revision = 1;
        ended.ended_at = Some(active.fixture.clock.now_utc());
        active
            .fixture
            .repository
            .save_focus_session(&ended, None)
            .unwrap();

        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task =
            tokio::spawn(
                async move { runtime.run_reasoning_scheduler(owner, loop_shutdown).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3 * 60)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reasoning_scheduler_skips_missed_ticks_instead_of_catching_up() {
        let active = start(fixture(
            vec![
                ModelReasoningOutput::Silence {
                    reason_code: "first_scheduled_silence".to_owned(),
                },
                ModelReasoningOutput::Silence {
                    reason_code: "second_scheduled_silence".to_owned(),
                },
            ],
            true,
        ))
        .await;
        observe(&active);
        stop_synthetic_background_tasks(&active);
        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task =
            tokio::spawn(
                async move { runtime.run_reasoning_scheduler(owner, loop_shutdown).await },
            );
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        wait_for_model_calls(&active.fixture.model, 1).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);

        active.fixture.clock.advance(Duration::from_secs(5 * 60));
        refresh_workspace_and_observe(&active).await;
        tokio::time::advance(Duration::from_secs(60)).await;
        wait_for_model_calls(&active.fixture.model, 2).await;
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reasoning_scheduler_shutdown_cancels_an_in_flight_cycle() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        stop_synthetic_background_tasks(&active);
        active.fixture.model.hang.store(true, Ordering::SeqCst);
        let shutdown = CancellationToken::new();
        let runtime = active.fixture.runtime.clone();
        let owner = active.fixture.owner;
        let loop_shutdown = shutdown.clone();
        let task =
            tokio::spawn(
                async move { runtime.run_reasoning_scheduler(owner, loop_shutdown).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        wait_for_model_calls(&active.fixture.model, 1).await;
        assert!(
            active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .model_request_in_flight
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("scheduler shutdown remained bounded")
            .unwrap()
            .unwrap();
        wait_for_cancellation_observation(&active.fixture.model.cancellation_observed).await;
        assert!(
            !active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .model_request_in_flight
        );
    }

    #[tokio::test]
    async fn async_phase2_paths_publish_views_without_raw_observations_or_replay_duplicates() {
        let fixture = fixture(vec![candidate()], true);
        let publication = ViewPublication::new(128, Uuid::now_v7());
        fixture
            .runtime
            .attach_publication(publication.clone())
            .unwrap();
        let mut receiver = publication
            .capture(|_, receiver| Ok::<_, ()>(receiver))
            .unwrap();
        let active = start(fixture).await;

        let startup = drain_events(&mut receiver);
        assert_eq!(
            startup
                .iter()
                .filter(|event| matches!(event, CoreEvent::PermissionViewChanged { .. }))
                .count(),
            9,
            "idempotent route, grant, and start replays must not republish"
        );
        assert!(startup.iter().any(|event| matches!(
            event,
            CoreEvent::FocusSessionViewChanged {
                change: FocusSessionViewChange::Requested,
                ..
            }
        )));
        assert!(startup.iter().any(|event| matches!(
            event,
            CoreEvent::FocusSessionViewChanged {
                change: FocusSessionViewChange::Started,
                ..
            }
        )));

        observe(&active);
        let observation_events = drain_events(&mut receiver);
        assert_eq!(observation_events.len(), 1);
        assert!(matches!(
            observation_events[0],
            CoreEvent::CaptureStateChanged { .. }
        ));
        assert!(!format!("{observation_events:?}").contains("Modified"));

        let intervention = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(value) => *value,
            ReasoningCycleResult::Silence { reason_code } => {
                panic!("expected intervention, received silence: {reason_code}")
            }
        };
        let delivery = drain_events(&mut receiver);
        assert!(
            delivery
                .iter()
                .any(|event| matches!(event, CoreEvent::InterventionAvailable { .. }))
        );
        assert!(
            delivery
                .iter()
                .any(|event| matches!(event, CoreEvent::InterventionHistoryChanged { .. }))
        );
        assert!(
            delivery
                .iter()
                .any(|event| matches!(event, CoreEvent::DeliveryChannelViewChanged { .. }))
        );

        active
            .fixture
            .runtime
            .record_feedback(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                intervention.id,
                intervention.revision,
                InterventionOutcome::Accepted,
                None,
            )
            .unwrap();
        assert!(
            drain_events(&mut receiver)
                .iter()
                .any(|event| matches!(event, CoreEvent::InterventionViewChanged { .. }))
        );

        let session =
            find_session(&*active.fixture.runtime.repository, active.fixture.session).unwrap();
        let stopping = active
            .fixture
            .runtime
            .end_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                session.id,
                session.revision,
                EndFocusReason::UserRequested,
            )
            .unwrap();
        active
            .fixture
            .runtime
            .finish_end_focus_session(active.fixture.owner, stopping.id, stopping.revision)
            .await
            .unwrap();
        let ending = drain_events(&mut receiver);
        assert!(ending.iter().any(|event| matches!(
            event,
            CoreEvent::FocusSessionViewChanged {
                change: FocusSessionViewChange::Stopping,
                ..
            }
        )));
        assert!(ending.iter().any(|event| matches!(
            event,
            CoreEvent::FocusSessionViewChanged {
                change: FocusSessionViewChange::Ended,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn phase2_intervention_source_fixture_proves_validated_audited_policy_allow_once() {
        let candidate_id = CandidateId::new_v7();
        assert!(
            validate_candidate(
                NEAR_DEADLINE_QUALIFIED_TEXT,
                "success_condition_unobserved",
                NEAR_DEADLINE_EVIDENCE_SUMMARY,
                8_000,
            )
            .is_ok()
        );
        let active = start(fixture(
            vec![near_deadline_uncertainty_candidate(candidate_id)],
            true,
        ))
        .await;
        let now = active.fixture.clock.now_utc();
        let goal = active
            .fixture
            .repository
            .load_goals(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|goal| {
                goal.id
                    == find_session(&active.fixture.repository, active.fixture.session)
                        .unwrap()
                        .goal_id
            })
            .unwrap();
        let remaining = goal.deadline.unwrap() - now;
        assert_eq!(remaining, time::Duration::minutes(20));
        assert!(
            remaining
                <= time::Duration::try_from(active.fixture.runtime.config.deadline_risk_horizon)
                    .unwrap()
        );

        observe(&active);
        let intervention = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(value) => *value,
            other => panic!("expected one intervention, got {other:?}"),
        };

        assert_eq!(intervention.candidate_id, candidate_id);
        assert_eq!(intervention.candidate_revision, 1);
        assert_eq!(intervention.focus_session_id, active.fixture.session);
        assert_eq!(intervention.goal_id, goal.id);
        assert_eq!(intervention.state, InterventionState::AcceptedByChannel);
        assert_eq!(intervention.user_visible_text, NEAR_DEADLINE_QUALIFIED_TEXT);
        assert_eq!(intervention.reason_code, "success_condition_unobserved");
        assert_eq!(
            intervention.evidence_summary,
            NEAR_DEADLINE_EVIDENCE_SUMMARY
        );
        assert_eq!(intervention.evidence.len(), 1);
        assert_eq!(
            intervention.evidence[0].category,
            DataCategory::WorkspaceActivity
        );
        assert_eq!(
            intervention.evidence[0].role,
            crate::EvidenceRole::SupportsDeadlineRisk
        );
        assert_eq!(intervention.evidence[0].confidence_basis_points, 9_000);

        let model_receipt = active
            .fixture
            .runtime
            .latest_model_request_receipt(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            model_receipt.outcome,
            ModelRequestReceiptOutcome::CompletedStrictCandidate
        );
        assert!(model_receipt.completed_at.is_some());

        let decision = active
            .fixture
            .repository
            .find_policy_decision(intervention.policy_decision_id)
            .unwrap()
            .unwrap();
        assert_eq!(decision.candidate_id, candidate_id);
        assert_eq!(decision.candidate_revision, 1);
        assert_eq!(decision.focus_session_id, active.fixture.session);
        assert_eq!(decision.outcome, PolicyOutcome::Allow);
        assert_eq!(
            decision.reason_codes,
            vec![
                format!("policy_profile:{POLICY_PROFILE_ID}"),
                "policy_checks_passed".to_owned(),
            ]
        );
        assert_eq!(decision.policy_version, POLICY_PROFILE_ID);
        assert_eq!(decision.channel, NATIVE_NOTIFICATION_CHANNEL);
        assert!(decision.policy_trace.is_complete());

        let baseline_audit = active
            .fixture
            .repository
            .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
            .unwrap();
        let significance_audits: Vec<_> = baseline_audit
            .iter()
            .filter(|record| record.kind == AuditKind::SignificanceDecision)
            .collect();
        assert_eq!(significance_audits.len(), 1);
        let significance_audit = significance_audits[0];
        assert_eq!(
            significance_audit.subject_id,
            active.fixture.session.as_uuid()
        );
        assert_eq!(
            significance_audit.reason_codes,
            vec!["significance_policy_passed".to_owned()]
        );
        assert_eq!(
            significance_audit.evidence_categories,
            BTreeSet::from([DataCategory::WorkspaceActivity])
        );
        assert!(
            significance_audit
                .policy_trace
                .as_ref()
                .is_some_and(PolicyTrace::is_complete)
        );

        let decision_audits: Vec<_> = baseline_audit
            .iter()
            .filter(|record| record.kind == AuditKind::InterventionDecision)
            .collect();
        assert_eq!(decision_audits.len(), 1);
        let decision_audit = decision_audits[0];
        assert_eq!(decision_audit.subject_id, candidate_id.as_uuid());
        assert_eq!(decision_audit.reason_codes, decision.reason_codes);
        assert_eq!(
            decision_audit.evidence_categories,
            BTreeSet::from([DataCategory::WorkspaceActivity])
        );
        assert_eq!(decision_audit.evidence_age_ms, Some(0));
        assert_eq!(decision_audit.confidence_basis_points, Some(8_000));
        assert_eq!(
            decision_audit.policy_trace.as_ref(),
            Some(&decision.policy_trace)
        );
        let policy_audit_json =
            serde_json::to_string(&(significance_audit, decision_audit, &decision.policy_trace))
                .unwrap();
        assert!(!policy_audit_json.contains(NEAR_DEADLINE_QUALIFIED_TEXT));
        assert!(!policy_audit_json.contains(NEAR_DEADLINE_EVIDENCE_SUMMARY));
        assert!(!policy_audit_json.contains("synthetic release ledger"));
        assert!(
            active
                .fixture
                .notification
                .audit_seen_before_delivery
                .load(Ordering::SeqCst)
        );
        assert!(
            active
                .fixture
                .notification
                .attempt_marker_seen_before_delivery
                .load(Ordering::SeqCst)
        );
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap(),
            vec![intervention]
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_owner_state(active.fixture.owner)
                .unwrap()
                .policy_decisions,
            vec![decision]
        );

        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "no_relevant_state_change"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_owner_state(active.fixture.owner)
                .unwrap()
                .policy_decisions
                .len(),
            1
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
                .unwrap(),
            baseline_audit
        );
    }

    #[tokio::test]
    async fn full_loop_records_audited_delivery_and_ephemeral_correction() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        let intervention = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(value) => value,
            other => panic!("expected an intervention, got {other:?}"),
        };
        assert_eq!(intervention.state, InterventionState::AcceptedByChannel);
        let model_receipt = active
            .fixture
            .runtime
            .latest_model_request_receipt(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            model_receipt.outcome,
            ModelRequestReceiptOutcome::CompletedStrictCandidate
        );
        assert_eq!(
            model_receipt.model_route_approval_id,
            find_session(&active.fixture.repository, active.fixture.session)
                .unwrap()
                .model_route_approval_id
        );
        assert_eq!(model_receipt.model_route_revision, 1);
        assert!(model_receipt.completed_at.is_some());
        assert!(
            active
                .fixture
                .notification
                .audit_seen_before_delivery
                .load(Ordering::SeqCst)
        );
        assert!(
            active
                .fixture
                .notification
                .attempt_marker_seen_before_delivery
                .load(Ordering::SeqCst)
        );
        let policy_decision = active
            .fixture
            .repository
            .find_policy_decision(intervention.policy_decision_id)
            .unwrap()
            .unwrap();
        let expected_preferences_revision = active
            .fixture
            .repository
            .load_preferences(active.fixture.owner)
            .unwrap()
            .unwrap()
            .revision;
        assert!(policy_decision.policy_trace.is_complete());
        assert_eq!(
            policy_decision.policy_trace.policy_profile_id,
            POLICY_PROFILE_ID
        );
        assert_eq!(
            policy_decision.policy_trace.user_preferences_revision,
            expected_preferences_revision
        );
        let policy_audits = active
            .fixture
            .repository
            .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
            .unwrap();
        assert!(policy_audits.iter().any(|record| {
            record.kind == AuditKind::SignificanceDecision
                && record
                    .policy_trace
                    .as_ref()
                    .is_some_and(PolicyTrace::is_complete)
        }));
        assert!(policy_audits.iter().any(|record| {
            record.kind == AuditKind::InterventionDecision
                && record.subject_id == policy_decision.candidate_id.as_uuid()
                && record.policy_trace.as_ref() == Some(&policy_decision.policy_trace)
        }));

        let preferences_before_correction = active
            .fixture
            .repository
            .load_preferences(active.fixture.owner)
            .unwrap();
        let corrected = active
            .fixture
            .runtime
            .record_feedback(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                intervention.id,
                intervention.revision,
                InterventionOutcome::Corrected,
                Some(SensitiveText::new(
                    "The synthetic fixture is waiting on a local checksum, not review.",
                )),
            )
            .unwrap();
        assert_eq!(
            corrected.correction_summary.as_deref(),
            Some("current_context_corrected")
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_preferences(active.fixture.owner)
                .unwrap(),
            preferences_before_correction,
        );
        let durable = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap();
        assert!(
            !serde_json::to_string(&durable)
                .unwrap()
                .contains("waiting on a local checksum")
        );
        let bounded_audit = serde_json::to_string(
            &active
                .fixture
                .repository
                .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
                .unwrap(),
        )
        .unwrap();
        assert!(!bounded_audit.contains("release ledger"));
        assert!(!bounded_audit.contains("selected-workspace activity"));
        let bounded_policy = serde_json::to_string(
            &active
                .fixture
                .repository
                .load_owner_state(active.fixture.owner)
                .unwrap()
                .policy_decisions,
        )
        .unwrap();
        assert!(!bounded_policy.contains("release ledger"));
        assert!(!bounded_policy.contains("selected-workspace activity"));
    }

    #[tokio::test]
    async fn feedback_is_rejected_before_an_eligible_terminal_delivery_state() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected queued intervention, got {other:?}"),
        };
        assert_eq!(queued.state, InterventionState::Queued);
        let error = active
            .fixture
            .runtime
            .record_feedback(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                queued.id,
                queued.revision,
                InterventionOutcome::Accepted,
                None,
            )
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        assert_eq!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()[0],
            queued
        );
    }

    #[tokio::test]
    async fn authenticated_feedback_can_resolve_a_delivery_unknown_record() {
        let active = start(fixture(vec![candidate()], true)).await;
        *active.fixture.notification.acknowledgement.lock().unwrap() =
            ChannelAcknowledgement::DeliveryUnknown;
        observe(&active);
        let unknown = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected delivery-unknown intervention, got {other:?}"),
        };
        assert_eq!(unknown.state, InterventionState::DeliveryUnknown);
        let accepted = active
            .fixture
            .runtime
            .record_feedback(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                unknown.id,
                unknown.revision,
                InterventionOutcome::Accepted,
                None,
            )
            .unwrap();
        assert_eq!(accepted.outcome, InterventionOutcome::Accepted);
        assert!(accepted.outcome_at.is_some());
    }

    #[tokio::test]
    async fn foreground_churn_is_silent_without_another_significance_evaluation() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Intervention(_)
        ));
        let evaluated_before_churn = active
            .fixture
            .repository
            .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == AuditKind::SignificanceDecision)
            .count();
        assert_eq!(evaluated_before_churn, 1);
        observe_foreground_churn(&active).await;
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "no_relevant_state_change"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
        let evaluated_after_churn = active
            .fixture
            .repository
            .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == AuditKind::SignificanceDecision)
            .count();
        assert_eq!(evaluated_after_churn, evaluated_before_churn);
        active.fixture.clock.advance(Duration::from_secs(5 * 60));
        refresh_workspace_and_observe(&active).await;
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "intervention_cooldown"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn significance_and_model_cooldowns_are_deterministic() {
        let active = start(fixture(
            vec![
                ModelReasoningOutput::Silence {
                    reason_code: "first_evaluation_was_silent".to_owned(),
                },
                ModelReasoningOutput::Silence {
                    reason_code: "second_evaluation_was_silent".to_owned(),
                },
            ],
            true,
        ))
        .await;
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "first_evaluation_was_silent"
        ));

        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "significance_rate_limited"
        ));
        active.fixture.clock.advance(Duration::from_secs(60));
        refresh_workspace_and_observe(&active).await;
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "model_request_cooldown"
        ));
        active.fixture.clock.advance(Duration::from_secs(4 * 60));
        refresh_workspace_and_observe(&active).await;
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "second_evaluation_was_silent"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn model_budget_allows_only_one_in_flight_and_twelve_per_rolling_hour() {
        let active = start(fixture(Vec::new(), true)).await;
        let permit = active
            .fixture
            .runtime
            .begin_model_request(active.fixture.session, 12)
            .unwrap()
            .unwrap();
        assert!(matches!(
            active
                .fixture
                .runtime
                .begin_model_request(active.fixture.session, 12)
                .unwrap(),
            Err("model_request_in_flight")
        ));
        drop(permit);
        assert!(matches!(
            active
                .fixture
                .runtime
                .begin_model_request(active.fixture.session, 12)
                .unwrap(),
            Err("model_request_cooldown")
        ));

        active.fixture.clock.advance(Duration::from_secs(3_599));
        {
            let mut state = active.fixture.runtime.ephemeral.lock().unwrap();
            let session = state.sessions.get_mut(&active.fixture.session).unwrap();
            session.model_request_history = VecDeque::from(vec![Duration::ZERO; 12]);
            session.model_request_in_flight = false;
        }
        assert!(matches!(
            active
                .fixture
                .runtime
                .begin_model_request(active.fixture.session, 12)
                .unwrap(),
            Err("model_hourly_budget_exhausted")
        ));
    }

    #[tokio::test]
    async fn explicit_mute_dnd_and_channel_preferences_fail_closed_before_model_use() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.proactive_interventions_muted = true;
        let saved = active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "interventions_muted"
        ));

        let mut preferences = saved;
        let expected = preferences.revision;
        preferences.proactive_interventions_muted = false;
        preferences.do_not_disturb_windows = vec![DoNotDisturbWindow {
            start_minute_local: 9 * 60,
            end_minute_local: 11 * 60,
            utc_offset_minutes: 0,
        }];
        let saved = active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "do_not_disturb"
        ));

        let mut preferences = saved;
        let expected = preferences.revision;
        preferences.do_not_disturb_windows.clear();
        preferences.allowed_delivery_channels.clear();
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "delivery_channel_not_allowed"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proactive_interventions_require_explicit_opt_in_before_model_use() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.proactive_interventions_enabled = false;
        let disabled = active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();

        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "proactive_interventions_disabled"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);

        let mut preferences = disabled;
        let expected = preferences.revision;
        preferences.proactive_interventions_enabled = true;
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();

        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Intervention(_)
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disabling_proactive_interventions_cancels_an_in_flight_model_without_stopping_observation()
     {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        active.fixture.model.hang.store(true, Ordering::SeqCst);
        let runtime = active.fixture.runtime.clone();
        let session_id = active.fixture.session;
        let cycle = tokio::spawn(async move { runtime.run_reasoning_cycle(session_id).await });
        wait_for_model_calls(&active.fixture.model, 1).await;

        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.proactive_interventions_enabled = false;
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();

        wait_for_cancellation_observation(&active.fixture.model.cancellation_observed).await;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), cycle)
                .await
                .expect("the cancelled model cycle remained bounded")
                .unwrap()
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "reasoning_cancelled_or_timed_out"
        ));
        let ephemeral = active.fixture.runtime.ephemeral.lock().unwrap();
        let session = ephemeral.sessions.get(&active.fixture.session).unwrap();
        assert!(!session.cancellation.is_cancelled());
        assert!(session.proactive_cancellation.is_cancelled());
        assert!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn equally_permissive_preference_revision_rotates_the_in_flight_token() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        active.fixture.model.hang.store(true, Ordering::SeqCst);
        let runtime = active.fixture.runtime.clone();
        let session_id = active.fixture.session;
        let cycle = tokio::spawn(async move { runtime.run_reasoning_cycle(session_id).await });
        wait_for_model_calls(&active.fixture.model, 1).await;

        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.preferred_form_of_address = Some("Synthetic operator".to_owned());
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();

        wait_for_cancellation_observation(&active.fixture.model.cancellation_observed).await;
        assert!(matches!(
            cycle.await.unwrap().unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "reasoning_cancelled_or_timed_out"
        ));
        let ephemeral = active.fixture.runtime.ephemeral.lock().unwrap();
        let session = ephemeral.sessions.get(&active.fixture.session).unwrap();
        assert!(!session.cancellation.is_cancelled());
        assert!(
            !session.proactive_cancellation.is_cancelled(),
            "a successful permissive revision must rotate fresh authority"
        );
        assert_eq!(
            session
                .latest_model_request_receipt
                .as_ref()
                .unwrap()
                .outcome,
            ModelRequestReceiptOutcome::Cancelled
        );
    }

    #[tokio::test]
    async fn goal_edit_cancels_an_in_flight_model_before_the_revision_commit() {
        let active = start(fixture(Vec::new(), true)).await;
        observe(&active);
        active.fixture.model.hang.store(true, Ordering::SeqCst);
        let runtime = active.fixture.runtime.clone();
        let session_id = active.fixture.session;
        let cycle = tokio::spawn(async move { runtime.run_reasoning_cycle(session_id).await });
        wait_for_model_calls(&active.fixture.model, 1).await;

        let goal = active
            .fixture
            .runtime
            .get_goal(active.fixture.owner, active.grants[0].goal_id)
            .unwrap();
        active
            .fixture
            .runtime
            .update_goal(
                ClientAssurance::PrivateCapabilityBound,
                UpdateGoal {
                    actor: active.fixture.owner,
                    id: goal.id,
                    expected_revision: goal.revision,
                    patch: GoalPatch {
                        title: Some("Revised synthetic focus".to_owned()),
                        success_statement: None,
                        deadline: None,
                    },
                },
            )
            .unwrap();

        wait_for_cancellation_observation(&active.fixture.model.cancellation_observed).await;
        assert!(matches!(
            cycle.await.unwrap().unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "reasoning_cancelled_or_timed_out"
        ));
        let ephemeral = active.fixture.runtime.ephemeral.lock().unwrap();
        assert!(
            ephemeral
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .proactive_cancellation
                .is_cancelled(),
            "the old session cannot be rearmed against a new goal revision"
        );
    }

    #[tokio::test]
    async fn zero_user_intervention_cap_avoids_model_cost() {
        let active = start(fixture(vec![candidate()], true)).await;
        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.maximum_interventions_per_session = 0;
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "session_intervention_cap"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn goal_revision_change_fences_the_old_session_before_model_use() {
        let active = start(fixture(vec![candidate()], true)).await;
        let goal = active
            .fixture
            .runtime
            .get_goal(active.fixture.owner, active.grants[0].goal_id)
            .unwrap();
        active
            .fixture
            .runtime
            .update_goal(
                ClientAssurance::PrivateCapabilityBound,
                UpdateGoal {
                    actor: active.fixture.owner,
                    id: goal.id,
                    expected_revision: goal.revision,
                    patch: GoalPatch {
                        title: None,
                        success_statement: None,
                        deadline: Some(Some(
                            active.fixture.clock.now_utc() + time::Duration::hours(2),
                        )),
                    },
                },
            )
            .unwrap();
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "reasoning_authority_unavailable"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_evidence_becomes_silence_without_calling_the_model() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        active.fixture.clock.advance(Duration::from_secs(31));
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "no_fresh_significant_evidence"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn slow_audit_ack_denies_delivery_without_a_partial_decision() {
        let config = SecondMindConfig {
            audit_append_deadline: Duration::from_millis(1),
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(vec![candidate()], true, config)).await;
        active
            .fixture
            .repository
            .set_decision_commit_delay(Some(Duration::from_millis(50)));
        observe(&active);
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "audit_acknowledgement_unavailable"
        ));
        let snapshot = active
            .fixture
            .repository
            .load_owner_state(active.fixture.owner)
            .unwrap();
        assert!(snapshot.policy_decisions.is_empty());
        assert!(snapshot.interventions.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
        assert!(
            !active
                .fixture
                .repository
                .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 100)
                .unwrap()
                .iter()
                .any(|audit| audit.kind == AuditKind::InterventionDecision)
        );
    }

    #[tokio::test]
    async fn atomic_decision_revision_conflict_leaves_no_partial_policy_or_audit() {
        let active = start(fixture(vec![candidate()], true)).await;
        observe(&active);
        let intervention = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected delivered intervention, got {other:?}"),
        };
        let delivered = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|value| value.id == intervention.id)
            .unwrap();
        let delivered_decision = active
            .fixture
            .repository
            .find_policy_decision(delivered.policy_decision_id)
            .unwrap()
            .unwrap();
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();
        let original = queue_synthetic_clone(
            &active,
            &delivered,
            &delivered_decision,
            notification_grant,
            active.fixture.session,
        );
        let mut decision = active
            .fixture
            .repository
            .find_policy_decision(original.policy_decision_id)
            .unwrap()
            .unwrap();
        decision.id = PolicyDecisionId::new_v7();
        let audit = active.fixture.runtime.build_audit_record(
            active.fixture.owner,
            AuditKind::InterventionDecision,
            decision.candidate_id.as_uuid(),
            AuditDetails::new(decision.reason_codes.clone(), BTreeSet::new())
                .with_policy_trace(decision.policy_trace.clone()),
        );
        let mut attempted = original.clone();
        attempted.policy_decision_id = decision.id;
        let stale_expected = original.revision.saturating_add(99);
        attempted.revision = stale_expected.saturating_add(1);
        attempted.updated_at = active.fixture.clock.now_utc();
        let write = InterventionDecisionWrite {
            decision: decision.clone(),
            audit: audit.clone(),
            intervention: Some(attempted),
            expected_intervention_revision: Some(stale_expected),
        };
        assert_eq!(
            active
                .fixture
                .repository
                .commit_intervention_decision(&write)
                .await
                .unwrap_err()
                .kind,
            RepositoryErrorKind::Conflict
        );
        assert!(
            active
                .fixture
                .repository
                .find_policy_decision(decision.id)
                .unwrap()
                .is_none()
        );
        assert!(
            !active
                .fixture
                .repository
                .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
                .unwrap()
                .iter()
                .any(|record| record.id == audit.id)
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()
                .into_iter()
                .find(|value| value.id == original.id)
                .unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn model_deadline_cancels_the_in_flight_request_without_a_candidate() {
        let config = SecondMindConfig {
            model_deadline: Duration::from_millis(1),
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(vec![candidate()], true, config)).await;
        active.fixture.model.hang.store(true, Ordering::SeqCst);
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "reasoning_cancelled_or_timed_out"
        ));
        assert_eq!(active.fixture.model.calls.load(Ordering::SeqCst), 1);
        let receipt = active
            .fixture
            .runtime
            .latest_model_request_receipt(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.outcome,
            ModelRequestReceiptOutcome::DeadlineExceeded
        );
        assert!(receipt.completed_at.is_some());
        assert!(
            !active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .model_request_in_flight
        );
        assert!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn latest_model_request_receipt_is_private_ephemeral_and_route_exact() {
        let active = start(fixture(
            vec![ModelReasoningOutput::Silence {
                reason_code: "synthetic_strict_silence".to_owned(),
            }],
            true,
        ))
        .await;
        assert!(
            active
                .fixture
                .runtime
                .latest_model_request_receipt(
                    ClientAssurance::PrivateCapabilityBound,
                    active.fixture.owner,
                    active.fixture.session,
                )
                .unwrap()
                .is_none()
        );
        assert!(
            active
                .fixture
                .runtime
                .latest_model_request_receipt(
                    ClientAssurance::Diagnostic,
                    active.fixture.owner,
                    active.fixture.session,
                )
                .is_err()
        );

        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "synthetic_strict_silence"
        ));
        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let receipt = active
            .fixture
            .runtime
            .latest_model_request_receipt(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.focus_session_id, session.id);
        assert_eq!(
            receipt.model_route_approval_id,
            session.model_route_approval_id
        );
        assert_eq!(receipt.model_route_revision, 1);
        assert_eq!(
            receipt.outcome,
            ModelRequestReceiptOutcome::CompletedStrictSilence
        );
        assert!(receipt.completed_at.is_some());

        let restarted = SecondMindRuntime::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(active.fixture.repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: Arc::new(UnavailableObservationPort),
                model: Arc::new(UnavailableModelGateway),
                notification: Arc::new(UnavailableNotificationPort),
                native_status: Arc::new(UnavailableNativeStatusPort),
                emergency_control: Arc::new(UnavailableEmergencyControlPort),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        assert!(
            restarted
                .latest_model_request_receipt(
                    ClientAssurance::PrivateCapabilityBound,
                    active.fixture.owner,
                    active.fixture.session,
                )
                .unwrap()
                .is_none(),
            "a daemon restart must not reconstruct an ephemeral model receipt"
        );
    }

    #[tokio::test]
    async fn invalid_model_candidate_closes_as_failed_never_strict_candidate() {
        let mut invalid_candidate = candidate();
        let ModelReasoningOutput::Candidate {
            user_visible_text, ..
        } = &mut invalid_candidate
        else {
            unreachable!("the synthetic candidate helper returns a candidate")
        };
        user_visible_text.clear();
        let active = start(fixture(vec![invalid_candidate], true)).await;
        observe(&active);

        let error = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::InvalidArgument);
        let receipt = active
            .fixture
            .runtime
            .latest_model_request_receipt(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.outcome, ModelRequestReceiptOutcome::Failed);
        assert!(receipt.completed_at.is_some());
        assert!(
            active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn model_receipt_start_racing_session_end_never_recreates_ephemeral_state() {
        let active = start(fixture(Vec::new(), true)).await;
        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let route = find_route(
            &active.fixture.repository,
            active.fixture.owner,
            session.model_route_approval_id,
        )
        .unwrap();
        let stopping = active
            .fixture
            .runtime
            .end_focus_session(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                session.id,
                session.revision,
                EndFocusReason::UserRequested,
            )
            .unwrap();
        active
            .fixture
            .runtime
            .finish_end_focus_session(active.fixture.owner, stopping.id, stopping.revision)
            .await
            .unwrap();

        assert!(
            !active
                .fixture
                .runtime
                .record_model_request_started(ModelRequestReceipt {
                    request_id: Uuid::now_v7(),
                    focus_session_id: session.id,
                    model_route_approval_id: route.id,
                    model_route_revision: route.revision,
                    started_at: active.fixture.clock.now_utc(),
                    completed_at: None,
                    outcome: ModelRequestReceiptOutcome::InFlight,
                })
                .unwrap()
        );
        assert!(
            !active
                .fixture
                .runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session.id)
        );
        assert!(
            active
                .fixture
                .runtime
                .latest_model_request_receipt(
                    ClientAssurance::PrivateCapabilityBound,
                    active.fixture.owner,
                    session.id,
                )
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn notification_timeout_is_terminal_delivery_unknown_and_never_queued() {
        let config = SecondMindConfig {
            notification_attempt_deadline: Duration::from_millis(1),
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(vec![candidate()], true, config)).await;
        active
            .fixture
            .notification
            .hang
            .store(true, Ordering::SeqCst);
        observe(&active);
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::DeliveryUnknown
        ));
        assert!(
            active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 1);
        wait_for_cancellation_observation(&active.fixture.notification.cancellation_observed).await;
    }

    #[tokio::test]
    async fn interrupted_direct_delivery_recovers_as_unknown_without_resubmission() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let decision = active
            .fixture
            .repository
            .find_policy_decision(queued.policy_decision_id)
            .unwrap()
            .unwrap();
        let mut direct = allowed_synthetic_clone(&active, &queued, &decision);
        let expected = direct.revision;
        direct.state = InterventionState::Delivering;
        direct.revision += 1;
        direct.updated_at = active.fixture.clock.now_utc();
        active
            .fixture
            .runtime
            .persist_intervention_transition(
                &direct,
                expected,
                AuditKind::InterventionDelivery,
                AuditDetails::new(vec!["delivery_attempt_started".to_owned()], BTreeSet::new())
                    .with_policy_trace(decision.policy_trace.clone()),
                None,
            )
            .unwrap();

        let recovered = active
            .fixture
            .runtime
            .reconcile_interrupted_deliveries(active.fixture.owner)
            .unwrap();
        let recovered_direct = recovered
            .iter()
            .find(|intervention| intervention.id == direct.id)
            .unwrap();
        assert_eq!(recovered_direct.state, InterventionState::DeliveryUnknown);
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
        assert!(
            !active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .iter()
                .any(|delivery| delivery.intervention_id == direct.id)
        );
        assert!(
            active
                .fixture
                .runtime
                .reconcile_interrupted_deliveries(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
        let audit = active
            .fixture
            .repository
            .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
            .unwrap();
        assert!(audit.iter().any(|record| {
            record.subject_id == direct.id.as_uuid()
                && record.kind == AuditKind::InterventionDelivery
                && record
                    .reason_codes
                    .iter()
                    .any(|reason| reason == "delivery_unknown_after_restart")
        }));
        assert!(
            !serde_json::to_string(&audit)
                .unwrap()
                .contains(&direct.user_visible_text)
        );
    }

    #[tokio::test]
    async fn orphan_allowed_intervention_is_scrubbed_without_submission_on_recovery() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let decision = active
            .fixture
            .repository
            .find_policy_decision(queued.policy_decision_id)
            .unwrap()
            .unwrap();
        let orphan = allowed_synthetic_clone(&active, &queued, &decision);

        let recovered = active
            .fixture
            .runtime
            .reconcile_interrupted_deliveries(active.fixture.owner)
            .unwrap();
        let recovered_orphan = recovered
            .iter()
            .find(|intervention| intervention.id == orphan.id)
            .unwrap();
        assert_eq!(recovered_orphan.state, InterventionState::Cancelled);
        assert_eq!(recovered_orphan.outcome, InterventionOutcome::Expired);
        assert!(recovered_orphan.user_visible_text.is_empty());
        assert!(recovered_orphan.evidence_summary.is_empty());
        assert!(recovered_orphan.evidence.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn restart_scrubs_a_queued_pair_when_its_durable_grant_revision_is_stale() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let mut notification_grant = active
            .fixture
            .repository
            .load_grants(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();
        let expected_grant_revision = notification_grant.revision;
        notification_grant.revision = notification_grant.revision.saturating_add(1);
        notification_grant.purpose = "Synthetic post-crash authority revision".to_owned();
        active
            .fixture
            .repository
            .save_grant(&notification_grant, Some(expected_grant_revision))
            .unwrap();

        let restarted = SecondMindRuntime::new(
            active.fixture.runtime.config.clone(),
            SecondMindPorts {
                repository: Arc::new(active.fixture.repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: active.fixture.observation.clone(),
                model: active.fixture.model.clone(),
                notification: active.fixture.notification.clone(),
                native_status: active.fixture.status.clone(),
                emergency_control: active.fixture.emergency.clone(),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        let changed = restarted
            .reconcile_interrupted_deliveries(active.fixture.owner)
            .unwrap();

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].id, queued.id);
        assert_eq!(changed[0].state, InterventionState::Cancelled);
        assert_eq!(changed[0].outcome, InterventionOutcome::Expired);
        assert_eq!(
            changed[0].reason_code,
            "queued_authority_invalid_after_restart"
        );
        assert!(changed[0].user_visible_text.is_empty());
        let delivery = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|delivery| delivery.intervention_id == queued.id)
            .unwrap();
        assert_eq!(delivery.state, OutboxState::Cancelled);
        assert!(delivery.user_visible_text.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn queued_interventions_reconcile_terminal_outbox_states_without_retry() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let base = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let decision = active
            .fixture
            .repository
            .find_policy_decision(base.policy_decision_id)
            .unwrap()
            .unwrap();
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();
        let mut interventions = vec![base.clone()];
        for _ in 0..4 {
            interventions.push(queue_synthetic_clone(
                &active,
                &base,
                &decision,
                notification_grant,
                active.fixture.session,
            ));
        }
        let terminal_states = [
            OutboxState::AcceptedByChannel,
            OutboxState::DeliveryUnknown,
            OutboxState::DeliveryFailed,
            OutboxState::Expired,
            OutboxState::Cancelled,
        ];

        for (intervention, terminal_state) in interventions.iter().zip(terminal_states) {
            let mut delivery = active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .into_iter()
                .find(|delivery| delivery.intervention_id == intervention.id)
                .unwrap();
            if matches!(
                terminal_state,
                OutboxState::AcceptedByChannel
                    | OutboxState::DeliveryUnknown
                    | OutboxState::DeliveryFailed
            ) {
                delivery.state = OutboxState::Delivering;
                delivery.attempt_count += 1;
                delivery.last_attempt_at = Some(active.fixture.clock.now_utc());
                active.fixture.repository.save_delivery(&delivery).unwrap();
            }
            delivery.state = terminal_state;
            delivery.user_visible_text.clear();
            active.fixture.repository.save_delivery(&delivery).unwrap();
        }

        let reconciled = active
            .fixture
            .runtime
            .reconcile_interrupted_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(reconciled.len(), terminal_states.len());
        let durable_interventions = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap();
        let durable_deliveries = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        for ((intervention, outbox_state), expected_intervention_state) in
            interventions.iter().zip(terminal_states).zip([
                InterventionState::AcceptedByChannel,
                InterventionState::DeliveryUnknown,
                InterventionState::DeliveryFailed,
                InterventionState::Expired,
                InterventionState::Cancelled,
            ])
        {
            assert_eq!(
                durable_interventions
                    .iter()
                    .find(|durable| durable.id == intervention.id)
                    .unwrap()
                    .state,
                expected_intervention_state
            );
            let delivery = durable_deliveries
                .iter()
                .find(|delivery| delivery.intervention_id == intervention.id)
                .unwrap();
            assert_eq!(delivery.state, outbox_state);
            assert!(delivery.user_visible_text.is_empty());
        }
        assert!(
            active
                .fixture
                .runtime
                .revalidate_pending_deliveries(active.fixture.owner)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_mute_cancels_an_in_flight_notification_and_scrubs_the_intervention() {
        let active = start(fixture(vec![candidate()], true)).await;
        active
            .fixture
            .notification
            .hang
            .store(true, Ordering::SeqCst);
        observe(&active);
        let runtime = active.fixture.runtime.clone();
        let session_id = active.fixture.session;
        let cycle = tokio::spawn(async move { runtime.run_reasoning_cycle(session_id).await });
        wait_for_notification_calls(&active.fixture.notification, 1).await;

        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let muted = active
            .fixture
            .runtime
            .set_interventions_muted(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
                session.revision,
                true,
            )
            .await
            .unwrap();
        assert!(muted.muted);
        wait_for_cancellation_observation(&active.fixture.notification.cancellation_observed).await;
        let result = tokio::time::timeout(Duration::from_secs(1), cycle)
            .await
            .expect("the muted notification cycle remained bounded")
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Cancelled
                    && intervention.user_visible_text.is_empty()
                    && intervention.evidence_summary.is_empty()
                    && intervention.evidence.is_empty()
        ));
        {
            let ephemeral = active.fixture.runtime.ephemeral.lock().unwrap();
            let session = ephemeral.sessions.get(&active.fixture.session).unwrap();
            assert!(!session.cancellation.is_cancelled());
            assert!(session.proactive_cancellation.is_cancelled());
        }
        let unmuted = active
            .fixture
            .runtime
            .set_interventions_muted(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                active.fixture.session,
                muted.revision,
                false,
            )
            .await
            .unwrap();
        assert!(!unmuted.muted);
        let ephemeral = active.fixture.runtime.ephemeral.lock().unwrap();
        assert!(
            !ephemeral
                .sessions
                .get(&active.fixture.session)
                .unwrap()
                .proactive_cancellation
                .is_cancelled()
        );
    }

    #[tokio::test]
    async fn unavailable_channel_queues_then_fresh_recovery_delivers_once() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Queued
        ));
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);
        let recovered = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, InterventionState::AcceptedByChannel);
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 1);
        let outbox = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(outbox[0].state, OutboxState::AcceptedByChannel);
        assert!(outbox[0].user_visible_text.is_empty());
    }

    #[tokio::test]
    async fn authority_change_during_recovered_failed_delivery_cancels_and_scrubs() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap()
            .clone();
        *active
            .fixture
            .notification
            .revoke_on_delivery
            .lock()
            .unwrap() = Some(notification_grant);
        *active.fixture.notification.acknowledgement.lock().unwrap() =
            ChannelAcknowledgement::DeliveryFailed;
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);

        let changed = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].id, queued.id);
        assert_eq!(changed[0].state, InterventionState::Cancelled);
        assert_eq!(changed[0].outcome, InterventionOutcome::Expired);
        assert_eq!(
            changed[0].reason_code,
            "authority_changed_during_failed_delivery"
        );
        assert!(changed[0].user_visible_text.is_empty());
        assert!(changed[0].evidence_summary.is_empty());
        assert!(changed[0].evidence.is_empty());
        let delivery = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|delivery| delivery.intervention_id == queued.id)
            .unwrap();
        assert_eq!(delivery.state, OutboxState::Cancelled);
        assert!(delivery.user_visible_text.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn authority_change_after_revalidation_cancels_without_repointing_the_queued_record() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let original_decision_id = queued.policy_decision_id;
        active
            .fixture
            .runtime
            .set_after_recovery_revalidation_commit_hook({
                let repository = active.fixture.repository.clone();
                let clock = active.fixture.clock.clone();
                let session_id = active.fixture.session;
                move || {
                    let mut session = find_session(&repository, session_id).unwrap();
                    let expected = session.revision;
                    session.muted = true;
                    session.revision = session.revision.saturating_add(1);
                    session.updated_at = clock.now_utc();
                    repository
                        .save_focus_session(&session, Some(expected))
                        .unwrap();
                }
            });
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);

        let changed = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].state, InterventionState::Cancelled);
        assert_eq!(changed[0].outcome, InterventionOutcome::Expired);
        assert!(changed[0].user_visible_text.is_empty());
        assert_ne!(changed[0].policy_decision_id, original_decision_id);
        let delivery = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|delivery| delivery.intervention_id == queued.id)
            .unwrap();
        assert_eq!(delivery.state, OutboxState::Cancelled);
        assert_eq!(delivery.policy_decision_id, original_decision_id);
        assert!(delivery.user_visible_text.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mute_between_unavailable_check_and_enqueue_cancels_the_late_queue() {
        let active = start(fixture(vec![candidate()], false)).await;
        let runtime = active.fixture.runtime.clone();
        let repository = active.fixture.repository.clone();
        let session_id = active.fixture.session;
        runtime.set_before_queue_commit_hook({
            let runtime = runtime.clone();
            move || {
                runtime.cancel_proactive_cancellation(session_id).unwrap();
                let mut session = find_session(&repository, session_id).unwrap();
                let expected = session.revision;
                session.muted = true;
                session.revision = session.revision.saturating_add(1);
                session.updated_at = OffsetDateTime::now_utc();
                repository
                    .save_focus_session(&session, Some(expected))
                    .unwrap();
            }
        });
        observe(&active);

        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "authority_changed_after_enqueue"
        ));
        let intervention = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(intervention.state, InterventionState::Cancelled);
        assert!(intervention.user_visible_text.is_empty());
        let delivery = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(delivery.state, OutboxState::Cancelled);
        assert!(delivery.user_visible_text.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn disabling_proactive_interventions_immediately_cancels_and_scrubs_queued_delivery() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Queued
        ));

        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.proactive_interventions_enabled = false;
        active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);

        let interventions = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap();
        assert_eq!(interventions.len(), 1);
        assert_eq!(interventions[0].state, InterventionState::Cancelled);
        assert_eq!(interventions[0].outcome, InterventionOutcome::Expired);
        assert_eq!(
            interventions[0].reason_code,
            "proactive_interventions_disabled"
        );
        assert!(interventions[0].user_visible_text.is_empty());
        assert!(interventions[0].evidence_summary.is_empty());
        assert!(interventions[0].evidence.is_empty());
        let outbox = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].state, OutboxState::Cancelled);
        assert!(outbox[0].user_visible_text.is_empty());

        let changed = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();
        assert!(changed.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn any_preferences_revision_change_invalidates_a_queued_policy_decision() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        assert!(matches!(
            active
                .fixture
                .runtime
                .run_reasoning_cycle(active.fixture.session)
                .await
                .unwrap(),
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Queued
        ));

        let mut preferences = active
            .fixture
            .runtime
            .user_preferences(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let expected = preferences.revision;
        preferences.preferred_form_of_address = Some("Synthetic operator".to_owned());
        let updated = active
            .fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                preferences,
                Some(expected),
            )
            .unwrap();
        assert_eq!(updated.revision, expected + 1);
        assert!(updated.proactive_interventions_enabled);
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);

        let changed = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();
        assert!(changed.is_empty());
        let durable = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap();
        assert_eq!(durable[0].state, InterventionState::Cancelled);
        assert!(durable[0].user_visible_text.is_empty());
        let outbox = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(outbox[0].state, OutboxState::Cancelled);
        assert!(outbox[0].user_visible_text.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_queued_item_becomes_scrubbed_missed_history() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        active.fixture.clock.advance(Duration::from_secs(31));
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);
        let recovered = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, InterventionState::Expired);
        assert_eq!(recovered[0].outcome, InterventionOutcome::Expired);
        assert_eq!(recovered[0].reason_code, "missed_intervention");
        assert!(recovered[0].user_visible_text.is_empty());
        assert!(recovered[0].evidence_summary.is_empty());
        assert!(recovered[0].evidence.is_empty());
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
        let outbox = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(outbox[0].state, OutboxState::Expired);
        assert!(outbox[0].user_visible_text.is_empty());
    }

    #[tokio::test]
    async fn phase2_retention_outbox_scrubs_at_exact_actionability_boundary() {
        const INTERVENTION_MARKER: &str = "Synthetic retention intervention marker v1.";
        const EVIDENCE_MARKER: &str = "Synthetic retention evidence marker v1.";
        let candidate = || ModelReasoningOutput::Candidate {
            candidate_id: CandidateId::new_v7(),
            user_visible_text: INTERVENTION_MARKER.to_owned(),
            reason_code: "synthetic_retention_boundary".to_owned(),
            evidence_summary: EVIDENCE_MARKER.to_owned(),
            urgency: Urgency::Normal,
            confidence_basis_points: 8_000,
        };
        let before_active = start(fixture(vec![candidate()], false)).await;
        observe(&before_active);
        let queued = match before_active
            .fixture
            .runtime
            .run_reasoning_cycle(before_active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        assert_eq!(queued.state, InterventionState::Queued);
        assert_eq!(queued.user_visible_text, INTERVENTION_MARKER);
        assert_eq!(queued.evidence_summary, EVIDENCE_MARKER);
        let delivery = before_active
            .fixture
            .repository
            .load_pending_deliveries(before_active.fixture.owner)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(delivery.state, OutboxState::Queued);
        assert_eq!(delivery.user_visible_text, INTERVENTION_MARKER);
        assert_eq!(
            delivery.expires_at - before_active.fixture.clock.now_utc(),
            time::Duration::seconds(30)
        );

        let before_session = find_session(
            &before_active.fixture.repository,
            before_active.fixture.session,
        )
        .unwrap();
        let before_route = find_route(
            &before_active.fixture.repository,
            before_active.fixture.owner,
            before_session.model_route_approval_id,
        )
        .unwrap();
        let context_before = before_active
            .fixture
            .runtime
            .assemble_context(&before_session, &before_route, &before_active.grants)
            .unwrap()
            .0;
        assert!(!context_before.is_empty());
        assert!(context_before.iter().all(|item| {
            item.value.expose() != INTERVENTION_MARKER && item.value.expose() != EVIDENCE_MARKER
        }));

        before_active
            .fixture
            .clock
            .advance(Duration::from_secs(29) + Duration::from_nanos(999_999_999));
        assert!(
            before_active
                .fixture
                .runtime
                .revalidate_pending_deliveries(before_active.fixture.owner)
                .await
                .unwrap()
                .is_empty()
        );
        let immediately_before = before_active
            .fixture
            .repository
            .load_owner_state(before_active.fixture.owner)
            .unwrap();
        assert_eq!(immediately_before.interventions.len(), 1);
        assert_eq!(
            immediately_before.interventions[0].user_visible_text,
            INTERVENTION_MARKER
        );
        assert_eq!(immediately_before.pending_deliveries.len(), 1);
        assert_eq!(
            immediately_before.pending_deliveries[0].user_visible_text,
            INTERVENTION_MARKER
        );

        // Use a fresh owner/runtime at the exact boundary so the public
        // recovery-batch throttle does not turn the immediately-before probe
        // into an artificial ten-second delay.
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let queued = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected a queued intervention, got {other:?}"),
        };
        let delivery = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(queued.state, InterventionState::Queued);
        assert_eq!(delivery.state, OutboxState::Queued);
        assert_eq!(
            delivery.expires_at - active.fixture.clock.now_utc(),
            time::Duration::seconds(30)
        );
        let session = find_session(&active.fixture.repository, active.fixture.session).unwrap();
        let route = find_route(
            &active.fixture.repository,
            active.fixture.owner,
            session.model_route_approval_id,
        )
        .unwrap();
        active.fixture.clock.advance(Duration::from_secs(30));
        assert_eq!(active.fixture.clock.now_utc(), delivery.expires_at);
        let expired = active
            .fixture
            .runtime
            .revalidate_pending_deliveries(active.fixture.owner)
            .await
            .unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].state, InterventionState::Expired);
        assert_eq!(expired[0].outcome, InterventionOutcome::Expired);
        assert!(expired[0].user_visible_text.is_empty());
        assert!(expired[0].evidence_summary.is_empty());
        assert!(expired[0].evidence.is_empty());

        let assert_all_reads_scrubbed = || {
            let interventions = active
                .fixture
                .repository
                .load_interventions(active.fixture.owner)
                .unwrap();
            assert_eq!(interventions.len(), 1);
            assert_eq!(interventions[0].state, InterventionState::Expired);
            assert!(interventions[0].user_visible_text.is_empty());
            assert!(interventions[0].evidence_summary.is_empty());
            assert!(interventions[0].evidence.is_empty());

            let deliveries = active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap();
            assert_eq!(deliveries.len(), 1);
            assert_eq!(deliveries[0].state, OutboxState::Expired);
            assert!(deliveries[0].user_visible_text.is_empty());

            for snapshot in [
                active
                    .fixture
                    .repository
                    .load_owner_state(active.fixture.owner)
                    .unwrap(),
                active
                    .fixture
                    .runtime
                    .owner_state_snapshot(
                        ClientAssurance::PrivateCapabilityBound,
                        active.fixture.owner,
                    )
                    .unwrap(),
            ] {
                assert_eq!(snapshot.interventions, interventions);
                assert_eq!(snapshot.pending_deliveries, deliveries);
            }

            let context = active
                .fixture
                .runtime
                .assemble_context(&session, &route, &active.grants)
                .unwrap()
                .0;
            assert!(context.iter().all(|item| {
                item.value.expose() != INTERVENTION_MARKER && item.value.expose() != EVIDENCE_MARKER
            }));
        };
        assert_all_reads_scrubbed();

        active.fixture.clock.advance(Duration::from_nanos(1));
        assert!(
            active
                .fixture
                .runtime
                .revalidate_pending_deliveries(active.fixture.owner)
                .await
                .unwrap()
                .is_empty()
        );
        assert_all_reads_scrubbed();
        assert_eq!(active.fixture.notification.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn outbox_enforces_per_session_and_per_user_capacity_without_eviction() {
        let config = SecondMindConfig {
            outbox_capacity_per_user: 2,
            outbox_capacity_per_session: 1,
            ..SecondMindConfig::default()
        };
        let active = start(fixture_with_config(vec![candidate()], false, config)).await;
        observe(&active);
        let base = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected queued intervention, got {other:?}"),
        };
        let decision = active
            .fixture
            .repository
            .find_policy_decision(base.policy_decision_id)
            .unwrap()
            .unwrap();
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();

        let session_rejected = queue_synthetic_clone(
            &active,
            &base,
            &decision,
            notification_grant,
            active.fixture.session,
        );
        assert_eq!(session_rejected.state, InterventionState::Cancelled);
        assert_eq!(session_rejected.reason_code, "outbox_capacity");
        assert!(session_rejected.user_visible_text.is_empty());

        let other_session = FocusSessionId::new_v7();
        assert_eq!(
            queue_synthetic_clone(&active, &base, &decision, notification_grant, other_session,)
                .state,
            InterventionState::Queued
        );
        let user_rejected = queue_synthetic_clone(
            &active,
            &base,
            &decision,
            notification_grant,
            FocusSessionId::new_v7(),
        );
        assert_eq!(user_rejected.state, InterventionState::Cancelled);
        assert_eq!(user_rejected.reason_code, "outbox_capacity");
        assert_eq!(
            active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .iter()
                .filter(|entry| entry.state == OutboxState::Queued)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn recovery_processes_three_items_per_ten_second_batch() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let base = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(intervention) => *intervention,
            other => panic!("expected queued intervention, got {other:?}"),
        };
        let decision = active
            .fixture
            .repository
            .find_policy_decision(base.policy_decision_id)
            .unwrap()
            .unwrap();
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                queue_synthetic_clone(
                    &active,
                    &base,
                    &decision,
                    notification_grant,
                    active.fixture.session,
                )
                .state,
                InterventionState::Queued
            );
        }
        active.fixture.clock.advance(Duration::from_secs(31));
        active
            .fixture
            .notification
            .available
            .store(true, Ordering::SeqCst);
        assert_eq!(
            active
                .fixture
                .runtime
                .revalidate_pending_deliveries(active.fixture.owner)
                .await
                .unwrap()
                .len(),
            3
        );
        assert!(
            active
                .fixture
                .runtime
                .revalidate_pending_deliveries(active.fixture.owner)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .iter()
                .filter(|entry| entry.state == OutboxState::Queued)
                .count(),
            1
        );
        active.fixture.clock.advance(Duration::from_secs(10));
        assert_eq!(
            active
                .fixture
                .runtime
                .revalidate_pending_deliveries(active.fixture.owner)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn revocation_during_failed_delivery_cancels_and_scrubs() {
        let active = start(fixture(vec![candidate()], true)).await;
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap()
            .clone();
        *active
            .fixture
            .notification
            .revoke_on_delivery
            .lock()
            .unwrap() = Some(notification_grant);
        *active.fixture.notification.acknowledgement.lock().unwrap() =
            ChannelAcknowledgement::DeliveryFailed;
        observe(&active);
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Cancelled
                    && intervention.user_visible_text.is_empty()
                    && intervention.evidence.is_empty()
        ));
        assert!(
            active
                .fixture
                .repository
                .load_pending_deliveries(active.fixture.owner)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn revoked_notification_grant_cancels_and_scrubs_queued_delivery() {
        let active = start(fixture(vec![candidate()], false)).await;
        observe(&active);
        let result = active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Intervention(ref intervention)
                if intervention.state == InterventionState::Queued
        ));
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap();
        active
            .fixture
            .runtime
            .revoke_permission(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                notification_grant.id,
                notification_grant.revision,
                "Synthetic revocation".to_owned(),
            )
            .await
            .unwrap();
        let outbox = active
            .fixture
            .repository
            .load_pending_deliveries(active.fixture.owner)
            .unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].state, OutboxState::Cancelled);
        assert!(outbox[0].user_visible_text.is_empty());
        let intervention = active
            .fixture
            .repository
            .load_interventions(active.fixture.owner)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(intervention.state, InterventionState::Cancelled);
        assert_eq!(intervention.outcome, InterventionOutcome::Expired);
        assert!(intervention.user_visible_text.is_empty());
        assert!(
            active
                .fixture
                .repository
                .load_audit(active.fixture.owner, OffsetDateTime::UNIX_EPOCH, 200)
                .unwrap()
                .iter()
                .any(|record| {
                    record.subject_id == intervention.id.as_uuid()
                        && record.kind == AuditKind::InterventionDelivery
                        && record
                            .reason_codes
                            .iter()
                            .any(|reason| reason == "permission_revoked")
                })
        );
        assert_eq!(
            find_session(&active.fixture.repository, active.fixture.session)
                .unwrap()
                .state,
            FocusSessionState::Ended,
            "revoking a required delivery grant must end the bound session"
        );
    }

    #[tokio::test]
    async fn failed_permission_revocation_rearms_proactive_work_without_cancelling_session_root() {
        let active = start(fixture(vec![candidate()], true)).await;
        let notification_grant = active
            .grants
            .iter()
            .find(|grant| grant.scope == PermissionScope::InterveneDesktopNotification)
            .unwrap()
            .clone();
        let concurrent_grant_id = notification_grant.id;
        let (root_before, proactive_before) = {
            let state = active.fixture.runtime.ephemeral.lock().unwrap();
            let ephemeral = state.sessions.get(&active.fixture.session).unwrap();
            (
                ephemeral.cancellation.clone(),
                ephemeral.proactive_cancellation.clone(),
            )
        };
        active
            .fixture
            .runtime
            .set_before_permission_revocation_commit_hook({
                let repository = active.fixture.repository.clone();
                let owner = active.fixture.owner;
                move || {
                    let mut concurrent = repository
                        .load_grants(owner)
                        .unwrap()
                        .into_iter()
                        .find(|grant| grant.id == concurrent_grant_id)
                        .unwrap();
                    let expected = concurrent.revision;
                    concurrent.revision = concurrent.revision.saturating_add(1);
                    concurrent.purpose = "Synthetic concurrent active grant update".to_owned();
                    repository.save_grant(&concurrent, Some(expected)).unwrap();
                }
            });

        let error = active
            .fixture
            .runtime
            .revoke_permission(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                notification_grant.id,
                notification_grant.revision,
                "Synthetic conflicting revocation".to_owned(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::Conflict);
        assert!(proactive_before.is_cancelled());
        assert!(!root_before.is_cancelled());
        let durable_grant = active
            .fixture
            .repository
            .load_grants(active.fixture.owner)
            .unwrap()
            .into_iter()
            .find(|grant| grant.id == notification_grant.id)
            .unwrap();
        assert_eq!(durable_grant.state, GrantState::Active);
        assert_eq!(
            find_session(&active.fixture.repository, active.fixture.session)
                .unwrap()
                .state,
            FocusSessionState::Active
        );
        let state = active.fixture.runtime.ephemeral.lock().unwrap();
        let ephemeral = state.sessions.get(&active.fixture.session).unwrap();
        assert!(!ephemeral.cancellation.is_cancelled());
        assert!(!ephemeral.proactive_cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn restart_recovery_requires_authorized_continuity_and_fresh_health() {
        let active = start(fixture(vec![candidate()], true)).await;
        active
            .fixture
            .runtime
            .ephemeral
            .lock()
            .unwrap()
            .sessions
            .get(&active.fixture.session)
            .unwrap()
            .cancellation
            .cancel();
        let new_model = Arc::new(ScriptedModel::new([candidate()]));
        let recovered_observation = Arc::new(AvailableObservation::default());
        let recovered_runtime = SecondMindRuntime::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(active.fixture.repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: recovered_observation.clone(),
                model: new_model.clone(),
                notification: active.fixture.notification.clone(),
                native_status: Arc::new(TestStatus::default()),
                emergency_control: Arc::new(TestEmergency::default()),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        let recovered = recovered_runtime
            .recover_owner(active.fixture.owner)
            .unwrap();
        assert_eq!(recovered[0].state, FocusSessionState::Recovering);
        let recovering_revision = recovered[0].revision;
        let repeated = recovered_runtime
            .recover_owner(active.fixture.owner)
            .unwrap();
        assert_eq!(repeated[0].state, FocusSessionState::Recovering);
        assert_eq!(repeated[0].revision, recovering_revision);
        let result = recovered_runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(result, ReasoningCycleResult::Silence { .. }));
        assert_eq!(new_model.calls.load(Ordering::SeqCst), 0);

        let session = recovered_runtime
            .reactivate_recovered_focus_session(active.fixture.owner, active.fixture.session)
            .await
            .unwrap();
        assert_eq!(session.state, FocusSessionState::Active);
        assert_eq!(
            recovered_observation.start_calls.load(Ordering::SeqCst),
            2,
            "recovery may become active only after every real observation adapter restarts"
        );
        let result = recovered_runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ReasoningCycleResult::Silence { ref reason_code }
                if reason_code == "presence_not_active"
        ));
        assert_eq!(new_model.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn recovered_activation_status_loss_cleans_sources_and_remains_retryable() {
        let active = start(fixture(vec![candidate()], true)).await;
        active
            .fixture
            .runtime
            .ephemeral
            .lock()
            .unwrap()
            .sessions
            .get(&active.fixture.session)
            .unwrap()
            .cancellation
            .cancel();
        let repository = active.fixture.repository.clone();
        let recovered_observation = Arc::new(AvailableObservation::tracking(repository.clone()));
        let recovered_status = Arc::new(TestStatus::default());
        recovered_status.fail_publish_on_call(2);
        let recovered_runtime = SecondMindRuntime::new(
            SecondMindConfig::default(),
            SecondMindPorts {
                repository: Arc::new(repository.clone()),
                clock: active.fixture.clock.clone(),
                observation: recovered_observation.clone(),
                model: Arc::new(ScriptedModel::new([candidate()])),
                notification: active.fixture.notification.clone(),
                native_status: recovered_status.clone(),
                emergency_control: Arc::new(TestEmergency::default()),
                secret_store: Arc::new(crate::UnavailableSecretStore::default()),
                resource_selection: Arc::new(crate::UnavailableResourceSelectionPort),
            },
        )
        .unwrap();
        let recovered = recovered_runtime
            .recover_owner(active.fixture.owner)
            .unwrap();
        assert_eq!(recovered[0].state, FocusSessionState::Recovering);

        let error = recovered_runtime
            .reactivate_recovered_focus_session(active.fixture.owner, active.fixture.session)
            .await
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::Unavailable);
        let pending = repository
            .find_focus_session(active.fixture.session)
            .unwrap()
            .expect("recovery-pending focus session remains durable");
        assert_eq!(pending.state, FocusSessionState::Recovering);
        assert!(pending.source_degraded);
        assert_eq!(
            pending.failure_reason.as_deref(),
            Some("native_status_acknowledgement_lost_during_recovery")
        );
        assert_eq!(
            recovered_observation
                .cleanup_states
                .lock()
                .unwrap()
                .as_slice(),
            &[FocusSessionState::Active, FocusSessionState::Active]
        );
        assert_eq!(
            recovered_status.clears.lock().unwrap().as_slice(),
            &[(active.fixture.session, 4)]
        );
        assert!(
            !recovered_runtime
                .ephemeral
                .lock()
                .unwrap()
                .sessions
                .contains_key(&active.fixture.session)
        );

        recovered_status.fail_publish_on_call(0);
        let retried = recovered_runtime
            .reactivate_recovered_focus_session(active.fixture.owner, active.fixture.session)
            .await
            .unwrap();
        assert_eq!(retried.state, FocusSessionState::Active);
        assert_eq!(recovered_observation.start_calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn phase2_identity_revision_conflict_preserves_current_preferences() {
        let fixture = fixture(Vec::new(), true);
        let original = fixture
            .runtime
            .user_preferences(ClientAssurance::PrivateCapabilityBound, fixture.owner)
            .unwrap();
        let mut winning = original.clone();
        winning.preferred_form_of_address = Some("Current synthetic value".to_owned());
        let winning = fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                winning,
                Some(original.revision),
            )
            .unwrap();
        let winning_json = serde_json::to_vec(&winning).unwrap();
        let stale_revision = original.revision;

        let mut stale = original;
        stale.preferred_form_of_address = Some("Stale synthetic value".to_owned());
        let error = fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                stale,
                Some(stale_revision),
            )
            .unwrap_err();

        assert_eq!(error.code, SecondMindErrorCode::Conflict);
        let durable = fixture
            .repository
            .load_preferences(fixture.owner)
            .unwrap()
            .unwrap();
        assert_eq!(durable.revision, winning.revision);
        assert_eq!(serde_json::to_vec(&durable).unwrap(), winning_json);
    }

    #[test]
    fn phase2_identity_stricter_preferences_produce_quieter_effective_policy() {
        let fixture = fixture(Vec::new(), true);
        let defaults = fixture
            .runtime
            .user_preferences(ClientAssurance::PrivateCapabilityBound, fixture.owner)
            .unwrap();
        let mut permissive = defaults.clone();
        permissive.proactive_interventions_enabled = true;
        permissive.remote_processing_enabled = true;
        permissive.restart_continuity_default = true;
        let permissive = fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                permissive,
                Some(defaults.revision),
            )
            .unwrap();
        let permissive_policy = fixture
            .runtime
            .effective_policy_view(ClientAssurance::PrivateCapabilityBound, fixture.owner)
            .unwrap();

        let mut stricter = permissive.clone();
        stricter.maximum_interventions_per_session = 1;
        stricter.maximum_model_requests_per_hour = 2;
        stricter.minimum_intervention_cooldown_seconds += 60;
        stricter.proactive_interventions_muted = true;
        stricter.allowed_delivery_channels.clear();
        stricter.remote_processing_enabled = false;
        stricter.restart_continuity_default = false;
        let stricter = fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                stricter,
                Some(permissive.revision),
            )
            .unwrap();
        let stricter_policy = fixture
            .runtime
            .effective_policy_view(ClientAssurance::PrivateCapabilityBound, fixture.owner)
            .unwrap();

        assert_eq!(stricter_policy.user_preferences_revision, stricter.revision);
        assert!(stricter_policy.proactive_interventions_muted);
        assert!(
            stricter_policy.maximum_interventions_per_session
                < permissive_policy.maximum_interventions_per_session
        );
        assert!(
            stricter_policy.maximum_model_requests_per_hour
                < permissive_policy.maximum_model_requests_per_hour
        );
        assert!(stricter_policy.intervention_cooldown > permissive_policy.intervention_cooldown);
        assert!(stricter_policy.allowed_delivery_channels.is_empty());
        assert!(!stricter_policy.remote_processing_enabled);
        assert!(!stricter_policy.restart_continuity_default);

        let mut diagnostic_attempt = stricter.clone();
        diagnostic_attempt.preferred_form_of_address = Some("Diagnostic mutation".to_owned());
        let error = fixture
            .runtime
            .save_preferences(
                ClientAssurance::Diagnostic,
                diagnostic_attempt,
                Some(stricter.revision),
            )
            .unwrap_err();
        assert_eq!(error.code, SecondMindErrorCode::PermissionDenied);
        assert_eq!(
            fixture.repository.load_preferences(fixture.owner).unwrap(),
            Some(stricter)
        );
    }

    #[tokio::test]
    async fn phase2_identity_observation_model_and_feedback_do_not_mutate_durable_records() {
        let mut model_candidate = candidate();
        let ModelReasoningOutput::Candidate {
            user_visible_text, ..
        } = &mut model_candidate
        else {
            unreachable!("the synthetic model fixture must produce a candidate")
        };
        *user_visible_text =
            "The synthetic activity suggests you prefer to be called Commander.".to_owned();
        let active = start(fixture(vec![model_candidate], true)).await;
        active
            .fixture
            .runtime
            .stein_identity(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
            )
            .unwrap();
        let before =
            identity_preferences_snapshot(&active.fixture.repository, active.fixture.owner);

        observe(&active);
        assert_eq!(
            identity_preferences_snapshot(&active.fixture.repository, active.fixture.owner),
            before,
            "accepted observations must preserve both revisions and canonical values"
        );

        let intervention = match active
            .fixture
            .runtime
            .run_reasoning_cycle(active.fixture.session)
            .await
            .unwrap()
        {
            ReasoningCycleResult::Intervention(value) => *value,
            other => panic!("expected an intervention, got {other:?}"),
        };
        assert_eq!(intervention.state, InterventionState::AcceptedByChannel);
        assert_eq!(
            identity_preferences_snapshot(&active.fixture.repository, active.fixture.owner),
            before,
            "model output must preserve both revisions and canonical values"
        );

        active
            .fixture
            .runtime
            .record_feedback(
                ClientAssurance::PrivateCapabilityBound,
                active.fixture.owner,
                intervention.id,
                intervention.revision,
                InterventionOutcome::Corrected,
                Some(SensitiveText::new(
                    "For this session, call the synthetic operator Commander.",
                )),
            )
            .unwrap();
        assert_eq!(
            identity_preferences_snapshot(&active.fixture.repository, active.fixture.owner),
            before,
            "corrective feedback must preserve both revisions and canonical values"
        );
    }

    #[test]
    fn explicit_preferences_are_validated_and_never_inferred() {
        let fixture = fixture(Vec::new(), true);
        let saved = fixture
            .runtime
            .save_preferences(
                ClientAssurance::PrivateCapabilityBound,
                ExplicitPreferences {
                    schema_version: USER_PREFERENCES_SCHEMA_V1,
                    owner: fixture.owner,
                    revision: 0,
                    preferred_form_of_address: Some("Captain".to_owned()),
                    intervention_tone: InterventionTone::Concise,
                    default_focus_minutes: 45,
                    maximum_interventions_per_session: 2,
                    maximum_model_requests_per_hour: 10,
                    minimum_intervention_cooldown_seconds: 15 * 60,
                    proactive_interventions_enabled: true,
                    proactive_interventions_muted: false,
                    do_not_disturb_windows: Vec::new(),
                    allowed_delivery_channels: BTreeSet::from([
                        NATIVE_NOTIFICATION_CHANNEL.to_owned()
                    ]),
                    remote_processing_enabled: false,
                    restart_continuity_default: false,
                    provenance: crate::RecordProvenance {
                        source: crate::RecordProvenanceSource::DirectUser,
                        version: "test".to_owned(),
                        recorded_at: OffsetDateTime::UNIX_EPOCH,
                    },
                    updated_at: OffsetDateTime::UNIX_EPOCH,
                },
                None,
            )
            .unwrap();
        assert_eq!(saved.revision, 1);
        assert_eq!(saved.schema_version, USER_PREFERENCES_SCHEMA_V1);
        assert_eq!(saved.maximum_model_requests_per_hour, 10);
        assert_eq!(saved.minimum_intervention_cooldown_seconds, 15 * 60);
        assert_eq!(
            fixture.repository.load_preferences(fixture.owner).unwrap(),
            Some(saved.clone())
        );

        let mut legacy = serde_json::to_value(&saved).unwrap();
        let legacy = legacy.as_object_mut().unwrap();
        for field in [
            "schema_version",
            "maximum_model_requests_per_hour",
            "minimum_intervention_cooldown_seconds",
            "proactive_interventions_muted",
            "do_not_disturb_windows",
            "allowed_delivery_channels",
            "remote_processing_enabled",
        ] {
            legacy.remove(field);
        }
        let migrated: ExplicitPreferences =
            serde_json::from_value(serde_json::Value::Object(legacy.clone())).unwrap();
        assert_eq!(migrated.schema_version, USER_PREFERENCES_SCHEMA_V1);
        assert_eq!(migrated.maximum_model_requests_per_hour, 12);
        assert_eq!(migrated.minimum_intervention_cooldown_seconds, 15 * 60);
        assert_eq!(
            migrated.allowed_delivery_channels,
            BTreeSet::from([NATIVE_NOTIFICATION_CHANNEL.to_owned()])
        );
        assert!(!migrated.remote_processing_enabled);

        let mut invalid = saved;
        invalid.do_not_disturb_windows = vec![DoNotDisturbWindow {
            start_minute_local: 100,
            end_minute_local: 100,
            utc_offset_minutes: 0,
        }];
        assert_eq!(
            fixture
                .runtime
                .save_preferences(ClientAssurance::PrivateCapabilityBound, invalid, Some(1),)
                .unwrap_err()
                .code,
            SecondMindErrorCode::InvalidArgument
        );
    }
}
