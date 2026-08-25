use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AuthorityReference, ClientInstanceId, DaemonInstanceId, DeliveryChannelId, DeviceId,
    FocusSessionId, GoalId, InterventionId, ModelRouteApprovalId, ObservationSourceId,
    PermissionGrantId, PolicyDecisionId, ProtocolVersion, RequestId, RetentionClass,
    SelectedResourceId, SensitivityClass, SnapshotId, UtcTimestamp,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    Snapshot,
    RuntimeStatus,
    GoalCreate,
    GoalUpdate,
    DelayEcho,
    RuntimeShutdown,
    ViewEvents,
    RequestCancellation,
    ModelRouteApproval,
    SessionPermissions,
    FocusSessions,
    CaptureState,
    DeliveryChannels,
    InterventionFeedback,
    InterventionHistory,
    InterventionExplanation,
    DesktopObservation,
    ModelReasoning,
    DurablePersistence,
    NativeNotification,
    NativeStatus,
    EmergencyControl,
    SecretStore,
    GoalDelete,
    SteinIdentity,
    UserPreferences,
    EffectivePolicy,
    SelectedResources,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityUnavailableReason {
    NotImplemented,
    UnsupportedPlatform,
    DependencyUnavailable,
    DisabledByConfiguration,
    Starting,
    Stopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityHealth {
    pub capability: CapabilityId,
    pub schema_version: u16,
    pub state: HealthState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<CapabilityUnavailableReason>,
}

/// Compatibility alias used by architecture documentation.
pub type CapabilityView = CapabilityHealth;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Starting,
    Ready,
    Degraded,
    Stopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeStatus {
    pub daemon_instance_id: DaemonInstanceId,
    pub state: RuntimeState,
    pub started_at: UtcTimestamp,
    pub observed_at: UtcTimestamp,
    pub build_id: String,
    pub protocol_version: ProtocolVersion,
    pub active_connections: u32,
}

/// Compatibility alias for callers that prefer an explicit view suffix.
pub type RuntimeStatusView = RuntimeStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalState {
    Draft,
    Active,
    Completed,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalView {
    pub goal_id: GoalId,
    pub revision: u64,
    pub owner_id: ActorId,
    pub title: String,
    pub success_statement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<UtcTimestamp>,
    pub state: GoalState,
    pub created_at: UtcTimestamp,
    pub updated_at: UtcTimestamp,
}

/// The minimum protocol version in which the Phase 2 second-mind loop appears.
pub const PHASE_2_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V1_1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedResourceKind {
    Application,
    Window,
    BrowserSurface,
    Document,
    Workspace,
    ScreenRegion,
    Display,
}

/// Privacy-filtered resource identity. Native paths, URLs, window handles, and
/// capture coordinates remain in the daemon-owned adapter registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedResourceView {
    pub selected_resource_id: SelectedResourceId,
    pub kind: SelectedResourceKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<UtcTimestamp>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordProvenanceSource {
    ProductMigration,
    ProductDefault,
    DirectUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordProvenanceView {
    pub source: RecordProvenanceSource,
    pub version: String,
    pub recorded_at: UtcTimestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteinIdentityConstraint {
    AdvisesRatherThanActs,
    PreservesUncertainty,
    RespectsSilence,
    NeverImpersonatesUser,
    NeverBypassesPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteinIdentityV1View {
    pub schema_version: u16,
    pub owner_id: ActorId,
    pub revision: u64,
    pub display_name: String,
    pub role_statement: String,
    pub invariant_behavioral_constraints: Vec<SteinIdentityConstraint>,
    pub provenance: RecordProvenanceView,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionStyle {
    Concise,
    Neutral,
    Reflective,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DoNotDisturbWindowView {
    pub start_minute_local: u16,
    pub end_minute_local: u16,
    pub utc_offset_minutes: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserPreferencesV1View {
    pub schema_version: u16,
    pub owner_id: ActorId,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_form_of_address: Option<String>,
    pub intervention_style: InterventionStyle,
    pub proactive_enabled: bool,
    pub proactive_muted: bool,
    pub maximum_interventions_per_session: u16,
    pub maximum_model_requests_per_hour: u16,
    pub minimum_intervention_cooldown_ms: u64,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindowView>,
    pub allowed_delivery_channels: Vec<DeliveryChannelClass>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
    pub provenance: RecordProvenanceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectivePolicyView {
    pub schema_version: u16,
    pub policy_profile_id: String,
    pub user_preferences_revision: u64,
    pub source_stale_after_ms: u64,
    pub maximum_model_evidence_age_ms: u64,
    pub model_request_cooldown_ms: u64,
    pub maximum_model_requests_per_hour: u16,
    pub intervention_cooldown_ms: u64,
    pub maximum_interventions_per_session: u16,
    pub proactive_enabled: bool,
    pub proactive_muted: bool,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindowView>,
    pub allowed_delivery_channels: Vec<DeliveryChannelClass>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
    pub outbox_capacity_per_user: u16,
    pub outbox_capacity_per_session: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalDeletionTombstoneView {
    pub goal_id: GoalId,
    pub deleted_revision: u64,
    pub deleted_at: UtcTimestamp,
    pub focus_sessions_deleted: u64,
    pub grants_deleted: u64,
    pub interventions_deleted: u64,
    pub pending_deliveries_deleted: u64,
    pub private_audit_records_deleted: u64,
    pub resource_bindings_deleted: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedResourceDeletionTombstoneView {
    pub selected_resource_id: SelectedResourceId,
    pub deleted_revision: u64,
    pub deleted_at: UtcTimestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCategory {
    Presence,
    ForegroundApplication,
    WindowMetadata,
    BrowserLocation,
    VisibleText,
    SelectedDocument,
    ScreenPixels,
    WorkspaceActivity,
    SourceHealth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum PermissionScope {
    #[serde(rename = "observe.desktop.presence")]
    ObserveDesktopPresence,
    #[serde(rename = "observe.desktop.foreground_application")]
    ObserveDesktopForegroundApplication,
    #[serde(rename = "observe.desktop.window_metadata")]
    ObserveDesktopWindowMetadata,
    #[serde(rename = "observe.browser.location")]
    ObserveBrowserLocation,
    #[serde(rename = "observe.content.visible_text")]
    ObserveContentVisibleText,
    #[serde(rename = "observe.content.selected_document")]
    ObserveContentSelectedDocument,
    #[serde(rename = "observe.screen.pixels")]
    ObserveScreenPixels,
    #[serde(rename = "observe.workspace.activity")]
    ObserveWorkspaceActivity,
    #[serde(rename = "reason.focus_context")]
    ReasonFocusContext,
    #[serde(rename = "intervene.desktop.notification")]
    InterveneDesktopNotification,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionContinuity {
    pub while_client_disconnected: bool,
    pub after_daemon_restart: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionState {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionGrantView {
    pub permission_grant_id: PermissionGrantId,
    pub revision: u64,
    pub owner_id: ActorId,
    pub requested_by_client: ClientInstanceId,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus_session_id: Option<FocusSessionId>,
    pub goal_id: GoalId,
    pub scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_resource_id: Option<SelectedResourceId>,
    pub purpose: String,
    pub continuity: PermissionContinuity,
    pub state: PermissionState,
    pub effective_at: UtcTimestamp,
    pub expires_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    pub consent_copy_version: String,
    pub sensitivity: SensitivityClass,
    pub retention: RetentionClass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelDataCategory {
    Goal,
    FocusSession,
    EvidenceAggregates,
    WindowMetadata,
    BrowserLocation,
    VisibleText,
    SelectedDocument,
    ScreenPixels,
    WorkspaceActivity,
    DeliveryConstraints,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPlacement {
    Local,
    Remote,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderRetentionPolicy {
    None,
    Transient,
    Bounded { maximum_seconds: u64 },
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrainingUse {
    Excluded,
    MayUse,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderHandlingProfile {
    pub retention: ProviderRetentionPolicy,
    pub training_use: ProviderTrainingUse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_residency: Option<String>,
    pub profile_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRouteReference {
    pub provider_id: String,
    pub route_id: String,
    pub placement: ModelPlacement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteApprovalState {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRouteApprovalView {
    pub model_route_approval_id: ModelRouteApprovalId,
    pub revision: u64,
    pub owner_id: ActorId,
    pub route: ModelRouteReference,
    pub account_profile: String,
    pub allowed_data_categories: Vec<ModelDataCategory>,
    pub handling: ProviderHandlingProfile,
    pub purpose: String,
    pub maximum_request_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ModelRouteReference>,
    pub state: ModelRouteApprovalState,
    pub effective_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<UtcTimestamp>,
    pub disclosure_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
pub enum PermissionRecordView {
    SessionGrant(PermissionGrantView),
    ModelRouteApproval(ModelRouteApprovalView),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "permission_type", rename_all = "snake_case")]
pub enum PermissionReference {
    SessionGrant {
        permission_grant_id: PermissionGrantId,
    },
    ModelRouteApproval {
        model_route_approval_id: ModelRouteApprovalId,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusSessionState {
    Requested,
    Starting,
    Active,
    Recovering,
    Stopping,
    Ended,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FocusSessionView {
    pub focus_session_id: FocusSessionId,
    pub revision: u64,
    pub goal_id: GoalId,
    pub goal_revision: u64,
    pub state: FocusSessionState,
    pub interventions_muted: bool,
    pub source_degraded: bool,
    pub model_route_approval_id: ModelRouteApprovalId,
    pub permission_grant_ids: Vec<PermissionGrantId>,
    pub selected_resource_ids: Vec<SelectedResourceId>,
    pub continuity: PermissionContinuity,
    pub created_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<UtcTimestamp>,
    pub updated_at: UtcTimestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRequestReceiptOutcome {
    InFlight,
    CompletedStrictSilence,
    CompletedStrictCandidate,
    Cancelled,
    DeadlineExceeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRequestReceiptView {
    pub request_id: RequestId,
    pub focus_session_id: FocusSessionId,
    pub model_route_approval_id: ModelRouteApprovalId,
    pub model_route_revision: u64,
    pub started_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<UtcTimestamp>,
    pub outcome: ModelRequestReceiptOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSourceHealth {
    Unknown,
    Starting,
    Healthy,
    Degraded,
    Paused,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationSourceView {
    pub observation_source_id: ObservationSourceId,
    pub category: ObservationCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_resource_id: Option<SelectedResourceId>,
    pub health: ObservationSourceHealth,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_complete_at: Option<UtcTimestamp>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Stopped,
    Starting,
    Active,
    Paused,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptureStateView {
    pub focus_session_id: FocusSessionId,
    pub revision: u64,
    pub state: CaptureState,
    pub active_categories: Vec<ObservationCategory>,
    pub sources: Vec<ObservationSourceView>,
    pub native_status_visible: bool,
    pub emergency_stop_available: bool,
    pub updated_at: UtcTimestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryChannelClass {
    NativeDesktopNotification,
    ConnectedDesktop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryChannelState {
    Healthy,
    Degraded,
    Unavailable,
    Suppressed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryChannelView {
    pub delivery_channel_id: DeliveryChannelId,
    pub class: DeliveryChannelClass,
    pub state: DeliveryChannelState,
    pub may_show_content_while_locked: bool,
    pub observed_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionUrgency {
    Low,
    Normal,
    High,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionReasonCode {
    DeadlineNear,
    SuccessConditionUnobserved,
    RecentRelevantProgress,
    EvidenceStale,
    SourceUnhealthy,
    UserUnavailable,
    InterventionsMuted,
    CooldownActive,
    SessionLimitReached,
    PermissionMissing,
    RouteApprovalMissing,
    AuditUnavailable,
    ChannelUnavailable,
    CorrectedContext,
    CandidateInvalid,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionOutcome {
    Allow,
    Deny,
    RequireConfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDecisionView {
    pub policy_decision_id: PolicyDecisionId,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_trace: Option<PolicyTraceView>,
    pub outcome: PolicyDecisionOutcome,
    pub reason_codes: Vec<InterventionReasonCode>,
    pub authority: Vec<AuthorityReference>,
    pub issued_at: UtcTimestamp,
    pub expires_at: UtcTimestamp,
}

/// Content-free provenance for one deterministic policy evaluation. Legacy
/// decisions omit this additive field and are not delivery-authoritative.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyTraceView {
    pub policy_profile_id: String,
    pub user_preferences_revision: u64,
    pub proposed_input_schema_version: u16,
    pub proposed_input_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Fresh,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    SupportsProgress,
    SupportsDeadlineRisk,
    Uncertain,
    CorrectedRelevantWork,
}

/// A deliberately content-free explanation of which evidence class mattered.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceSummaryView {
    pub category: ObservationCategory,
    pub freshness: EvidenceFreshness,
    pub confidence: ConfidenceBand,
    pub role: EvidenceRole,
    pub observed_from: UtcTimestamp,
    pub observed_until: UtcTimestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionState {
    Candidate,
    Denied,
    Allowed,
    Queued,
    Delivering,
    AcceptedByChannel,
    DeliveryUnknown,
    DeliveryFailed,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionOutcome {
    Unacknowledged,
    Accepted,
    Dismissed,
    Corrected,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionView {
    pub intervention_id: InterventionId,
    pub revision: u64,
    pub candidate_revision: u64,
    pub focus_session_id: FocusSessionId,
    pub goal_id: GoalId,
    pub urgency: InterventionUrgency,
    pub reason_codes: Vec<InterventionReasonCode>,
    pub state: InterventionState,
    pub outcome: InterventionOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_visible_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_channel_id: Option<DeliveryChannelId>,
    pub sensitivity: SensitivityClass,
    pub retention: RetentionClass,
    pub created_at: UtcTimestamp,
    pub expires_at: UtcTimestamp,
    pub updated_at: UtcTimestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionHistoryView {
    pub as_of: UtcTimestamp,
    pub entries: Vec<InterventionView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionExplanationView {
    pub intervention_id: InterventionId,
    pub candidate_revision: u64,
    pub focus_session_id: FocusSessionId,
    pub evidence: Vec<EvidenceSummaryView>,
    pub decision: PolicyDecisionView,
    pub delivery_state: InterventionState,
    pub outcome: InterventionOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_text: Option<String>,
    pub correction_recorded: bool,
}

/// The additive state introduced by protocol 1.1. Protocol 1.0 snapshots omit
/// this object entirely and therefore retain their original JSON shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase2Snapshot {
    pub selected_resources: Vec<SelectedResourceView>,
    pub permission_records: Vec<PermissionRecordView>,
    pub focus_sessions: Vec<FocusSessionView>,
    pub capture_states: Vec<CaptureStateView>,
    pub delivery_channels: Vec<DeliveryChannelView>,
    pub intervention_history: InterventionHistoryView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stein_identity: Option<SteinIdentityV1View>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_preferences: Option<UserPreferencesV1View>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_policy: Option<EffectivePolicyView>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventCursor {
    pub daemon_instance_id: DaemonInstanceId,
    pub sequence: u64,
}

impl EventCursor {
    #[must_use]
    pub const fn next(self) -> Self {
        Self {
            daemon_instance_id: self.daemon_instance_id,
            sequence: self.sequence.saturating_add(1),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientSnapshot {
    pub snapshot_id: SnapshotId,
    pub as_of: UtcTimestamp,
    pub cursor: EventCursor,
    pub runtime: RuntimeStatus,
    pub capabilities: Vec<CapabilityHealth>,
    pub goals: Vec<GoalView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase2: Option<Box<Phase2Snapshot>>,
}
