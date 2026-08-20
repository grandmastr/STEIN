use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ActorId, GoalId};

macro_rules! domain_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

domain_id!(DeviceId);
domain_id!(ClientId);
domain_id!(ResourceId);
domain_id!(PermissionGrantId);
domain_id!(ModelRouteApprovalId);
domain_id!(FocusSessionId);
domain_id!(InterventionId);
domain_id!(CandidateId);
domain_id!(PolicyDecisionId);
domain_id!(AuditRecordId);
domain_id!(OutboxEntryId);

pub const STEIN_IDENTITY_SCHEMA_V1: u16 = 1;
pub const STEIN_IDENTITY_MIGRATION_V1: &str = "stein-identity-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordProvenanceSource {
    ProductMigration,
    ProductDefault,
    DirectUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordProvenance {
    pub source: RecordProvenanceSource,
    pub version: String,
    pub recorded_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteinIdentityConstraint {
    AdvisesRatherThanActs,
    PreservesUncertainty,
    RespectsSilence,
    NeverImpersonatesUser,
    NeverBypassesPolicy,
}

impl SteinIdentityConstraint {
    pub const ALL: [Self; 5] = [
        Self::AdvisesRatherThanActs,
        Self::PreservesUncertainty,
        Self::RespectsSilence,
        Self::NeverImpersonatesUser,
        Self::NeverBypassesPolicy,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScope {
    ObserveDesktopPresence,
    ObserveDesktopForegroundApplication,
    ObserveDesktopWindowMetadata,
    ObserveBrowserLocation,
    ObserveContentVisibleText,
    ObserveContentSelectedDocument,
    ObserveScreenPixels,
    ObserveWorkspaceActivity,
    ReasonFocusContext,
    InterveneDesktopNotification,
}

impl PermissionScope {
    pub const ALL: [Self; 10] = [
        Self::ObserveDesktopPresence,
        Self::ObserveDesktopForegroundApplication,
        Self::ObserveDesktopWindowMetadata,
        Self::ObserveBrowserLocation,
        Self::ObserveContentVisibleText,
        Self::ObserveContentSelectedDocument,
        Self::ObserveScreenPixels,
        Self::ObserveWorkspaceActivity,
        Self::ReasonFocusContext,
        Self::InterveneDesktopNotification,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ObserveDesktopPresence => "observe.desktop.presence",
            Self::ObserveDesktopForegroundApplication => "observe.desktop.foreground_application",
            Self::ObserveDesktopWindowMetadata => "observe.desktop.window_metadata",
            Self::ObserveBrowserLocation => "observe.browser.location",
            Self::ObserveContentVisibleText => "observe.content.visible_text",
            Self::ObserveContentSelectedDocument => "observe.content.selected_document",
            Self::ObserveScreenPixels => "observe.screen.pixels",
            Self::ObserveWorkspaceActivity => "observe.workspace.activity",
            Self::ReasonFocusContext => "reason.focus_context",
            Self::InterveneDesktopNotification => "intervene.desktop.notification",
        }
    }

    pub const fn is_observation(self) -> bool {
        matches!(
            self,
            Self::ObserveDesktopPresence
                | Self::ObserveDesktopForegroundApplication
                | Self::ObserveDesktopWindowMetadata
                | Self::ObserveBrowserLocation
                | Self::ObserveContentVisibleText
                | Self::ObserveContentSelectedDocument
                | Self::ObserveScreenPixels
                | Self::ObserveWorkspaceActivity
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
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

impl DataCategory {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Goal => "goal",
            Self::FocusSession => "focus_session",
            Self::EvidenceAggregates => "evidence_aggregates",
            Self::WindowMetadata => "window_metadata",
            Self::BrowserLocation => "browser_location",
            Self::VisibleText => "visible_text",
            Self::SelectedDocument => "selected_document",
            Self::ScreenPixels => "screen_pixels",
            Self::WorkspaceActivity => "workspace_activity",
            Self::DeliveryConstraints => "delivery_constraints",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Device,
    Application,
    Window,
    BrowserSurface,
    Document,
    Workspace,
    ScreenRegion,
}

/// Durable resource metadata contains an opaque platform-owned reference and a
/// user-facing label, never a full path, URL, window title, or source content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceBinding {
    pub id: ResourceId,
    pub owner: ActorId,
    pub kind: ResourceKind,
    pub opaque_reference: String,
    pub display_label: String,
    pub revision: u64,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRegistration {
    pub owner: ActorId,
    pub device_id: DeviceId,
    pub issued_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedResourceDeletionTombstone {
    pub owner: ActorId,
    pub resource_id: ResourceId,
    pub deleted_revision: u64,
    pub deleted_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Active,
    Revoked,
    Expired,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionGrant {
    pub id: PermissionGrantId,
    pub revision: u64,
    pub owner: ActorId,
    pub goal_id: GoalId,
    pub authenticated_client: ClientId,
    pub device_id: DeviceId,
    pub focus_session_id: Option<FocusSessionId>,
    pub scope: PermissionScope,
    pub selected_resource_id: Option<ResourceId>,
    pub model_route_approval_id: Option<ModelRouteApprovalId>,
    pub purpose: String,
    pub placement: Option<ModelPlacement>,
    pub client_disconnect_allowed: bool,
    pub daemon_restart_allowed: bool,
    pub issued_at: OffsetDateTime,
    pub effective_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub state: GrantState,
    pub revoked_at: Option<OffsetDateTime>,
    pub revocation_reason: Option<String>,
    pub consent_copy_version: String,
}

impl PermissionGrant {
    pub fn is_current_at(&self, now: OffsetDateTime) -> bool {
        self.state == GrantState::Active && self.effective_at <= now && now < self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPlacement {
    Local,
    Remote,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelHandlingProfile {
    pub profile_id: String,
    pub retention: ProviderRetentionPolicy,
    pub training_use: ProviderTrainingUse,
    pub data_residency: Option<String>,
    pub core_persists_prompt_or_response: bool,
    pub tools_enabled: bool,
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
pub struct ModelRouteReference {
    pub provider_id: String,
    pub route_id: String,
    pub placement: ModelPlacement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRouteApproval {
    pub id: ModelRouteApprovalId,
    pub revision: u64,
    pub owner: ActorId,
    pub authenticated_client: ClientId,
    pub provider: String,
    pub account_profile: String,
    pub model: String,
    pub secret_ref: crate::SecretRef,
    pub placement: ModelPlacement,
    pub allowed_categories: BTreeSet<DataCategory>,
    pub handling: ModelHandlingProfile,
    pub purpose: String,
    pub maximum_input_tokens: u32,
    pub maximum_output_tokens: u32,
    pub fallback: Option<ModelRouteReference>,
    pub fallback_allowed: bool,
    pub effective_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub disclosure_version: String,
}

impl ModelRouteApproval {
    pub fn is_current_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none()
            && self.effective_at <= now
            && self.expires_at.is_none_or(|expiry| now < expiry)
            && !self.handling.tools_enabled
            && !self.handling.core_persists_prompt_or_response
    }
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
pub struct FocusSession {
    pub id: FocusSessionId,
    pub revision: u64,
    pub owner: ActorId,
    pub goal_id: GoalId,
    pub goal_revision: u64,
    pub state: FocusSessionState,
    pub muted: bool,
    pub source_degraded: bool,
    pub client_disconnect_allowed: bool,
    pub daemon_restart_allowed: bool,
    pub permission_grant_ids: BTreeSet<PermissionGrantId>,
    pub selected_resource_ids: BTreeSet<ResourceId>,
    pub model_route_approval_id: ModelRouteApprovalId,
    pub requested_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
    pub failure_reason: Option<String>,
}

impl FocusSession {
    pub const fn is_working(&self) -> bool {
        matches!(
            self.state,
            FocusSessionState::Starting | FocusSessionState::Active | FocusSessionState::Recovering
        )
    }
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    SupportsProgress,
    SupportsDeadlineRisk,
    Uncertain,
    CorrectedRelevantWork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceSummary {
    pub category: DataCategory,
    pub observed_from: OffsetDateTime,
    pub observed_until: OffsetDateTime,
    pub confidence_basis_points: u16,
    pub role: EvidenceRole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    Low,
    Normal,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Intervention {
    pub id: InterventionId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u64,
    pub policy_decision_id: PolicyDecisionId,
    pub revision: u64,
    pub owner: ActorId,
    pub focus_session_id: FocusSessionId,
    pub goal_id: GoalId,
    pub state: InterventionState,
    pub outcome: InterventionOutcome,
    pub user_visible_text: String,
    pub reason_code: String,
    pub evidence_summary: String,
    pub evidence: Vec<EvidenceSummary>,
    pub urgency: Urgency,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub delivery_channel: Option<String>,
    pub delivered_at: Option<OffsetDateTime>,
    pub outcome_at: Option<OffsetDateTime>,
    pub correction_summary: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Deny,
    RequireConfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDecision {
    pub id: PolicyDecisionId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u64,
    pub owner: ActorId,
    pub focus_session_id: FocusSessionId,
    pub outcome: PolicyOutcome,
    pub reason_codes: Vec<String>,
    pub permission_grant_revisions: Vec<(PermissionGrantId, u64)>,
    pub model_route_revision: u64,
    pub channel: String,
    pub policy_version: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    PermissionGranted,
    PermissionRevoked,
    ModelRouteApproved,
    ModelRouteRevoked,
    FocusSessionStateChanged,
    InterventionDecision,
    InterventionDelivery,
    InterventionOutcome,
    Deletion,
}

/// One repository transaction at the intervention action boundary.
///
/// An allow decision must not become deliverable unless its privacy-aware audit
/// acknowledgement and intervention record commit with the exact decision. A
/// deny decision has no intervention record but still commits its decision and
/// audit together. Recovery may revise an existing intervention by supplying
/// its expected revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionDecisionWrite {
    pub decision: PolicyDecision,
    pub audit: AuditRecord,
    pub intervention: Option<Intervention>,
    pub expected_intervention_revision: Option<u64>,
}

/// Audit deliberately stores only bounded explanations and identifiers. It has
/// no field capable of holding a raw observation, prompt, response, URL, path,
/// UI tree, or frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecord {
    pub id: AuditRecordId,
    pub owner: ActorId,
    pub kind: AuditKind,
    pub subject_id: Uuid,
    pub correlation_id: Uuid,
    pub reason_codes: Vec<String>,
    pub evidence_categories: BTreeSet<DataCategory>,
    pub evidence_age_ms: Option<u64>,
    pub confidence_basis_points: Option<u16>,
    pub occurred_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Queued,
    Delivering,
    AcceptedByChannel,
    DeliveryUnknown,
    DeliveryFailed,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingInterventionDelivery {
    pub id: OutboxEntryId,
    pub owner: ActorId,
    pub intervention_id: InterventionId,
    pub candidate_revision: u64,
    pub policy_decision_id: PolicyDecisionId,
    pub permission_grant_ids: BTreeSet<PermissionGrantId>,
    pub user_visible_text: String,
    pub reason_code: String,
    pub urgency: Urgency,
    pub sensitivity: String,
    pub permitted_channels: BTreeSet<String>,
    pub deduplication_key: Uuid,
    pub state: OutboxState,
    pub attempt_count: u8,
    pub created_at: OffsetDateTime,
    pub not_before: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_attempt_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteinIdentity {
    #[serde(default = "stein_identity_schema_v1")]
    pub schema_version: u16,
    pub owner: ActorId,
    pub revision: u64,
    /// Compatibility name for the shipped display name. It is product-owned,
    /// not a user preference; user address belongs in ExplicitPreferences.
    pub preferred_name: Option<String>,
    pub identity_statement: String,
    #[serde(default = "stein_identity_constraints_v1")]
    pub invariant_behavioral_constraints: BTreeSet<SteinIdentityConstraint>,
    #[serde(default = "legacy_identity_provenance")]
    pub provenance: RecordProvenance,
    pub updated_at: OffsetDateTime,
}

impl SteinIdentity {
    #[must_use]
    pub fn shipped_v1(owner: ActorId, recorded_at: OffsetDateTime) -> Self {
        Self {
            schema_version: STEIN_IDENTITY_SCHEMA_V1,
            owner,
            revision: 1,
            preferred_name: Some("STEIN".to_owned()),
            identity_statement:
                "A second mind that advises while the user remains the decision-maker and actor."
                    .to_owned(),
            invariant_behavioral_constraints: stein_identity_constraints_v1(),
            provenance: RecordProvenance {
                source: RecordProvenanceSource::ProductMigration,
                version: STEIN_IDENTITY_MIGRATION_V1.to_owned(),
                recorded_at,
            },
            updated_at: recorded_at,
        }
    }

    #[must_use]
    pub fn has_shipped_v1_invariants(&self) -> bool {
        self.schema_version == STEIN_IDENTITY_SCHEMA_V1
            && self.invariant_behavioral_constraints == stein_identity_constraints_v1()
            && self.provenance.source == RecordProvenanceSource::ProductMigration
            && self.provenance.version == STEIN_IDENTITY_MIGRATION_V1
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionTone {
    Concise,
    Neutral,
    Reflective,
}

pub const USER_PREFERENCES_SCHEMA_V1: u16 = 1;

/// A deterministic fixed-offset do-not-disturb interval. Start is inclusive,
/// end is exclusive, and a window may wrap across midnight. Persisting the
/// user's chosen offset avoids silently changing policy when host timezone
/// configuration changes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DoNotDisturbWindow {
    pub start_minute_local: u16,
    pub end_minute_local: u16,
    pub utc_offset_minutes: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplicitPreferences {
    #[serde(default = "user_preferences_schema_v1")]
    pub schema_version: u16,
    pub owner: ActorId,
    pub revision: u64,
    #[serde(default)]
    pub preferred_form_of_address: Option<String>,
    pub intervention_tone: InterventionTone,
    pub default_focus_minutes: u16,
    pub maximum_interventions_per_session: u16,
    #[serde(default = "default_model_requests_per_hour")]
    pub maximum_model_requests_per_hour: u16,
    #[serde(default = "default_intervention_cooldown_seconds")]
    pub minimum_intervention_cooldown_seconds: u64,
    #[serde(default)]
    pub proactive_interventions_enabled: bool,
    #[serde(default)]
    pub proactive_interventions_muted: bool,
    #[serde(default)]
    pub do_not_disturb_windows: Vec<DoNotDisturbWindow>,
    #[serde(default = "default_delivery_channels")]
    pub allowed_delivery_channels: BTreeSet<String>,
    #[serde(default)]
    pub remote_processing_enabled: bool,
    #[serde(default)]
    pub restart_continuity_default: bool,
    #[serde(default = "legacy_preferences_provenance")]
    pub provenance: RecordProvenance,
    pub updated_at: OffsetDateTime,
}

impl ExplicitPreferences {
    #[must_use]
    pub fn phase2_defaults(owner: ActorId, updated_at: OffsetDateTime) -> Self {
        Self {
            schema_version: USER_PREFERENCES_SCHEMA_V1,
            owner,
            revision: 1,
            preferred_form_of_address: None,
            intervention_tone: InterventionTone::Concise,
            default_focus_minutes: 45,
            maximum_interventions_per_session: 3,
            maximum_model_requests_per_hour: default_model_requests_per_hour(),
            minimum_intervention_cooldown_seconds: default_intervention_cooldown_seconds(),
            proactive_interventions_enabled: false,
            proactive_interventions_muted: false,
            do_not_disturb_windows: Vec::new(),
            allowed_delivery_channels: default_delivery_channels(),
            remote_processing_enabled: false,
            restart_continuity_default: false,
            provenance: RecordProvenance {
                source: RecordProvenanceSource::ProductDefault,
                version: "phase2-focus-v1".to_owned(),
                recorded_at: updated_at,
            },
            updated_at,
        }
    }
}

const fn user_preferences_schema_v1() -> u16 {
    USER_PREFERENCES_SCHEMA_V1
}

const fn default_model_requests_per_hour() -> u16 {
    12
}

const fn default_intervention_cooldown_seconds() -> u64 {
    15 * 60
}

fn default_delivery_channels() -> BTreeSet<String> {
    BTreeSet::from(["windows.native_notification".to_owned()])
}

const fn stein_identity_schema_v1() -> u16 {
    STEIN_IDENTITY_SCHEMA_V1
}

fn stein_identity_constraints_v1() -> BTreeSet<SteinIdentityConstraint> {
    SteinIdentityConstraint::ALL.into_iter().collect()
}

fn legacy_identity_provenance() -> RecordProvenance {
    RecordProvenance {
        source: RecordProvenanceSource::ProductMigration,
        version: STEIN_IDENTITY_MIGRATION_V1.to_owned(),
        recorded_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn legacy_preferences_provenance() -> RecordProvenance {
    RecordProvenance {
        source: RecordProvenanceSource::ProductDefault,
        version: "phase2-focus-v1".to_owned(),
        recorded_at: OffsetDateTime::UNIX_EPOCH,
    }
}
