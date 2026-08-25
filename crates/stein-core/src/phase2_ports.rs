use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    CandidateId, DataCategory, DeviceId, FocusSessionId, InterventionId, ModelRouteApproval,
    PermissionGrant, PermissionGrantId, PermissionScope, PolicyDecisionId, ResourceBinding,
    ResourceId, Urgency,
};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sensitive runtime text intentionally has no serialization implementation and
/// a redacted Debug representation. It may enter a bounded provider request but
/// cannot be placed directly in a durable record.
#[derive(Clone, Eq, PartialEq)]
pub struct SensitiveText(String);

impl SensitiveText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn clear(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SensitiveText {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for SensitiveText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveText")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceState {
    Active,
    Idle,
    Locked,
    SwitchedAway,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForegroundApplicationState {
    Selected { application_id: String },
    OutsideSelectedScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceActivityKind {
    Created,
    Modified,
    Renamed,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedObservationValue {
    Presence(PresenceState),
    ForegroundApplication(ForegroundApplicationState),
    WindowMetadata {
        bounded_text: SensitiveText,
    },
    BrowserLocation {
        origin: Option<SensitiveText>,
        path: Option<SensitiveText>,
        query_included: bool,
        fragment_included: bool,
    },
    VisibleText {
        bounded_text: SensitiveText,
    },
    SelectedDocument {
        bounded_text: SensitiveText,
    },
    PixelDerivedSummary {
        bounded_text: SensitiveText,
    },
    WorkspaceActivity {
        activity: WorkspaceActivityKind,
    },
}

impl NormalizedObservationValue {
    pub const fn category(&self) -> DataCategory {
        match self {
            Self::Presence(_) | Self::ForegroundApplication(_) => DataCategory::EvidenceAggregates,
            Self::WindowMetadata { .. } => DataCategory::WindowMetadata,
            Self::BrowserLocation { .. } => DataCategory::BrowserLocation,
            Self::VisibleText { .. } => DataCategory::VisibleText,
            Self::SelectedDocument { .. } => DataCategory::SelectedDocument,
            Self::PixelDerivedSummary { .. } => DataCategory::ScreenPixels,
            Self::WorkspaceActivity { .. } => DataCategory::WorkspaceActivity,
        }
    }

    pub const fn required_scope(&self) -> PermissionScope {
        match self {
            Self::Presence(_) => PermissionScope::ObserveDesktopPresence,
            Self::ForegroundApplication(_) => PermissionScope::ObserveDesktopForegroundApplication,
            Self::WindowMetadata { .. } => PermissionScope::ObserveDesktopWindowMetadata,
            Self::BrowserLocation { .. } => PermissionScope::ObserveBrowserLocation,
            Self::VisibleText { .. } => PermissionScope::ObserveContentVisibleText,
            Self::SelectedDocument { .. } => PermissionScope::ObserveContentSelectedDocument,
            Self::PixelDerivedSummary { .. } => PermissionScope::ObserveScreenPixels,
            Self::WorkspaceActivity { .. } => PermissionScope::ObserveWorkspaceActivity,
        }
    }

    pub fn bounded_text(&self) -> Option<&SensitiveText> {
        match self {
            Self::WindowMetadata { bounded_text }
            | Self::VisibleText { bounded_text }
            | Self::SelectedDocument { bounded_text }
            | Self::PixelDerivedSummary { bounded_text } => Some(bounded_text),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationSensitivity {
    Personal,
    Restricted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRetention {
    EphemeralSession,
    SingleOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserLocationGranularity {
    pub origin: bool,
    pub path: bool,
    pub query: bool,
    pub fragment: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationProvenance {
    pub source_id: String,
    pub source_event_id: Uuid,
    pub selected_resource_id: Option<ResourceId>,
    pub observed_at: OffsetDateTime,
    pub received_at: OffsetDateTime,
    pub extraction_version: String,
    pub redaction_version: String,
    pub normalization_schema_version: String,
    pub confidence_basis_points: u16,
    pub complete: bool,
    pub sensitivity: ObservationSensitivity,
    pub retention: ObservationRetention,
    pub browser_granularity: Option<BrowserLocationGranularity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedObservation {
    pub observation_id: Uuid,
    pub session_id: FocusSessionId,
    pub grant_id: PermissionGrantId,
    pub grant_revision: u64,
    pub device_id: DeviceId,
    pub value: NormalizedObservationValue,
    pub provenance: ObservationProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceHealth {
    Unknown,
    Healthy,
    Degraded,
    Paused,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSourceStatus {
    pub source_id: String,
    pub grant_id: PermissionGrantId,
    pub scope: PermissionScope,
    pub resource_id: Option<ResourceId>,
    pub health: SourceHealth,
    pub detail: &'static str,
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationLimits {
    pub maximum_payload_bytes: usize,
    pub minimum_interval: std::time::Duration,
    pub heartbeat_interval: std::time::Duration,
    pub stale_after: std::time::Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationStartRequest {
    pub grant: PermissionGrant,
    pub resource: Option<ResourceBinding>,
    pub limits: ObservationLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationAdapterEvent {
    Observation(Box<NormalizedObservation>),
    SourceStatus(ObservationSourceStatus),
}

pub struct ObservationSubscription {
    pub initial_status: ObservationSourceStatus,
    pub events: mpsc::Receiver<ObservationAdapterEvent>,
}

pub trait ObservationPort: Send + Sync {
    fn availability(&self, scope: PermissionScope) -> crate::PlatformPortAvailability;

    fn start<'a>(
        &'a self,
        request: &'a ObservationStartRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<ObservationSubscription, ObservationPortError>>;

    fn stop<'a>(
        &'a self,
        session_id: FocusSessionId,
        grant_id: crate::PermissionGrantId,
    ) -> PortFuture<'a, Result<(), ObservationPortError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationPortErrorKind {
    BoundaryLost,
    ProtectedSurface,
    PermissionDenied,
    Cancelled,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationPortError {
    pub kind: ObservationPortErrorKind,
    pub summary: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkingContextItem {
    pub category: DataCategory,
    pub value: SensitiveText,
    pub source_id: String,
    pub resource_id: Option<ResourceId>,
    pub observed_at: OffsetDateTime,
    pub age_ms: u64,
    pub confidence_basis_points: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReasoningRequest {
    pub request_id: Uuid,
    pub session_id: FocusSessionId,
    pub route: ModelRouteApproval,
    pub goal_title: SensitiveText,
    pub success_statement: SensitiveText,
    pub deadline: Option<OffsetDateTime>,
    pub context: Vec<WorkingContextItem>,
    pub permitted_categories: BTreeSet<DataCategory>,
    pub issued_at: OffsetDateTime,
    pub deadline_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelReasoningOutput {
    Silence {
        reason_code: String,
    },
    Candidate {
        candidate_id: CandidateId,
        user_visible_text: String,
        reason_code: String,
        evidence_summary: String,
        urgency: Urgency,
        confidence_basis_points: u16,
    },
}

pub trait ModelGateway: Send + Sync {
    fn availability(&self) -> crate::PlatformPortAvailability;

    fn reason<'a>(
        &'a self,
        request: &'a ModelReasoningRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<ModelReasoningOutput, ModelGatewayError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelGatewayErrorKind {
    RouteNotApproved,
    HandlingMismatch,
    InvalidResponse,
    BudgetExceeded,
    DeadlineExceeded,
    Cancelled,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelGatewayError {
    pub kind: ModelGatewayErrorKind,
    pub summary: &'static str,
    pub retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationDelivery {
    pub intervention_id: InterventionId,
    pub policy_decision_id: PolicyDecisionId,
    pub title: String,
    pub body: String,
    pub urgency: Urgency,
    pub deduplication_key: Uuid,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelAcknowledgement {
    AcceptedByChannel,
    DeliveryUnknown,
    DeliveryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationPortError {
    pub summary: &'static str,
    pub retryable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryChannelHealth {
    Healthy,
    Suppressed,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryChannelStatus {
    pub channel_id: String,
    pub health: DeliveryChannelHealth,
    pub detail: &'static str,
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeResourceStatus {
    pub grant_id: PermissionGrantId,
    pub scope: PermissionScope,
    pub display_label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCaptureStatus {
    pub revision: u64,
    pub session_id: FocusSessionId,
    pub active_scopes: BTreeSet<PermissionScope>,
    pub resources: Vec<NativeResourceStatus>,
    pub muted: bool,
    pub source_degraded: bool,
    pub published_at: OffsetDateTime,
    pub heartbeat_deadline: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStatusAcknowledgement {
    pub session_id: FocusSessionId,
    pub revision: u64,
    pub acknowledged_at: OffsetDateTime,
    pub heartbeat_deadline: OffsetDateTime,
}

/// An adapter-originated proof that the independent native status/control
/// surface is still servicing the exact status revision for a focus session.
/// CORE owns the timeout; adapters must not synthesize heartbeats from a cached
/// availability flag after their message loop or native registration is lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStatusHeartbeat {
    pub session_id: FocusSessionId,
    pub revision: u64,
    pub emitted_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStatusError {
    pub summary: &'static str,
    pub retryable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyCommand {
    OpenStein,
    SetInterventionsMuted {
        session_id: FocusSessionId,
        muted: bool,
    },
    StopAllObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyCommandEnvelope {
    pub command_id: Uuid,
    pub revision: u64,
    pub issued_at: OffsetDateTime,
    pub command: EmergencyCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyCommandStatus {
    Accepted,
    Rejected,
    CleanupIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyCommandAcknowledgement {
    pub command_id: Uuid,
    pub revision: u64,
    pub status: EmergencyCommandStatus,
    pub acknowledged_at: OffsetDateTime,
}
