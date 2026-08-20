//! Provider- and platform-neutral application core for the Phase 1 proof.
//!
//! This crate deliberately owns no transport, daemon-supervision, presentation,
//! database, or model-provider implementation. Infrastructure calls the typed
//! application API and maps the resulting views to `stein-protocol` DTOs.

mod application;
mod clock;
mod domain;
mod error;
mod phase2_domain;
mod phase2_ports;
mod ports;
mod protocol_adapter;
mod repository;
mod second_mind;
mod view_publication;

pub use application::{
    CapabilityHealth, CapabilityState, ClientSnapshot, CoreApplication, CoreRuntime, DelayEcho,
    EventStreamError, RuntimeCapabilityInputs, RuntimeHealth, RuntimeStatus, Subscription,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use domain::{
    ActorId, CreateGoal, Goal, GoalId, GoalPatch, GoalState, IdempotencyKey, Revision, UpdateGoal,
};
pub use error::{ApplicationError, ErrorCode, FieldViolation};
pub use phase2_domain::{
    AuditKind, AuditRecord, AuditRecordId, CandidateId, ClientId, DataCategory, DeviceId,
    DeviceRegistration, DoNotDisturbWindow, EvidenceRole, EvidenceSummary, ExplicitPreferences,
    FocusSession, FocusSessionId, FocusSessionState, GrantState, Intervention,
    InterventionDecisionWrite, InterventionId, InterventionOutcome, InterventionState,
    InterventionTone, ModelHandlingProfile, ModelPlacement, ModelRouteApproval,
    ModelRouteApprovalId, ModelRouteReference, OutboxEntryId, OutboxState,
    PendingInterventionDelivery, PermissionGrant, PermissionGrantId, PermissionScope,
    PolicyDecision, PolicyDecisionId, PolicyOutcome, PolicyTrace, ProviderRetentionPolicy,
    ProviderTrainingUse, RecordProvenance, RecordProvenanceSource, ResourceBinding, ResourceId,
    ResourceKind, STEIN_IDENTITY_MIGRATION_V1, STEIN_IDENTITY_SCHEMA_V1,
    SelectedResourceDeletionTombstone, SteinIdentity, SteinIdentityConstraint,
    USER_PREFERENCES_SCHEMA_V1, Urgency,
};
pub use phase2_ports::{
    BrowserLocationGranularity, ChannelAcknowledgement, DeliveryChannelHealth,
    DeliveryChannelStatus, EmergencyCommand, EmergencyCommandAcknowledgement,
    EmergencyCommandEnvelope, EmergencyCommandStatus, ForegroundApplicationState, ModelGateway,
    ModelGatewayError, ModelGatewayErrorKind, ModelReasoningOutput, ModelReasoningRequest,
    NativeCaptureStatus, NativeResourceStatus, NativeStatusAcknowledgement, NativeStatusError,
    NativeStatusHeartbeat, NormalizedObservation, NormalizedObservationValue, NotificationDelivery,
    NotificationPortError, ObservationAdapterEvent, ObservationLimits, ObservationPort,
    ObservationPortError, ObservationPortErrorKind, ObservationProvenance, ObservationRetention,
    ObservationSensitivity, ObservationSourceStatus, ObservationStartRequest,
    ObservationSubscription, PortFuture, PresenceState, SensitiveText, SourceHealth,
    WorkingContextItem, WorkspaceActivityKind,
};
pub use ports::{
    ConfigError, ConfigProvider, CoreConfig, EmergencyControlPort, NativeResourceBinding,
    NativeSelectedResource, NativeStatusPort, NotificationPort, PlatformPortAvailability,
    ResourceSelectionError, ResourceSelectionErrorKind, ResourceSelectionPort, SecretHealthState,
    SecretKey, SecretPurpose, SecretRef, SecretStore, SecretStoreError, SecretStoreErrorKind,
    SecretStoreHealth, SecretValue, StaticConfigProvider, UnavailableEmergencyControlPort,
    UnavailableNativeStatusPort, UnavailableNotificationPort, UnavailableResourceSelectionPort,
    UnavailableSecretStore,
};
pub use protocol_adapter::{ProtocolEvent, ProtocolRequestContext, ProtocolSubscription};
pub use repository::{
    DeletionSummary, DurableRepository, FocusSessionLifecycleWrite, GoalCreateReceipt,
    GoalDeletionResult, GoalDeletionTombstone, InterventionTransitionWrite, MemoryRepository,
    NativeResourceCleanup, OperationKind, OperationReceipt, OwnerStateSnapshot,
    PendingDeliveryTransition, PermissionGrantRevocationWrite, RepositoryError,
    RepositoryErrorKind, SecretDeletionCleanup, SelectedResourceDeletionResult,
};
pub use second_mind::{
    CleanupMaintenanceResult, ClientAssurance, EffectivePolicy, EndFocusReason, GrantPermission,
    IdempotencyContext, ReasoningCycleResult, RetentionMaintenanceResult, SecondMindConfig,
    SecondMindError, SecondMindErrorCode, SecondMindPorts, SecondMindRuntime, StartFocusSession,
    UnavailableModelGateway, UnavailableObservationPort,
};
pub use view_publication::{
    CaptureViewProjection, CoreEvent, CoreEventActorKind, CoreEventEnvelope,
    FocusSessionViewChange, GoalViewChange, InterventionHistoryViewChange, PermissionRecord,
    PermissionViewChange, SelectedResourceViewChange,
};

/// The canonical public wire schema lives in this dependency. Re-exporting it
/// makes the boundary explicit without allowing protocol DTOs to become domain
/// entities.
pub use stein_protocol as protocol;
