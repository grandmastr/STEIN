use serde::{Deserialize, Serialize};

use crate::{
    ActorReference, CancellationId, CapabilityHealth, CapabilityId, ClientInstanceId,
    ClientSnapshot, Component, CorrelationId, DaemonInstanceId, DeliveryChannelView, DeviceId,
    DoNotDisturbWindowView, EffectivePolicyView, EventCursor, EventMetadata, FocusSessionId,
    FocusSessionView, GoalDeletionTombstoneView, GoalId, GoalView, InterventionExplanationView,
    InterventionHistoryView, InterventionId, InterventionOutcome, InterventionStyle,
    InterventionView, MessageId, ModelDataCategory, ModelRouteApprovalId, ModelRouteApprovalView,
    ModelRouteReference, PermissionContinuity, PermissionGrantId, PermissionGrantView,
    PermissionRecordView, PermissionReference, PermissionScope, ProtocolSupport, ProtocolVersion,
    ProviderHandlingProfile, RequestId, RequestMetadata, ResponseMetadata, RetentionClass,
    RuntimeStatus, SelectedResourceDeletionTombstoneView, SelectedResourceId, SelectedResourceKind,
    SelectedResourceView, SensitivityClass, SteinIdentityV1View, UserPreferencesV1View,
    UtcTimestamp,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "message_type", content = "body", rename_all = "snake_case")]
pub enum ClientMessage {
    OpenSession(ClientHello),
    Request(RequestEnvelope),
    Cancel(CancelRequest),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMessageKind {
    OpenSession,
    Request,
    Cancel,
}

impl ClientMessageKind {
    pub const ALL: [Self; 3] = [Self::OpenSession, Self::Request, Self::Cancel];
}

impl ClientMessage {
    #[must_use]
    pub const fn kind(&self) -> ClientMessageKind {
        match self {
            Self::OpenSession(_) => ClientMessageKind::OpenSession,
            Self::Request(_) => ClientMessageKind::Request,
            Self::Cancel(_) => ClientMessageKind::Cancel,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "message_type", content = "body", rename_all = "snake_case")]
pub enum ServerMessage {
    SessionOpened(SessionOpened),
    Response(ResponseEnvelope),
    Event(EventEnvelope),
    CancelAcknowledged(CancelAcknowledged),
    EventGap(EventGap),
    Fatal(FatalFrame),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerMessageKind {
    SessionOpened,
    Response,
    Event,
    CancelAcknowledged,
    EventGap,
    Fatal,
}

impl ServerMessageKind {
    pub const ALL: [Self; 6] = [
        Self::SessionOpened,
        Self::Response,
        Self::Event,
        Self::CancelAcknowledged,
        Self::EventGap,
        Self::Fatal,
    ];
}

impl ServerMessage {
    #[must_use]
    pub const fn kind(&self) -> ServerMessageKind {
        match self {
            Self::SessionOpened(_) => ServerMessageKind::SessionOpened,
            Self::Response(_) => ServerMessageKind::Response,
            Self::Event(_) => ServerMessageKind::Event,
            Self::CancelAcknowledged(_) => ServerMessageKind::CancelAcknowledged,
            Self::EventGap(_) => ServerMessageKind::EventGap,
            Self::Fatal(_) => ServerMessageKind::Fatal,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientHello {
    pub client_instance_id: ClientInstanceId,
    pub client_name: String,
    pub client_build_id: String,
    pub protocol_support: ProtocolSupport,
    pub max_frame_bytes: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionOpened {
    pub protocol_version: ProtocolVersion,
    pub server_build_id: String,
    pub daemon_instance_id: DaemonInstanceId,
    pub authenticated_actor: ActorReference,
    pub max_frame_bytes: u32,
    pub capabilities: Vec<CapabilityHealth>,
    pub snapshot: ClientSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    pub request_id: RequestId,
    pub metadata: RequestMetadata,
    pub body: RequestBody,
}

impl RequestEnvelope {
    #[must_use]
    pub fn new(metadata: RequestMetadata, body: RequestBody) -> Self {
        Self {
            request_id: RequestId::new_v7(),
            metadata,
            body,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "request_type", content = "payload", rename_all = "snake_case")]
pub enum RequestBody {
    CreateGoal(CreateGoalRequest),
    UpdateGoal(Box<UpdateGoalRequest>),
    CompleteGoal(Box<CompleteGoalRequest>),
    AbandonGoal(Box<AbandonGoalRequest>),
    DeleteGoal(Box<DeleteGoalRequest>),
    ApproveModelRoute(Box<ApproveModelRouteRequest>),
    GrantSessionPermission(Box<GrantSessionPermissionRequest>),
    RevokePermission(Box<RevokePermissionRequest>),
    StartFocusSession(Box<StartFocusSessionRequest>),
    SetInterventionsMuted(Box<SetInterventionsMutedRequest>),
    EndFocusSession(Box<EndFocusSessionRequest>),
    RecordInterventionFeedback(Box<RecordInterventionFeedbackRequest>),
    RegisterSelectedResource(Box<RegisterSelectedResourceRequest>),
    RemoveSelectedResource(Box<RemoveSelectedResourceRequest>),
    UpdateUserPreferences(Box<UpdateUserPreferencesRequest>),
    GetSnapshot(GetSnapshotRequest),
    GetRuntimeStatus(GetRuntimeStatusRequest),
    GetGoal(GetGoalRequest),
    GetFocusSessionView(GetFocusSessionViewRequest),
    GetCapabilityHealth(GetCapabilityHealthRequest),
    GetPermissionView(GetPermissionViewRequest),
    GetInterventionHistory(GetInterventionHistoryRequest),
    ExplainIntervention(ExplainInterventionRequest),
    GetSteinIdentity(GetSteinIdentityRequest),
    GetUserPreferences(GetUserPreferencesRequest),
    GetEffectivePolicy(GetEffectivePolicyRequest),
    GetSelectedResources(GetSelectedResourcesRequest),
    DelayEcho(DelayEchoRequest),
    Shutdown(ShutdownRequest),
}

impl RequestBody {
    #[must_use]
    pub const fn kind(&self) -> RequestKind {
        match self {
            Self::CreateGoal(_) => RequestKind::CreateGoal,
            Self::UpdateGoal(_) => RequestKind::UpdateGoal,
            Self::CompleteGoal(_) => RequestKind::CompleteGoal,
            Self::AbandonGoal(_) => RequestKind::AbandonGoal,
            Self::DeleteGoal(_) => RequestKind::DeleteGoal,
            Self::ApproveModelRoute(_) => RequestKind::ApproveModelRoute,
            Self::GrantSessionPermission(_) => RequestKind::GrantSessionPermission,
            Self::RevokePermission(_) => RequestKind::RevokePermission,
            Self::StartFocusSession(_) => RequestKind::StartFocusSession,
            Self::SetInterventionsMuted(_) => RequestKind::SetInterventionsMuted,
            Self::EndFocusSession(_) => RequestKind::EndFocusSession,
            Self::RecordInterventionFeedback(_) => RequestKind::RecordInterventionFeedback,
            Self::RegisterSelectedResource(_) => RequestKind::RegisterSelectedResource,
            Self::RemoveSelectedResource(_) => RequestKind::RemoveSelectedResource,
            Self::UpdateUserPreferences(_) => RequestKind::UpdateUserPreferences,
            Self::GetSnapshot(_) => RequestKind::GetSnapshot,
            Self::GetRuntimeStatus(_) => RequestKind::GetRuntimeStatus,
            Self::GetGoal(_) => RequestKind::GetGoal,
            Self::GetFocusSessionView(_) => RequestKind::GetFocusSessionView,
            Self::GetCapabilityHealth(_) => RequestKind::GetCapabilityHealth,
            Self::GetPermissionView(_) => RequestKind::GetPermissionView,
            Self::GetInterventionHistory(_) => RequestKind::GetInterventionHistory,
            Self::ExplainIntervention(_) => RequestKind::ExplainIntervention,
            Self::GetSteinIdentity(_) => RequestKind::GetSteinIdentity,
            Self::GetUserPreferences(_) => RequestKind::GetUserPreferences,
            Self::GetEffectivePolicy(_) => RequestKind::GetEffectivePolicy,
            Self::GetSelectedResources(_) => RequestKind::GetSelectedResources,
            Self::DelayEcho(_) => RequestKind::DelayEcho,
            Self::Shutdown(_) => RequestKind::Shutdown,
        }
    }

    #[must_use]
    pub const fn minimum_protocol_version(&self) -> ProtocolVersion {
        self.kind().minimum_protocol_version()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    CreateGoal,
    UpdateGoal,
    CompleteGoal,
    AbandonGoal,
    DeleteGoal,
    ApproveModelRoute,
    GrantSessionPermission,
    RevokePermission,
    StartFocusSession,
    SetInterventionsMuted,
    EndFocusSession,
    RecordInterventionFeedback,
    RegisterSelectedResource,
    RemoveSelectedResource,
    UpdateUserPreferences,
    GetSnapshot,
    GetRuntimeStatus,
    GetGoal,
    GetFocusSessionView,
    GetCapabilityHealth,
    GetPermissionView,
    GetInterventionHistory,
    ExplainIntervention,
    GetSteinIdentity,
    GetUserPreferences,
    GetEffectivePolicy,
    GetSelectedResources,
    DelayEcho,
    Shutdown,
}

impl RequestKind {
    pub const ALL: [Self; 29] = [
        Self::CreateGoal,
        Self::UpdateGoal,
        Self::CompleteGoal,
        Self::AbandonGoal,
        Self::DeleteGoal,
        Self::ApproveModelRoute,
        Self::GrantSessionPermission,
        Self::RevokePermission,
        Self::StartFocusSession,
        Self::SetInterventionsMuted,
        Self::EndFocusSession,
        Self::RecordInterventionFeedback,
        Self::RegisterSelectedResource,
        Self::RemoveSelectedResource,
        Self::UpdateUserPreferences,
        Self::GetSnapshot,
        Self::GetRuntimeStatus,
        Self::GetGoal,
        Self::GetFocusSessionView,
        Self::GetCapabilityHealth,
        Self::GetPermissionView,
        Self::GetInterventionHistory,
        Self::ExplainIntervention,
        Self::GetSteinIdentity,
        Self::GetUserPreferences,
        Self::GetEffectivePolicy,
        Self::GetSelectedResources,
        Self::DelayEcho,
        Self::Shutdown,
    ];

    #[must_use]
    pub const fn minimum_protocol_version(self) -> ProtocolVersion {
        match self {
            Self::CreateGoal
            | Self::GetSnapshot
            | Self::GetRuntimeStatus
            | Self::DelayEcho
            | Self::Shutdown => ProtocolVersion::V1_0,
            Self::UpdateGoal
            | Self::CompleteGoal
            | Self::AbandonGoal
            | Self::ApproveModelRoute
            | Self::GrantSessionPermission
            | Self::RevokePermission
            | Self::StartFocusSession
            | Self::SetInterventionsMuted
            | Self::EndFocusSession
            | Self::RecordInterventionFeedback
            | Self::GetGoal
            | Self::GetFocusSessionView
            | Self::GetCapabilityHealth
            | Self::GetPermissionView
            | Self::GetInterventionHistory
            | Self::ExplainIntervention => ProtocolVersion::V1_1,
            Self::DeleteGoal
            | Self::RegisterSelectedResource
            | Self::RemoveSelectedResource
            | Self::UpdateUserPreferences
            | Self::GetSteinIdentity
            | Self::GetUserPreferences
            | Self::GetEffectivePolicy
            | Self::GetSelectedResources => ProtocolVersion::V1_2,
        }
    }

    /// Aggregate-creating commands require an actor-scoped idempotency key in
    /// request metadata. Expected-revision commands remain conflict-safe.
    #[must_use]
    pub const fn requires_idempotency_key(self) -> bool {
        matches!(
            self,
            Self::CreateGoal
                | Self::ApproveModelRoute
                | Self::GrantSessionPermission
                | Self::StartFocusSession
                | Self::RegisterSelectedResource
        )
    }

    #[must_use]
    pub const fn requires_expected_revision(self) -> bool {
        matches!(
            self,
            Self::UpdateGoal
                | Self::CompleteGoal
                | Self::AbandonGoal
                | Self::DeleteGoal
                | Self::RevokePermission
                | Self::SetInterventionsMuted
                | Self::EndFocusSession
                | Self::RecordInterventionFeedback
                | Self::RemoveSelectedResource
                | Self::UpdateUserPreferences
        )
    }

    /// Conservative payload classification used when a client constructs request
    /// metadata. An authenticated server still validates the classification and
    /// resolves every authority reference itself.
    #[must_use]
    pub const fn sensitivity(self) -> SensitivityClass {
        match self {
            Self::GetRuntimeStatus | Self::GetCapabilityHealth | Self::Shutdown => {
                SensitivityClass::Operational
            }
            Self::ApproveModelRoute
            | Self::GrantSessionPermission
            | Self::RevokePermission
            | Self::StartFocusSession
            | Self::SetInterventionsMuted
            | Self::EndFocusSession
            | Self::GetSnapshot
            | Self::GetFocusSessionView
            | Self::GetPermissionView
            | Self::RegisterSelectedResource
            | Self::RemoveSelectedResource
            | Self::UpdateUserPreferences
            | Self::GetSteinIdentity
            | Self::GetUserPreferences
            | Self::GetEffectivePolicy
            | Self::GetSelectedResources => SensitivityClass::Restricted,
            Self::CreateGoal
            | Self::UpdateGoal
            | Self::CompleteGoal
            | Self::AbandonGoal
            | Self::DeleteGoal
            | Self::RecordInterventionFeedback
            | Self::GetGoal
            | Self::GetInterventionHistory
            | Self::ExplainIntervention
            | Self::DelayEcho => SensitivityClass::Personal,
        }
    }

    #[must_use]
    pub const fn retention(self) -> RetentionClass {
        RetentionClass::Runtime
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateGoalRequest {
    pub title: String,
    pub success_statement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<UtcTimestamp>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum GoalDeadlinePatch {
    Clear,
    Set { deadline: UtcTimestamp },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<GoalDeadlinePatch>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateGoalRequest {
    pub goal_id: GoalId,
    pub expected_revision: u64,
    pub patch: GoalPatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteGoalRequest {
    pub goal_id: GoalId,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbandonGoalRequest {
    pub goal_id: GoalId,
    pub expected_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteGoalRequest {
    pub goal_id: GoalId,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApproveModelRouteRequest {
    pub route: ModelRouteReference,
    pub account_profile: String,
    pub allowed_data_categories: Vec<ModelDataCategory>,
    pub handling: ProviderHandlingProfile,
    pub purpose: String,
    pub maximum_request_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ModelRouteReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
    pub disclosure_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantSessionPermissionRequest {
    pub goal_id: GoalId,
    /// Retained for protocol 1.1 decoding. Protocol 1.2 clients omit this
    /// field; CORE binds the grant to its durable current-device identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_resource_id: Option<SelectedResourceId>,
    pub purpose: String,
    pub expires_at: UtcTimestamp,
    pub continuity: PermissionContinuity,
    pub consent_copy_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevokePermissionRequest {
    pub target: PermissionReference,
    pub expected_revision: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartFocusSessionRequest {
    pub goal_id: GoalId,
    pub goal_revision: u64,
    pub selected_resource_ids: Vec<SelectedResourceId>,
    pub permission_grant_ids: Vec<PermissionGrantId>,
    pub model_route_approval_id: ModelRouteApprovalId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetInterventionsMutedRequest {
    pub focus_session_id: FocusSessionId,
    pub expected_revision: u64,
    pub muted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusSessionEndReason {
    UserRequested,
    GoalCompleted,
    GoalAbandoned,
    PermissionRevoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndFocusSessionRequest {
    pub focus_session_id: FocusSessionId,
    pub expected_revision: u64,
    pub reason: FocusSessionEndReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum InterventionFeedback {
    Accepted,
    Dismissed,
    Corrected {
        correction: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        associate_resource_id: Option<SelectedResourceId>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordInterventionFeedbackRequest {
    pub intervention_id: InterventionId,
    pub expected_revision: u64,
    pub feedback: InterventionFeedback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSelectedResourceRequest {
    pub kind: SelectedResourceKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoveSelectedResourceRequest {
    pub selected_resource_id: SelectedResourceId,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserPreferencesV1Input {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_form_of_address: Option<String>,
    pub intervention_style: InterventionStyle,
    pub proactive_enabled: bool,
    pub proactive_muted: bool,
    pub maximum_interventions_per_session: u16,
    pub maximum_model_requests_per_hour: u16,
    pub minimum_intervention_cooldown_ms: u64,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindowView>,
    pub allowed_delivery_channels: Vec<crate::DeliveryChannelClass>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateUserPreferencesRequest {
    pub expected_revision: u64,
    pub preferences: UserPreferencesV1Input,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSnapshotRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetRuntimeStatusRequest {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetGoalRequest {
    pub goal_id: GoalId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetFocusSessionViewRequest {
    pub focus_session_id: FocusSessionId,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetCapabilityHealthRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetPermissionViewRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<PermissionGrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_route_approval_id: Option<ModelRouteApprovalId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetInterventionHistoryRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus_session_id: Option<FocusSessionId>,
    pub limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<UtcTimestamp>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplainInterventionRequest {
    pub intervention_id: InterventionId,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSteinIdentityRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetUserPreferencesRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetEffectivePolicyRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSelectedResourcesRequest {}

/// A synthetic cancellable request used to validate transport behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelayEchoRequest {
    pub delay_ms: u64,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownReason {
    UserRequested,
    Upgrade,
    Uninstall,
    Test,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShutdownRequest {
    pub reason: ShutdownReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResponseEnvelope {
    pub request_id: RequestId,
    pub metadata: ResponseMetadata,
    pub outcome: ResponseOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", content = "body", rename_all = "snake_case")]
pub enum ResponseOutcome {
    Success(ResponseBody),
    Error(PublicError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "response_type", content = "payload", rename_all = "snake_case")]
pub enum ResponseBody {
    CreateGoal(CreateGoalResponse),
    UpdateGoal(Box<UpdateGoalResponse>),
    CompleteGoal(Box<CompleteGoalResponse>),
    AbandonGoal(Box<AbandonGoalResponse>),
    DeleteGoal(Box<DeleteGoalResponse>),
    ApproveModelRoute(Box<ApproveModelRouteResponse>),
    GrantSessionPermission(Box<GrantSessionPermissionResponse>),
    RevokePermission(Box<RevokePermissionResponse>),
    StartFocusSession(Box<StartFocusSessionResponse>),
    SetInterventionsMuted(Box<SetInterventionsMutedResponse>),
    EndFocusSession(Box<EndFocusSessionResponse>),
    RecordInterventionFeedback(Box<RecordInterventionFeedbackResponse>),
    RegisterSelectedResource(Box<RegisterSelectedResourceResponse>),
    RemoveSelectedResource(Box<RemoveSelectedResourceResponse>),
    UpdateUserPreferences(Box<UpdateUserPreferencesResponse>),
    GetSnapshot(GetSnapshotResponse),
    GetRuntimeStatus(GetRuntimeStatusResponse),
    GetGoal(Box<GetGoalResponse>),
    GetFocusSessionView(Box<GetFocusSessionViewResponse>),
    GetCapabilityHealth(Box<GetCapabilityHealthResponse>),
    GetPermissionView(Box<GetPermissionViewResponse>),
    GetInterventionHistory(Box<GetInterventionHistoryResponse>),
    ExplainIntervention(Box<ExplainInterventionResponse>),
    GetSteinIdentity(Box<GetSteinIdentityResponse>),
    GetUserPreferences(Box<GetUserPreferencesResponse>),
    GetEffectivePolicy(Box<GetEffectivePolicyResponse>),
    GetSelectedResources(Box<GetSelectedResourcesResponse>),
    DelayEcho(DelayEchoResponse),
    Shutdown(ShutdownResponse),
}

impl ResponseBody {
    #[must_use]
    pub const fn kind(&self) -> RequestKind {
        match self {
            Self::CreateGoal(_) => RequestKind::CreateGoal,
            Self::UpdateGoal(_) => RequestKind::UpdateGoal,
            Self::CompleteGoal(_) => RequestKind::CompleteGoal,
            Self::AbandonGoal(_) => RequestKind::AbandonGoal,
            Self::DeleteGoal(_) => RequestKind::DeleteGoal,
            Self::ApproveModelRoute(_) => RequestKind::ApproveModelRoute,
            Self::GrantSessionPermission(_) => RequestKind::GrantSessionPermission,
            Self::RevokePermission(_) => RequestKind::RevokePermission,
            Self::StartFocusSession(_) => RequestKind::StartFocusSession,
            Self::SetInterventionsMuted(_) => RequestKind::SetInterventionsMuted,
            Self::EndFocusSession(_) => RequestKind::EndFocusSession,
            Self::RecordInterventionFeedback(_) => RequestKind::RecordInterventionFeedback,
            Self::RegisterSelectedResource(_) => RequestKind::RegisterSelectedResource,
            Self::RemoveSelectedResource(_) => RequestKind::RemoveSelectedResource,
            Self::UpdateUserPreferences(_) => RequestKind::UpdateUserPreferences,
            Self::GetSnapshot(_) => RequestKind::GetSnapshot,
            Self::GetRuntimeStatus(_) => RequestKind::GetRuntimeStatus,
            Self::GetGoal(_) => RequestKind::GetGoal,
            Self::GetFocusSessionView(_) => RequestKind::GetFocusSessionView,
            Self::GetCapabilityHealth(_) => RequestKind::GetCapabilityHealth,
            Self::GetPermissionView(_) => RequestKind::GetPermissionView,
            Self::GetInterventionHistory(_) => RequestKind::GetInterventionHistory,
            Self::ExplainIntervention(_) => RequestKind::ExplainIntervention,
            Self::GetSteinIdentity(_) => RequestKind::GetSteinIdentity,
            Self::GetUserPreferences(_) => RequestKind::GetUserPreferences,
            Self::GetEffectivePolicy(_) => RequestKind::GetEffectivePolicy,
            Self::GetSelectedResources(_) => RequestKind::GetSelectedResources,
            Self::DelayEcho(_) => RequestKind::DelayEcho,
            Self::Shutdown(_) => RequestKind::Shutdown,
        }
    }

    #[must_use]
    pub const fn minimum_protocol_version(&self) -> ProtocolVersion {
        self.kind().minimum_protocol_version()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateGoalResponse {
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateGoalResponse {
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteGoalResponse {
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbandonGoalResponse {
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteGoalResponse {
    pub tombstone: GoalDeletionTombstoneView,
    pub already_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApproveModelRouteResponse {
    pub approval: ModelRouteApprovalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantSessionPermissionResponse {
    pub permission: PermissionGrantView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevokePermissionResponse {
    pub permission: PermissionRecordView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartFocusSessionResponse {
    pub focus_session: FocusSessionView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetInterventionsMutedResponse {
    pub focus_session: FocusSessionView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndFocusSessionResponse {
    pub focus_session: FocusSessionView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordInterventionFeedbackResponse {
    pub intervention: InterventionView,
    pub outcome: InterventionOutcome,
    pub context_correction_applied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSelectedResourceResponse {
    pub resource: SelectedResourceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoveSelectedResourceResponse {
    pub tombstone: SelectedResourceDeletionTombstoneView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateUserPreferencesResponse {
    pub preferences: UserPreferencesV1View,
    pub effective_policy: EffectivePolicyView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSnapshotResponse {
    pub snapshot: ClientSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetRuntimeStatusResponse {
    pub runtime: RuntimeStatus,
    pub capabilities: Vec<CapabilityHealth>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetGoalResponse {
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetFocusSessionViewResponse {
    pub focus_session: FocusSessionView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<crate::CaptureStateView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetCapabilityHealthResponse {
    pub capabilities: Vec<CapabilityHealth>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetPermissionViewResponse {
    pub records: Vec<PermissionRecordView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetInterventionHistoryResponse {
    pub history: InterventionHistoryView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplainInterventionResponse {
    pub explanation: InterventionExplanationView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSteinIdentityResponse {
    pub identity: SteinIdentityV1View,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetUserPreferencesResponse {
    pub preferences: UserPreferencesV1View,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetEffectivePolicyResponse {
    pub effective_policy: EffectivePolicyView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSelectedResourcesResponse {
    pub resources: Vec<SelectedResourceView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelayEchoResponse {
    pub text: String,
    pub completed_after_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShutdownResponse {
    pub daemon_instance_id: DaemonInstanceId,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub cursor: EventCursor,
    pub metadata: EventMetadata,
    pub event: ViewEvent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event_type", content = "payload", rename_all = "snake_case")]
pub enum ViewEvent {
    GoalViewChanged(GoalViewChanged),
    RuntimeStatusChanged(RuntimeStatusChanged),
    FocusSessionViewChanged(FocusSessionViewChanged),
    CaptureStateChanged(CaptureStateChanged),
    CapabilityHealthChanged(CapabilityHealthChanged),
    DeliveryChannelViewChanged(DeliveryChannelViewChanged),
    PermissionViewChanged(PermissionViewChanged),
    InterventionAvailable(InterventionAvailable),
    InterventionViewChanged(InterventionViewChanged),
    InterventionHistoryChanged(InterventionHistoryChanged),
    GoalDeleted(GoalDeleted),
    SelectedResourceViewChanged(SelectedResourceViewChanged),
    UserPreferencesViewChanged(UserPreferencesViewChanged),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewEventKind {
    GoalViewChanged,
    RuntimeStatusChanged,
    FocusSessionViewChanged,
    CaptureStateChanged,
    CapabilityHealthChanged,
    DeliveryChannelViewChanged,
    PermissionViewChanged,
    InterventionAvailable,
    InterventionViewChanged,
    InterventionHistoryChanged,
    GoalDeleted,
    SelectedResourceViewChanged,
    UserPreferencesViewChanged,
}

impl ViewEventKind {
    pub const ALL: [Self; 13] = [
        Self::GoalViewChanged,
        Self::RuntimeStatusChanged,
        Self::FocusSessionViewChanged,
        Self::CaptureStateChanged,
        Self::CapabilityHealthChanged,
        Self::DeliveryChannelViewChanged,
        Self::PermissionViewChanged,
        Self::InterventionAvailable,
        Self::InterventionViewChanged,
        Self::InterventionHistoryChanged,
        Self::GoalDeleted,
        Self::SelectedResourceViewChanged,
        Self::UserPreferencesViewChanged,
    ];

    #[must_use]
    pub const fn minimum_protocol_version(self) -> ProtocolVersion {
        match self {
            Self::GoalViewChanged | Self::RuntimeStatusChanged => ProtocolVersion::V1_0,
            Self::FocusSessionViewChanged
            | Self::CaptureStateChanged
            | Self::CapabilityHealthChanged
            | Self::DeliveryChannelViewChanged
            | Self::PermissionViewChanged
            | Self::InterventionAvailable
            | Self::InterventionViewChanged
            | Self::InterventionHistoryChanged => ProtocolVersion::V1_1,
            Self::GoalDeleted
            | Self::SelectedResourceViewChanged
            | Self::UserPreferencesViewChanged => ProtocolVersion::V1_2,
        }
    }

    #[must_use]
    pub const fn sensitivity(self) -> SensitivityClass {
        match self {
            Self::RuntimeStatusChanged
            | Self::CapabilityHealthChanged
            | Self::DeliveryChannelViewChanged => SensitivityClass::Operational,
            Self::FocusSessionViewChanged
            | Self::CaptureStateChanged
            | Self::PermissionViewChanged
            | Self::SelectedResourceViewChanged
            | Self::UserPreferencesViewChanged => SensitivityClass::Restricted,
            Self::GoalViewChanged
            | Self::InterventionAvailable
            | Self::InterventionViewChanged
            | Self::InterventionHistoryChanged
            | Self::GoalDeleted => SensitivityClass::Personal,
        }
    }

    #[must_use]
    pub const fn retention(self) -> RetentionClass {
        RetentionClass::Runtime
    }
}

impl ViewEvent {
    #[must_use]
    pub const fn kind(&self) -> ViewEventKind {
        match self {
            Self::GoalViewChanged(_) => ViewEventKind::GoalViewChanged,
            Self::RuntimeStatusChanged(_) => ViewEventKind::RuntimeStatusChanged,
            Self::FocusSessionViewChanged(_) => ViewEventKind::FocusSessionViewChanged,
            Self::CaptureStateChanged(_) => ViewEventKind::CaptureStateChanged,
            Self::CapabilityHealthChanged(_) => ViewEventKind::CapabilityHealthChanged,
            Self::DeliveryChannelViewChanged(_) => ViewEventKind::DeliveryChannelViewChanged,
            Self::PermissionViewChanged(_) => ViewEventKind::PermissionViewChanged,
            Self::InterventionAvailable(_) => ViewEventKind::InterventionAvailable,
            Self::InterventionViewChanged(_) => ViewEventKind::InterventionViewChanged,
            Self::InterventionHistoryChanged(_) => ViewEventKind::InterventionHistoryChanged,
            Self::GoalDeleted(_) => ViewEventKind::GoalDeleted,
            Self::SelectedResourceViewChanged(_) => ViewEventKind::SelectedResourceViewChanged,
            Self::UserPreferencesViewChanged(_) => ViewEventKind::UserPreferencesViewChanged,
        }
    }

    #[must_use]
    pub const fn minimum_protocol_version(&self) -> ProtocolVersion {
        self.kind().minimum_protocol_version()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalChangeKind {
    Created,
    Updated,
    Completed,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalViewChanged {
    pub change: GoalChangeKind,
    pub goal: GoalView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeStatusChanged {
    pub runtime: RuntimeStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusSessionChangeKind {
    Requested,
    Started,
    Muted,
    Unmuted,
    RecoveryStarted,
    Recovered,
    Stopping,
    Ended,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FocusSessionViewChanged {
    pub change: FocusSessionChangeKind,
    pub focus_session: FocusSessionView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptureStateChanged {
    pub capture: crate::CaptureStateView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityHealthChanged {
    pub capability: CapabilityHealth,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryChannelViewChanged {
    pub channel: DeliveryChannelView,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionChangeKind {
    Granted,
    Updated,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionViewChanged {
    pub change: PermissionChangeKind,
    pub permission: PermissionRecordView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionAvailable {
    pub intervention: InterventionView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionViewChanged {
    pub intervention: InterventionView,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionHistoryChangeKind {
    Added,
    Updated,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterventionHistoryChanged {
    pub change: InterventionHistoryChangeKind,
    pub intervention_id: InterventionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<InterventionView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoalDeleted {
    pub tombstone: GoalDeletionTombstoneView,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedResourceChangeKind {
    Registered,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedResourceViewChanged {
    pub change: SelectedResourceChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<SelectedResourceView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone: Option<SelectedResourceDeletionTombstoneView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserPreferencesViewChanged {
    pub preferences: UserPreferencesV1View,
    pub effective_policy: EffectivePolicyView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelRequest {
    pub message_id: MessageId,
    pub issued_at: UtcTimestamp,
    pub correlation_id: CorrelationId,
    pub origin: Component,
    pub target_request_id: RequestId,
    pub cancellation_id: CancellationId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationStatus {
    CancellationRequested,
    RequestNotFound,
    RequestAlreadyCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelAcknowledged {
    pub message_id: MessageId,
    pub issued_at: UtcTimestamp,
    pub correlation_id: CorrelationId,
    pub causation_id: MessageId,
    pub actor: ActorReference,
    pub target_request_id: RequestId,
    pub cancellation_id: CancellationId,
    pub status: CancellationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventGapReason {
    ConsumerLagged,
    SequenceMismatch,
    DaemonInstanceChanged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventGapAction {
    ReconnectForSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventGap {
    pub message_id: MessageId,
    pub occurred_at: UtcTimestamp,
    pub reason: EventGapReason,
    pub expected_cursor: EventCursor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_cursor: Option<EventCursor>,
    pub action: EventGapAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    ConfirmationRequired,
    NotFound,
    Conflict,
    IncompatibleVersion,
    Unavailable,
    DeadlineExceeded,
    Cancelled,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    ConfirmationRequired,
    NotFound,
    Conflict,
    IncompatibleProtocol,
    UnsupportedSchema,
    CapabilityUnavailable,
    DeadlineExceeded,
    Cancelled,
    RateLimited,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicError {
    pub code: ErrorCode,
    pub category: ErrorCategory,
    /// A safe, user-facing summary. It must never echo private input.
    pub summary: String,
    pub retryable: bool,
    pub correlation_id: CorrelationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "detail_type", content = "detail", rename_all = "snake_case")]
pub enum ErrorDetails {
    Validation(ValidationErrorDetails),
    Compatibility(CompatibilityErrorDetails),
    SupportedSchema(SupportedSchemaDetails),
    CurrentRevision(CurrentRevisionDetails),
    Limit(LimitErrorDetails),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationErrorDetails {
    pub violations: Vec<FieldViolation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldViolation {
    pub field: ValidationField,
    pub reason: ValidationReason,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationField {
    Title,
    SuccessStatement,
    Deadline,
    ExpectedRevision,
    GoalId,
    FocusSessionId,
    InterventionId,
    PermissionGrantId,
    ModelRouteApprovalId,
    SelectedResourceId,
    Scope,
    Purpose,
    ExpiresAt,
    Continuity,
    ConsentCopyVersion,
    Provider,
    Route,
    Placement,
    DataCategories,
    HandlingProfile,
    Feedback,
    DelayMs,
    Text,
    SchemaVersion,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationReason {
    Required,
    TooLong,
    OutOfRange,
    InvalidFormat,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompatibilityErrorDetails {
    pub client_support: ProtocolSupport,
    pub server_support: ProtocolSupport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupportedSchemaDetails {
    pub request_kind: RequestKind,
    pub supported_versions: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentRevisionDetails {
    pub current_revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    FrameBytes,
    RequestRate,
    ConcurrentRequests,
    DelayMilliseconds,
    TextBytes,
    ObservationBytes,
    ModelTokens,
    OutboxEntries,
    InterventionsPerSession,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LimitErrorDetails {
    pub limit: LimitKind,
    pub maximum: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FatalReason {
    HandshakeRequired,
    AuthenticationFailed,
    IncompatibleProtocol,
    MalformedFrame,
    FrameLimitExceeded,
    ServerStopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FatalFrame {
    pub reason: FatalReason,
    pub error: PublicError,
}

macro_rules! impl_boxed_request_conversion {
    ($request:ty, $variant:ident) => {
        impl From<$request> for RequestBody {
            fn from(value: $request) -> Self {
                Self::$variant(Box::new(value))
            }
        }
    };
}

impl_boxed_request_conversion!(UpdateGoalRequest, UpdateGoal);
impl_boxed_request_conversion!(CompleteGoalRequest, CompleteGoal);
impl_boxed_request_conversion!(AbandonGoalRequest, AbandonGoal);
impl_boxed_request_conversion!(DeleteGoalRequest, DeleteGoal);
impl_boxed_request_conversion!(ApproveModelRouteRequest, ApproveModelRoute);
impl_boxed_request_conversion!(GrantSessionPermissionRequest, GrantSessionPermission);
impl_boxed_request_conversion!(RevokePermissionRequest, RevokePermission);
impl_boxed_request_conversion!(StartFocusSessionRequest, StartFocusSession);
impl_boxed_request_conversion!(SetInterventionsMutedRequest, SetInterventionsMuted);
impl_boxed_request_conversion!(EndFocusSessionRequest, EndFocusSession);
impl_boxed_request_conversion!(
    RecordInterventionFeedbackRequest,
    RecordInterventionFeedback
);
impl_boxed_request_conversion!(RegisterSelectedResourceRequest, RegisterSelectedResource);
impl_boxed_request_conversion!(RemoveSelectedResourceRequest, RemoveSelectedResource);
impl_boxed_request_conversion!(UpdateUserPreferencesRequest, UpdateUserPreferences);

macro_rules! impl_boxed_response_conversion {
    ($response:ty, $variant:ident) => {
        impl From<$response> for ResponseBody {
            fn from(value: $response) -> Self {
                Self::$variant(Box::new(value))
            }
        }
    };
}

impl_boxed_response_conversion!(UpdateGoalResponse, UpdateGoal);
impl_boxed_response_conversion!(CompleteGoalResponse, CompleteGoal);
impl_boxed_response_conversion!(AbandonGoalResponse, AbandonGoal);
impl_boxed_response_conversion!(DeleteGoalResponse, DeleteGoal);
impl_boxed_response_conversion!(ApproveModelRouteResponse, ApproveModelRoute);
impl_boxed_response_conversion!(GrantSessionPermissionResponse, GrantSessionPermission);
impl_boxed_response_conversion!(RevokePermissionResponse, RevokePermission);
impl_boxed_response_conversion!(StartFocusSessionResponse, StartFocusSession);
impl_boxed_response_conversion!(SetInterventionsMutedResponse, SetInterventionsMuted);
impl_boxed_response_conversion!(EndFocusSessionResponse, EndFocusSession);
impl_boxed_response_conversion!(
    RecordInterventionFeedbackResponse,
    RecordInterventionFeedback
);
impl_boxed_response_conversion!(RegisterSelectedResourceResponse, RegisterSelectedResource);
impl_boxed_response_conversion!(RemoveSelectedResourceResponse, RemoveSelectedResource);
impl_boxed_response_conversion!(UpdateUserPreferencesResponse, UpdateUserPreferences);
impl_boxed_response_conversion!(GetGoalResponse, GetGoal);
impl_boxed_response_conversion!(GetFocusSessionViewResponse, GetFocusSessionView);
impl_boxed_response_conversion!(GetCapabilityHealthResponse, GetCapabilityHealth);
impl_boxed_response_conversion!(GetPermissionViewResponse, GetPermissionView);
impl_boxed_response_conversion!(GetInterventionHistoryResponse, GetInterventionHistory);
impl_boxed_response_conversion!(ExplainInterventionResponse, ExplainIntervention);
impl_boxed_response_conversion!(GetSteinIdentityResponse, GetSteinIdentity);
impl_boxed_response_conversion!(GetUserPreferencesResponse, GetUserPreferences);
impl_boxed_response_conversion!(GetEffectivePolicyResponse, GetEffectivePolicy);
impl_boxed_response_conversion!(GetSelectedResourcesResponse, GetSelectedResources);

// Naming aliases retained for adapters and tests that describe transport frames
// rather than protocol messages.
pub type ClientFrame = ClientMessage;
pub type ServerFrame = ServerMessage;
pub type ClientRequest = RequestBody;
pub type ServerResponse = ResponseBody;
pub type ServerEvent = ViewEvent;

// The accepted architecture uses the longer query name. Keep the established
// v1.0 wire tag (`get_snapshot`) while offering source-level terminology that
// matches the Phase 2 contract.
pub type GetClientSnapshotRequest = GetSnapshotRequest;
pub type GetClientSnapshotResponse = GetSnapshotResponse;
