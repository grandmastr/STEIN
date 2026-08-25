use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stein_protocol::{
    CapabilityHealth, CapabilityId, CapabilityUnavailableReason, CaptureStateView, ClientSnapshot,
    DeliveryChannelView as ProtocolDeliveryChannelView,
    EffectivePolicyView as ProtocolEffectivePolicyView, EventEnvelope,
    FocusSessionView as ProtocolFocusSessionView, GoalDeletionTombstoneView,
    GoalState as ProtocolGoalState, GoalView as ProtocolGoalView,
    InterventionExplanationView as ProtocolExplanationView,
    InterventionView as ProtocolInterventionView,
    ModelRequestReceiptView as ProtocolModelRequestReceiptView, ModelRouteApprovalView,
    ObservationSourceView as ProtocolObservationSourceView, PermissionGrantView,
    PermissionRecordView, RuntimeState as ProtocolRuntimeState,
    SelectedResourceDeletionTombstoneView, SelectedResourceView,
    SteinIdentityV1View as ProtocolSteinIdentityView,
    UserPreferencesV1View as ProtocolUserPreferencesView, ViewEvent,
};

pub const DESKTOP_BRIDGE_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSnapshot {
    pub bridge_schema_version: u16,
    pub observed_at: String,
    pub connection: ConnectionView,
    pub access: ClientAccessView,
    pub runtime: RuntimeView,
    pub capabilities: Vec<CapabilityView>,
    pub goals: Vec<GoalView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stein_identity: Option<SteinIdentityView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_preferences: Option<UserPreferencesView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_policy: Option<EffectivePolicyView>,
    pub selected_resources: Vec<ResourceView>,
    pub session_grants: Vec<SessionGrantView>,
    pub model_routes: Vec<ModelRouteView>,
    pub focus_sessions: Vec<FocusSessionView>,
    pub capture_states: Vec<CaptureView>,
    pub delivery_channels: Vec<DeliveryChannelView>,
    pub intervention_history: Vec<InterventionView>,
    pub cursor: String,
    pub recent_events: Vec<CoreEventView>,
}

impl DashboardSnapshot {
    pub fn from_protocol(
        snapshot: &ClientSnapshot,
        connection: ConnectionView,
        private_protocol_available: bool,
        recent_events: Vec<CoreEventView>,
    ) -> Self {
        let mut selected_resources = Vec::new();
        let mut current_device_id = None;
        let mut stein_identity = None;
        let mut user_preferences = None;
        let mut effective_policy = None;
        let mut session_grants = Vec::new();
        let mut model_routes = Vec::new();
        let mut focus_sessions = Vec::new();
        let mut capture_states = Vec::new();
        let mut delivery_channels = Vec::new();
        let mut intervention_history = Vec::new();

        if private_protocol_available && let Some(phase2) = snapshot.phase2.as_deref() {
            current_device_id = phase2.current_device_id.map(|id| id.to_string());
            stein_identity = phase2
                .stein_identity
                .as_ref()
                .map(SteinIdentityView::from_protocol);
            user_preferences = phase2
                .user_preferences
                .as_ref()
                .map(UserPreferencesView::from_protocol);
            effective_policy = phase2
                .effective_policy
                .as_ref()
                .map(EffectivePolicyView::from_protocol);
            selected_resources = phase2
                .selected_resources
                .iter()
                .map(ResourceView::from_protocol)
                .collect();
            for record in &phase2.permission_records {
                match record {
                    PermissionRecordView::SessionGrant(grant) => {
                        session_grants.push(SessionGrantView::from_protocol(grant));
                    }
                    PermissionRecordView::ModelRouteApproval(route) => {
                        model_routes.push(ModelRouteView::from_protocol(route));
                    }
                }
            }
            focus_sessions = phase2
                .focus_sessions
                .iter()
                .map(FocusSessionView::from_protocol)
                .collect();
            capture_states = phase2
                .capture_states
                .iter()
                .map(CaptureView::from_protocol)
                .collect();
            delivery_channels = phase2
                .delivery_channels
                .iter()
                .map(DeliveryChannelView::from_protocol)
                .collect();
            intervention_history = phase2
                .intervention_history
                .entries
                .iter()
                .map(InterventionView::from_protocol)
                .collect();
        }

        Self {
            bridge_schema_version: DESKTOP_BRIDGE_SCHEMA_VERSION,
            observed_at: snapshot.as_of.to_string(),
            connection,
            access: ClientAccessView::new(private_protocol_available),
            runtime: RuntimeView::from_snapshot(snapshot),
            capabilities: snapshot
                .capabilities
                .iter()
                .map(|capability| {
                    CapabilityView::from_protocol(capability, snapshot.as_of.to_string())
                })
                .collect(),
            goals: if private_protocol_available {
                snapshot.goals.iter().map(GoalView::from_protocol).collect()
            } else {
                Vec::new()
            },
            current_device_id,
            stein_identity,
            user_preferences,
            effective_policy,
            selected_resources,
            session_grants,
            model_routes,
            focus_sessions,
            capture_states,
            delivery_channels,
            intervention_history,
            cursor: cursor_string(snapshot.cursor),
            recent_events: if private_protocol_available {
                recent_events
            } else {
                Vec::new()
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAccessView {
    pub assurance: ClientAssuranceView,
    pub private_protocol_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl ClientAccessView {
    fn new(private_protocol_available: bool) -> Self {
        if private_protocol_available {
            Self {
                assurance: ClientAssuranceView::PrivateCapabilityBound,
                private_protocol_available: true,
                unavailable_reason: None,
            }
        } else {
            Self {
                assurance: ClientAssuranceView::Diagnostic,
                private_protocol_available: false,
                unavailable_reason: Some(
                    "Private views and controls require signed-package broker admission; this connection is diagnostic-only."
                        .to_owned(),
                ),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAssuranceView {
    Diagnostic,
    PrivateCapabilityBound,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    pub phase: ConnectionPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    pub reconnect_attempt: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PublicErrorView>,
}

impl ConnectionView {
    pub fn connecting(at: String, attempt: u32) -> Self {
        Self {
            phase: ConnectionPhase::Connecting,
            connected_at: None,
            last_attempt_at: Some(at),
            reconnect_attempt: attempt,
            error: None,
        }
    }

    pub fn connected(at: String, attempt: u32) -> Self {
        Self {
            phase: ConnectionPhase::Connected,
            connected_at: Some(at.clone()),
            last_attempt_at: Some(at),
            reconnect_attempt: attempt,
            error: None,
        }
    }

    pub fn disconnected(at: String, attempt: u32, error: PublicErrorView) -> Self {
        Self {
            phase: ConnectionPhase::Disconnected,
            connected_at: None,
            last_attempt_at: Some(at),
            reconnect_attempt: attempt,
            error: Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeView {
    pub phase: RuntimePhase,
    pub daemon_instance_id: String,
    pub build_id: String,
    pub started_at: String,
    pub protocol: ProtocolVersionView,
}

impl RuntimeView {
    fn from_snapshot(snapshot: &ClientSnapshot) -> Self {
        let runtime = &snapshot.runtime;
        Self {
            phase: match runtime.state {
                ProtocolRuntimeState::Starting => RuntimePhase::Starting,
                ProtocolRuntimeState::Ready => RuntimePhase::Ready,
                ProtocolRuntimeState::Degraded => RuntimePhase::Degraded,
                ProtocolRuntimeState::Stopping => RuntimePhase::Stopping,
            },
            daemon_instance_id: runtime.daemon_instance_id.to_string(),
            build_id: runtime.build_id.clone(),
            started_at: runtime.started_at.to_string(),
            protocol: ProtocolVersionView {
                major: runtime.protocol_version.major,
                minor: runtime.protocol_version.minor,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Starting,
    Ready,
    Degraded,
    Stopping,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolVersionView {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityView {
    pub id: String,
    pub label: String,
    pub state: HealthState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub checked_at: String,
}

impl CapabilityView {
    fn from_protocol(capability: &CapabilityHealth, checked_at: String) -> Self {
        let (id, label) = capability_identity(capability.capability);
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            state: match capability.state {
                stein_protocol::HealthState::Healthy => HealthState::Healthy,
                stein_protocol::HealthState::Degraded => HealthState::Degraded,
                stein_protocol::HealthState::Unavailable => HealthState::Unavailable,
            },
            detail: capability.unavailable_reason.map(unavailable_reason),
            checked_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoalView {
    pub id: String,
    pub revision: u64,
    pub title: String,
    pub success_statement: String,
    pub state: GoalState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl GoalView {
    pub fn from_protocol(goal: &ProtocolGoalView) -> Self {
        Self {
            id: goal.goal_id.to_string(),
            revision: goal.revision,
            title: goal.title.clone(),
            success_statement: goal.success_statement.clone(),
            state: match goal.state {
                ProtocolGoalState::Draft => GoalState::Draft,
                ProtocolGoalState::Active => GoalState::Active,
                ProtocolGoalState::Completed => GoalState::Completed,
                ProtocolGoalState::Abandoned => GoalState::Abandoned,
            },
            deadline: goal.deadline.map(|deadline| deadline.to_string()),
            created_at: goal.created_at.to_string(),
            updated_at: goal.updated_at.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalState {
    Draft,
    Active,
    Completed,
    Abandoned,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceView {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl ResourceView {
    pub fn from_protocol(resource: &SelectedResourceView) -> Self {
        Self {
            id: resource.selected_resource_id.to_string(),
            kind: snake_debug(resource.kind),
            display_name: resource.display_name.clone(),
            revision: resource.revision,
            created_at: resource.created_at.map(|time| time.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordProvenanceView {
    pub source: String,
    pub version: String,
    pub recorded_at: String,
}

impl RecordProvenanceView {
    fn from_protocol(provenance: &stein_protocol::RecordProvenanceView) -> Self {
        Self {
            source: snake_debug(provenance.source),
            version: provenance.version.clone(),
            recorded_at: provenance.recorded_at.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SteinIdentityView {
    pub schema_version: u16,
    pub owner_id: String,
    pub revision: u64,
    pub display_name: String,
    pub role_statement: String,
    pub invariant_behavioral_constraints: Vec<String>,
    pub provenance: RecordProvenanceView,
}

impl SteinIdentityView {
    pub fn from_protocol(identity: &ProtocolSteinIdentityView) -> Self {
        Self {
            schema_version: identity.schema_version,
            owner_id: identity.owner_id.to_string(),
            revision: identity.revision,
            display_name: identity.display_name.clone(),
            role_statement: identity.role_statement.clone(),
            invariant_behavioral_constraints: identity
                .invariant_behavioral_constraints
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            provenance: RecordProvenanceView::from_protocol(&identity.provenance),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DoNotDisturbWindowView {
    pub start_minute_local: u16,
    pub end_minute_local: u16,
    pub utc_offset_minutes: i16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPreferencesView {
    pub schema_version: u16,
    pub owner_id: String,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_form_of_address: Option<String>,
    pub intervention_style: String,
    pub proactive_enabled: bool,
    pub proactive_muted: bool,
    pub maximum_interventions_per_session: u16,
    pub maximum_model_requests_per_hour: u16,
    pub minimum_intervention_cooldown_ms: u64,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindowView>,
    pub allowed_delivery_channels: Vec<String>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
    pub provenance: RecordProvenanceView,
}

impl UserPreferencesView {
    pub fn from_protocol(preferences: &ProtocolUserPreferencesView) -> Self {
        Self {
            schema_version: preferences.schema_version,
            owner_id: preferences.owner_id.to_string(),
            revision: preferences.revision,
            preferred_form_of_address: preferences.preferred_form_of_address.clone(),
            intervention_style: snake_debug(preferences.intervention_style),
            proactive_enabled: preferences.proactive_enabled,
            proactive_muted: preferences.proactive_muted,
            maximum_interventions_per_session: preferences.maximum_interventions_per_session,
            maximum_model_requests_per_hour: preferences.maximum_model_requests_per_hour,
            minimum_intervention_cooldown_ms: preferences.minimum_intervention_cooldown_ms,
            do_not_disturb_windows: preferences
                .do_not_disturb_windows
                .iter()
                .map(|window| DoNotDisturbWindowView {
                    start_minute_local: window.start_minute_local,
                    end_minute_local: window.end_minute_local,
                    utc_offset_minutes: window.utc_offset_minutes,
                })
                .collect(),
            allowed_delivery_channels: preferences
                .allowed_delivery_channels
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            remote_processing_enabled: preferences.remote_processing_enabled,
            restart_continuity_default: preferences.restart_continuity_default,
            provenance: RecordProvenanceView::from_protocol(&preferences.provenance),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
    pub allowed_delivery_channels: Vec<String>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
    pub outbox_capacity_per_user: u16,
    pub outbox_capacity_per_session: u16,
}

impl EffectivePolicyView {
    pub fn from_protocol(policy: &ProtocolEffectivePolicyView) -> Self {
        Self {
            schema_version: policy.schema_version,
            policy_profile_id: policy.policy_profile_id.clone(),
            user_preferences_revision: policy.user_preferences_revision,
            source_stale_after_ms: policy.source_stale_after_ms,
            maximum_model_evidence_age_ms: policy.maximum_model_evidence_age_ms,
            model_request_cooldown_ms: policy.model_request_cooldown_ms,
            maximum_model_requests_per_hour: policy.maximum_model_requests_per_hour,
            intervention_cooldown_ms: policy.intervention_cooldown_ms,
            maximum_interventions_per_session: policy.maximum_interventions_per_session,
            proactive_enabled: policy.proactive_enabled,
            proactive_muted: policy.proactive_muted,
            do_not_disturb_windows: policy
                .do_not_disturb_windows
                .iter()
                .map(|window| DoNotDisturbWindowView {
                    start_minute_local: window.start_minute_local,
                    end_minute_local: window.end_minute_local,
                    utc_offset_minutes: window.utc_offset_minutes,
                })
                .collect(),
            allowed_delivery_channels: policy
                .allowed_delivery_channels
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            remote_processing_enabled: policy.remote_processing_enabled,
            restart_continuity_default: policy.restart_continuity_default,
            outbox_capacity_per_user: policy.outbox_capacity_per_user,
            outbox_capacity_per_session: policy.outbox_capacity_per_session,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoalDeletionView {
    pub goal_id: String,
    pub deleted_revision: u64,
    pub deleted_at: String,
    pub focus_sessions_deleted: u64,
    pub grants_deleted: u64,
    pub interventions_deleted: u64,
    pub pending_deliveries_deleted: u64,
    pub private_audit_records_deleted: u64,
    pub resource_bindings_deleted: u64,
    pub already_deleted: bool,
}

impl GoalDeletionView {
    pub fn from_protocol(tombstone: &GoalDeletionTombstoneView, already_deleted: bool) -> Self {
        Self {
            goal_id: tombstone.goal_id.to_string(),
            deleted_revision: tombstone.deleted_revision,
            deleted_at: tombstone.deleted_at.to_string(),
            focus_sessions_deleted: tombstone.focus_sessions_deleted,
            grants_deleted: tombstone.grants_deleted,
            interventions_deleted: tombstone.interventions_deleted,
            pending_deliveries_deleted: tombstone.pending_deliveries_deleted,
            private_audit_records_deleted: tombstone.private_audit_records_deleted,
            resource_bindings_deleted: tombstone.resource_bindings_deleted,
            already_deleted,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedResourceDeletionView {
    pub selected_resource_id: String,
    pub deleted_revision: u64,
    pub deleted_at: String,
}

impl SelectedResourceDeletionView {
    pub fn from_protocol(tombstone: &SelectedResourceDeletionTombstoneView) -> Self {
        Self {
            selected_resource_id: tombstone.selected_resource_id.to_string(),
            deleted_revision: tombstone.deleted_revision,
            deleted_at: tombstone.deleted_at.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPreferencesUpdateView {
    pub preferences: UserPreferencesView,
    pub effective_policy: EffectivePolicyView,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionGrantView {
    pub id: String,
    pub revision: u64,
    pub goal_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus_session_id: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_resource_id: Option<String>,
    pub purpose: String,
    pub while_client_disconnected: bool,
    pub after_daemon_restart: bool,
    pub state: String,
    pub effective_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    pub consent_copy_version: String,
    pub sensitivity: String,
    pub retention: String,
}

impl SessionGrantView {
    pub fn from_protocol(grant: &PermissionGrantView) -> Self {
        Self {
            id: grant.permission_grant_id.to_string(),
            revision: grant.revision,
            goal_id: grant.goal_id.to_string(),
            device_id: grant.device_id.to_string(),
            focus_session_id: grant.focus_session_id.map(|id| id.to_string()),
            scope: permission_scope(grant.scope).to_owned(),
            selected_resource_id: grant.selected_resource_id.map(|id| id.to_string()),
            purpose: grant.purpose.clone(),
            while_client_disconnected: grant.continuity.while_client_disconnected,
            after_daemon_restart: grant.continuity.after_daemon_restart,
            state: snake_debug(grant.state),
            effective_at: grant.effective_at.to_string(),
            expires_at: grant.expires_at.to_string(),
            revoked_at: grant.revoked_at.map(|time| time.to_string()),
            revocation_reason: grant.revocation_reason.clone(),
            consent_copy_version: grant.consent_copy_version.clone(),
            sensitivity: snake_debug(grant.sensitivity),
            retention: snake_debug(grant.retention),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRouteView {
    pub id: String,
    pub revision: u64,
    pub provider_id: String,
    pub route_id: String,
    pub placement: String,
    pub account_profile: String,
    pub allowed_data_categories: Vec<String>,
    pub retention: String,
    pub training_use: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_residency: Option<String>,
    pub handling_profile_version: String,
    pub purpose: String,
    pub maximum_request_tokens: u32,
    pub has_fallback: bool,
    pub state: String,
    pub effective_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub disclosure_version: String,
}

impl ModelRouteView {
    pub fn from_protocol(route: &ModelRouteApprovalView) -> Self {
        Self {
            id: route.model_route_approval_id.to_string(),
            revision: route.revision,
            provider_id: route.route.provider_id.clone(),
            route_id: route.route.route_id.clone(),
            placement: snake_debug(route.route.placement),
            account_profile: route.account_profile.clone(),
            allowed_data_categories: route
                .allowed_data_categories
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            retention: provider_retention(&route.handling.retention),
            training_use: snake_debug(route.handling.training_use),
            data_residency: route.handling.data_residency.clone(),
            handling_profile_version: route.handling.profile_version.clone(),
            purpose: route.purpose.clone(),
            maximum_request_tokens: route.maximum_request_tokens,
            has_fallback: route.fallback.is_some(),
            state: snake_debug(route.state),
            effective_at: route.effective_at.to_string(),
            expires_at: route.expires_at.map(|time| time.to_string()),
            revoked_at: route.revoked_at.map(|time| time.to_string()),
            disclosure_version: route.disclosure_version.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FocusSessionView {
    pub id: String,
    pub revision: u64,
    pub goal_id: String,
    pub goal_revision: u64,
    pub state: String,
    pub interventions_muted: bool,
    pub source_degraded: bool,
    pub model_route_approval_id: String,
    pub permission_grant_ids: Vec<String>,
    pub selected_resource_ids: Vec<String>,
    pub while_client_disconnected: bool,
    pub after_daemon_restart: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub updated_at: String,
}

impl FocusSessionView {
    pub fn from_protocol(session: &ProtocolFocusSessionView) -> Self {
        Self {
            id: session.focus_session_id.to_string(),
            revision: session.revision,
            goal_id: session.goal_id.to_string(),
            goal_revision: session.goal_revision,
            state: snake_debug(session.state),
            interventions_muted: session.interventions_muted,
            source_degraded: session.source_degraded,
            model_route_approval_id: session.model_route_approval_id.to_string(),
            permission_grant_ids: session
                .permission_grant_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            selected_resource_ids: session
                .selected_resource_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            while_client_disconnected: session.continuity.while_client_disconnected,
            after_daemon_restart: session.continuity.after_daemon_restart,
            created_at: session.created_at.to_string(),
            started_at: session.started_at.map(|time| time.to_string()),
            ended_at: session.ended_at.map(|time| time.to_string()),
            updated_at: session.updated_at.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRequestReceiptView {
    pub request_id: String,
    pub focus_session_id: String,
    pub model_route_approval_id: String,
    pub model_route_revision: u64,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub outcome: String,
}

impl ModelRequestReceiptView {
    pub fn from_protocol(receipt: &ProtocolModelRequestReceiptView) -> Self {
        Self {
            request_id: receipt.request_id.to_string(),
            focus_session_id: receipt.focus_session_id.to_string(),
            model_route_approval_id: receipt.model_route_approval_id.to_string(),
            model_route_revision: receipt.model_route_revision,
            started_at: receipt.started_at.to_string(),
            completed_at: receipt.completed_at.map(|time| time.to_string()),
            outcome: snake_debug(receipt.outcome),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationSourceView {
    pub id: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_resource_id: Option<String>,
    pub health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_complete_at: Option<String>,
}

impl ObservationSourceView {
    fn from_protocol(source: &ProtocolObservationSourceView) -> Self {
        Self {
            id: source.observation_source_id.to_string(),
            category: snake_debug(source.category),
            selected_resource_id: source.selected_resource_id.map(|id| id.to_string()),
            health: snake_debug(source.health),
            last_complete_at: source.last_complete_at.map(|time| time.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureView {
    pub focus_session_id: String,
    pub revision: u64,
    pub state: String,
    pub active_categories: Vec<String>,
    pub sources: Vec<ObservationSourceView>,
    pub native_status_visible: bool,
    pub emergency_stop_available: bool,
    pub updated_at: String,
}

impl CaptureView {
    fn from_protocol(capture: &CaptureStateView) -> Self {
        Self {
            focus_session_id: capture.focus_session_id.to_string(),
            revision: capture.revision,
            state: snake_debug(capture.state),
            active_categories: capture
                .active_categories
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            sources: capture
                .sources
                .iter()
                .map(ObservationSourceView::from_protocol)
                .collect(),
            native_status_visible: capture.native_status_visible,
            emergency_stop_available: capture.emergency_stop_available,
            updated_at: capture.updated_at.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryChannelView {
    pub id: String,
    pub class: String,
    pub state: String,
    pub may_show_content_while_locked: bool,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
}

impl DeliveryChannelView {
    fn from_protocol(channel: &ProtocolDeliveryChannelView) -> Self {
        Self {
            id: channel.delivery_channel_id.to_string(),
            class: snake_debug(channel.class),
            state: snake_debug(channel.state),
            may_show_content_while_locked: channel.may_show_content_while_locked,
            observed_at: channel.observed_at.to_string(),
            status_code: channel.status_code.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterventionView {
    pub id: String,
    pub revision: u64,
    pub candidate_revision: u64,
    pub focus_session_id: String,
    pub goal_id: String,
    pub urgency: String,
    pub reason_codes: Vec<String>,
    pub state: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_visible_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_channel_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub updated_at: String,
}

impl InterventionView {
    pub fn from_protocol(intervention: &ProtocolInterventionView) -> Self {
        Self {
            id: intervention.intervention_id.to_string(),
            revision: intervention.revision,
            candidate_revision: intervention.candidate_revision,
            focus_session_id: intervention.focus_session_id.to_string(),
            goal_id: intervention.goal_id.to_string(),
            urgency: snake_debug(intervention.urgency),
            reason_codes: intervention
                .reason_codes
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            state: snake_debug(intervention.state),
            outcome: snake_debug(intervention.outcome),
            user_visible_text: intervention.user_visible_text.clone(),
            delivery_channel_id: intervention.delivery_channel_id.map(|id| id.to_string()),
            created_at: intervention.created_at.to_string(),
            expires_at: intervention.expires_at.to_string(),
            updated_at: intervention.updated_at.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceView {
    pub category: String,
    pub freshness: String,
    pub confidence: String,
    pub role: String,
    pub observed_from: String,
    pub observed_until: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTraceView {
    pub policy_profile_id: String,
    pub user_preferences_revision: u64,
    pub input_schema_version: u16,
    pub input_digest_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterventionExplanationView {
    pub intervention_id: String,
    pub candidate_revision: u64,
    pub focus_session_id: String,
    pub evidence: Vec<EvidenceView>,
    pub policy_decision_id: String,
    pub policy_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_trace: Option<PolicyTraceView>,
    pub decision: String,
    pub decision_reason_codes: Vec<String>,
    pub decision_issued_at: String,
    pub decision_expires_at: String,
    pub delivery_state: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_text: Option<String>,
    pub correction_recorded: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterventionHistoryView {
    pub as_of: String,
    pub entries: Vec<InterventionView>,
}

impl InterventionHistoryView {
    pub fn from_protocol(history: &stein_protocol::InterventionHistoryView) -> Self {
        Self {
            as_of: history.as_of.to_string(),
            entries: history
                .entries
                .iter()
                .map(InterventionView::from_protocol)
                .collect(),
        }
    }
}

impl InterventionExplanationView {
    pub fn from_protocol(explanation: &ProtocolExplanationView) -> Self {
        Self {
            intervention_id: explanation.intervention_id.to_string(),
            candidate_revision: explanation.candidate_revision,
            focus_session_id: explanation.focus_session_id.to_string(),
            evidence: explanation
                .evidence
                .iter()
                .map(|evidence| EvidenceView {
                    category: snake_debug(evidence.category),
                    freshness: snake_debug(evidence.freshness),
                    confidence: snake_debug(evidence.confidence),
                    role: snake_debug(evidence.role),
                    observed_from: evidence.observed_from.to_string(),
                    observed_until: evidence.observed_until.to_string(),
                })
                .collect(),
            policy_decision_id: explanation.decision.policy_decision_id.to_string(),
            policy_version: explanation.decision.policy_version.clone(),
            policy_trace: explanation
                .decision
                .policy_trace
                .as_ref()
                .map(|trace| PolicyTraceView {
                    policy_profile_id: trace.policy_profile_id.clone(),
                    user_preferences_revision: trace.user_preferences_revision,
                    input_schema_version: trace.proposed_input_schema_version,
                    input_digest_sha256: lowercase_hex(&trace.proposed_input_digest),
                }),
            decision: snake_debug(explanation.decision.outcome),
            decision_reason_codes: explanation
                .decision
                .reason_codes
                .iter()
                .copied()
                .map(snake_debug)
                .collect(),
            decision_issued_at: explanation.decision.issued_at.to_string(),
            decision_expires_at: explanation.decision.expires_at.to_string(),
            delivery_state: snake_debug(explanation.delivery_state),
            outcome: snake_debug(explanation.outcome),
            delivered_text: explanation.delivered_text.clone(),
            correction_recorded: explanation.correction_recorded,
        }
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreEventView {
    pub message_id: String,
    pub message_type: String,
    pub schema_version: u16,
    pub occurred_at: String,
    pub summary: String,
    pub cursor: String,
}

impl CoreEventView {
    pub fn from_protocol(event: &EventEnvelope) -> Self {
        let (message_type, summary) = match &event.event {
            ViewEvent::GoalViewChanged(change) => (
                "goal_view_changed",
                format!(
                    "Goal “{}” is now {}.",
                    change.goal.title,
                    snake_debug(change.goal.state)
                ),
            ),
            ViewEvent::GoalDeleted(_) => (
                "goal_deleted",
                "A goal was deleted from authoritative state.".to_owned(),
            ),
            ViewEvent::RuntimeStatusChanged(change) => (
                "runtime_status_changed",
                format!("CORE runtime is now {}.", snake_debug(change.runtime.state)),
            ),
            ViewEvent::FocusSessionViewChanged(change) => (
                "focus_session_view_changed",
                format!(
                    "Focus session is now {}.",
                    snake_debug(change.focus_session.state)
                ),
            ),
            ViewEvent::CaptureStateChanged(change) => (
                "capture_state_changed",
                format!("Capture is now {}.", snake_debug(change.capture.state)),
            ),
            ViewEvent::CapabilityHealthChanged(change) => (
                "capability_health_changed",
                format!(
                    "{} is {}.",
                    capability_identity(change.capability.capability).1,
                    snake_debug(change.capability.state)
                ),
            ),
            ViewEvent::DeliveryChannelViewChanged(change) => (
                "delivery_channel_view_changed",
                format!("Delivery channel is {}.", snake_debug(change.channel.state)),
            ),
            ViewEvent::PermissionViewChanged(change) => (
                "permission_view_changed",
                format!("Permission was {}.", snake_debug(change.change)),
            ),
            ViewEvent::InterventionAvailable(change) => (
                "intervention_available",
                format!(
                    "A {} intervention is available.",
                    snake_debug(change.intervention.urgency)
                ),
            ),
            ViewEvent::InterventionViewChanged(change) => (
                "intervention_view_changed",
                format!(
                    "Intervention is now {}.",
                    snake_debug(change.intervention.state)
                ),
            ),
            ViewEvent::InterventionHistoryChanged(change) => (
                "intervention_history_changed",
                format!("Intervention history was {}.", snake_debug(change.change)),
            ),
            ViewEvent::SelectedResourceViewChanged(change) => (
                "selected_resource_view_changed",
                format!("A selected resource was {}.", snake_debug(change.change)),
            ),
            ViewEvent::UserPreferencesViewChanged(_) => (
                "user_preferences_view_changed",
                "User preferences and effective policy were updated.".to_owned(),
            ),
        };
        Self {
            message_id: event.metadata.message_id.to_string(),
            message_type: message_type.to_owned(),
            schema_version: event.metadata.schema_version,
            occurred_at: event.metadata.occurred_at.to_string(),
            summary,
            cursor: cursor_string(event.cursor),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateGoalInput {
    pub title: String,
    pub success_statement: String,
    pub deadline: Option<String>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoalRevisionInput {
    pub goal_id: String,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoalPatchInput {
    pub title: Option<String>,
    pub success_statement: Option<String>,
    pub deadline: Option<GoalDeadlinePatchInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GoalDeadlinePatchInput {
    Clear,
    Set { deadline: String },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateGoalInput {
    pub goal_id: String,
    pub expected_revision: u64,
    pub patch: GoalPatchInput,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbandonGoalInput {
    pub goal_id: String,
    pub expected_revision: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveModelRouteInput {
    pub provider_id: String,
    pub route_id: String,
    pub placement: String,
    pub account_profile: String,
    pub allowed_data_categories: Vec<String>,
    pub retention_kind: String,
    pub retention_maximum_seconds: Option<u64>,
    pub training_use: String,
    pub data_residency: Option<String>,
    pub handling_profile_version: String,
    pub purpose: String,
    pub maximum_request_tokens: u32,
    pub expires_at: Option<String>,
    pub disclosure_version: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantPermissionInput {
    pub goal_id: String,
    /// Accepted for bridge compatibility, but protocol 1.2 binds the grant to
    /// CORE's authenticated durable current-device identity.
    pub device_id: Option<String>,
    pub scope: String,
    pub selected_resource_id: Option<String>,
    pub purpose: String,
    pub expires_at: String,
    pub while_client_disconnected: bool,
    pub after_daemon_restart: bool,
    pub consent_copy_version: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokePermissionInput {
    pub permission_type: String,
    pub permission_id: String,
    pub expected_revision: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartFocusSessionInput {
    pub goal_id: String,
    pub goal_revision: u64,
    pub selected_resource_ids: Vec<String>,
    pub permission_grant_ids: Vec<String>,
    pub model_route_approval_id: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterSelectedResourceInput {
    pub kind: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveSelectedResourceInput {
    pub selected_resource_id: String,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserPreferencesInput {
    pub preferred_form_of_address: Option<String>,
    pub intervention_style: String,
    pub proactive_enabled: bool,
    pub proactive_muted: bool,
    pub maximum_interventions_per_session: u16,
    pub maximum_model_requests_per_hour: u16,
    pub minimum_intervention_cooldown_ms: u64,
    pub do_not_disturb_windows: Vec<DoNotDisturbWindowView>,
    pub allowed_delivery_channels: Vec<String>,
    pub remote_processing_enabled: bool,
    pub restart_continuity_default: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUserPreferencesInput {
    pub expected_revision: u64,
    pub preferences: UserPreferencesInput,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetMutedInput {
    pub focus_session_id: String,
    pub expected_revision: u64,
    pub muted: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndFocusSessionInput {
    pub focus_session_id: String,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterventionFeedbackInput {
    pub intervention_id: String,
    pub expected_revision: u64,
    pub feedback: String,
    pub correction: Option<String>,
    pub associate_resource_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplainInterventionInput {
    pub intervention_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LatestModelRequestReceiptInput {
    pub focus_session_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterventionHistoryInput {
    pub focus_session_id: Option<String>,
    pub limit: u16,
    pub before: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicErrorView {
    pub code: String,
    pub category: ErrorCategory,
    pub summary: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_errors: Option<BTreeMap<String, String>>,
}

impl PublicErrorView {
    pub fn unavailable(code: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            category: ErrorCategory::Unavailable,
            summary: summary.into(),
            retryable: true,
            correlation_id: None,
            field_errors: None,
        }
    }

    pub fn permission_denied(code: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            category: ErrorCategory::PermissionDenied,
            summary: summary.into(),
            retryable: false,
            correlation_id: None,
            field_errors: None,
        }
    }

    pub fn invalid_argument(
        code: impl Into<String>,
        summary: impl Into<String>,
        field_errors: BTreeMap<String, String>,
    ) -> Self {
        Self {
            code: code.into(),
            category: ErrorCategory::InvalidArgument,
            summary: summary.into(),
            retryable: false,
            correlation_id: None,
            field_errors: Some(field_errors),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DesktopBridgeEvent {
    SnapshotChanged {
        schema_version: u16,
        snapshot: Box<DashboardSnapshot>,
    },
    ConnectionChanged {
        schema_version: u16,
        connection: ConnectionView,
    },
    ViewEvent {
        schema_version: u16,
        event: CoreEventView,
    },
}

fn capability_identity(capability: CapabilityId) -> (&'static str, &'static str) {
    match capability {
        CapabilityId::Snapshot => ("snapshot", "Authoritative snapshot"),
        CapabilityId::RuntimeStatus => ("runtime_status", "Runtime status"),
        CapabilityId::GoalCreate => ("goal_create", "Goal creation"),
        CapabilityId::GoalUpdate => ("goal_update", "Goal updates"),
        CapabilityId::GoalDelete => ("goal_delete", "Goal deletion"),
        CapabilityId::DelayEcho => ("delay_echo", "Cancellation proof"),
        CapabilityId::RuntimeShutdown => ("runtime_shutdown", "Clean shutdown"),
        CapabilityId::ViewEvents => ("view_events", "View events"),
        CapabilityId::RequestCancellation => ("request_cancellation", "Request cancellation"),
        CapabilityId::ModelRouteApproval => ("model_route_approval", "Model route approval"),
        CapabilityId::SessionPermissions => ("session_permissions", "Session permissions"),
        CapabilityId::FocusSessions => ("focus_sessions", "Focus sessions"),
        CapabilityId::CaptureState => ("capture_state", "Capture state"),
        CapabilityId::DeliveryChannels => ("delivery_channels", "Delivery channels"),
        CapabilityId::InterventionFeedback => ("intervention_feedback", "Intervention feedback"),
        CapabilityId::InterventionHistory => ("intervention_history", "Intervention history"),
        CapabilityId::InterventionExplanation => {
            ("intervention_explanation", "Intervention explanation")
        }
        CapabilityId::DesktopObservation => ("desktop_observation", "Desktop observation"),
        CapabilityId::ModelReasoning => ("model_reasoning", "Model reasoning"),
        CapabilityId::DurablePersistence => ("durable_persistence", "Durable persistence"),
        CapabilityId::NativeNotification => ("native_notification", "Native notifications"),
        CapabilityId::NativeStatus => ("native_status", "Native background status"),
        CapabilityId::EmergencyControl => ("emergency_control", "Emergency control"),
        CapabilityId::SecretStore => ("secret_store", "Secret storage"),
        CapabilityId::SteinIdentity => ("stein_identity", "STEIN identity"),
        CapabilityId::UserPreferences => ("user_preferences", "User preferences"),
        CapabilityId::EffectivePolicy => ("effective_policy", "Effective policy"),
        CapabilityId::SelectedResources => ("selected_resources", "Selected resources"),
    }
}

fn unavailable_reason(reason: CapabilityUnavailableReason) -> String {
    match reason {
        CapabilityUnavailableReason::NotImplemented => "Not implemented",
        CapabilityUnavailableReason::UnsupportedPlatform => "Unsupported on this platform",
        CapabilityUnavailableReason::DependencyUnavailable => "Dependency unavailable",
        CapabilityUnavailableReason::DisabledByConfiguration => "Disabled by configuration",
        CapabilityUnavailableReason::Starting => "Starting",
        CapabilityUnavailableReason::Stopping => "Stopping",
    }
    .to_owned()
}

fn permission_scope(scope: stein_protocol::PermissionScope) -> &'static str {
    match scope {
        stein_protocol::PermissionScope::ObserveDesktopPresence => "observe.desktop.presence",
        stein_protocol::PermissionScope::ObserveDesktopForegroundApplication => {
            "observe.desktop.foreground_application"
        }
        stein_protocol::PermissionScope::ObserveDesktopWindowMetadata => {
            "observe.desktop.window_metadata"
        }
        stein_protocol::PermissionScope::ObserveBrowserLocation => "observe.browser.location",
        stein_protocol::PermissionScope::ObserveContentVisibleText => {
            "observe.content.visible_text"
        }
        stein_protocol::PermissionScope::ObserveContentSelectedDocument => {
            "observe.content.selected_document"
        }
        stein_protocol::PermissionScope::ObserveScreenPixels => "observe.screen.pixels",
        stein_protocol::PermissionScope::ObserveWorkspaceActivity => "observe.workspace.activity",
        stein_protocol::PermissionScope::ReasonFocusContext => "reason.focus_context",
        stein_protocol::PermissionScope::InterveneDesktopNotification => {
            "intervene.desktop.notification"
        }
    }
}

fn provider_retention(retention: &stein_protocol::ProviderRetentionPolicy) -> String {
    match retention {
        stein_protocol::ProviderRetentionPolicy::None => "none".to_owned(),
        stein_protocol::ProviderRetentionPolicy::Transient => "transient".to_owned(),
        stein_protocol::ProviderRetentionPolicy::Bounded { maximum_seconds } => {
            format!("bounded:{maximum_seconds}")
        }
        stein_protocol::ProviderRetentionPolicy::Unknown => "unknown".to_owned(),
    }
}

fn snake_debug(value: impl std::fmt::Debug) -> String {
    let debug = format!("{value:?}");
    let mut output = String::with_capacity(debug.len() + 4);
    for (index, character) in debug.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

fn cursor_string(cursor: stein_protocol::EventCursor) -> String {
    format!("{}:{}", cursor.daemon_instance_id, cursor.sequence)
}

#[cfg(test)]
mod tests {
    use stein_protocol::{
        ActorId, DaemonInstanceId, DeliveryChannelClass, DeviceId,
        EffectivePolicyView as ProtocolEffectivePolicyView, EventCursor, InterventionHistoryView,
        InterventionStyle, Phase2Snapshot, ProtocolVersion, RecordProvenanceSource,
        RecordProvenanceView as ProtocolProvenanceView, RuntimeStatus, SnapshotId,
        SteinIdentityConstraint, SteinIdentityV1View, UserPreferencesV1View, UtcTimestamp,
    };

    use super::*;

    fn snapshot(phase2: Option<Box<Phase2Snapshot>>) -> ClientSnapshot {
        let now = UtcTimestamp::now();
        let daemon = DaemonInstanceId::new_v7();
        ClientSnapshot {
            snapshot_id: SnapshotId::new_v7(),
            as_of: now,
            cursor: EventCursor {
                daemon_instance_id: daemon,
                sequence: 7,
            },
            runtime: RuntimeStatus {
                daemon_instance_id: daemon,
                state: ProtocolRuntimeState::Ready,
                started_at: now,
                observed_at: now,
                build_id: "test".to_owned(),
                protocol_version: ProtocolVersion::V1_2,
                active_connections: 1,
            },
            capabilities: Vec::new(),
            goals: vec![ProtocolGoalView {
                goal_id: stein_protocol::GoalId::new_v7(),
                revision: 1,
                owner_id: ActorId::new_v7(),
                title: "Synthetic goal".to_owned(),
                success_statement: "Synthetic success".to_owned(),
                deadline: None,
                state: ProtocolGoalState::Active,
                created_at: now,
                updated_at: now,
            }],
            phase2,
        }
    }

    #[test]
    fn diagnostic_projection_never_exposes_private_snapshot_fields() {
        let private = Phase2Snapshot {
            selected_resources: Vec::new(),
            permission_records: Vec::new(),
            focus_sessions: Vec::new(),
            capture_states: Vec::new(),
            delivery_channels: Vec::new(),
            intervention_history: InterventionHistoryView {
                as_of: UtcTimestamp::now(),
                entries: Vec::new(),
            },
            current_device_id: None,
            stein_identity: None,
            user_preferences: None,
            effective_policy: None,
        };
        let view = DashboardSnapshot::from_protocol(
            &snapshot(Some(Box::new(private))),
            ConnectionView::connected(UtcTimestamp::now().to_string(), 1),
            false,
            vec![CoreEventView {
                message_id: "private".to_owned(),
                message_type: "private".to_owned(),
                schema_version: 1,
                occurred_at: UtcTimestamp::now().to_string(),
                summary: "private".to_owned(),
                cursor: "private".to_owned(),
            }],
        );

        assert!(view.goals.is_empty());
        assert!(view.recent_events.is_empty());
        assert!(view.focus_sessions.is_empty());
        assert!(view.current_device_id.is_none());
        assert!(view.stein_identity.is_none());
        assert!(view.user_preferences.is_none());
        assert!(view.effective_policy.is_none());
        assert!(!view.access.private_protocol_available);
    }

    #[test]
    fn private_projection_includes_private_goal_state() {
        let view = DashboardSnapshot::from_protocol(
            &snapshot(None),
            ConnectionView::connected(UtcTimestamp::now().to_string(), 1),
            true,
            Vec::new(),
        );
        assert_eq!(view.goals.len(), 1);
        assert!(view.access.private_protocol_available);
    }

    #[test]
    fn private_projection_retains_v12_device_identity_preferences_and_policy() {
        let now = UtcTimestamp::now();
        let owner_id = ActorId::new_v7();
        let provenance = ProtocolProvenanceView {
            source: RecordProvenanceSource::DirectUser,
            version: "synthetic-v1".to_owned(),
            recorded_at: now,
        };
        let preferences = UserPreferencesV1View {
            schema_version: 1,
            owner_id,
            revision: 2,
            preferred_form_of_address: Some("Synthetic collaborator".to_owned()),
            intervention_style: InterventionStyle::Concise,
            proactive_enabled: true,
            proactive_muted: false,
            maximum_interventions_per_session: 2,
            maximum_model_requests_per_hour: 6,
            minimum_intervention_cooldown_ms: 900_000,
            do_not_disturb_windows: Vec::new(),
            allowed_delivery_channels: vec![DeliveryChannelClass::NativeDesktopNotification],
            remote_processing_enabled: false,
            restart_continuity_default: false,
            provenance: provenance.clone(),
        };
        let policy = ProtocolEffectivePolicyView {
            schema_version: 1,
            policy_profile_id: "phase2-focus-v1".to_owned(),
            user_preferences_revision: preferences.revision,
            source_stale_after_ms: 30_000,
            maximum_model_evidence_age_ms: 120_000,
            model_request_cooldown_ms: 300_000,
            maximum_model_requests_per_hour: 6,
            intervention_cooldown_ms: 900_000,
            maximum_interventions_per_session: 2,
            proactive_enabled: true,
            proactive_muted: false,
            do_not_disturb_windows: Vec::new(),
            allowed_delivery_channels: vec![DeliveryChannelClass::NativeDesktopNotification],
            remote_processing_enabled: false,
            restart_continuity_default: false,
            outbox_capacity_per_user: 20,
            outbox_capacity_per_session: 5,
        };
        let device_id = DeviceId::new_v7();
        let private = Phase2Snapshot {
            selected_resources: Vec::new(),
            permission_records: Vec::new(),
            focus_sessions: Vec::new(),
            capture_states: Vec::new(),
            delivery_channels: Vec::new(),
            intervention_history: InterventionHistoryView {
                as_of: now,
                entries: Vec::new(),
            },
            current_device_id: Some(device_id),
            stein_identity: Some(SteinIdentityV1View {
                schema_version: 1,
                owner_id,
                revision: 1,
                display_name: "STEIN".to_owned(),
                role_statement: "Synthetic adviser".to_owned(),
                invariant_behavioral_constraints: vec![
                    SteinIdentityConstraint::AdvisesRatherThanActs,
                    SteinIdentityConstraint::NeverBypassesPolicy,
                ],
                provenance,
            }),
            user_preferences: Some(preferences),
            effective_policy: Some(policy),
        };
        let view = DashboardSnapshot::from_protocol(
            &snapshot(Some(Box::new(private))),
            ConnectionView::connected(now.to_string(), 1),
            true,
            Vec::new(),
        );

        assert_eq!(view.current_device_id, Some(device_id.to_string()));
        assert_eq!(
            view.stein_identity
                .as_ref()
                .map(|value| value.display_name.as_str()),
            Some("STEIN")
        );
        assert_eq!(
            view.user_preferences.as_ref().map(|value| value.revision),
            Some(2)
        );
        assert_eq!(
            view.effective_policy
                .as_ref()
                .map(|value| value.user_preferences_revision),
            Some(2)
        );
    }

    #[test]
    fn intervention_explanation_retains_content_free_policy_trace() {
        let now = UtcTimestamp::now();
        let explanation = ProtocolExplanationView {
            intervention_id: stein_protocol::InterventionId::new_v7(),
            candidate_revision: 3,
            focus_session_id: stein_protocol::FocusSessionId::new_v7(),
            evidence: Vec::new(),
            decision: stein_protocol::PolicyDecisionView {
                policy_decision_id: stein_protocol::PolicyDecisionId::new_v7(),
                policy_version: "phase2-focus-v1".to_owned(),
                policy_trace: Some(stein_protocol::PolicyTraceView {
                    policy_profile_id: "phase2-focus-v1".to_owned(),
                    user_preferences_revision: 7,
                    proposed_input_schema_version: 1,
                    proposed_input_digest: [0xab; 32],
                }),
                outcome: stein_protocol::PolicyDecisionOutcome::Allow,
                reason_codes: vec![stein_protocol::InterventionReasonCode::DeadlineNear],
                authority: Vec::new(),
                issued_at: now,
                expires_at: now,
            },
            delivery_state: stein_protocol::InterventionState::AcceptedByChannel,
            outcome: stein_protocol::InterventionOutcome::Unacknowledged,
            delivered_text: Some("Synthetic intervention".to_owned()),
            correction_recorded: false,
        };

        let view = InterventionExplanationView::from_protocol(&explanation);
        let trace = view.policy_trace.expect("policy trace is projected");

        assert_eq!(trace.policy_profile_id, "phase2-focus-v1");
        assert_eq!(trace.user_preferences_revision, 7);
        assert_eq!(trace.input_schema_version, 1);
        assert_eq!(trace.input_digest_sha256, "ab".repeat(32));
    }

    #[test]
    fn model_request_receipt_projection_is_content_free_and_route_exact() {
        let now = UtcTimestamp::now();
        let protocol = ProtocolModelRequestReceiptView {
            request_id: stein_protocol::RequestId::new_v7(),
            focus_session_id: stein_protocol::FocusSessionId::new_v7(),
            model_route_approval_id: stein_protocol::ModelRouteApprovalId::new_v7(),
            model_route_revision: 4,
            started_at: now,
            completed_at: Some(now),
            outcome: stein_protocol::ModelRequestReceiptOutcome::CompletedStrictSilence,
        };

        let view = ModelRequestReceiptView::from_protocol(&protocol);
        assert_eq!(view.request_id, protocol.request_id.to_string());
        assert_eq!(view.focus_session_id, protocol.focus_session_id.to_string());
        assert_eq!(
            view.model_route_approval_id,
            protocol.model_route_approval_id.to_string()
        );
        assert_eq!(view.model_route_revision, 4);
        assert_eq!(view.outcome, "completed_strict_silence");

        let encoded = serde_json::to_value(view).unwrap();
        let keys = encoded.as_object().unwrap().keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 7);
        for forbidden in [
            "prompt",
            "response",
            "candidateText",
            "providerError",
            "credential",
            "secret",
        ] {
            assert!(encoded.get(forbidden).is_none());
        }
    }
}
