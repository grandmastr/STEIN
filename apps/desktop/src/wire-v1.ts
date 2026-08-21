/**
 * Maintained TypeScript mirror of the public v1 CORE wire contract.
 *
 * The renderer does not open the named pipe—the Tauri backend does—but these
 * types and decoders keep the checked-in JSON fixtures independently consumable
 * from TypeScript. Decoders validate nested tagged bodies, not just envelopes.
 */

export type Uuid = string;
export type UtcTimestamp = string;

export type Component =
  | "desktop_client"
  | "core_cli"
  | "core_daemon"
  | "core_application"
  | "test_fixture";
export type ActorKind = "local_os_user" | "client" | "core_daemon" | "system";
export type SensitivityClass =
  | "public"
  | "operational"
  | "personal"
  | "sensitive"
  | "restricted"
  | "highly_sensitive";
export type RetentionClass =
  | "transient_processing"
  | "ephemeral"
  | "runtime"
  | "durable_until_expiry"
  | "durable_until_deleted"
  | "bounded_audit"
  | "operational";
export type CapabilityId =
  | "snapshot"
  | "runtime_status"
  | "goal_create"
  | "goal_update"
  | "goal_delete"
  | "delay_echo"
  | "runtime_shutdown"
  | "view_events"
  | "request_cancellation"
  | "model_route_approval"
  | "session_permissions"
  | "focus_sessions"
  | "capture_state"
  | "delivery_channels"
  | "intervention_feedback"
  | "intervention_history"
  | "intervention_explanation"
  | "stein_identity"
  | "user_preferences"
  | "effective_policy"
  | "selected_resources"
  | "desktop_observation"
  | "model_reasoning"
  | "durable_persistence"
  | "native_notification"
  | "native_status"
  | "emergency_control"
  | "secret_store";

export interface ProtocolVersion {
  major: number;
  minor: number;
}

export interface ProtocolSupport {
  major: number;
  minimum_minor: number;
  maximum_minor: number;
}

export interface ActorReference {
  actor_id: Uuid;
  kind: ActorKind;
}

export interface RequestMetadata {
  message_id: Uuid;
  schema_version: number;
  issued_at: UtcTimestamp;
  correlation_id: Uuid;
  causation_id?: Uuid;
  origin: Component;
  authority?: Array<{ authority_id: Uuid; revision: number }>;
  sensitivity: SensitivityClass;
  retention: RetentionClass;
  idempotency_key?: Uuid;
  deadline_at?: UtcTimestamp;
  cancellation_id?: Uuid;
  trace_context?: { trace_id: Uuid; span_id: number };
}

export interface ResponseMetadata {
  message_id: Uuid;
  schema_version: number;
  issued_at: UtcTimestamp;
  correlation_id: Uuid;
  causation_id: Uuid;
  actor: ActorReference;
  origin: Component;
  sensitivity: SensitivityClass;
  retention: RetentionClass;
  trace_context?: { trace_id: Uuid; span_id: number };
}

export interface EventMetadata {
  message_id: Uuid;
  schema_version: number;
  occurred_at: UtcTimestamp;
  correlation_id: Uuid;
  causation_id?: Uuid;
  actor: ActorReference;
  origin: Component;
  sensitivity: SensitivityClass;
  retention: RetentionClass;
  trace_context?: { trace_id: Uuid; span_id: number };
}

export interface CapabilityHealth {
  capability: CapabilityId;
  schema_version: number;
  state: "healthy" | "degraded" | "unavailable";
  unavailable_reason?:
    | "not_implemented"
    | "unsupported_platform"
    | "dependency_unavailable"
    | "disabled_by_configuration"
    | "starting"
    | "stopping";
}

export interface EventCursor {
  daemon_instance_id: Uuid;
  sequence: number;
}

export interface RuntimeStatus {
  daemon_instance_id: Uuid;
  state: "starting" | "ready" | "degraded" | "stopping";
  started_at: UtcTimestamp;
  observed_at: UtcTimestamp;
  build_id: string;
  protocol_version: ProtocolVersion;
  active_connections: number;
}

export interface GoalView {
  goal_id: Uuid;
  revision: number;
  owner_id: Uuid;
  title: string;
  success_statement: string;
  deadline?: UtcTimestamp;
  state: "draft" | "active" | "completed" | "abandoned";
  created_at: UtcTimestamp;
  updated_at: UtcTimestamp;
}

export interface ClientSnapshot {
  snapshot_id: Uuid;
  as_of: UtcTimestamp;
  cursor: EventCursor;
  runtime: RuntimeStatus;
  capabilities: CapabilityHealth[];
  goals: GoalView[];
  phase2?: Phase2Snapshot;
}

export type ModelDataCategory = "goal" | "focus_session" | "evidence_aggregates" | "window_metadata" | "browser_location" | "visible_text" | "selected_document" | "screen_pixels" | "workspace_activity" | "delivery_constraints";
export type PermissionScope = "observe.desktop.presence" | "observe.desktop.foreground_application" | "observe.desktop.window_metadata" | "observe.browser.location" | "observe.content.visible_text" | "observe.content.selected_document" | "observe.screen.pixels" | "observe.workspace.activity" | "reason.focus_context" | "intervene.desktop.notification";

export interface PermissionContinuity {
  while_client_disconnected: boolean;
  after_daemon_restart: boolean;
}

export interface SelectedResourceView {
  selected_resource_id: Uuid;
  kind: SelectedResourceKind;
  display_name: string;
  revision?: number;
  created_at?: UtcTimestamp;
}

export type DeliveryChannelClass = "native_desktop_notification" | "connected_desktop";
export type SelectedResourceKind =
  | "application"
  | "window"
  | "browser_surface"
  | "document"
  | "workspace"
  | "screen_region"
  | "display";
export type InterventionStyle = "concise" | "neutral" | "reflective";
export interface DoNotDisturbWindowView {
  start_minute_local: number;
  end_minute_local: number;
  utc_offset_minutes: number;
}
export interface RecordProvenanceView {
  source: "product_migration" | "product_default" | "direct_user";
  version: string;
  recorded_at: UtcTimestamp;
}
export interface SteinIdentityV1View {
  schema_version: number;
  owner_id: Uuid;
  revision: number;
  display_name: string;
  role_statement: string;
  invariant_behavioral_constraints: Array<
    | "advises_rather_than_acts"
    | "preserves_uncertainty"
    | "respects_silence"
    | "never_impersonates_user"
    | "never_bypasses_policy"
  >;
  provenance: RecordProvenanceView;
}
export interface UserPreferencesV1Input {
  preferred_form_of_address?: string;
  intervention_style: InterventionStyle;
  proactive_enabled: boolean;
  proactive_muted: boolean;
  maximum_interventions_per_session: number;
  maximum_model_requests_per_hour: number;
  minimum_intervention_cooldown_ms: number;
  do_not_disturb_windows: DoNotDisturbWindowView[];
  allowed_delivery_channels: DeliveryChannelClass[];
  remote_processing_enabled: boolean;
  restart_continuity_default: boolean;
}
export interface UserPreferencesV1View extends UserPreferencesV1Input {
  schema_version: number;
  owner_id: Uuid;
  revision: number;
  provenance: RecordProvenanceView;
}
export interface EffectivePolicyView {
  schema_version: number;
  policy_profile_id: string;
  user_preferences_revision: number;
  source_stale_after_ms: number;
  maximum_model_evidence_age_ms: number;
  model_request_cooldown_ms: number;
  maximum_model_requests_per_hour: number;
  intervention_cooldown_ms: number;
  maximum_interventions_per_session: number;
  proactive_enabled: boolean;
  proactive_muted: boolean;
  do_not_disturb_windows: DoNotDisturbWindowView[];
  allowed_delivery_channels: DeliveryChannelClass[];
  remote_processing_enabled: boolean;
  restart_continuity_default: boolean;
  outbox_capacity_per_user: number;
  outbox_capacity_per_session: number;
}
export interface GoalDeletionTombstoneView {
  goal_id: Uuid;
  deleted_revision: number;
  deleted_at: UtcTimestamp;
  focus_sessions_deleted: number;
  grants_deleted: number;
  interventions_deleted: number;
  pending_deliveries_deleted: number;
  private_audit_records_deleted: number;
  resource_bindings_deleted: number;
}
export interface SelectedResourceDeletionTombstoneView {
  selected_resource_id: Uuid;
  deleted_revision: number;
  deleted_at: UtcTimestamp;
}

export interface ModelRouteReference {
  provider_id: string;
  route_id: string;
  placement: "local" | "remote";
}

export interface ProviderHandlingProfile {
  retention: { kind: "none" | "transient" | "unknown" } | { kind: "bounded"; maximum_seconds: number };
  training_use: "excluded" | "may_use" | "unknown";
  data_residency?: string;
  profile_version: string;
}

export interface ModelRouteApprovalView {
  model_route_approval_id: Uuid;
  revision: number;
  owner_id: Uuid;
  route: ModelRouteReference;
  account_profile: string;
  allowed_data_categories: ModelDataCategory[];
  handling: ProviderHandlingProfile;
  purpose: string;
  maximum_request_tokens: number;
  fallback?: ModelRouteReference;
  state: "active" | "expired" | "revoked";
  effective_at: UtcTimestamp;
  expires_at?: UtcTimestamp;
  revoked_at?: UtcTimestamp;
  disclosure_version: string;
}

export interface PermissionGrantView {
  permission_grant_id: Uuid;
  revision: number;
  owner_id: Uuid;
  requested_by_client: Uuid;
  device_id: Uuid;
  focus_session_id?: Uuid;
  goal_id: Uuid;
  scope: PermissionScope;
  selected_resource_id?: Uuid;
  purpose: string;
  continuity: PermissionContinuity;
  state: "active" | "expired" | "revoked";
  effective_at: UtcTimestamp;
  expires_at: UtcTimestamp;
  revoked_at?: UtcTimestamp;
  revocation_reason?: string;
  consent_copy_version: string;
  sensitivity: SensitivityClass;
  retention: RetentionClass;
}

export type PermissionRecordView =
  | { record_type: "session_grant"; record: PermissionGrantView }
  | { record_type: "model_route_approval"; record: ModelRouteApprovalView };

export interface FocusSessionView {
  focus_session_id: Uuid;
  revision: number;
  goal_id: Uuid;
  goal_revision: number;
  state: "requested" | "starting" | "active" | "recovering" | "stopping" | "ended" | "failed";
  interventions_muted: boolean;
  source_degraded: boolean;
  model_route_approval_id: Uuid;
  permission_grant_ids: Uuid[];
  selected_resource_ids: Uuid[];
  continuity: PermissionContinuity;
  created_at: UtcTimestamp;
  started_at?: UtcTimestamp;
  ended_at?: UtcTimestamp;
  updated_at: UtcTimestamp;
}

export type ModelRequestReceiptOutcome =
  | "in_flight"
  | "completed_strict_silence"
  | "completed_strict_candidate"
  | "cancelled"
  | "deadline_exceeded"
  | "failed";

export interface ModelRequestReceiptView {
  request_id: Uuid;
  focus_session_id: Uuid;
  model_route_approval_id: Uuid;
  model_route_revision: number;
  started_at: UtcTimestamp;
  completed_at?: UtcTimestamp;
  outcome: ModelRequestReceiptOutcome;
}

export interface CaptureStateView {
  focus_session_id: Uuid;
  revision: number;
  state: "stopped" | "starting" | "active" | "paused" | "stopping" | "failed";
  active_categories: string[];
  sources: Array<{ observation_source_id: Uuid; category: string; selected_resource_id?: Uuid; health: string; last_complete_at?: UtcTimestamp }>;
  native_status_visible: boolean;
  emergency_stop_available: boolean;
  updated_at: UtcTimestamp;
}

export interface DeliveryChannelView {
  delivery_channel_id: Uuid;
  class: "native_desktop_notification" | "connected_desktop";
  state: "healthy" | "degraded" | "unavailable" | "suppressed";
  may_show_content_while_locked: boolean;
  observed_at: UtcTimestamp;
  status_code?: string;
}

export interface InterventionView {
  intervention_id: Uuid;
  revision: number;
  candidate_revision: number;
  focus_session_id: Uuid;
  goal_id: Uuid;
  urgency: "low" | "normal" | "high";
  reason_codes: string[];
  state: string;
  outcome: "unacknowledged" | "accepted" | "dismissed" | "corrected" | "expired";
  user_visible_text?: string;
  delivery_channel_id?: Uuid;
  sensitivity: SensitivityClass;
  retention: RetentionClass;
  created_at: UtcTimestamp;
  expires_at: UtcTimestamp;
  updated_at: UtcTimestamp;
}

export interface InterventionExplanationView {
  intervention_id: Uuid;
  candidate_revision: number;
  focus_session_id: Uuid;
  evidence: Array<{ category: string; freshness: string; confidence: string; role: string; observed_from: UtcTimestamp; observed_until: UtcTimestamp }>;
  decision: { policy_decision_id: Uuid; policy_version: string; outcome: "allow" | "deny" | "require_confirmation"; reason_codes: string[]; authority: Array<{ authority_id: Uuid; revision: number }>; issued_at: UtcTimestamp; expires_at: UtcTimestamp };
  delivery_state: string;
  outcome: string;
  delivered_text?: string;
  correction_recorded: boolean;
}

export interface Phase2Snapshot {
  selected_resources: SelectedResourceView[];
  permission_records: PermissionRecordView[];
  focus_sessions: FocusSessionView[];
  capture_states: CaptureStateView[];
  delivery_channels: DeliveryChannelView[];
  intervention_history: { as_of: UtcTimestamp; entries: InterventionView[] };
  current_device_id?: Uuid;
  stein_identity?: SteinIdentityV1View;
  user_preferences?: UserPreferencesV1View;
  effective_policy?: EffectivePolicyView;
}

export type RequestBody =
  | {
      request_type: "create_goal";
      payload: { title: string; success_statement: string; deadline?: UtcTimestamp };
    }
  | { request_type: "update_goal"; payload: { goal_id: Uuid; expected_revision: number; patch: { title?: string; success_statement?: string; deadline?: { operation: "clear" } | { operation: "set"; deadline: UtcTimestamp } } } }
  | { request_type: "complete_goal"; payload: { goal_id: Uuid; expected_revision: number } }
  | { request_type: "abandon_goal"; payload: { goal_id: Uuid; expected_revision: number; reason?: string } }
  | { request_type: "delete_goal"; payload: { goal_id: Uuid; expected_revision: number } }
  | { request_type: "approve_model_route"; payload: { route: ModelRouteReference; account_profile: string; allowed_data_categories: ModelDataCategory[]; handling: ProviderHandlingProfile; purpose: string; maximum_request_tokens: number; fallback?: ModelRouteReference; expires_at?: UtcTimestamp; disclosure_version: string } }
  | { request_type: "grant_session_permission"; payload: { goal_id: Uuid; device_id?: Uuid; scope: PermissionScope; selected_resource_id?: Uuid; purpose: string; expires_at: UtcTimestamp; continuity: PermissionContinuity; consent_copy_version: string } }
  | { request_type: "revoke_permission"; payload: { target: { permission_type: "session_grant"; permission_grant_id: Uuid } | { permission_type: "model_route_approval"; model_route_approval_id: Uuid }; expected_revision: number; reason: string } }
  | { request_type: "start_focus_session"; payload: { goal_id: Uuid; goal_revision: number; selected_resource_ids: Uuid[]; permission_grant_ids: Uuid[]; model_route_approval_id: Uuid } }
  | { request_type: "set_interventions_muted"; payload: { focus_session_id: Uuid; expected_revision: number; muted: boolean } }
  | { request_type: "end_focus_session"; payload: { focus_session_id: Uuid; expected_revision: number; reason: "user_requested" | "goal_completed" | "goal_abandoned" | "permission_revoked" | "expired" } }
  | { request_type: "record_intervention_feedback"; payload: { intervention_id: Uuid; expected_revision: number; feedback: { outcome: "accepted" | "dismissed" } | { outcome: "corrected"; correction: string; associate_resource_id?: Uuid } } }
  | { request_type: "register_selected_resource"; payload: { kind: SelectedResourceKind } }
  | { request_type: "remove_selected_resource"; payload: { selected_resource_id: Uuid; expected_revision: number } }
  | { request_type: "update_user_preferences"; payload: { expected_revision: number; preferences: UserPreferencesV1Input } }
  | { request_type: "get_snapshot"; payload: Record<string, never> }
  | { request_type: "get_runtime_status"; payload: Record<string, never> }
  | { request_type: "get_goal"; payload: { goal_id: Uuid } }
  | { request_type: "get_focus_session_view"; payload: { focus_session_id: Uuid } }
  | { request_type: "get_capability_health"; payload: Record<string, never> }
  | { request_type: "get_permission_view"; payload: { permission_grant_id?: Uuid; model_route_approval_id?: Uuid } }
  | { request_type: "get_intervention_history"; payload: { focus_session_id?: Uuid; limit: number; before?: UtcTimestamp } }
  | { request_type: "explain_intervention"; payload: { intervention_id: Uuid } }
  | { request_type: "get_stein_identity"; payload: Record<string, never> }
  | { request_type: "get_user_preferences"; payload: Record<string, never> }
  | { request_type: "get_effective_policy"; payload: Record<string, never> }
  | { request_type: "get_selected_resources"; payload: Record<string, never> }
  | { request_type: "delay_echo"; payload: { delay_ms: number; text: string } }
  | {
      request_type: "shutdown";
      payload: { reason: "user_requested" | "upgrade" | "uninstall" | "test" };
    };

export type ClientMessageV1 =
  | {
      message_type: "open_session";
      body: {
        client_instance_id: Uuid;
        client_name: string;
        client_build_id: string;
        protocol_support: ProtocolSupport;
        max_frame_bytes: number;
        capabilities?: CapabilityId[];
      };
    }
  | {
      message_type: "request";
      body: { request_id: Uuid; metadata: RequestMetadata; body: RequestBody };
    }
  | {
      message_type: "cancel";
      body: {
        message_id: Uuid;
        issued_at: UtcTimestamp;
        correlation_id: Uuid;
        origin: Component;
        target_request_id: Uuid;
        cancellation_id: Uuid;
      };
    };

export type ResponseBody =
  | { response_type: "create_goal"; payload: { goal: GoalView } }
  | { response_type: "update_goal" | "complete_goal" | "abandon_goal"; payload: { goal: GoalView } }
  | { response_type: "delete_goal"; payload: { tombstone: GoalDeletionTombstoneView; already_deleted: boolean } }
  | { response_type: "approve_model_route"; payload: { approval: ModelRouteApprovalView } }
  | { response_type: "grant_session_permission"; payload: { permission: PermissionGrantView } }
  | { response_type: "revoke_permission"; payload: { permission: PermissionRecordView } }
  | { response_type: "start_focus_session" | "set_interventions_muted" | "end_focus_session"; payload: { focus_session: FocusSessionView } }
  | { response_type: "record_intervention_feedback"; payload: { intervention: InterventionView; outcome: string; context_correction_applied: boolean } }
  | { response_type: "register_selected_resource"; payload: { resource: SelectedResourceView } }
  | { response_type: "remove_selected_resource"; payload: { tombstone: SelectedResourceDeletionTombstoneView } }
  | { response_type: "update_user_preferences"; payload: { preferences: UserPreferencesV1View; effective_policy: EffectivePolicyView } }
  | { response_type: "get_snapshot"; payload: { snapshot: ClientSnapshot } }
  | {
      response_type: "get_runtime_status";
      payload: { runtime: RuntimeStatus; capabilities: CapabilityHealth[] };
    }
  | { response_type: "get_goal"; payload: { goal: GoalView } }
  | { response_type: "get_focus_session_view"; payload: { focus_session: FocusSessionView; capture?: CaptureStateView; latest_model_request_receipt?: ModelRequestReceiptView } }
  | { response_type: "get_capability_health"; payload: { capabilities: CapabilityHealth[] } }
  | { response_type: "get_permission_view"; payload: { records: PermissionRecordView[] } }
  | { response_type: "get_intervention_history"; payload: { history: { as_of: UtcTimestamp; entries: InterventionView[] } } }
  | { response_type: "explain_intervention"; payload: { explanation: InterventionExplanationView } }
  | { response_type: "get_stein_identity"; payload: { identity: SteinIdentityV1View } }
  | { response_type: "get_user_preferences"; payload: { preferences: UserPreferencesV1View } }
  | { response_type: "get_effective_policy"; payload: { effective_policy: EffectivePolicyView } }
  | { response_type: "get_selected_resources"; payload: { resources: SelectedResourceView[] } }
  | { response_type: "delay_echo"; payload: { text: string; completed_after_ms: number } }
  | { response_type: "shutdown"; payload: { daemon_instance_id: Uuid; accepted: boolean } };

export type ErrorDetails =
  | {
      detail_type: "validation";
      detail: {
        violations: Array<{
          field:
            | "title"
            | "success_statement"
            | "deadline"
            | "expected_revision"
            | "goal_id"
            | "focus_session_id"
            | "intervention_id"
            | "permission_grant_id"
            | "model_route_approval_id"
            | "selected_resource_id"
            | "scope"
            | "purpose"
            | "expires_at"
            | "continuity"
            | "consent_copy_version"
            | "provider"
            | "route"
            | "placement"
            | "data_categories"
            | "handling_profile"
            | "feedback"
            | "delay_ms"
            | "text"
            | "schema_version";
          reason: "required" | "too_long" | "out_of_range" | "invalid_format" | "unsupported";
        }>;
      };
    }
  | {
      detail_type: "compatibility";
      detail: { client_support: ProtocolSupport; server_support: ProtocolSupport };
    }
  | {
      detail_type: "supported_schema";
      detail: { request_kind: RequestBody["request_type"]; supported_versions: number[] };
    }
  | { detail_type: "current_revision"; detail: { current_revision: number } }
  | {
      detail_type: "limit";
      detail: {
        limit:
          | "frame_bytes"
          | "request_rate"
          | "concurrent_requests"
          | "delay_milliseconds"
          | "text_bytes"
          | "observation_bytes"
          | "model_tokens"
          | "outbox_entries"
          | "interventions_per_session";
        maximum: number;
      };
    };

export interface PublicError {
  code:
    | "invalid_argument"
    | "unauthenticated"
    | "permission_denied"
    | "confirmation_required"
    | "not_found"
    | "conflict"
    | "incompatible_protocol"
    | "unsupported_schema"
    | "capability_unavailable"
    | "deadline_exceeded"
    | "cancelled"
    | "rate_limited"
    | "internal";
  category:
    | "invalid_argument"
    | "unauthenticated"
    | "permission_denied"
    | "confirmation_required"
    | "not_found"
    | "conflict"
    | "incompatible_version"
    | "unavailable"
    | "deadline_exceeded"
    | "cancelled"
    | "internal";
  summary: string;
  retryable: boolean;
  correlation_id: Uuid;
  details?: ErrorDetails;
}

export type ViewEvent =
  | {
      event_type: "goal_view_changed";
      payload: { change: "created" | "updated" | "completed" | "abandoned"; goal: GoalView };
    }
  | { event_type: "runtime_status_changed"; payload: { runtime: RuntimeStatus } }
  | { event_type: "focus_session_view_changed"; payload: { change: string; focus_session: FocusSessionView } }
  | { event_type: "capture_state_changed"; payload: { capture: CaptureStateView } }
  | { event_type: "capability_health_changed"; payload: { capability: CapabilityHealth } }
  | { event_type: "delivery_channel_view_changed"; payload: { channel: DeliveryChannelView } }
  | { event_type: "permission_view_changed"; payload: { change: string; permission: PermissionRecordView } }
  | { event_type: "intervention_available"; payload: { intervention: InterventionView } }
  | { event_type: "intervention_view_changed"; payload: { intervention: InterventionView } }
  | { event_type: "intervention_history_changed"; payload: { change: string; intervention_id: Uuid; entry?: InterventionView } }
  | { event_type: "goal_deleted"; payload: { tombstone: GoalDeletionTombstoneView } }
  | {
      event_type: "selected_resource_view_changed";
      payload: {
        change: "registered" | "removed";
        resource?: SelectedResourceView;
        tombstone?: SelectedResourceDeletionTombstoneView;
      };
    }
  | {
      event_type: "user_preferences_view_changed";
      payload: { preferences: UserPreferencesV1View; effective_policy: EffectivePolicyView };
    };

export type ServerMessageV1 =
  | {
      message_type: "session_opened";
      body: {
        protocol_version: ProtocolVersion;
        server_build_id: string;
        daemon_instance_id: Uuid;
        authenticated_actor: ActorReference;
        max_frame_bytes: number;
        capabilities: CapabilityHealth[];
        snapshot: ClientSnapshot;
      };
    }
  | {
      message_type: "response";
      body: {
        request_id: Uuid;
        metadata: ResponseMetadata;
        outcome:
          | { outcome: "success"; body: ResponseBody }
          | { outcome: "error"; body: PublicError };
      };
    }
  | {
      message_type: "event";
      body: { cursor: EventCursor; metadata: EventMetadata; event: ViewEvent };
    }
  | {
      message_type: "cancel_acknowledged";
      body: {
        message_id: Uuid;
        issued_at: UtcTimestamp;
        correlation_id: Uuid;
        causation_id: Uuid;
        actor: ActorReference;
        target_request_id: Uuid;
        cancellation_id: Uuid;
        status: "cancellation_requested" | "request_not_found" | "request_already_completed";
      };
    }
  | {
      message_type: "event_gap";
      body: {
        message_id: Uuid;
        occurred_at: UtcTimestamp;
        reason: "consumer_lagged" | "sequence_mismatch" | "daemon_instance_changed";
        expected_cursor: EventCursor;
        observed_cursor?: EventCursor;
        action: "reconnect_for_snapshot";
      };
    }
  | {
      message_type: "fatal";
      body: {
        reason:
          | "handshake_required"
          | "authentication_failed"
          | "incompatible_protocol"
          | "malformed_frame"
          | "frame_limit_exceeded"
          | "server_stopping";
        error: PublicError;
      };
    };

type JsonObject = Record<string, unknown>;

function object(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as JsonObject;
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string") throw new Error(`${path} must be a string`);
  return value;
}

function number(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${path} must be a non-negative safe integer`);
  }
  return value;
}

function integer(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${path} must be a safe integer`);
  }
  return value;
}

function bool(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be a boolean`);
  return value;
}

function oneOf<const T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} has an unsupported value`);
  }
  return value as T;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
  return value;
}

function uuid(value: unknown, path: string): Uuid {
  const result = text(value, path);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(result)) {
    throw new Error(`${path} must be a canonical UUID`);
  }
  return result;
}

function timestamp(value: unknown, path: string): UtcTimestamp {
  const result = text(value, path);
  if (!result.endsWith("Z") || Number.isNaN(Date.parse(result))) {
    throw new Error(`${path} must be an RFC3339 UTC timestamp`);
  }
  return result;
}

function optional(value: unknown, validate: (item: unknown, path: string) => unknown, path: string): void {
  if (value !== undefined) validate(value, path);
}

const COMPONENTS = ["desktop_client", "core_cli", "core_daemon", "core_application", "test_fixture"] as const;
const ACTOR_KINDS = ["local_os_user", "client", "core_daemon", "system"] as const;
const SENSITIVITY = ["public", "operational", "personal", "sensitive", "restricted", "highly_sensitive"] as const;
const RETENTION = ["transient_processing", "ephemeral", "runtime", "durable_until_expiry", "durable_until_deleted", "bounded_audit", "operational"] as const;
const CAPABILITIES = ["snapshot", "runtime_status", "goal_create", "goal_update", "goal_delete", "delay_echo", "runtime_shutdown", "view_events", "request_cancellation", "model_route_approval", "session_permissions", "focus_sessions", "capture_state", "delivery_channels", "intervention_feedback", "intervention_history", "intervention_explanation", "stein_identity", "user_preferences", "effective_policy", "selected_resources", "desktop_observation", "model_reasoning", "durable_persistence", "native_notification", "native_status", "emergency_control", "secret_store"] as const;
const REQUEST_TYPES = ["create_goal", "update_goal", "complete_goal", "abandon_goal", "delete_goal", "approve_model_route", "grant_session_permission", "revoke_permission", "start_focus_session", "set_interventions_muted", "end_focus_session", "record_intervention_feedback", "register_selected_resource", "remove_selected_resource", "update_user_preferences", "get_snapshot", "get_runtime_status", "get_goal", "get_focus_session_view", "get_capability_health", "get_permission_view", "get_intervention_history", "explain_intervention", "get_stein_identity", "get_user_preferences", "get_effective_policy", "get_selected_resources", "delay_echo", "shutdown"] as const;
const VIEW_EVENT_TYPES = ["goal_view_changed", "runtime_status_changed", "focus_session_view_changed", "capture_state_changed", "capability_health_changed", "delivery_channel_view_changed", "permission_view_changed", "intervention_available", "intervention_view_changed", "intervention_history_changed", "goal_deleted", "selected_resource_view_changed", "user_preferences_view_changed"] as const;
const MODEL_DATA_CATEGORIES = ["goal", "focus_session", "evidence_aggregates", "window_metadata", "browser_location", "visible_text", "selected_document", "screen_pixels", "workspace_activity", "delivery_constraints"] as const;
const PERMISSION_SCOPES = ["observe.desktop.presence", "observe.desktop.foreground_application", "observe.desktop.window_metadata", "observe.browser.location", "observe.content.visible_text", "observe.content.selected_document", "observe.screen.pixels", "observe.workspace.activity", "reason.focus_context", "intervene.desktop.notification"] as const;
const OBSERVATION_CATEGORIES = ["presence", "foreground_application", "window_metadata", "browser_location", "visible_text", "selected_document", "screen_pixels", "workspace_activity", "source_health"] as const;
const SELECTED_RESOURCE_KINDS = ["application", "window", "browser_surface", "document", "workspace", "screen_region", "display"] as const;
const DELIVERY_CHANNEL_CLASSES = ["native_desktop_notification", "connected_desktop"] as const;
const IDENTITY_CONSTRAINTS = ["advises_rather_than_acts", "preserves_uncertainty", "respects_silence", "never_impersonates_user", "never_bypasses_policy"] as const;

function protocolVersion(value: unknown, path: string): void {
  const item = object(value, path);
  number(item.major, `${path}.major`);
  number(item.minor, `${path}.minor`);
}

function protocolSupport(value: unknown, path: string): void {
  const item = object(value, path);
  number(item.major, `${path}.major`);
  number(item.minimum_minor, `${path}.minimum_minor`);
  number(item.maximum_minor, `${path}.maximum_minor`);
}

function actor(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.actor_id, `${path}.actor_id`);
  oneOf(item.kind, ACTOR_KINDS, `${path}.kind`);
}

function trace(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.trace_id, `${path}.trace_id`);
  number(item.span_id, `${path}.span_id`);
}

function requestMetadata(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.message_id, `${path}.message_id`);
  number(item.schema_version, `${path}.schema_version`);
  timestamp(item.issued_at, `${path}.issued_at`);
  uuid(item.correlation_id, `${path}.correlation_id`);
  optional(item.causation_id, uuid, `${path}.causation_id`);
  oneOf(item.origin, COMPONENTS, `${path}.origin`);
  if (item.authority !== undefined) {
    array(item.authority, `${path}.authority`).forEach((authorityValue, index) => {
      const authority = object(authorityValue, `${path}.authority[${index}]`);
      uuid(authority.authority_id, `${path}.authority[${index}].authority_id`);
      number(authority.revision, `${path}.authority[${index}].revision`);
    });
  }
  oneOf(item.sensitivity, SENSITIVITY, `${path}.sensitivity`);
  oneOf(item.retention, RETENTION, `${path}.retention`);
  optional(item.idempotency_key, uuid, `${path}.idempotency_key`);
  optional(item.deadline_at, timestamp, `${path}.deadline_at`);
  optional(item.cancellation_id, uuid, `${path}.cancellation_id`);
  optional(item.trace_context, trace, `${path}.trace_context`);
}

function responseMetadata(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.message_id, `${path}.message_id`);
  number(item.schema_version, `${path}.schema_version`);
  timestamp(item.issued_at, `${path}.issued_at`);
  uuid(item.correlation_id, `${path}.correlation_id`);
  uuid(item.causation_id, `${path}.causation_id`);
  actor(item.actor, `${path}.actor`);
  oneOf(item.origin, COMPONENTS, `${path}.origin`);
  oneOf(item.sensitivity, SENSITIVITY, `${path}.sensitivity`);
  oneOf(item.retention, RETENTION, `${path}.retention`);
  optional(item.trace_context, trace, `${path}.trace_context`);
}

function eventMetadata(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.message_id, `${path}.message_id`);
  number(item.schema_version, `${path}.schema_version`);
  timestamp(item.occurred_at, `${path}.occurred_at`);
  uuid(item.correlation_id, `${path}.correlation_id`);
  optional(item.causation_id, uuid, `${path}.causation_id`);
  actor(item.actor, `${path}.actor`);
  oneOf(item.origin, COMPONENTS, `${path}.origin`);
  oneOf(item.sensitivity, SENSITIVITY, `${path}.sensitivity`);
  oneOf(item.retention, RETENTION, `${path}.retention`);
  optional(item.trace_context, trace, `${path}.trace_context`);
}

function capability(value: unknown, path: string): void {
  const item = object(value, path);
  oneOf(item.capability, CAPABILITIES, `${path}.capability`);
  number(item.schema_version, `${path}.schema_version`);
  oneOf(item.state, ["healthy", "degraded", "unavailable"] as const, `${path}.state`);
  optional(
    item.unavailable_reason,
    (reason, reasonPath) => oneOf(reason, ["not_implemented", "unsupported_platform", "dependency_unavailable", "disabled_by_configuration", "starting", "stopping"] as const, reasonPath),
    `${path}.unavailable_reason`,
  );
}

function cursor(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.daemon_instance_id, `${path}.daemon_instance_id`);
  number(item.sequence, `${path}.sequence`);
}

function runtime(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.daemon_instance_id, `${path}.daemon_instance_id`);
  oneOf(item.state, ["starting", "ready", "degraded", "stopping"] as const, `${path}.state`);
  timestamp(item.started_at, `${path}.started_at`);
  timestamp(item.observed_at, `${path}.observed_at`);
  text(item.build_id, `${path}.build_id`);
  protocolVersion(item.protocol_version, `${path}.protocol_version`);
  number(item.active_connections, `${path}.active_connections`);
}

function goal(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.goal_id, `${path}.goal_id`);
  number(item.revision, `${path}.revision`);
  uuid(item.owner_id, `${path}.owner_id`);
  text(item.title, `${path}.title`);
  text(item.success_statement, `${path}.success_statement`);
  optional(item.deadline, timestamp, `${path}.deadline`);
  oneOf(item.state, ["draft", "active", "completed", "abandoned"] as const, `${path}.state`);
  timestamp(item.created_at, `${path}.created_at`);
  timestamp(item.updated_at, `${path}.updated_at`);
}

function continuity(value: unknown, path: string): void {
  const item = object(value, path);
  bool(item.while_client_disconnected, `${path}.while_client_disconnected`);
  bool(item.after_daemon_restart, `${path}.after_daemon_restart`);
}

function provenance(value: unknown, path: string): void {
  const item = object(value, path);
  oneOf(item.source, ["product_migration", "product_default", "direct_user"] as const, `${path}.source`);
  text(item.version, `${path}.version`);
  timestamp(item.recorded_at, `${path}.recorded_at`);
}

function selectedResource(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.selected_resource_id, `${path}.selected_resource_id`);
  oneOf(item.kind, SELECTED_RESOURCE_KINDS, `${path}.kind`);
  text(item.display_name, `${path}.display_name`);
  optional(item.revision, number, `${path}.revision`);
  optional(item.created_at, timestamp, `${path}.created_at`);
}

function doNotDisturbWindow(value: unknown, path: string): void {
  const item = object(value, path);
  number(item.start_minute_local, `${path}.start_minute_local`);
  number(item.end_minute_local, `${path}.end_minute_local`);
  integer(item.utc_offset_minutes, `${path}.utc_offset_minutes`);
}

function userPreferencesInput(value: unknown, path: string): void {
  const item = object(value, path);
  optional(item.preferred_form_of_address, text, `${path}.preferred_form_of_address`);
  oneOf(item.intervention_style, ["concise", "neutral", "reflective"] as const, `${path}.intervention_style`);
  bool(item.proactive_enabled, `${path}.proactive_enabled`);
  bool(item.proactive_muted, `${path}.proactive_muted`);
  number(item.maximum_interventions_per_session, `${path}.maximum_interventions_per_session`);
  number(item.maximum_model_requests_per_hour, `${path}.maximum_model_requests_per_hour`);
  number(item.minimum_intervention_cooldown_ms, `${path}.minimum_intervention_cooldown_ms`);
  array(item.do_not_disturb_windows, `${path}.do_not_disturb_windows`).forEach((entry, index) =>
    doNotDisturbWindow(entry, `${path}.do_not_disturb_windows[${index}]`),
  );
  array(item.allowed_delivery_channels, `${path}.allowed_delivery_channels`).forEach((entry, index) =>
    oneOf(entry, DELIVERY_CHANNEL_CLASSES, `${path}.allowed_delivery_channels[${index}]`),
  );
  bool(item.remote_processing_enabled, `${path}.remote_processing_enabled`);
  bool(item.restart_continuity_default, `${path}.restart_continuity_default`);
}

function userPreferences(value: unknown, path: string): void {
  const item = object(value, path);
  userPreferencesInput(item, path);
  number(item.schema_version, `${path}.schema_version`);
  uuid(item.owner_id, `${path}.owner_id`);
  number(item.revision, `${path}.revision`);
  provenance(item.provenance, `${path}.provenance`);
}

function steinIdentity(value: unknown, path: string): void {
  const item = object(value, path);
  number(item.schema_version, `${path}.schema_version`);
  uuid(item.owner_id, `${path}.owner_id`);
  number(item.revision, `${path}.revision`);
  text(item.display_name, `${path}.display_name`);
  text(item.role_statement, `${path}.role_statement`);
  array(item.invariant_behavioral_constraints, `${path}.invariant_behavioral_constraints`).forEach((entry, index) =>
    oneOf(entry, IDENTITY_CONSTRAINTS, `${path}.invariant_behavioral_constraints[${index}]`),
  );
  provenance(item.provenance, `${path}.provenance`);
}

function effectivePolicy(value: unknown, path: string): void {
  const item = object(value, path);
  number(item.schema_version, `${path}.schema_version`);
  text(item.policy_profile_id, `${path}.policy_profile_id`);
  number(item.user_preferences_revision, `${path}.user_preferences_revision`);
  number(item.source_stale_after_ms, `${path}.source_stale_after_ms`);
  number(item.maximum_model_evidence_age_ms, `${path}.maximum_model_evidence_age_ms`);
  number(item.model_request_cooldown_ms, `${path}.model_request_cooldown_ms`);
  number(item.maximum_model_requests_per_hour, `${path}.maximum_model_requests_per_hour`);
  number(item.intervention_cooldown_ms, `${path}.intervention_cooldown_ms`);
  number(item.maximum_interventions_per_session, `${path}.maximum_interventions_per_session`);
  bool(item.proactive_enabled, `${path}.proactive_enabled`);
  bool(item.proactive_muted, `${path}.proactive_muted`);
  array(item.do_not_disturb_windows, `${path}.do_not_disturb_windows`).forEach((entry, index) =>
    doNotDisturbWindow(entry, `${path}.do_not_disturb_windows[${index}]`),
  );
  array(item.allowed_delivery_channels, `${path}.allowed_delivery_channels`).forEach((entry, index) =>
    oneOf(entry, DELIVERY_CHANNEL_CLASSES, `${path}.allowed_delivery_channels[${index}]`),
  );
  bool(item.remote_processing_enabled, `${path}.remote_processing_enabled`);
  bool(item.restart_continuity_default, `${path}.restart_continuity_default`);
  number(item.outbox_capacity_per_user, `${path}.outbox_capacity_per_user`);
  number(item.outbox_capacity_per_session, `${path}.outbox_capacity_per_session`);
}

function goalDeletionTombstone(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.goal_id, `${path}.goal_id`);
  number(item.deleted_revision, `${path}.deleted_revision`);
  timestamp(item.deleted_at, `${path}.deleted_at`);
  number(item.focus_sessions_deleted, `${path}.focus_sessions_deleted`);
  number(item.grants_deleted, `${path}.grants_deleted`);
  number(item.interventions_deleted, `${path}.interventions_deleted`);
  number(item.pending_deliveries_deleted, `${path}.pending_deliveries_deleted`);
  number(item.private_audit_records_deleted, `${path}.private_audit_records_deleted`);
  number(item.resource_bindings_deleted, `${path}.resource_bindings_deleted`);
}

function selectedResourceDeletionTombstone(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.selected_resource_id, `${path}.selected_resource_id`);
  number(item.deleted_revision, `${path}.deleted_revision`);
  timestamp(item.deleted_at, `${path}.deleted_at`);
}

function modelRouteReference(value: unknown, path: string): void {
  const item = object(value, path);
  text(item.provider_id, `${path}.provider_id`);
  text(item.route_id, `${path}.route_id`);
  oneOf(item.placement, ["local", "remote"] as const, `${path}.placement`);
}

function providerHandling(value: unknown, path: string): void {
  const item = object(value, path);
  const retention = object(item.retention, `${path}.retention`);
  const kind = oneOf(retention.kind, ["none", "transient", "bounded", "unknown"] as const, `${path}.retention.kind`);
  if (kind === "bounded") number(retention.maximum_seconds, `${path}.retention.maximum_seconds`);
  oneOf(item.training_use, ["excluded", "may_use", "unknown"] as const, `${path}.training_use`);
  optional(item.data_residency, text, `${path}.data_residency`);
  text(item.profile_version, `${path}.profile_version`);
}

function modelRouteApproval(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.model_route_approval_id, `${path}.model_route_approval_id`);
  number(item.revision, `${path}.revision`);
  uuid(item.owner_id, `${path}.owner_id`);
  modelRouteReference(item.route, `${path}.route`);
  text(item.account_profile, `${path}.account_profile`);
  array(item.allowed_data_categories, `${path}.allowed_data_categories`).forEach((entry, index) => oneOf(entry, MODEL_DATA_CATEGORIES, `${path}.allowed_data_categories[${index}]`));
  providerHandling(item.handling, `${path}.handling`);
  text(item.purpose, `${path}.purpose`);
  number(item.maximum_request_tokens, `${path}.maximum_request_tokens`);
  optional(item.fallback, modelRouteReference, `${path}.fallback`);
  oneOf(item.state, ["active", "expired", "revoked"] as const, `${path}.state`);
  timestamp(item.effective_at, `${path}.effective_at`);
  optional(item.expires_at, timestamp, `${path}.expires_at`);
  optional(item.revoked_at, timestamp, `${path}.revoked_at`);
  text(item.disclosure_version, `${path}.disclosure_version`);
}

function permissionGrant(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.permission_grant_id, `${path}.permission_grant_id`);
  number(item.revision, `${path}.revision`);
  uuid(item.owner_id, `${path}.owner_id`);
  uuid(item.requested_by_client, `${path}.requested_by_client`);
  uuid(item.device_id, `${path}.device_id`);
  optional(item.focus_session_id, uuid, `${path}.focus_session_id`);
  uuid(item.goal_id, `${path}.goal_id`);
  oneOf(item.scope, PERMISSION_SCOPES, `${path}.scope`);
  optional(item.selected_resource_id, uuid, `${path}.selected_resource_id`);
  text(item.purpose, `${path}.purpose`);
  continuity(item.continuity, `${path}.continuity`);
  oneOf(item.state, ["active", "expired", "revoked"] as const, `${path}.state`);
  timestamp(item.effective_at, `${path}.effective_at`);
  timestamp(item.expires_at, `${path}.expires_at`);
  optional(item.revoked_at, timestamp, `${path}.revoked_at`);
  optional(item.revocation_reason, text, `${path}.revocation_reason`);
  text(item.consent_copy_version, `${path}.consent_copy_version`);
  oneOf(item.sensitivity, SENSITIVITY, `${path}.sensitivity`);
  oneOf(item.retention, RETENTION, `${path}.retention`);
}

function permissionRecord(value: unknown, path: string): void {
  const item = object(value, path);
  const kind = oneOf(item.record_type, ["session_grant", "model_route_approval"] as const, `${path}.record_type`);
  if (kind === "session_grant") permissionGrant(item.record, `${path}.record`);
  else modelRouteApproval(item.record, `${path}.record`);
}

function focusSession(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.focus_session_id, `${path}.focus_session_id`);
  number(item.revision, `${path}.revision`);
  uuid(item.goal_id, `${path}.goal_id`);
  number(item.goal_revision, `${path}.goal_revision`);
  oneOf(item.state, ["requested", "starting", "active", "recovering", "stopping", "ended", "failed"] as const, `${path}.state`);
  bool(item.interventions_muted, `${path}.interventions_muted`);
  bool(item.source_degraded, `${path}.source_degraded`);
  uuid(item.model_route_approval_id, `${path}.model_route_approval_id`);
  array(item.permission_grant_ids, `${path}.permission_grant_ids`).forEach((entry, index) => uuid(entry, `${path}.permission_grant_ids[${index}]`));
  array(item.selected_resource_ids, `${path}.selected_resource_ids`).forEach((entry, index) => uuid(entry, `${path}.selected_resource_ids[${index}]`));
  continuity(item.continuity, `${path}.continuity`);
  timestamp(item.created_at, `${path}.created_at`);
  optional(item.started_at, timestamp, `${path}.started_at`);
  optional(item.ended_at, timestamp, `${path}.ended_at`);
  timestamp(item.updated_at, `${path}.updated_at`);
}

function modelRequestReceipt(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.request_id, `${path}.request_id`);
  uuid(item.focus_session_id, `${path}.focus_session_id`);
  uuid(item.model_route_approval_id, `${path}.model_route_approval_id`);
  number(item.model_route_revision, `${path}.model_route_revision`);
  timestamp(item.started_at, `${path}.started_at`);
  optional(item.completed_at, timestamp, `${path}.completed_at`);
  oneOf(
    item.outcome,
    [
      "in_flight",
      "completed_strict_silence",
      "completed_strict_candidate",
      "cancelled",
      "deadline_exceeded",
      "failed",
    ] as const,
    `${path}.outcome`,
  );
}

function capture(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.focus_session_id, `${path}.focus_session_id`);
  number(item.revision, `${path}.revision`);
  oneOf(item.state, ["stopped", "starting", "active", "paused", "stopping", "failed"] as const, `${path}.state`);
  array(item.active_categories, `${path}.active_categories`).forEach((entry, index) => oneOf(entry, OBSERVATION_CATEGORIES, `${path}.active_categories[${index}]`));
  array(item.sources, `${path}.sources`).forEach((entry, index) => {
    const source = object(entry, `${path}.sources[${index}]`);
    uuid(source.observation_source_id, `${path}.sources[${index}].observation_source_id`);
    oneOf(source.category, OBSERVATION_CATEGORIES, `${path}.sources[${index}].category`);
    optional(source.selected_resource_id, uuid, `${path}.sources[${index}].selected_resource_id`);
    oneOf(source.health, ["unknown", "starting", "healthy", "degraded", "paused", "failed", "stopped"] as const, `${path}.sources[${index}].health`);
    optional(source.last_complete_at, timestamp, `${path}.sources[${index}].last_complete_at`);
  });
  bool(item.native_status_visible, `${path}.native_status_visible`);
  bool(item.emergency_stop_available, `${path}.emergency_stop_available`);
  timestamp(item.updated_at, `${path}.updated_at`);
}

function deliveryChannel(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.delivery_channel_id, `${path}.delivery_channel_id`);
  oneOf(item.class, ["native_desktop_notification", "connected_desktop"] as const, `${path}.class`);
  oneOf(item.state, ["healthy", "degraded", "unavailable", "suppressed"] as const, `${path}.state`);
  bool(item.may_show_content_while_locked, `${path}.may_show_content_while_locked`);
  timestamp(item.observed_at, `${path}.observed_at`);
  optional(item.status_code, text, `${path}.status_code`);
}

function intervention(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.intervention_id, `${path}.intervention_id`);
  number(item.revision, `${path}.revision`);
  number(item.candidate_revision, `${path}.candidate_revision`);
  uuid(item.focus_session_id, `${path}.focus_session_id`);
  uuid(item.goal_id, `${path}.goal_id`);
  oneOf(item.urgency, ["low", "normal", "high"] as const, `${path}.urgency`);
  array(item.reason_codes, `${path}.reason_codes`).forEach((entry, index) => text(entry, `${path}.reason_codes[${index}]`));
  oneOf(item.state, ["candidate", "denied", "allowed", "queued", "delivering", "accepted_by_channel", "delivery_unknown", "delivery_failed", "expired", "cancelled"] as const, `${path}.state`);
  oneOf(item.outcome, ["unacknowledged", "accepted", "dismissed", "corrected", "expired"] as const, `${path}.outcome`);
  optional(item.user_visible_text, text, `${path}.user_visible_text`);
  optional(item.delivery_channel_id, uuid, `${path}.delivery_channel_id`);
  oneOf(item.sensitivity, SENSITIVITY, `${path}.sensitivity`);
  oneOf(item.retention, RETENTION, `${path}.retention`);
  timestamp(item.created_at, `${path}.created_at`);
  timestamp(item.expires_at, `${path}.expires_at`);
  timestamp(item.updated_at, `${path}.updated_at`);
}

function interventionHistory(value: unknown, path: string): void {
  const item = object(value, path);
  timestamp(item.as_of, `${path}.as_of`);
  array(item.entries, `${path}.entries`).forEach((entry, index) => intervention(entry, `${path}.entries[${index}]`));
}

function explanation(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.intervention_id, `${path}.intervention_id`);
  number(item.candidate_revision, `${path}.candidate_revision`);
  uuid(item.focus_session_id, `${path}.focus_session_id`);
  array(item.evidence, `${path}.evidence`).forEach((entry, index) => {
    const evidence = object(entry, `${path}.evidence[${index}]`);
    oneOf(evidence.category, OBSERVATION_CATEGORIES, `${path}.evidence[${index}].category`);
    oneOf(evidence.freshness, ["fresh", "stale", "unknown"] as const, `${path}.evidence[${index}].freshness`);
    oneOf(evidence.confidence, ["low", "medium", "high", "unknown"] as const, `${path}.evidence[${index}].confidence`);
    oneOf(evidence.role, ["supports_progress", "supports_deadline_risk", "uncertain", "corrected_relevant_work"] as const, `${path}.evidence[${index}].role`);
    timestamp(evidence.observed_from, `${path}.evidence[${index}].observed_from`);
    timestamp(evidence.observed_until, `${path}.evidence[${index}].observed_until`);
  });
  const decision = object(item.decision, `${path}.decision`);
  uuid(decision.policy_decision_id, `${path}.decision.policy_decision_id`);
  text(decision.policy_version, `${path}.decision.policy_version`);
  oneOf(decision.outcome, ["allow", "deny", "require_confirmation"] as const, `${path}.decision.outcome`);
  array(decision.reason_codes, `${path}.decision.reason_codes`).forEach((entry, index) => text(entry, `${path}.decision.reason_codes[${index}]`));
  array(decision.authority, `${path}.decision.authority`).forEach((entry, index) => {
    const authority = object(entry, `${path}.decision.authority[${index}]`);
    uuid(authority.authority_id, `${path}.decision.authority[${index}].authority_id`);
    number(authority.revision, `${path}.decision.authority[${index}].revision`);
  });
  timestamp(decision.issued_at, `${path}.decision.issued_at`);
  timestamp(decision.expires_at, `${path}.decision.expires_at`);
  text(item.delivery_state, `${path}.delivery_state`);
  text(item.outcome, `${path}.outcome`);
  optional(item.delivered_text, text, `${path}.delivered_text`);
  bool(item.correction_recorded, `${path}.correction_recorded`);
}

function phase2Snapshot(value: unknown, path: string): void {
  const item = object(value, path);
  array(item.selected_resources, `${path}.selected_resources`).forEach((entry, index) =>
    selectedResource(entry, `${path}.selected_resources[${index}]`),
  );
  array(item.permission_records, `${path}.permission_records`).forEach((entry, index) => permissionRecord(entry, `${path}.permission_records[${index}]`));
  array(item.focus_sessions, `${path}.focus_sessions`).forEach((entry, index) => focusSession(entry, `${path}.focus_sessions[${index}]`));
  array(item.capture_states, `${path}.capture_states`).forEach((entry, index) => capture(entry, `${path}.capture_states[${index}]`));
  array(item.delivery_channels, `${path}.delivery_channels`).forEach((entry, index) => deliveryChannel(entry, `${path}.delivery_channels[${index}]`));
  interventionHistory(item.intervention_history, `${path}.intervention_history`);
  optional(item.current_device_id, uuid, `${path}.current_device_id`);
  optional(item.stein_identity, steinIdentity, `${path}.stein_identity`);
  optional(item.user_preferences, userPreferences, `${path}.user_preferences`);
  optional(item.effective_policy, effectivePolicy, `${path}.effective_policy`);
}

function snapshot(value: unknown, path: string): void {
  const item = object(value, path);
  uuid(item.snapshot_id, `${path}.snapshot_id`);
  timestamp(item.as_of, `${path}.as_of`);
  cursor(item.cursor, `${path}.cursor`);
  runtime(item.runtime, `${path}.runtime`);
  array(item.capabilities, `${path}.capabilities`).forEach((entry, index) => capability(entry, `${path}.capabilities[${index}]`));
  array(item.goals, `${path}.goals`).forEach((entry, index) => goal(entry, `${path}.goals[${index}]`));
  optional(item.phase2, phase2Snapshot, `${path}.phase2`);
}

function requestBody(value: unknown, path: string): void {
  const item = object(value, path);
  const kind = oneOf(item.request_type, REQUEST_TYPES, `${path}.request_type`);
  const payload = object(item.payload, `${path}.payload`);
  switch (kind) {
    case "create_goal":
      text(payload.title, `${path}.payload.title`);
      text(payload.success_statement, `${path}.payload.success_statement`);
      optional(payload.deadline, timestamp, `${path}.payload.deadline`);
      break;
    case "update_goal": {
      uuid(payload.goal_id, `${path}.payload.goal_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      const patch = object(payload.patch, `${path}.payload.patch`);
      optional(patch.title, text, `${path}.payload.patch.title`);
      optional(patch.success_statement, text, `${path}.payload.patch.success_statement`);
      if (patch.deadline !== undefined) {
        const deadline = object(patch.deadline, `${path}.payload.patch.deadline`);
        const operation = oneOf(deadline.operation, ["clear", "set"] as const, `${path}.payload.patch.deadline.operation`);
        if (operation === "set") timestamp(deadline.deadline, `${path}.payload.patch.deadline.deadline`);
      }
      break;
    }
    case "complete_goal":
    case "delete_goal":
    case "abandon_goal":
      uuid(payload.goal_id, `${path}.payload.goal_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      optional(payload.reason, text, `${path}.payload.reason`);
      break;
    case "approve_model_route":
      modelRouteReference(payload.route, `${path}.payload.route`);
      text(payload.account_profile, `${path}.payload.account_profile`);
      array(payload.allowed_data_categories, `${path}.payload.allowed_data_categories`).forEach((entry, index) => oneOf(entry, MODEL_DATA_CATEGORIES, `${path}.payload.allowed_data_categories[${index}]`));
      providerHandling(payload.handling, `${path}.payload.handling`);
      text(payload.purpose, `${path}.payload.purpose`);
      number(payload.maximum_request_tokens, `${path}.payload.maximum_request_tokens`);
      optional(payload.fallback, modelRouteReference, `${path}.payload.fallback`);
      optional(payload.expires_at, timestamp, `${path}.payload.expires_at`);
      text(payload.disclosure_version, `${path}.payload.disclosure_version`);
      break;
    case "grant_session_permission":
      uuid(payload.goal_id, `${path}.payload.goal_id`);
      optional(payload.device_id, uuid, `${path}.payload.device_id`);
      oneOf(payload.scope, PERMISSION_SCOPES, `${path}.payload.scope`);
      optional(payload.selected_resource_id, uuid, `${path}.payload.selected_resource_id`);
      text(payload.purpose, `${path}.payload.purpose`);
      timestamp(payload.expires_at, `${path}.payload.expires_at`);
      continuity(payload.continuity, `${path}.payload.continuity`);
      text(payload.consent_copy_version, `${path}.payload.consent_copy_version`);
      break;
    case "revoke_permission": {
      const target = object(payload.target, `${path}.payload.target`);
      const targetKind = oneOf(target.permission_type, ["session_grant", "model_route_approval"] as const, `${path}.payload.target.permission_type`);
      if (targetKind === "session_grant") uuid(target.permission_grant_id, `${path}.payload.target.permission_grant_id`);
      else uuid(target.model_route_approval_id, `${path}.payload.target.model_route_approval_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      text(payload.reason, `${path}.payload.reason`);
      break;
    }
    case "start_focus_session":
      uuid(payload.goal_id, `${path}.payload.goal_id`);
      number(payload.goal_revision, `${path}.payload.goal_revision`);
      array(payload.selected_resource_ids, `${path}.payload.selected_resource_ids`).forEach((entry, index) => uuid(entry, `${path}.payload.selected_resource_ids[${index}]`));
      array(payload.permission_grant_ids, `${path}.payload.permission_grant_ids`).forEach((entry, index) => uuid(entry, `${path}.payload.permission_grant_ids[${index}]`));
      uuid(payload.model_route_approval_id, `${path}.payload.model_route_approval_id`);
      break;
    case "set_interventions_muted":
      uuid(payload.focus_session_id, `${path}.payload.focus_session_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      bool(payload.muted, `${path}.payload.muted`);
      break;
    case "end_focus_session":
      uuid(payload.focus_session_id, `${path}.payload.focus_session_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      oneOf(payload.reason, ["user_requested", "goal_completed", "goal_abandoned", "permission_revoked", "expired"] as const, `${path}.payload.reason`);
      break;
    case "record_intervention_feedback": {
      uuid(payload.intervention_id, `${path}.payload.intervention_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      const feedback = object(payload.feedback, `${path}.payload.feedback`);
      const outcome = oneOf(feedback.outcome, ["accepted", "dismissed", "corrected"] as const, `${path}.payload.feedback.outcome`);
      if (outcome === "corrected") {
        text(feedback.correction, `${path}.payload.feedback.correction`);
        optional(feedback.associate_resource_id, uuid, `${path}.payload.feedback.associate_resource_id`);
      }
      break;
    }
    case "register_selected_resource":
      oneOf(payload.kind, SELECTED_RESOURCE_KINDS, `${path}.payload.kind`);
      break;
    case "remove_selected_resource":
      uuid(payload.selected_resource_id, `${path}.payload.selected_resource_id`);
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      break;
    case "update_user_preferences":
      number(payload.expected_revision, `${path}.payload.expected_revision`);
      userPreferencesInput(payload.preferences, `${path}.payload.preferences`);
      break;
    case "get_goal":
      uuid(payload.goal_id, `${path}.payload.goal_id`);
      break;
    case "get_focus_session_view":
      uuid(payload.focus_session_id, `${path}.payload.focus_session_id`);
      break;
    case "get_permission_view":
      optional(payload.permission_grant_id, uuid, `${path}.payload.permission_grant_id`);
      optional(payload.model_route_approval_id, uuid, `${path}.payload.model_route_approval_id`);
      break;
    case "get_intervention_history":
      optional(payload.focus_session_id, uuid, `${path}.payload.focus_session_id`);
      number(payload.limit, `${path}.payload.limit`);
      optional(payload.before, timestamp, `${path}.payload.before`);
      break;
    case "explain_intervention":
      uuid(payload.intervention_id, `${path}.payload.intervention_id`);
      break;
    case "delay_echo":
      number(payload.delay_ms, `${path}.payload.delay_ms`);
      text(payload.text, `${path}.payload.text`);
      break;
    case "shutdown":
      oneOf(payload.reason, ["user_requested", "upgrade", "uninstall", "test"] as const, `${path}.payload.reason`);
      break;
    case "get_snapshot":
    case "get_runtime_status":
    case "get_capability_health":
    case "get_stein_identity":
    case "get_user_preferences":
    case "get_effective_policy":
    case "get_selected_resources":
      break;
  }
}

function responseBody(value: unknown, path: string): void {
  const item = object(value, path);
  const kind = oneOf(item.response_type, REQUEST_TYPES, `${path}.response_type`);
  const payload = object(item.payload, `${path}.payload`);
  switch (kind) {
    case "create_goal":
    case "update_goal":
    case "complete_goal":
    case "abandon_goal":
    case "get_goal":
      goal(payload.goal, `${path}.payload.goal`);
      break;
    case "delete_goal":
      goalDeletionTombstone(payload.tombstone, `${path}.payload.tombstone`);
      bool(payload.already_deleted, `${path}.payload.already_deleted`);
      break;
    case "approve_model_route":
      modelRouteApproval(payload.approval, `${path}.payload.approval`);
      break;
    case "grant_session_permission":
      permissionGrant(payload.permission, `${path}.payload.permission`);
      break;
    case "revoke_permission":
      permissionRecord(payload.permission, `${path}.payload.permission`);
      break;
    case "start_focus_session":
    case "set_interventions_muted":
    case "end_focus_session":
      focusSession(payload.focus_session, `${path}.payload.focus_session`);
      break;
    case "record_intervention_feedback":
      intervention(payload.intervention, `${path}.payload.intervention`);
      text(payload.outcome, `${path}.payload.outcome`);
      bool(payload.context_correction_applied, `${path}.payload.context_correction_applied`);
      break;
    case "register_selected_resource":
      selectedResource(payload.resource, `${path}.payload.resource`);
      break;
    case "remove_selected_resource":
      selectedResourceDeletionTombstone(payload.tombstone, `${path}.payload.tombstone`);
      break;
    case "update_user_preferences":
      userPreferences(payload.preferences, `${path}.payload.preferences`);
      effectivePolicy(payload.effective_policy, `${path}.payload.effective_policy`);
      break;
    case "get_snapshot":
      snapshot(payload.snapshot, `${path}.payload.snapshot`);
      break;
    case "get_runtime_status":
      runtime(payload.runtime, `${path}.payload.runtime`);
      array(payload.capabilities, `${path}.payload.capabilities`).forEach((entry, index) => capability(entry, `${path}.payload.capabilities[${index}]`));
      break;
    case "get_focus_session_view":
      focusSession(payload.focus_session, `${path}.payload.focus_session`);
      optional(payload.capture, capture, `${path}.payload.capture`);
      optional(
        payload.latest_model_request_receipt,
        modelRequestReceipt,
        `${path}.payload.latest_model_request_receipt`,
      );
      break;
    case "get_capability_health":
      array(payload.capabilities, `${path}.payload.capabilities`).forEach((entry, index) => capability(entry, `${path}.payload.capabilities[${index}]`));
      break;
    case "get_permission_view":
      array(payload.records, `${path}.payload.records`).forEach((entry, index) => permissionRecord(entry, `${path}.payload.records[${index}]`));
      break;
    case "get_intervention_history":
      interventionHistory(payload.history, `${path}.payload.history`);
      break;
    case "explain_intervention":
      explanation(payload.explanation, `${path}.payload.explanation`);
      break;
    case "get_stein_identity":
      steinIdentity(payload.identity, `${path}.payload.identity`);
      break;
    case "get_user_preferences":
      userPreferences(payload.preferences, `${path}.payload.preferences`);
      break;
    case "get_effective_policy":
      effectivePolicy(payload.effective_policy, `${path}.payload.effective_policy`);
      break;
    case "get_selected_resources":
      array(payload.resources, `${path}.payload.resources`).forEach((entry, index) =>
        selectedResource(entry, `${path}.payload.resources[${index}]`),
      );
      break;
    case "delay_echo":
      text(payload.text, `${path}.payload.text`);
      number(payload.completed_after_ms, `${path}.payload.completed_after_ms`);
      break;
    case "shutdown":
      uuid(payload.daemon_instance_id, `${path}.payload.daemon_instance_id`);
      bool(payload.accepted, `${path}.payload.accepted`);
      break;
  }
}

function error(value: unknown, path: string): void {
  const item = object(value, path);
  oneOf(item.code, ["invalid_argument", "unauthenticated", "permission_denied", "confirmation_required", "not_found", "conflict", "incompatible_protocol", "unsupported_schema", "capability_unavailable", "deadline_exceeded", "cancelled", "rate_limited", "internal"] as const, `${path}.code`);
  oneOf(item.category, ["invalid_argument", "unauthenticated", "permission_denied", "confirmation_required", "not_found", "conflict", "incompatible_version", "unavailable", "deadline_exceeded", "cancelled", "internal"] as const, `${path}.category`);
  text(item.summary, `${path}.summary`);
  bool(item.retryable, `${path}.retryable`);
  uuid(item.correlation_id, `${path}.correlation_id`);
  if (item.details !== undefined) {
    const details = object(item.details, `${path}.details`);
    const kind = oneOf(details.detail_type, ["validation", "compatibility", "supported_schema", "current_revision", "limit"] as const, `${path}.details.detail_type`);
    const detail = object(details.detail, `${path}.details.detail`);
    if (kind === "validation") {
      array(detail.violations, `${path}.details.detail.violations`).forEach((entry, index) => {
        const violation = object(entry, `${path}.details.detail.violations[${index}]`);
        oneOf(violation.field, ["title", "success_statement", "deadline", "expected_revision", "goal_id", "focus_session_id", "intervention_id", "permission_grant_id", "model_route_approval_id", "selected_resource_id", "scope", "purpose", "expires_at", "continuity", "consent_copy_version", "provider", "route", "placement", "data_categories", "handling_profile", "feedback", "delay_ms", "text", "schema_version"] as const, `${path}.details.detail.violations[${index}].field`);
        oneOf(violation.reason, ["required", "too_long", "out_of_range", "invalid_format", "unsupported"] as const, `${path}.details.detail.violations[${index}].reason`);
      });
    } else if (kind === "compatibility") {
      protocolSupport(detail.client_support, `${path}.details.detail.client_support`);
      protocolSupport(detail.server_support, `${path}.details.detail.server_support`);
    } else if (kind === "supported_schema") {
      oneOf(detail.request_kind, REQUEST_TYPES, `${path}.details.detail.request_kind`);
      array(detail.supported_versions, `${path}.details.detail.supported_versions`).forEach((entry, index) => number(entry, `${path}.details.detail.supported_versions[${index}]`));
    } else if (kind === "current_revision") {
      number(detail.current_revision, `${path}.details.detail.current_revision`);
    } else {
      oneOf(detail.limit, ["frame_bytes", "request_rate", "concurrent_requests", "delay_milliseconds", "text_bytes", "observation_bytes", "model_tokens", "outbox_entries", "interventions_per_session"] as const, `${path}.details.detail.limit`);
      number(detail.maximum, `${path}.details.detail.maximum`);
    }
  }
}

function viewEvent(value: unknown, path: string): void {
  const item = object(value, path);
  const kind = oneOf(item.event_type, VIEW_EVENT_TYPES, `${path}.event_type`);
  const payload = object(item.payload, `${path}.payload`);
  switch (kind) {
    case "goal_view_changed":
      oneOf(payload.change, ["created", "updated", "completed", "abandoned"] as const, `${path}.payload.change`);
      goal(payload.goal, `${path}.payload.goal`);
      break;
    case "runtime_status_changed":
      runtime(payload.runtime, `${path}.payload.runtime`);
      break;
    case "focus_session_view_changed":
      oneOf(payload.change, ["requested", "started", "muted", "unmuted", "recovery_started", "recovered", "stopping", "ended", "failed"] as const, `${path}.payload.change`);
      focusSession(payload.focus_session, `${path}.payload.focus_session`);
      break;
    case "capture_state_changed":
      capture(payload.capture, `${path}.payload.capture`);
      break;
    case "capability_health_changed":
      capability(payload.capability, `${path}.payload.capability`);
      break;
    case "delivery_channel_view_changed":
      deliveryChannel(payload.channel, `${path}.payload.channel`);
      break;
    case "permission_view_changed":
      oneOf(payload.change, ["granted", "updated", "revoked", "expired"] as const, `${path}.payload.change`);
      permissionRecord(payload.permission, `${path}.payload.permission`);
      break;
    case "intervention_available":
    case "intervention_view_changed":
      intervention(payload.intervention, `${path}.payload.intervention`);
      break;
    case "intervention_history_changed":
      oneOf(payload.change, ["added", "updated", "deleted"] as const, `${path}.payload.change`);
      uuid(payload.intervention_id, `${path}.payload.intervention_id`);
      optional(payload.entry, intervention, `${path}.payload.entry`);
      break;
    case "goal_deleted":
      goalDeletionTombstone(payload.tombstone, `${path}.payload.tombstone`);
      break;
    case "selected_resource_view_changed":
      oneOf(payload.change, ["registered", "removed"] as const, `${path}.payload.change`);
      optional(payload.resource, selectedResource, `${path}.payload.resource`);
      optional(payload.tombstone, selectedResourceDeletionTombstone, `${path}.payload.tombstone`);
      break;
    case "user_preferences_view_changed":
      userPreferences(payload.preferences, `${path}.payload.preferences`);
      effectivePolicy(payload.effective_policy, `${path}.payload.effective_policy`);
      break;
  }
}

export function decodePhase2RequestBodies(source: string): RequestBody[] {
  const values = array(JSON.parse(source) as unknown, "requests");
  values.forEach((value, index) => requestBody(value, `requests[${index}]`));
  return values as RequestBody[];
}

export function decodePhase2ResponseBodies(source: string): ResponseBody[] {
  const values = array(JSON.parse(source) as unknown, "responses");
  values.forEach((value, index) => responseBody(value, `responses[${index}]`));
  return values as ResponseBody[];
}

export function decodePhase2ViewEvents(source: string): ViewEvent[] {
  const values = array(JSON.parse(source) as unknown, "events");
  values.forEach((value, index) => viewEvent(value, `events[${index}]`));
  return values as ViewEvent[];
}

export function decodeClientMessageV1(source: string): ClientMessageV1 {
  const envelope = object(JSON.parse(source) as unknown, "message");
  const kind = oneOf(envelope.message_type, ["open_session", "request", "cancel"] as const, "message.message_type");
  const body = object(envelope.body, "message.body");
  if (kind === "open_session") {
    uuid(body.client_instance_id, "message.body.client_instance_id");
    text(body.client_name, "message.body.client_name");
    text(body.client_build_id, "message.body.client_build_id");
    protocolSupport(body.protocol_support, "message.body.protocol_support");
    number(body.max_frame_bytes, "message.body.max_frame_bytes");
    if (body.capabilities !== undefined) array(body.capabilities, "message.body.capabilities").forEach((entry, index) => oneOf(entry, CAPABILITIES, `message.body.capabilities[${index}]`));
  } else if (kind === "request") {
    uuid(body.request_id, "message.body.request_id");
    requestMetadata(body.metadata, "message.body.metadata");
    requestBody(body.body, "message.body.body");
  } else {
    uuid(body.message_id, "message.body.message_id");
    timestamp(body.issued_at, "message.body.issued_at");
    uuid(body.correlation_id, "message.body.correlation_id");
    oneOf(body.origin, COMPONENTS, "message.body.origin");
    uuid(body.target_request_id, "message.body.target_request_id");
    uuid(body.cancellation_id, "message.body.cancellation_id");
  }
  return envelope as ClientMessageV1;
}

export function decodeServerMessageV1(source: string): ServerMessageV1 {
  const envelope = object(JSON.parse(source) as unknown, "message");
  const kind = oneOf(envelope.message_type, ["session_opened", "response", "event", "cancel_acknowledged", "event_gap", "fatal"] as const, "message.message_type");
  const body = object(envelope.body, "message.body");
  if (kind === "session_opened") {
    protocolVersion(body.protocol_version, "message.body.protocol_version");
    text(body.server_build_id, "message.body.server_build_id");
    uuid(body.daemon_instance_id, "message.body.daemon_instance_id");
    actor(body.authenticated_actor, "message.body.authenticated_actor");
    number(body.max_frame_bytes, "message.body.max_frame_bytes");
    array(body.capabilities, "message.body.capabilities").forEach((entry, index) => capability(entry, `message.body.capabilities[${index}]`));
    snapshot(body.snapshot, "message.body.snapshot");
  } else if (kind === "response") {
    uuid(body.request_id, "message.body.request_id");
    responseMetadata(body.metadata, "message.body.metadata");
    const outcome = object(body.outcome, "message.body.outcome");
    const outcomeKind = oneOf(outcome.outcome, ["success", "error"] as const, "message.body.outcome.outcome");
    if (outcomeKind === "success") responseBody(outcome.body, "message.body.outcome.body");
    else error(outcome.body, "message.body.outcome.body");
  } else if (kind === "event") {
    cursor(body.cursor, "message.body.cursor");
    eventMetadata(body.metadata, "message.body.metadata");
    viewEvent(body.event, "message.body.event");
  } else if (kind === "cancel_acknowledged") {
    uuid(body.message_id, "message.body.message_id");
    timestamp(body.issued_at, "message.body.issued_at");
    uuid(body.correlation_id, "message.body.correlation_id");
    uuid(body.causation_id, "message.body.causation_id");
    actor(body.actor, "message.body.actor");
    uuid(body.target_request_id, "message.body.target_request_id");
    uuid(body.cancellation_id, "message.body.cancellation_id");
    oneOf(body.status, ["cancellation_requested", "request_not_found", "request_already_completed"] as const, "message.body.status");
  } else if (kind === "event_gap") {
    uuid(body.message_id, "message.body.message_id");
    timestamp(body.occurred_at, "message.body.occurred_at");
    oneOf(body.reason, ["consumer_lagged", "sequence_mismatch", "daemon_instance_changed"] as const, "message.body.reason");
    cursor(body.expected_cursor, "message.body.expected_cursor");
    optional(body.observed_cursor, cursor, "message.body.observed_cursor");
    oneOf(body.action, ["reconnect_for_snapshot"] as const, "message.body.action");
  } else {
    oneOf(body.reason, ["handshake_required", "authentication_failed", "incompatible_protocol", "malformed_frame", "frame_limit_exceeded", "server_stopping"] as const, "message.body.reason");
    error(body.error, "message.body.error");
  }
  return envelope as ServerMessageV1;
}
