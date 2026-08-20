/** Renderer-facing projection of the typed CORE protocol.
 *
 * Transport addresses, client capabilities, raw observations, provider
 * credentials, and native handles are intentionally absent.
 */

export const DESKTOP_BRIDGE_SCHEMA_VERSION = 2 as const;

export type ConnectionPhase = "connecting" | "connected" | "disconnected";
export type RuntimePhase = "starting" | "ready" | "degraded" | "stopping";
export type HealthState = "healthy" | "degraded" | "unavailable";
export type GoalState = "draft" | "active" | "completed" | "abandoned";
export type ClientAssurance = "diagnostic" | "private_capability_bound";

export interface ProtocolVersionView {
  major: number;
  minor: number;
}

export interface ConnectionView {
  phase: ConnectionPhase;
  connectedAt?: string;
  lastAttemptAt?: string;
  reconnectAttempt: number;
  error?: PublicErrorView;
}

export interface ClientAccessView {
  assurance: ClientAssurance;
  privateProtocolAvailable: boolean;
  unavailableReason?: string;
}

export interface RuntimeView {
  phase: RuntimePhase;
  daemonInstanceId: string;
  buildId: string;
  startedAt: string;
  protocol: ProtocolVersionView;
}

export interface CapabilityView {
  id: string;
  label: string;
  state: HealthState;
  detail?: string;
  checkedAt: string;
}

export interface GoalView {
  id: string;
  revision: number;
  title: string;
  successStatement: string;
  state: GoalState;
  deadline?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ResourceView {
  id: string;
  kind: SelectedResourceKind;
  displayName: string;
  revision?: number;
  createdAt?: string;
}

export type SelectedResourceKind =
  | "application"
  | "window"
  | "browser_surface"
  | "document"
  | "workspace"
  | "screen_region"
  | "display";

export type DeliveryChannelClass = "native_desktop_notification" | "connected_desktop";
export type InterventionStyle = "concise" | "neutral" | "reflective";

export interface RecordProvenanceView {
  source: "product_migration" | "product_default" | "direct_user";
  version: string;
  recordedAt: string;
}

export interface SteinIdentityView {
  schemaVersion: number;
  ownerId: string;
  revision: number;
  displayName: string;
  roleStatement: string;
  invariantBehavioralConstraints: Array<
    | "advises_rather_than_acts"
    | "preserves_uncertainty"
    | "respects_silence"
    | "never_impersonates_user"
    | "never_bypasses_policy"
  >;
  provenance: RecordProvenanceView;
}

export interface DoNotDisturbWindowView {
  startMinuteLocal: number;
  endMinuteLocal: number;
  utcOffsetMinutes: number;
}

export interface UserPreferencesView {
  schemaVersion: number;
  ownerId: string;
  revision: number;
  preferredFormOfAddress?: string;
  interventionStyle: InterventionStyle;
  proactiveEnabled: boolean;
  proactiveMuted: boolean;
  maximumInterventionsPerSession: number;
  maximumModelRequestsPerHour: number;
  minimumInterventionCooldownMs: number;
  doNotDisturbWindows: DoNotDisturbWindowView[];
  allowedDeliveryChannels: DeliveryChannelClass[];
  remoteProcessingEnabled: boolean;
  restartContinuityDefault: boolean;
  provenance: RecordProvenanceView;
}

export interface EffectivePolicyView {
  schemaVersion: number;
  policyProfileId: string;
  userPreferencesRevision: number;
  sourceStaleAfterMs: number;
  maximumModelEvidenceAgeMs: number;
  modelRequestCooldownMs: number;
  maximumModelRequestsPerHour: number;
  interventionCooldownMs: number;
  maximumInterventionsPerSession: number;
  proactiveEnabled: boolean;
  proactiveMuted: boolean;
  doNotDisturbWindows: DoNotDisturbWindowView[];
  allowedDeliveryChannels: DeliveryChannelClass[];
  remoteProcessingEnabled: boolean;
  restartContinuityDefault: boolean;
  outboxCapacityPerUser: number;
  outboxCapacityPerSession: number;
}

export interface SessionGrantView {
  id: string;
  revision: number;
  goalId: string;
  deviceId: string;
  focusSessionId?: string;
  scope: PermissionScope;
  selectedResourceId?: string;
  purpose: string;
  whileClientDisconnected: boolean;
  afterDaemonRestart: boolean;
  state: string;
  effectiveAt: string;
  expiresAt: string;
  revokedAt?: string;
  revocationReason?: string;
  consentCopyVersion: string;
  sensitivity: string;
  retention: string;
}

export interface ModelRouteView {
  id: string;
  revision: number;
  providerId: string;
  routeId: string;
  placement: "local" | "remote";
  accountProfile: string;
  allowedDataCategories: ModelDataCategory[];
  retention: string;
  trainingUse: string;
  dataResidency?: string;
  handlingProfileVersion: string;
  purpose: string;
  maximumRequestTokens: number;
  hasFallback: boolean;
  state: string;
  effectiveAt: string;
  expiresAt?: string;
  revokedAt?: string;
  disclosureVersion: string;
}

export interface FocusSessionView {
  id: string;
  revision: number;
  goalId: string;
  goalRevision: number;
  state: string;
  interventionsMuted: boolean;
  sourceDegraded: boolean;
  modelRouteApprovalId: string;
  permissionGrantIds: string[];
  selectedResourceIds: string[];
  whileClientDisconnected: boolean;
  afterDaemonRestart: boolean;
  createdAt: string;
  startedAt?: string;
  endedAt?: string;
  updatedAt: string;
}

export interface ObservationSourceView {
  id: string;
  category: string;
  selectedResourceId?: string;
  health: string;
  lastCompleteAt?: string;
}

export interface CaptureView {
  focusSessionId: string;
  revision: number;
  state: string;
  activeCategories: string[];
  sources: ObservationSourceView[];
  nativeStatusVisible: boolean;
  emergencyStopAvailable: boolean;
  updatedAt: string;
}

export interface DeliveryChannelView {
  id: string;
  class: string;
  state: string;
  mayShowContentWhileLocked: boolean;
  observedAt: string;
  statusCode?: string;
}

export interface InterventionView {
  id: string;
  revision: number;
  candidateRevision: number;
  focusSessionId: string;
  goalId: string;
  urgency: string;
  reasonCodes: string[];
  state: string;
  outcome: string;
  userVisibleText?: string;
  deliveryChannelId?: string;
  createdAt: string;
  expiresAt: string;
  updatedAt: string;
}

export interface EvidenceView {
  category: string;
  freshness: string;
  confidence: string;
  role: string;
  observedFrom: string;
  observedUntil: string;
}

export interface InterventionExplanationView {
  interventionId: string;
  candidateRevision: number;
  focusSessionId: string;
  evidence: EvidenceView[];
  policyDecisionId: string;
  policyVersion: string;
  policyTrace?: {
    policyProfileId: string;
    userPreferencesRevision: number;
    inputSchemaVersion: number;
    inputDigestSha256: string;
  };
  decision: string;
  decisionReasonCodes: string[];
  decisionIssuedAt: string;
  decisionExpiresAt: string;
  deliveryState: string;
  outcome: string;
  deliveredText?: string;
  correctionRecorded: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

/** Defensively validates the trusted-native toast event before it enters React state. */
export function isInterventionExplanationView(value: unknown): value is InterventionExplanationView {
  if (!isRecord(value) || !Array.isArray(value.evidence)) return false;
  const validEvidence = value.evidence.every((entry) =>
    isRecord(entry) &&
    typeof entry.category === "string" &&
    typeof entry.freshness === "string" &&
    typeof entry.confidence === "string" &&
    typeof entry.role === "string" &&
    typeof entry.observedFrom === "string" &&
    typeof entry.observedUntil === "string",
  );
  const validPolicyTrace = value.policyTrace === undefined || (
    isRecord(value.policyTrace) &&
    typeof value.policyTrace.policyProfileId === "string" &&
    value.policyTrace.policyProfileId.trim().length > 0 &&
    typeof value.policyTrace.userPreferencesRevision === "number" &&
    Number.isSafeInteger(value.policyTrace.userPreferencesRevision) &&
    value.policyTrace.userPreferencesRevision > 0 &&
    typeof value.policyTrace.inputSchemaVersion === "number" &&
    Number.isSafeInteger(value.policyTrace.inputSchemaVersion) &&
    value.policyTrace.inputSchemaVersion === 1 &&
    typeof value.policyTrace.inputDigestSha256 === "string" &&
    /^[0-9a-f]{64}$/.test(value.policyTrace.inputDigestSha256)
  );
  return (
    validEvidence &&
    validPolicyTrace &&
    typeof value.interventionId === "string" &&
    Number.isSafeInteger(value.candidateRevision) &&
    typeof value.focusSessionId === "string" &&
    typeof value.policyDecisionId === "string" &&
    typeof value.policyVersion === "string" &&
    typeof value.decision === "string" &&
    isStringArray(value.decisionReasonCodes) &&
    typeof value.decisionIssuedAt === "string" &&
    typeof value.decisionExpiresAt === "string" &&
    typeof value.deliveryState === "string" &&
    typeof value.outcome === "string" &&
    (value.deliveredText === undefined || typeof value.deliveredText === "string") &&
    typeof value.correctionRecorded === "boolean"
  );
}

export interface InterventionHistoryView {
  asOf: string;
  entries: InterventionView[];
}

export interface CoreEventView {
  messageId: string;
  messageType: string;
  schemaVersion: number;
  occurredAt: string;
  summary: string;
  cursor: string;
}

export interface DashboardSnapshot {
  bridgeSchemaVersion: typeof DESKTOP_BRIDGE_SCHEMA_VERSION;
  observedAt: string;
  connection: ConnectionView;
  access: ClientAccessView;
  runtime: RuntimeView;
  capabilities: CapabilityView[];
  goals: GoalView[];
  currentDeviceId?: string;
  steinIdentity?: SteinIdentityView;
  userPreferences?: UserPreferencesView;
  effectivePolicy?: EffectivePolicyView;
  selectedResources: ResourceView[];
  sessionGrants: SessionGrantView[];
  modelRoutes: ModelRouteView[];
  focusSessions: FocusSessionView[];
  captureStates: CaptureView[];
  deliveryChannels: DeliveryChannelView[];
  interventionHistory: InterventionView[];
  cursor: string;
  recentEvents: CoreEventView[];
}

export type ModelDataCategory =
  | "goal"
  | "focus_session"
  | "evidence_aggregates"
  | "window_metadata"
  | "browser_location"
  | "visible_text"
  | "selected_document"
  | "screen_pixels"
  | "workspace_activity"
  | "delivery_constraints";

export type PermissionScope =
  | "observe.desktop.presence"
  | "observe.desktop.foreground_application"
  | "observe.desktop.window_metadata"
  | "observe.browser.location"
  | "observe.content.visible_text"
  | "observe.content.selected_document"
  | "observe.screen.pixels"
  | "observe.workspace.activity"
  | "reason.focus_context"
  | "intervene.desktop.notification";

export interface CreateGoalInput {
  title: string;
  successStatement: string;
  deadline?: string;
  idempotencyKey: string;
}

export interface GoalRevisionInput {
  goalId: string;
  expectedRevision: number;
}

export interface UpdateGoalInput extends GoalRevisionInput {
  patch: {
    title?: string;
    successStatement?: string;
    deadline?: { operation: "clear" } | { operation: "set"; deadline: string };
  };
}

export interface GoalDeletionView {
  goalId: string;
  deletedRevision: number;
  deletedAt: string;
  focusSessionsDeleted: number;
  grantsDeleted: number;
  interventionsDeleted: number;
  pendingDeliveriesDeleted: number;
  privateAuditRecordsDeleted: number;
  resourceBindingsDeleted: number;
  alreadyDeleted: boolean;
}

export interface AbandonGoalInput extends GoalRevisionInput {
  reason?: string;
}

export interface ApproveModelRouteInput {
  providerId: string;
  routeId: string;
  placement: "local" | "remote";
  accountProfile: string;
  allowedDataCategories: ModelDataCategory[];
  retentionKind: "none" | "transient" | "bounded" | "unknown";
  retentionMaximumSeconds?: number;
  trainingUse: "excluded" | "may_use" | "unknown";
  dataResidency?: string;
  handlingProfileVersion: string;
  purpose: string;
  maximumRequestTokens: number;
  expiresAt?: string;
  disclosureVersion: string;
  idempotencyKey: string;
}

export interface GrantPermissionInput {
  goalId: string;
  /** Deprecated compatibility field. Protocol 1.2 binds the current device in CORE. */
  deviceId?: string;
  scope: PermissionScope;
  selectedResourceId?: string;
  purpose: string;
  expiresAt: string;
  whileClientDisconnected: boolean;
  afterDaemonRestart: boolean;
  consentCopyVersion: string;
  idempotencyKey: string;
}

export interface RegisterSelectedResourceInput {
  kind: SelectedResourceKind;
  idempotencyKey: string;
}

export interface RemoveSelectedResourceInput {
  selectedResourceId: string;
  expectedRevision: number;
}

export interface SelectedResourceDeletionView {
  selectedResourceId: string;
  deletedRevision: number;
  deletedAt: string;
}

export interface UserPreferencesInput {
  preferredFormOfAddress?: string;
  interventionStyle: InterventionStyle;
  proactiveEnabled: boolean;
  proactiveMuted: boolean;
  maximumInterventionsPerSession: number;
  maximumModelRequestsPerHour: number;
  minimumInterventionCooldownMs: number;
  doNotDisturbWindows: DoNotDisturbWindowView[];
  allowedDeliveryChannels: DeliveryChannelClass[];
  remoteProcessingEnabled: boolean;
  restartContinuityDefault: boolean;
}

export interface UpdateUserPreferencesInput {
  expectedRevision: number;
  preferences: UserPreferencesInput;
}

export interface UserPreferencesUpdateView {
  preferences: UserPreferencesView;
  effectivePolicy: EffectivePolicyView;
}

export interface RevokePermissionInput {
  permissionType: "session_grant" | "model_route_approval";
  permissionId: string;
  expectedRevision: number;
  reason: string;
}

export interface StartFocusSessionInput {
  goalId: string;
  goalRevision: number;
  selectedResourceIds: string[];
  permissionGrantIds: string[];
  modelRouteApprovalId: string;
  idempotencyKey: string;
}

export interface SetMutedInput {
  focusSessionId: string;
  expectedRevision: number;
  muted: boolean;
}

export interface EndFocusSessionInput {
  focusSessionId: string;
  expectedRevision: number;
}

export interface InterventionFeedbackInput {
  interventionId: string;
  expectedRevision: number;
  feedback: "accepted" | "dismissed" | "corrected";
  correction?: string;
  associateResourceId?: string;
}

export interface ExplainInterventionInput {
  interventionId: string;
}

export interface InterventionHistoryInput {
  focusSessionId?: string;
  limit: number;
  before?: string;
}

export interface PublicErrorView {
  code: string;
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
  correlationId?: string;
  fieldErrors?: Record<string, string>;
}

export type DesktopBridgeEvent =
  | {
      type: "snapshotChanged";
      schemaVersion: typeof DESKTOP_BRIDGE_SCHEMA_VERSION;
      snapshot: DashboardSnapshot;
    }
  | {
      type: "connectionChanged";
      schemaVersion: typeof DESKTOP_BRIDGE_SCHEMA_VERSION;
      connection: ConnectionView;
    }
  | {
      type: "viewEvent";
      schemaVersion: typeof DESKTOP_BRIDGE_SCHEMA_VERSION;
      event: CoreEventView;
    };

export function isPublicErrorView(value: unknown): value is PublicErrorView {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<PublicErrorView>;
  return (
    typeof candidate.code === "string" &&
    typeof candidate.summary === "string" &&
    typeof candidate.retryable === "boolean"
  );
}

export function publicErrorFromUnknown(error: unknown): PublicErrorView {
  if (isPublicErrorView(error)) return error;
  if (typeof error === "string") {
    try {
      const parsed: unknown = JSON.parse(error);
      if (isPublicErrorView(parsed)) return parsed;
    } catch {
      // Tauri may reject with a plain renderer-safe string.
    }
    return {
      code: "desktop_bridge_error",
      category: "unavailable",
      summary: error,
      retryable: true,
    };
  }
  return {
    code: "desktop_bridge_error",
    category: "internal",
    summary: "The desktop bridge returned an unexpected error.",
    retryable: false,
  };
}
