import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type {
  ApproveModelRouteInput,
  DashboardSnapshot,
  DesktopBridgeEvent,
  GoalView,
  InterventionExplanationView,
  InterventionView,
} from "./protocol";

const rendererClient = vi.hoisted(() => ({
  bootstrap: vi.fn(),
  refresh: vi.fn(),
  reconnect: vi.fn(),
  createGoal: vi.fn(),
  updateGoal: vi.fn(),
  completeGoal: vi.fn(),
  abandonGoal: vi.fn(),
  deleteGoal: vi.fn(),
  setupModelRoute: vi.fn(),
  grantPermission: vi.fn(),
  revokePermission: vi.fn(),
  startFocusSession: vi.fn(),
  registerSelectedResource: vi.fn(),
  removeSelectedResource: vi.fn(),
  updateUserPreferences: vi.fn(),
  getSteinIdentity: vi.fn(),
  getUserPreferences: vi.fn(),
  getEffectivePolicy: vi.fn(),
  getSelectedResources: vi.fn(),
  setInterventionsMuted: vi.fn(),
  endFocusSession: vi.fn(),
  recordInterventionFeedback: vi.fn(),
  explainIntervention: vi.fn(),
  getInterventionHistory: vi.fn(),
  subscribe: vi.fn(),
  subscribeToastActivation: vi.fn(),
}));

vi.mock("./lib/core", () => ({
  core: rendererClient,
  DESKTOP_BRIDGE_EVENT: "stein://desktop-bridge",
}));

const goal: GoalView = {
  id: "0198c083-f38b-7000-8000-000000000002",
  revision: 1,
  title: "Finish the product brief",
  successStatement: "A reviewed brief ready to share.",
  state: "active",
  deadline: "2026-08-20T09:00:00Z",
  createdAt: "2026-08-19T08:00:00Z",
  updatedAt: "2026-08-19T08:00:00Z",
};

const intervention: InterventionView = {
  id: "0198c083-f38b-7000-8000-000000000090",
  revision: 2,
  candidateRevision: 1,
  focusSessionId: "0198c083-f38b-7000-8000-000000000060",
  goalId: goal.id,
  urgency: "normal",
  reasonCodes: ["deadline_near", "success_condition_unobserved"],
  state: "accepted_by_channel",
  outcome: "unacknowledged",
  userVisibleText: "The brief deadline is near and a recommendation is still missing.",
  createdAt: "2026-08-19T08:01:00Z",
  expiresAt: "2026-08-19T08:16:00Z",
  updatedAt: "2026-08-19T08:01:05Z",
};

const toastExplanation: InterventionExplanationView = {
  interventionId: intervention.id,
  candidateRevision: intervention.candidateRevision,
  focusSessionId: intervention.focusSessionId,
  evidence: [{
    category: "selected_document",
    freshness: "fresh",
    confidence: "high",
    role: "supports_deadline_risk",
    observedFrom: "2026-08-19T08:00:00Z",
    observedUntil: "2026-08-19T08:01:00Z",
  }],
  policyDecisionId: "0198c083-f38b-7000-8000-000000000091",
  policyVersion: "phase2-focus-v1",
  policyTrace: {
    policyProfileId: "phase2-focus-v1",
    userPreferencesRevision: 2,
    inputSchemaVersion: 1,
    inputDigestSha256: "ab".repeat(32),
  },
  decision: "allow",
  decisionReasonCodes: ["deadline_near", "success_condition_unobserved"],
  decisionIssuedAt: "2026-08-19T08:01:00Z",
  decisionExpiresAt: "2026-08-19T08:01:30Z",
  deliveryState: "accepted_by_channel",
  outcome: "unacknowledged",
  deliveredText: intervention.userVisibleText,
  correctionRecorded: false,
};

const scrollIntoView = vi.fn();
Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  configurable: true,
  value: scrollIntoView,
});

const diagnosticSnapshot: DashboardSnapshot = {
  bridgeSchemaVersion: 2,
  observedAt: "2026-08-19T08:00:00Z",
  connection: { phase: "connected", connectedAt: "2026-08-19T08:00:00Z", reconnectAttempt: 1 },
  access: {
    assurance: "diagnostic",
    privateProtocolAvailable: false,
    unavailableReason: "Signed-package broker admission is unavailable.",
  },
  runtime: {
    phase: "ready",
    daemonInstanceId: "0198c083-f38b-7000-8000-000000000001",
    buildId: "phase2-test",
    startedAt: "2026-08-19T07:55:00Z",
    protocol: { major: 1, minor: 2 },
  },
  capabilities: [{ id: "runtime_status", label: "Runtime status", state: "healthy", checkedAt: "2026-08-19T08:00:00Z" }],
  goals: [],
  selectedResources: [],
  sessionGrants: [],
  modelRoutes: [],
  focusSessions: [],
  captureStates: [],
  deliveryChannels: [],
  interventionHistory: [],
  cursor: "0198c083-f38b-7000-8000-000000000001:0",
  recentEvents: [],
};

const privateSnapshot: DashboardSnapshot = {
  ...diagnosticSnapshot,
  access: { assurance: "private_capability_bound", privateProtocolAvailable: true },
  goals: [goal],
  currentDeviceId: "0198c083-f38b-7000-8000-000000000009",
  steinIdentity: {
    schemaVersion: 1,
    ownerId: "0198c083-f38b-7000-8000-000000000001",
    revision: 1,
    displayName: "STEIN",
    roleStatement: "A second mind that advises while the user decides and acts.",
    invariantBehavioralConstraints: ["advises_rather_than_acts", "preserves_uncertainty", "respects_silence", "never_impersonates_user", "never_bypasses_policy"],
    provenance: { source: "product_default", version: "stein-identity-v1", recordedAt: "2026-08-19T08:00:00Z" },
  },
  userPreferences: {
    schemaVersion: 1,
    ownerId: "0198c083-f38b-7000-8000-000000000001",
    revision: 2,
    interventionStyle: "concise",
    proactiveEnabled: false,
    proactiveMuted: false,
    maximumInterventionsPerSession: 3,
    maximumModelRequestsPerHour: 12,
    minimumInterventionCooldownMs: 900_000,
    doNotDisturbWindows: [],
    allowedDeliveryChannels: ["native_desktop_notification"],
    remoteProcessingEnabled: false,
    restartContinuityDefault: false,
    provenance: { source: "product_default", version: "user-preferences-v1", recordedAt: "2026-08-19T08:00:00Z" },
  },
  effectivePolicy: {
    schemaVersion: 1,
    policyProfileId: "phase2-focus-v1",
    userPreferencesRevision: 2,
    sourceStaleAfterMs: 30_000,
    maximumModelEvidenceAgeMs: 120_000,
    modelRequestCooldownMs: 300_000,
    maximumModelRequestsPerHour: 12,
    interventionCooldownMs: 900_000,
    maximumInterventionsPerSession: 3,
    proactiveEnabled: false,
    proactiveMuted: false,
    doNotDisturbWindows: [],
    allowedDeliveryChannels: ["native_desktop_notification"],
    remoteProcessingEnabled: false,
    restartContinuityDefault: false,
    outboxCapacityPerUser: 20,
    outboxCapacityPerSession: 5,
  },
  selectedResources: [{
    id: "0198c083-f38b-7000-8000-000000000010",
    kind: "document",
    displayName: "Synthetic Atlas brief",
    revision: 1,
    createdAt: "2026-08-19T08:00:00Z",
  }],
  modelRoutes: [{
    id: "0198c083-f38b-7000-8000-000000000020",
    revision: 1,
    providerId: "openai",
    routeId: "exact-model",
    placement: "remote",
    accountProfile: "default",
    allowedDataCategories: ["goal", "evidence_aggregates"],
    retention: "bounded:2592000",
    trainingUse: "excluded",
    handlingProfileVersion: "openai-responses-default-2026-08",
    purpose: "reason.focus_context",
    maximumRequestTokens: 8000,
    hasFallback: false,
    state: "active",
    effectiveAt: "2026-08-19T08:00:00Z",
    disclosureVersion: "phase2-openai-responses-v1",
  }],
  sessionGrants: [],
  focusSessions: [],
  captureStates: [],
  deliveryChannels: [{
    id: "0198c083-f38b-7000-8000-000000000030",
    class: "native_desktop_notification",
    state: "healthy",
    mayShowContentWhileLocked: false,
    observedAt: "2026-08-19T08:00:00Z",
  }],
  interventionHistory: [intervention],
  recentEvents: [{
    messageId: "0198c083-f38b-7000-8000-000000000003",
    messageType: "goal_view_changed",
    schemaVersion: 1,
    occurredAt: "2026-08-19T08:00:00Z",
    summary: "Goal created.",
    cursor: "0198c083-f38b-7000-8000-000000000001:4",
  }],
};

describe("STEIN Phase 2 desktop", () => {
  beforeEach(() => {
    for (const mock of Object.values(rendererClient)) mock.mockReset();
    rendererClient.bootstrap.mockResolvedValue(diagnosticSnapshot);
    rendererClient.refresh.mockResolvedValue(diagnosticSnapshot);
    rendererClient.reconnect.mockResolvedValue(diagnosticSnapshot);
    rendererClient.createGoal.mockResolvedValue(goal);
    rendererClient.updateGoal.mockResolvedValue({ ...goal, revision: 2 });
    rendererClient.deleteGoal.mockResolvedValue({
      goalId: goal.id,
      deletedRevision: goal.revision,
      deletedAt: "2026-08-19T08:05:00Z",
      focusSessionsDeleted: 0,
      grantsDeleted: 0,
      interventionsDeleted: 0,
      pendingDeliveriesDeleted: 0,
      privateAuditRecordsDeleted: 0,
      resourceBindingsDeleted: 0,
      alreadyDeleted: false,
    });
    rendererClient.updateUserPreferences.mockResolvedValue({
      preferences: privateSnapshot.userPreferences,
      effectivePolicy: privateSnapshot.effectivePolicy,
    });
    rendererClient.registerSelectedResource.mockResolvedValue(privateSnapshot.selectedResources[0]);
    rendererClient.removeSelectedResource.mockResolvedValue({
      selectedResourceId: privateSnapshot.selectedResources[0]?.id,
      deletedRevision: 1,
      deletedAt: "2026-08-19T08:05:00Z",
    });
    rendererClient.setupModelRoute.mockResolvedValue(privateSnapshot.modelRoutes[0]);
    rendererClient.revokePermission.mockResolvedValue(undefined);
    rendererClient.subscribe.mockResolvedValue(() => undefined);
    rendererClient.subscribeToastActivation.mockResolvedValue(() => undefined);
    scrollIntoView.mockReset();
  });

  it("renders a truthful diagnostic-only state without private data or enabled mutations", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "CORE is ready" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Private Phase 2 state is locked" })).toBeInTheDocument();
    expect(screen.getByText(/no development or same-user bypass/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Private admission required" })).toBeDisabled();
    expect(screen.queryByText("Finish the product brief")).not.toBeInTheDocument();
    expect(screen.getByText("v1.2")).toBeInTheDocument();
  });

  it("renders private goals, exact route consent, native channels, and intervention controls", async () => {
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    render(<App />);
    expect((await screen.findAllByText("Finish the product brief")).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Model route" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Identity and effective policy" })).toBeInTheDocument();
    expect(screen.getByText("phase2-focus-v1")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "User preferences" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Selected resources" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Observation and delivery grants" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Focus sessions" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Intervention history" })).toBeInTheDocument();
    expect(screen.getByText(/accepted by channel.*never means displayed or seen/i)).toBeInTheDocument();
  });

  it("discards the private renderer cache until reconnect returns an authoritative snapshot", async () => {
    let listener: ((event: DesktopBridgeEvent) => void) | undefined;
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.subscribe.mockImplementation((handler: (event: DesktopBridgeEvent) => void) => {
      listener = handler;
      return Promise.resolve(() => undefined);
    });
    render(<App />);
    expect((await screen.findAllByText("Finish the product brief")).length).toBeGreaterThan(0);

    act(() => {
      listener?.({
        type: "connectionChanged",
        schemaVersion: 2,
        connection: {
          phase: "connecting",
          lastAttemptAt: "2026-08-19T08:00:02Z",
          reconnectAttempt: 2,
        },
      });
    });

    expect(screen.queryByText("Finish the product brief")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "CORE is not connected" })).toBeInTheDocument();
  });

  it("does not lose a private bridge event while the authoritative snapshot is loading", async () => {
    let resolveBootstrap: ((value: DashboardSnapshot) => void) | undefined;
    let listener: ((event: DesktopBridgeEvent) => void) | undefined;
    rendererClient.bootstrap.mockReturnValue(new Promise<DashboardSnapshot>((resolve) => { resolveBootstrap = resolve; }));
    rendererClient.subscribe.mockImplementation((handler: (event: DesktopBridgeEvent) => void) => { listener = handler; return Promise.resolve(() => undefined); });
    render(<App />);
    await waitFor(() => expect(listener).toBeDefined());
    act(() => {
      listener?.({ type: "viewEvent", schemaVersion: 2, event: { messageId: "0198c083-f38b-7000-8000-000000000099", messageType: "capture_state_changed", schemaVersion: 1, occurredAt: "2026-08-19T08:00:01Z", summary: "Capture became active.", cursor: "0198c083-f38b-7000-8000-000000000001:5" } });
      resolveBootstrap?.(privateSnapshot);
    });
    expect(await screen.findByText("Capture became active.")).toBeInTheDocument();
  });

  it("routes a cold-start toast activation buffered before private bootstrap", async () => {
    let resolveBootstrap: ((value: DashboardSnapshot) => void) | undefined;
    let toastListener: ((explanation: InterventionExplanationView) => void) | undefined;
    rendererClient.bootstrap.mockReturnValue(new Promise<DashboardSnapshot>((resolve) => { resolveBootstrap = resolve; }));
    rendererClient.subscribeToastActivation.mockImplementation((handler: (explanation: InterventionExplanationView) => void) => {
      toastListener = handler;
      return Promise.resolve(() => undefined);
    });
    render(<App />);
    await waitFor(() => expect(toastListener).toBeDefined());

    act(() => {
      toastListener?.(toastExplanation);
      resolveBootstrap?.(privateSnapshot);
    });

    expect(await screen.findByText("Why this occurred")).toBeInTheDocument();
    expect(screen.getByText("Policy phase2-focus-v1 evaluated candidate revision 1.")).toBeInTheDocument();
    expect(screen.getByLabelText("Policy decision trace")).toHaveTextContent("preferences revision 2");
    expect(screen.getByText("ab".repeat(32))).toBeInTheDocument();
    const selectedCard = screen.getByText(intervention.userVisibleText!).closest("article");
    expect(selectedCard).toHaveAttribute("aria-current", "true");
    await waitFor(() => expect(screen.getByLabelText("Selected intervention explanation")).toHaveFocus());
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
    expect(rendererClient.explainIntervention).not.toHaveBeenCalled();
  });

  it("focuses an authoritative toast explanation in an already-running private desktop", async () => {
    let toastListener: ((explanation: InterventionExplanationView) => void) | undefined;
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.subscribeToastActivation.mockImplementation((handler: (explanation: InterventionExplanationView) => void) => {
      toastListener = handler;
      return Promise.resolve(() => undefined);
    });
    render(<App />);
    await screen.findByRole("heading", { name: "Intervention history" });

    act(() => toastListener?.(toastExplanation));

    expect(await screen.findByText("Why this occurred")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText("Selected intervention explanation")).toHaveFocus());
    expect(scrollIntoView).toHaveBeenCalledOnce();
  });

  it("clears toast-derived private state on disconnect and does not replay activations received while disconnected", async () => {
    let bridgeListener: ((event: DesktopBridgeEvent) => void) | undefined;
    let toastListener: ((explanation: InterventionExplanationView) => void) | undefined;
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.reconnect.mockResolvedValue(privateSnapshot);
    rendererClient.subscribe.mockImplementation((handler: (event: DesktopBridgeEvent) => void) => {
      bridgeListener = handler;
      return Promise.resolve(() => undefined);
    });
    rendererClient.subscribeToastActivation.mockImplementation((handler: (explanation: InterventionExplanationView) => void) => {
      toastListener = handler;
      return Promise.resolve(() => undefined);
    });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Intervention history" });
    act(() => toastListener?.(toastExplanation));
    expect(await screen.findByText("Why this occurred")).toBeInTheDocument();

    act(() => bridgeListener?.({
      type: "connectionChanged",
      schemaVersion: 2,
      connection: { phase: "connecting", lastAttemptAt: "2026-08-19T08:02:00Z", reconnectAttempt: 2 },
    }));
    expect(await screen.findByRole("heading", { name: "CORE is not connected" })).toBeInTheDocument();
    act(() => toastListener?.(toastExplanation));
    await user.click(screen.getByRole("button", { name: "Reconnect to CORE" }));
    await screen.findByRole("heading", { name: "Intervention history" });
    expect(screen.queryByText("Why this occurred")).not.toBeInTheDocument();
  });

  it("unsubscribes both bridge event sources when the renderer unmounts", async () => {
    const bridgeUnlisten = vi.fn();
    const toastUnlisten = vi.fn();
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.subscribe.mockResolvedValue(bridgeUnlisten);
    rendererClient.subscribeToastActivation.mockResolvedValue(toastUnlisten);
    const view = render(<App />);
    await screen.findByRole("heading", { name: "CORE is ready" });

    view.unmount();

    expect(bridgeUnlisten).toHaveBeenCalledOnce();
    expect(toastUnlisten).toHaveBeenCalledOnce();
  });

  it("submits a direct create-goal command only under private admission", async () => {
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Create a goal" });
    await user.type(screen.getByLabelText("Title"), "Ship the proof");
    await user.type(screen.getByLabelText("Success looks like"), "The installed desktop reconnects to CORE.");
    await user.click(screen.getByRole("button", { name: "Create goal" }));
    await waitFor(() => expect(rendererClient.createGoal).toHaveBeenCalledOnce());
    expect(rendererClient.createGoal).toHaveBeenCalledWith(expect.objectContaining({ title: "Ship the proof" }));
  });

  it("uses one native setup transaction whose renderer payload contains metadata only", async () => {
    rendererClient.bootstrap.mockResolvedValue({ ...privateSnapshot, modelRoutes: [] });
    let resolveSetup: ((value: DashboardSnapshot["modelRoutes"][number]) => void) | undefined;
    rendererClient.setupModelRoute.mockReturnValue(new Promise((resolve) => { resolveSetup = resolve; }));
    const user = userEvent.setup();
    render(<App />);
    const route = await screen.findByLabelText("Exact OpenAI model identifier");
    expect(screen.queryByLabelText("Provider credential")).not.toBeInTheDocument();
    const requiredGoal = screen.getByRole("checkbox", { name: /Goal · required/i });
    expect(requiredGoal).toBeChecked();
    expect(requiredGoal).toBeDisabled();
    await user.type(route, "exact-model-v2");
    await user.click(screen.getByRole("button", { name: "Open Windows prompt and approve exact route" }));
    expect(rendererClient.setupModelRoute).toHaveBeenCalledOnce();
    expect(rendererClient.setupModelRoute).toHaveBeenCalledWith(expect.objectContaining({
      providerId: "openai",
      routeId: "exact-model-v2",
      placement: "remote",
      retentionKind: "bounded",
      retentionMaximumSeconds: 2_592_000,
      trainingUse: "excluded",
      handlingProfileVersion: "openai-responses-default-2026-08",
      disclosureVersion: "phase2-openai-responses-v1",
    }));
    const setupCalls = rendererClient.setupModelRoute.mock.calls as unknown as Array<[
      ApproveModelRouteInput,
    ]>;
    const setup = setupCalls[0]?.[0];
    expect(JSON.stringify(setup)).not.toMatch(/credential|secret|password|api.?key/i);
    act(() => resolveSetup?.({ ...privateSnapshot.modelRoutes[0]!, routeId: "exact-model-v2" }));
    await screen.findByText(/Approved openai\/exact-model-v2/);
  });

  it("does not replay a revoked approval after post-approval credential storage fails", async () => {
    rendererClient.bootstrap.mockResolvedValue({ ...privateSnapshot, modelRoutes: [] });
    rendererClient.setupModelRoute
      .mockRejectedValueOnce({
        code: "model_route_setup_store_failed",
        category: "unavailable",
        summary: "The provider credential could not be stored.",
        retryable: true,
      })
      .mockResolvedValue(privateSnapshot.modelRoutes[0]);
    const user = userEvent.setup();
    render(<App />);
    await user.type(await screen.findByLabelText("Exact OpenAI model identifier"), "exact-model");
    const submit = screen.getByRole("button", { name: "Open Windows prompt and approve exact route" });

    await user.click(submit);
    await screen.findAllByText("The provider credential could not be stored.");
    const setupCalls = rendererClient.setupModelRoute.mock.calls as unknown as Array<[
      ApproveModelRouteInput,
    ]>;
    const firstKey = setupCalls[0]?.[0].idempotencyKey;
    await user.click(submit);
    await waitFor(() => expect(rendererClient.setupModelRoute).toHaveBeenCalledTimes(2));
    const secondKey = setupCalls[1]?.[0].idempotencyKey;

    expect(firstKey).toBeTruthy();
    expect(secondKey).toBeTruthy();
    expect(secondKey).not.toBe(firstKey);
  });

  it("selects a resource through the narrow native command and refreshes authoritatively", async () => {
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.refresh.mockResolvedValue(privateSnapshot);
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Select workspace" }));

    await waitFor(() => expect(rendererClient.registerSelectedResource).toHaveBeenCalledOnce());
    const rawInput: unknown = rendererClient.registerSelectedResource.mock.calls[0]?.[0];
    expect(rawInput).not.toBeNull();
    expect(typeof rawInput).toBe("object");
    if (typeof rawInput !== "object" || rawInput === null) {
      throw new Error("The selected-resource input was not recorded.");
    }
    const input = rawInput as Record<string, unknown>;
    expect(Object.keys(input).sort()).toEqual(["idempotencyKey", "kind"]);
    expect(input.kind).toBe("workspace");
    await waitFor(() => expect(rendererClient.refresh).toHaveBeenCalledOnce());
  });

  it("keeps native picker cancellation out of the connection-alert surface", async () => {
    rendererClient.bootstrap.mockResolvedValue(privateSnapshot);
    rendererClient.registerSelectedResource.mockRejectedValue({
      code: "cancelled",
      category: "cancelled",
      summary: "Native resource selection was cancelled.",
      retryable: false,
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Select document" }));

    expect(await screen.findByText("Selection cancelled. No resource was added.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });

  it("shows an actionable presentation-only state when CORE is unavailable", async () => {
    rendererClient.bootstrap.mockRejectedValue({ code: "core_unavailable", category: "unavailable", summary: "The desktop bridge cannot reach CORE.", retryable: true });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "CORE is not connected" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reconnect to CORE" })).toBeEnabled();
  });
});
