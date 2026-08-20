import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { DashboardSnapshot, DesktopBridgeEvent, GoalView } from "./protocol";

const rendererClient = vi.hoisted(() => ({
  bootstrap: vi.fn(),
  refresh: vi.fn(),
  reconnect: vi.fn(),
  createGoal: vi.fn(),
  updateGoal: vi.fn(),
  completeGoal: vi.fn(),
  abandonGoal: vi.fn(),
  deleteGoal: vi.fn(),
  storeModelSecret: vi.fn(),
  approveModelRoute: vi.fn(),
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
  selectedResources: [{ id: "0198c083-f38b-7000-8000-000000000010", kind: "document", displayName: "Synthetic Atlas brief" }],
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
    handlingProfileVersion: "openai-default-abuse-monitoring-v1",
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
    rendererClient.storeModelSecret.mockResolvedValue({ routeId: "exact-model", configured: true });
    rendererClient.approveModelRoute.mockResolvedValue(privateSnapshot.modelRoutes[0]);
    rendererClient.revokePermission.mockResolvedValue(undefined);
    rendererClient.subscribe.mockResolvedValue(() => undefined);
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

  it("opens the native credential command with only a route identifier", async () => {
    rendererClient.bootstrap.mockResolvedValue({ ...privateSnapshot, modelRoutes: [] });
    let resolveStore: ((value: { routeId: string; configured: boolean }) => void) | undefined;
    rendererClient.storeModelSecret.mockReturnValue(new Promise((resolve) => { resolveStore = resolve; }));
    const user = userEvent.setup();
    render(<App />);
    const route = await screen.findByLabelText("Exact OpenAI model identifier");
    expect(screen.queryByLabelText("Provider credential")).not.toBeInTheDocument();
    await user.type(route, "exact-model-v2");
    await user.click(screen.getByRole("button", { name: "Open Windows prompt and approve exact route" }));
    expect(rendererClient.storeModelSecret).toHaveBeenCalledWith({ routeId: "exact-model-v2" });
    expect(rendererClient.approveModelRoute).not.toHaveBeenCalled();
    act(() => resolveStore?.({ routeId: "exact-model-v2", configured: true }));
    await waitFor(() => expect(rendererClient.approveModelRoute).toHaveBeenCalledOnce());
  });

  it("shows an actionable presentation-only state when CORE is unavailable", async () => {
    rendererClient.bootstrap.mockRejectedValue({ code: "core_unavailable", category: "unavailable", summary: "The desktop bridge cannot reach CORE.", retryable: true });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "CORE is not connected" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reconnect to CORE" })).toBeEnabled();
  });
});
