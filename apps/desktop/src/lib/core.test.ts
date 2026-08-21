import { beforeEach, describe, expect, it, vi } from "vitest";

const tauri = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: tauri.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: tauri.listen }));

import { core, TOAST_ACTIVATION_EVENT } from "./core";
import type { ApproveModelRouteInput, InterventionExplanationView } from "../protocol";

const explanation: InterventionExplanationView = {
  interventionId: "0198c083-f38b-7000-8000-000000000090",
  candidateRevision: 1,
  focusSessionId: "0198c083-f38b-7000-8000-000000000060",
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
  decisionReasonCodes: ["deadline_near"],
  decisionIssuedAt: "2026-08-19T08:01:00Z",
  decisionExpiresAt: "2026-08-19T08:01:30Z",
  deliveryState: "accepted_by_channel",
  outcome: "unacknowledged",
  correctionRecorded: false,
};

describe("renderer-to-Tauri boundary", () => {
  beforeEach(() => {
    tauri.invoke.mockReset();
    tauri.invoke.mockResolvedValue({ routeId: "exact-model" });
    tauri.listen.mockReset();
    tauri.listen.mockResolvedValue(vi.fn());
  });

  it("exposes one metadata-only native route setup command and no standalone secret write", async () => {
    const setup: ApproveModelRouteInput = {
      providerId: "openai",
      routeId: "exact-model",
      placement: "remote",
      accountProfile: "default",
      allowedDataCategories: ["goal"],
      retentionKind: "bounded",
      retentionMaximumSeconds: 2_592_000,
      trainingUse: "excluded",
      handlingProfileVersion: "openai-responses-default-2026-08",
      purpose: "reason.focus_context",
      maximumRequestTokens: 8_000,
      disclosureVersion: "phase2-openai-responses-v1",
      idempotencyKey: "0198c083-f38b-7000-8000-000000000099",
    };

    await core.setupModelRoute(setup);

    expect(tauri.invoke).toHaveBeenCalledWith("desktop_setup_model_route", {
      input: setup,
    });
    expect(core).not.toHaveProperty("storeModelSecret");
    expect(core).not.toHaveProperty("approveModelRoute");
    expect(JSON.stringify(setup)).not.toMatch(/credential|secret|password|api.?key/i);
  });

  it("exposes the complete protocol 1.2 command and query surface", async () => {
    const goal = "0198c083-f38b-7000-8000-000000000002";
    const resource = "0198c083-f38b-7000-8000-000000000010";
    const idempotencyKey = "0198c083-f38b-7000-8000-000000000099";

    await core.updateGoal({
      goalId: goal,
      expectedRevision: 1,
      patch: { successStatement: "Synthetic revised success" },
    });
    await core.deleteGoal({ goalId: goal, expectedRevision: 2 });
    await core.registerSelectedResource({ kind: "document", idempotencyKey });
    await core.removeSelectedResource({ selectedResourceId: resource, expectedRevision: 1 });
    await core.updateUserPreferences({
      expectedRevision: 1,
      preferences: {
        interventionStyle: "concise",
        proactiveEnabled: true,
        proactiveMuted: false,
        maximumInterventionsPerSession: 3,
        maximumModelRequestsPerHour: 12,
        minimumInterventionCooldownMs: 900_000,
        doNotDisturbWindows: [],
        allowedDeliveryChannels: ["native_desktop_notification"],
        remoteProcessingEnabled: false,
        restartContinuityDefault: false,
      },
    });
    await core.getSteinIdentity();
    await core.getUserPreferences();
    await core.getEffectivePolicy();
    await core.getSelectedResources();
    await core.getLatestModelRequestReceipt({
      focusSessionId: "0198c083-f38b-7000-8000-000000000060",
    });

    const calls = tauri.invoke.mock.calls as unknown as Array<[string, unknown?]>;
    expect(calls.map(([command]) => command)).toEqual([
      "desktop_update_goal",
      "desktop_delete_goal",
      "desktop_register_selected_resource",
      "desktop_remove_selected_resource",
      "desktop_update_user_preferences",
      "desktop_get_stein_identity",
      "desktop_get_user_preferences",
      "desktop_get_effective_policy",
      "desktop_get_selected_resources",
      "desktop_get_latest_model_request_receipt",
    ]);
  });

  it("exposes only a read-only content-free model request receipt query", async () => {
    const input = { focusSessionId: "0198c083-f38b-7000-8000-000000000060" };
    await core.getLatestModelRequestReceipt(input);

    expect(tauri.invoke).toHaveBeenCalledWith(
      "desktop_get_latest_model_request_receipt",
      { input },
    );
    expect(core).not.toHaveProperty("triggerModelRequest");
    expect(core).not.toHaveProperty("runReasoningCycle");
    expect(JSON.stringify(input)).not.toMatch(/prompt|response|candidate|credential|secret/i);
  });

  it("routes only structurally valid authoritative toast explanations", async () => {
    const onActivation = vi.fn();
    const unlisten = vi.fn();
    tauri.listen.mockResolvedValue(unlisten);

    const returnedUnlisten = await core.subscribeToastActivation(onActivation);

    expect(tauri.listen).toHaveBeenCalledWith(TOAST_ACTIVATION_EVENT, expect.any(Function));
    const calls = tauri.listen.mock.calls as unknown as Array<[
      string,
      (event: { payload: unknown }) => void,
    ]>;
    const handler = calls[0]?.[1];
    expect(handler).toBeDefined();
    handler?.({ payload: { ...explanation, candidateRevision: "not-a-number" } });
    handler?.({
      payload: {
        ...explanation,
        policyTrace: { ...explanation.policyTrace, inputSchemaVersion: 2 },
      },
    });
    handler?.({ payload: explanation });

    expect(onActivation).toHaveBeenCalledOnce();
    expect(onActivation).toHaveBeenCalledWith(explanation);
    expect(returnedUnlisten).toBe(unlisten);
  });
});
