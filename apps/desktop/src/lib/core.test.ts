import { beforeEach, describe, expect, it, vi } from "vitest";

const tauri = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: tauri.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: tauri.listen }));

import { core } from "./core";
import type { StoreModelSecretInput } from "../protocol";

describe("renderer-to-Tauri boundary", () => {
  beforeEach(() => {
    tauri.invoke.mockReset();
    tauri.invoke.mockResolvedValue({ routeId: "exact-model", configured: true });
  });

  it("constructs the native credential request from the route identifier alone", async () => {
    const rendererObject: StoreModelSecretInput & { unexpectedRendererProperty: string } = {
      routeId: "exact-model",
      unexpectedRendererProperty: "must-not-cross",
    };

    await core.storeModelSecret(rendererObject);

    expect(tauri.invoke).toHaveBeenCalledWith("desktop_store_model_secret", {
      input: { routeId: "exact-model" },
    });
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
    ]);
  });
});
