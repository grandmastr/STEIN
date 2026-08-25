import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type {
  EffectivePolicyView,
  UpdateUserPreferencesInput,
  UserPreferencesUpdateView,
  UserPreferencesView,
} from "../protocol";
import { UserPreferencesPanel } from "./UserPreferencesPanel";

const preferences: UserPreferencesView = {
  schemaVersion: 1,
  ownerId: "0198c083-f38b-7000-8000-000000000001",
  revision: 4,
  preferredFormOfAddress: "Captain",
  interventionStyle: "concise",
  proactiveEnabled: true,
  proactiveMuted: false,
  maximumInterventionsPerSession: 2,
  maximumModelRequestsPerHour: 6,
  minimumInterventionCooldownMs: 900_000,
  doNotDisturbWindows: [{ startMinuteLocal: 1_320, endMinuteLocal: 420, utcOffsetMinutes: 60 }],
  allowedDeliveryChannels: ["native_desktop_notification"],
  remoteProcessingEnabled: false,
  restartContinuityDefault: false,
  provenance: {
    source: "direct_user",
    version: "user-preferences-v1",
    recordedAt: "2026-08-19T08:00:00Z",
  },
};

const effectivePolicy: EffectivePolicyView = {
  schemaVersion: 1,
  policyProfileId: "phase2-focus-v1",
  userPreferencesRevision: 5,
  sourceStaleAfterMs: 30_000,
  maximumModelEvidenceAgeMs: 120_000,
  modelRequestCooldownMs: 300_000,
  maximumModelRequestsPerHour: 6,
  interventionCooldownMs: 900_000,
  maximumInterventionsPerSession: 2,
  proactiveEnabled: true,
  proactiveMuted: false,
  doNotDisturbWindows: preferences.doNotDisturbWindows,
  allowedDeliveryChannels: preferences.allowedDeliveryChannels,
  remoteProcessingEnabled: false,
  restartContinuityDefault: false,
  outboxCapacityPerUser: 20,
  outboxCapacityPerSession: 5,
};

function updatedPreferences(): UserPreferencesUpdateView {
  return { preferences: { ...preferences, revision: 5 }, effectivePolicy };
}

function renderPanel(overrides: Partial<React.ComponentProps<typeof UserPreferencesPanel>> = {}) {
  const props: React.ComponentProps<typeof UserPreferencesPanel> = {
    disabled: false,
    preferences,
    onUpdate: vi
      .fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>()
      .mockResolvedValue(updatedPreferences()),
    onRefresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
  render(<UserPreferencesPanel {...props} />);
  return props;
}

describe("UserPreferencesPanel", () => {
  it("submits every explicit field with the authoritative expected revision", async () => {
    const onUpdate = vi
      .fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>()
      .mockResolvedValue(updatedPreferences());
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onUpdate, onRefresh });

    await user.click(screen.getByRole("button", { name: "Save preferences" }));

    await waitFor(() => expect(onUpdate).toHaveBeenCalledOnce());
    expect(onUpdate).toHaveBeenCalledWith({
      expectedRevision: 4,
      preferences: {
        preferredFormOfAddress: "Captain",
        interventionStyle: "concise",
        proactiveEnabled: true,
        proactiveMuted: false,
        maximumInterventionsPerSession: 2,
        maximumModelRequestsPerHour: 6,
        minimumInterventionCooldownMs: 900_000,
        doNotDisturbWindows: [{ startMinuteLocal: 1_320, endMinuteLocal: 420, utcOffsetMinutes: 60 }],
        allowedDeliveryChannels: ["native_desktop_notification"],
        remoteProcessingEnabled: false,
        restartContinuityDefault: false,
      },
    });
    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText("Preferences revision 5 is now authoritative.")).toBeInTheDocument();
  });

  it("exposes every behavior control without claiming that preferences create authority", () => {
    renderPanel();
    expect(screen.getByLabelText("Preferred form of address")).toHaveValue("Captain");
    expect(screen.getByLabelText("Intervention style")).toHaveValue("concise");
    expect(screen.getByLabelText("Maximum interventions per session")).toHaveValue(2);
    expect(screen.getByLabelText("Maximum model requests per hour")).toHaveValue(6);
    expect(screen.getByLabelText("Minimum intervention cooldown")).toHaveValue(900);
    expect(screen.getByLabelText("Do not disturb 1 start")).toHaveValue("22:00");
    expect(screen.getByLabelText("Do not disturb 1 end")).toHaveValue("07:00");
    expect(screen.getByText(/observations, model output, silence, timing, corrections/i)).toBeInTheDocument();
    expect(screen.getByText(/cannot grant observation/i)).toBeInTheDocument();
  });

  it("edits restrictive and enabling choices only through explicit controls", async () => {
    const onUpdate = vi
      .fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>()
      .mockResolvedValue(updatedPreferences());
    const user = userEvent.setup();
    renderPanel({ onUpdate });

    await user.selectOptions(screen.getByLabelText("Intervention style"), "reflective");
    await user.click(screen.getByRole("checkbox", { name: /mute proactive delivery/i }));
    await user.click(screen.getByRole("checkbox", { name: /allow remote processing preference/i }));
    await user.click(screen.getByRole("checkbox", { name: /prefer restart continuity/i }));
    await user.click(screen.getByRole("checkbox", { name: /native desktop notification/i }));
    await user.click(screen.getByRole("checkbox", { name: /connected desktop/i }));
    const offset = screen.getByLabelText("Do not disturb 1 UTC offset");
    await user.clear(offset);
    await user.type(offset, "-300");
    await user.click(screen.getByRole("button", { name: "Save preferences" }));

    await waitFor(() => expect(onUpdate).toHaveBeenCalledOnce());
    const input = onUpdate.mock.calls[0]?.[0];
    expect(input?.preferences.interventionStyle).toBe("reflective");
    expect(input?.preferences.proactiveMuted).toBe(true);
    expect(input?.preferences.remoteProcessingEnabled).toBe(true);
    expect(input?.preferences.restartContinuityDefault).toBe(true);
    expect(input?.preferences.allowedDeliveryChannels).toEqual(["connected_desktop"]);
    expect(input?.preferences.doNotDisturbWindows[0]?.utcOffsetMinutes).toBe(-300);
  });

  it("rejects values that would weaken the accepted hard limits", async () => {
    const onUpdate = vi.fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>();
    const user = userEvent.setup();
    renderPanel({ onUpdate });
    const cooldown = screen.getByLabelText("Minimum intervention cooldown");
    await user.clear(cooldown);
    await user.type(cooldown, "899");
    await user.clear(screen.getByLabelText("Maximum model requests per hour"));
    await user.click(screen.getByRole("button", { name: "Save preferences" }));
    expect(await screen.findByText(/at least 900/i)).toBeInTheDocument();
    expect(screen.getByText(/whole number from 0 to 12/i)).toBeInTheDocument();
    expect(onUpdate).not.toHaveBeenCalled();
  });

  it("refreshes and reports a revision conflict truthfully", async () => {
    const onUpdate = vi
      .fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>()
      .mockRejectedValue({ code: "conflict", category: "conflict", summary: "Expected revision 4, current revision 5.", retryable: true });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onUpdate, onRefresh });

    await user.click(screen.getByRole("button", { name: "Save preferences" }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText(/rejected the update because the preference revision changed/i)).toBeInTheDocument();
  });

  it("disables all mutations under diagnostic admission", () => {
    renderPanel({ disabled: true });
    expect(screen.getByRole("button", { name: "Save preferences" })).toBeDisabled();
    expect(screen.getByLabelText("Preferred form of address")).toBeDisabled();
    expect(screen.getByLabelText("Intervention style")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Add do not disturb window" })).toBeDisabled();
  });

  it("does not invent editable defaults when no authoritative record is available", () => {
    const onUpdate = vi.fn<(input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>>();
    renderPanel({ preferences: undefined, onUpdate });
    expect(screen.getByText(/will not invent defaults/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save preferences" })).toBeDisabled();
    expect(screen.queryByLabelText("Preferred form of address")).not.toBeInTheDocument();
    expect(onUpdate).not.toHaveBeenCalled();
  });
});
