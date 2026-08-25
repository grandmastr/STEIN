import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { EffectivePolicyView, SteinIdentityView } from "../protocol";
import { IdentityPolicyPanel } from "./IdentityPolicyPanel";

const identity: SteinIdentityView = {
  schemaVersion: 1,
  ownerId: "0198c083-f38b-7000-8000-000000000001",
  revision: 2,
  displayName: "STEIN",
  roleStatement: "A second mind that advises while the user decides and acts.",
  invariantBehavioralConstraints: [
    "advises_rather_than_acts",
    "preserves_uncertainty",
    "respects_silence",
    "never_impersonates_user",
    "never_bypasses_policy",
  ],
  provenance: {
    source: "product_default",
    version: "stein-identity-v1",
    recordedAt: "2026-08-19T08:00:00Z",
  },
};

const policy: EffectivePolicyView = {
  schemaVersion: 1,
  policyProfileId: "phase2-focus-v1",
  userPreferencesRevision: 4,
  sourceStaleAfterMs: 30_000,
  maximumModelEvidenceAgeMs: 120_000,
  modelRequestCooldownMs: 300_000,
  maximumModelRequestsPerHour: 6,
  interventionCooldownMs: 900_000,
  maximumInterventionsPerSession: 2,
  proactiveEnabled: true,
  proactiveMuted: false,
  doNotDisturbWindows: [{ startMinuteLocal: 1_320, endMinuteLocal: 420, utcOffsetMinutes: 60 }],
  allowedDeliveryChannels: ["native_desktop_notification"],
  remoteProcessingEnabled: false,
  restartContinuityDefault: false,
  outboxCapacityPerUser: 20,
  outboxCapacityPerSession: 5,
};

describe("IdentityPolicyPanel", () => {
  it("presents the complete authoritative identity and effective policy read-only", () => {
    render(<IdentityPolicyPanel identity={identity} policy={policy} />);

    expect(screen.getByRole("heading", { name: "STEIN identity" })).toBeInTheDocument();
    expect(screen.getByText(identity.roleStatement)).toBeInTheDocument();
    for (const label of ["Advises rather than acts", "Preserves uncertainty", "Respects silence", "Never impersonates user", "Never bypasses policy"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByRole("heading", { name: "Effective policy" })).toBeInTheDocument();
    expect(screen.getByText("phase2-focus-v1")).toBeInTheDocument();
    expect(screen.getByText("preferences r4")).toBeInTheDocument();
    expect(screen.getByText("22:00–07:00 UTC+01:00")).toBeInTheDocument();
    expect(screen.getByText("Native desktop notification")).toBeInTheDocument();
    expect(screen.getByText(/never create a grant/i)).toBeInTheDocument();
  });

  it("reports absent private views without inventing identity or policy", () => {
    render(<IdentityPolicyPanel />);
    expect(screen.getByText("No private identity view is available.")).toBeInTheDocument();
    expect(screen.getByText("No private effective-policy view is available.")).toBeInTheDocument();
    expect(screen.queryByText("phase2-focus-v1")).not.toBeInTheDocument();
  });
});
