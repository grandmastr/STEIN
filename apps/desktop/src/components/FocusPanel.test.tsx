import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type {
  FocusSessionView,
  GoalView,
  ModelRequestReceiptView,
  ModelRouteView,
  ResourceView,
  SessionGrantView,
} from "../protocol";
import { FocusPanel } from "./FocusPanel";

const goal: GoalView = {
  id: "0198c083-f38b-7000-8000-000000000201",
  revision: 4,
  title: "Synthetic focus",
  successStatement: "Synthetic work is complete.",
  state: "active",
  createdAt: "2026-08-20T08:00:00Z",
  updatedAt: "2026-08-20T08:00:00Z",
};
const resource: ResourceView = {
  id: "0198c083-f38b-7000-8000-000000000202",
  kind: "window",
  displayName: "Synthetic selected window",
  revision: 2,
};
const grant: SessionGrantView = {
  id: "0198c083-f38b-7000-8000-000000000203",
  revision: 3,
  goalId: goal.id,
  deviceId: "0198c083-f38b-7000-8000-000000000204",
  scope: "observe.desktop.window_metadata",
  selectedResourceId: resource.id,
  purpose: "deadline_aware_focus",
  whileClientDisconnected: true,
  afterDaemonRestart: false,
  state: "active",
  effectiveAt: "2026-08-20T08:00:00Z",
  expiresAt: "2026-08-20T12:00:00Z",
  consentCopyVersion: "phase2-focus-consent-v1",
  sensitivity: "private",
  retention: "observation_10_minutes",
};
const route: ModelRouteView = {
  id: "0198c083-f38b-7000-8000-000000000205",
  revision: 1,
  providerId: "synthetic",
  routeId: "local-test",
  placement: "local",
  accountProfile: "test",
  allowedDataCategories: [],
  retention: "none",
  trainingUse: "none",
  handlingProfileVersion: "v1",
  purpose: "deadline_aware_focus",
  maximumRequestTokens: 128,
  hasFallback: false,
  state: "active",
  effectiveAt: "2026-08-20T08:00:00Z",
  disclosureVersion: "v1",
};
const session: FocusSessionView = {
  id: "0198c083-f38b-7000-8000-000000000206",
  revision: 2,
  goalId: goal.id,
  goalRevision: goal.revision,
  state: "active",
  interventionsMuted: false,
  sourceDegraded: false,
  modelRouteApprovalId: route.id,
  permissionGrantIds: [grant.id],
  selectedResourceIds: [resource.id],
  whileClientDisconnected: true,
  afterDaemonRestart: false,
  createdAt: "2026-08-20T08:00:00Z",
  startedAt: "2026-08-20T08:00:01Z",
  updatedAt: "2026-08-20T08:00:01Z",
};
const receipt: ModelRequestReceiptView = {
  requestId: "0198c083-f38b-7000-8000-000000000207",
  focusSessionId: session.id,
  modelRouteApprovalId: route.id,
  modelRouteRevision: route.revision,
  startedAt: "2026-08-20T08:01:00Z",
  completedAt: "2026-08-20T08:01:02Z",
  outcome: "completed_strict_candidate",
};

describe("FocusPanel", () => {
  it("derives the exact resource set from chosen grants and submits no independent UUID choices", async () => {
    const user = userEvent.setup();
    const onStart = vi.fn().mockRejectedValue({ summary: "Synthetic stop after command capture." });
    render(
      <FocusPanel
        captures={[]}
        disabled={false}
        goals={[goal]}
        grants={[grant]}
        resources={[resource]}
        routes={[route]}
        sessions={[]}
        onEnd={vi.fn()}
        onGetLatestModelRequestReceipt={vi.fn()}
        onSetMuted={vi.fn()}
        onStart={onStart}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Focus goal"), goal.id);
    await user.selectOptions(screen.getByLabelText("Focus model route"), route.id);
    await user.click(screen.getByRole("checkbox", { name: /observe\.desktop\.window_metadata/ }));

    expect(screen.getByLabelText("Derived selected-resource set")).toHaveTextContent(resource.displayName);
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Start exact focus session" }));
    await waitFor(() => expect(onStart).toHaveBeenCalledWith(expect.objectContaining({
      goalId: goal.id,
      goalRevision: goal.revision,
      permissionGrantIds: [grant.id],
      selectedResourceIds: [resource.id],
      modelRouteApprovalId: route.id,
    })));

    await user.selectOptions(screen.getByLabelText("Focus goal"), "");
    expect(screen.getByLabelText("Derived selected-resource set")).not.toHaveTextContent(resource.displayName);
  });

  it("lets a private operator read content-free latest-only model evidence without triggering work", async () => {
    const user = userEvent.setup();
    const onGetLatestModelRequestReceipt = vi.fn().mockResolvedValue(receipt);
    render(
      <FocusPanel
        captures={[]}
        disabled={false}
        goals={[goal]}
        grants={[grant]}
        resources={[resource]}
        routes={[route]}
        sessions={[session]}
        onEnd={vi.fn()}
        onGetLatestModelRequestReceipt={onGetLatestModelRequestReceipt}
        onSetMuted={vi.fn()}
        onStart={vi.fn()}
      />,
    );

    expect(screen.getByText(/never starts a model request/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check latest model request receipt" }));

    await waitFor(() => expect(onGetLatestModelRequestReceipt).toHaveBeenCalledWith({
      focusSessionId: session.id,
    }));
    const evidence = await screen.findByLabelText(`Latest model request receipt for ${session.id}`);
    expect(evidence).toHaveTextContent(receipt.outcome);
    expect(evidence).toHaveTextContent(receipt.requestId);
    expect(evidence).toHaveTextContent(receipt.modelRouteApprovalId);
    expect(evidence).not.toHaveTextContent("prompt");
    expect(evidence).not.toHaveTextContent("response");
  });
});
