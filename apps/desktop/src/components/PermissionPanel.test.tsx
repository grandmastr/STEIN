import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { GoalView, ResourceView } from "../protocol";
import { PermissionPanel } from "./PermissionPanel";

const goal: GoalView = {
  id: "0198c083-f38b-7000-8000-000000000101",
  revision: 1,
  title: "Synthetic focus goal",
  successStatement: "The synthetic task is complete.",
  state: "active",
  createdAt: "2026-08-20T08:00:00Z",
  updatedAt: "2026-08-20T08:00:00Z",
};

const resources: ResourceView[] = [
  {
    id: "0198c083-f38b-7000-8000-000000000104",
    kind: "application",
    displayName: "Synthetic application",
    revision: 1,
  },
  {
    id: "0198c083-f38b-7000-8000-000000000102",
    kind: "window",
    displayName: "Synthetic window",
    revision: 1,
  },
  {
    id: "0198c083-f38b-7000-8000-000000000103",
    kind: "screen_region",
    displayName: "Selected visual source",
    revision: 1,
  },
  {
    id: "0198c083-f38b-7000-8000-000000000105",
    kind: "browser_surface",
    displayName: "Synthetic Edge tab",
    revision: 1,
  },
  {
    id: "0198c083-f38b-7000-8000-000000000106",
    kind: "document",
    displayName: "Synthetic document",
    revision: 1,
  },
  {
    id: "0198c083-f38b-7000-8000-000000000107",
    kind: "workspace",
    displayName: "Synthetic workspace",
    revision: 1,
  },
];

describe("PermissionPanel", () => {
  it("limits pixel grants to a screen region and forces re-selection after restart", async () => {
    const user = userEvent.setup();
    const onGrant = vi.fn().mockRejectedValue({ summary: "Synthetic stop after command capture." });
    render(
      <PermissionPanel
        disabled={false}
        goals={[goal]}
        grants={[]}
        resources={resources}
        onGrant={onGrant}
        onRevoke={vi.fn()}
      />,
    );

    const restart = screen.getByRole("checkbox", { name: "Recover after supervised daemon restart" });
    await user.click(restart);
    expect(restart).toBeChecked();

    await user.selectOptions(screen.getByLabelText("Permission scope"), "observe.screen.pixels");

    expect(restart).not.toBeChecked();
    expect(restart).toBeDisabled();
    expect(screen.getByText(/Reselect the visual source and grant this scope again/)).toBeInTheDocument();
    const resource = screen.getByLabelText("Selected resource");
    expect(screen.getByRole("option", { name: "Selected visual source · screen_region" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Synthetic window · window" })).not.toBeInTheDocument();
    await user.selectOptions(resource, resources[2]!.id);
    expect(resource).toHaveValue(resources[2]!.id);
    await user.selectOptions(screen.getByLabelText("Grant goal"), goal.id);
    await user.click(screen.getByRole("button", { name: "Grant this scope" }));
    await waitFor(() => expect(onGrant).toHaveBeenCalledWith(expect.objectContaining({
      scope: "observe.screen.pixels",
      selectedResourceId: resources[2]!.id,
      afterDaemonRestart: false,
    })));
  });

  it.each([
    ["observe.desktop.presence", []],
    ["observe.desktop.foreground_application", ["application"]],
    ["observe.desktop.window_metadata", ["window"]],
    ["observe.browser.location", ["browser_surface"]],
    ["observe.content.visible_text", ["window", "browser_surface"]],
    ["observe.content.selected_document", ["document"]],
    ["observe.screen.pixels", ["screen_region"]],
    ["observe.workspace.activity", ["workspace"]],
    ["reason.focus_context", []],
    ["intervene.desktop.notification", []],
  ] as const)("filters %s to its exact eligible resource kinds", async (scope, expectedKinds) => {
    const user = userEvent.setup();
    render(
      <PermissionPanel
        disabled={false}
        goals={[goal]}
        grants={[]}
        resources={resources}
        onGrant={vi.fn()}
        onRevoke={vi.fn()}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Permission scope"), scope);
    const options = Array.from(
      screen.getByLabelText<HTMLSelectElement>("Selected resource").options,
    ).slice(1);
    expect(options.map((option) => option.text.split(" · ").at(-1))).toEqual(expectedKinds);
  });

  it("blocks a resource-bound scope until one exact eligible resource is selected", async () => {
    const user = userEvent.setup();
    const onGrant = vi.fn();
    render(
      <PermissionPanel
        disabled={false}
        goals={[goal]}
        grants={[]}
        resources={resources}
        onGrant={onGrant}
        onRevoke={vi.fn()}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Grant goal"), goal.id);
    await user.selectOptions(
      screen.getByLabelText("Permission scope"),
      "observe.desktop.window_metadata",
    );
    await user.click(screen.getByRole("button", { name: "Grant this scope" }));

    expect(onGrant).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Choose one exact selected resource for this observation scope.",
    );
  });

  it("caps consent at the earlier goal deadline", async () => {
    const user = userEvent.setup();
    const onGrant = vi.fn().mockRejectedValue({ summary: "Synthetic stop after command capture." });
    const deadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const deadlineGoal = { ...goal, deadline };
    render(
      <PermissionPanel
        disabled={false}
        goals={[deadlineGoal]}
        grants={[]}
        resources={resources}
        onGrant={onGrant}
        onRevoke={vi.fn()}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Grant goal"), deadlineGoal.id);
    const expiry = screen.getByLabelText<HTMLInputElement>("Grant expiry");
    expect(expiry.value).toBe(expiry.max);
    expect(new Date(expiry.value).getTime()).toBeLessThanOrEqual(new Date(deadline).getTime());

    await user.click(screen.getByRole("button", { name: "Grant this scope" }));
    await waitFor(() => expect(onGrant).toHaveBeenCalledOnce());
    const submitted: unknown = onGrant.mock.calls[0]?.[0];
    if (
      typeof submitted !== "object"
      || submitted === null
      || !("expiresAt" in submitted)
      || typeof submitted.expiresAt !== "string"
    ) {
      throw new Error("Expected a typed grant expiry.");
    }
    expect(new Date(submitted.expiresAt).getTime()).toBeLessThanOrEqual(new Date(deadline).getTime());
  });

  it("forces connection-bound Edge grants to require a fresh post-restart selection", async () => {
    const user = userEvent.setup();
    const onGrant = vi.fn().mockRejectedValue({ summary: "Synthetic stop after command capture." });
    render(
      <PermissionPanel
        disabled={false}
        goals={[goal]}
        grants={[]}
        resources={resources}
        onGrant={onGrant}
        onRevoke={vi.fn()}
      />,
    );

    const restart = screen.getByRole("checkbox", { name: "Recover after supervised daemon restart" });
    await user.click(restart);
    await user.selectOptions(screen.getByLabelText("Grant goal"), goal.id);
    await user.selectOptions(screen.getByLabelText("Permission scope"), "observe.browser.location");
    await user.selectOptions(screen.getByLabelText("Selected resource"), resources[3]!.id);

    expect(restart).not.toBeChecked();
    expect(restart).toBeDisabled();
    expect(screen.getByText(/Selected Edge authority is connection-bound/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Grant this scope" }));
    await waitFor(() => expect(onGrant).toHaveBeenCalledWith(expect.objectContaining({
      scope: "observe.browser.location",
      selectedResourceId: resources[3]!.id,
      afterDaemonRestart: false,
    })));
  });
});
