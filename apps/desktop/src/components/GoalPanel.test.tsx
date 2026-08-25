import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type {
  AbandonGoalInput,
  GoalDeletionView,
  GoalRevisionInput,
  GoalView,
  UpdateGoalInput,
} from "../protocol";
import { GoalPanel } from "./GoalPanel";

const goal: GoalView = {
  id: "0198c083-f38b-7000-8000-000000000002",
  revision: 4,
  title: "Finish the product brief",
  successStatement: "A reviewed brief ready to share.",
  state: "active",
  deadline: "2026-08-20T09:00:00Z",
  createdAt: "2026-08-19T08:00:00Z",
  updatedAt: "2026-08-19T08:00:00Z",
};

const deletion: GoalDeletionView = {
  goalId: goal.id,
  deletedRevision: 4,
  deletedAt: "2026-08-19T08:05:00Z",
  focusSessionsDeleted: 1,
  grantsDeleted: 2,
  interventionsDeleted: 0,
  pendingDeliveriesDeleted: 0,
  privateAuditRecordsDeleted: 1,
  resourceBindingsDeleted: 1,
  alreadyDeleted: false,
};

function renderPanel(overrides: Partial<React.ComponentProps<typeof GoalPanel>> = {}) {
  const props: React.ComponentProps<typeof GoalPanel> = {
    goals: [goal],
    disabled: false,
    onUpdate: vi.fn<(input: UpdateGoalInput) => Promise<GoalView>>().mockResolvedValue({ ...goal, title: "Revised product brief", revision: 5 }),
    onDelete: vi.fn<(input: GoalRevisionInput) => Promise<GoalDeletionView>>().mockResolvedValue(deletion),
    onComplete: vi.fn<(input: GoalRevisionInput) => Promise<GoalView>>().mockResolvedValue({ ...goal, state: "completed", revision: 5 }),
    onAbandon: vi.fn<(input: AbandonGoalInput) => Promise<GoalView>>().mockResolvedValue({ ...goal, state: "abandoned", revision: 5 }),
    onRefresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
  render(<GoalPanel {...props} />);
  return props;
}

describe("GoalPanel", () => {
  it("updates only changed fields with the authoritative expected revision", async () => {
    const onUpdate = vi.fn<(input: UpdateGoalInput) => Promise<GoalView>>().mockResolvedValue({ ...goal, title: "Revised product brief", revision: 5 });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onUpdate, onRefresh });

    await user.click(screen.getByRole("button", { name: `Edit ${goal.title}` }));
    const title = screen.getByLabelText(`Edit ${goal.title} title`);
    await user.clear(title);
    await user.type(title, "Revised product brief");
    await user.click(screen.getByRole("button", { name: "Save goal" }));

    await waitFor(() => expect(onUpdate).toHaveBeenCalledWith({
      goalId: goal.id,
      expectedRevision: 4,
      patch: { title: "Revised product brief" },
    }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
  });

  it("represents deliberate deadline removal as an explicit clear operation", async () => {
    const onUpdate = vi.fn<(input: UpdateGoalInput) => Promise<GoalView>>().mockResolvedValue({ ...goal, deadline: undefined, revision: 5 });
    const user = userEvent.setup();
    renderPanel({ onUpdate });
    await user.click(screen.getByRole("button", { name: `Edit ${goal.title}` }));
    await user.clear(screen.getByLabelText(`Edit ${goal.title} deadline`));
    await user.click(screen.getByRole("button", { name: "Save goal" }));
    await waitFor(() => expect(onUpdate).toHaveBeenCalledWith({
      goalId: goal.id,
      expectedRevision: 4,
      patch: { deadline: { operation: "clear" } },
    }));
  });

  it("requires confirmation and the current revision before deleting", async () => {
    const onDelete = vi.fn<(input: GoalRevisionInput) => Promise<GoalDeletionView>>().mockResolvedValue(deletion);
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onDelete, onRefresh });

    await user.click(screen.getByRole("button", { name: `Delete ${goal.title}` }));
    expect(onDelete).not.toHaveBeenCalled();
    expect(screen.getByText(/cascade its focus sessions, grants, interventions/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm delete" }));

    await waitFor(() => expect(onDelete).toHaveBeenCalledWith({ goalId: goal.id, expectedRevision: 4 }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText(/5 owned dependent records were removed/i)).toBeInTheDocument();
  });

  it("refreshes and preserves the server conflict summary when a goal revision changes", async () => {
    const onUpdate = vi
      .fn<(input: UpdateGoalInput) => Promise<GoalView>>()
      .mockRejectedValue({ code: "conflict", category: "conflict", summary: "Expected revision 4, current revision 5.", retryable: true });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onUpdate, onRefresh });
    await user.click(screen.getByRole("button", { name: `Edit ${goal.title}` }));
    const title = screen.getByLabelText(`Edit ${goal.title} title`);
    await user.clear(title);
    await user.type(title, "Stale edit");
    await user.click(screen.getByRole("button", { name: "Save goal" }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText(/expected revision 4, current revision 5.*authoritative goal list was refreshed/i)).toBeInTheDocument();
  });

  it("does not retry a delete against a stale revision and refreshes the conflict", async () => {
    const onDelete = vi
      .fn<(input: GoalRevisionInput) => Promise<GoalDeletionView>>()
      .mockRejectedValue({ code: "conflict", category: "conflict", summary: "Expected revision 4, current revision 6.", retryable: true });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ onDelete, onRefresh });

    await user.click(screen.getByRole("button", { name: `Delete ${goal.title}` }));
    await user.click(screen.getByRole("button", { name: "Confirm delete" }));

    await waitFor(() => expect(onDelete).toHaveBeenCalledOnce());
    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText(/expected revision 4, current revision 6.*authoritative goal list was refreshed/i)).toBeInTheDocument();
  });

  it("refuses an empty update patch", async () => {
    const onUpdate = vi.fn<(input: UpdateGoalInput) => Promise<GoalView>>();
    const user = userEvent.setup();
    renderPanel({ onUpdate });
    await user.click(screen.getByRole("button", { name: `Edit ${goal.title}` }));
    await user.click(screen.getByRole("button", { name: "Save goal" }));
    expect(await screen.findByText(/change at least one field/i)).toBeInTheDocument();
    expect(onUpdate).not.toHaveBeenCalled();
  });

  it("disables every goal mutation without private admission", () => {
    renderPanel({ disabled: true });
    expect(screen.getByRole("button", { name: `Edit ${goal.title}` })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Complete ${goal.title}` })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Abandon ${goal.title}` })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Delete ${goal.title}` })).toBeDisabled();
  });
});
