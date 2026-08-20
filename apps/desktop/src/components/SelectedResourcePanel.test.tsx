import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type {
  RegisterSelectedResourceInput,
  ResourceView,
  SelectedResourceKind,
} from "../protocol";
import { SelectedResourcePanel } from "./SelectedResourcePanel";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const documentResource: ResourceView = {
  id: "0198c083-f38b-7000-8000-000000000010",
  kind: "document",
  displayName: "Synthetic Atlas brief",
  revision: 7,
  createdAt: "2026-08-19T08:00:00Z",
};

function resourceFor(kind: SelectedResourceKind): ResourceView {
  return { ...documentResource, kind, displayName: `Synthetic ${kind}` };
}

function renderPanel(overrides: Partial<React.ComponentProps<typeof SelectedResourcePanel>> = {}) {
  const props: React.ComponentProps<typeof SelectedResourcePanel> = {
    disabled: false,
    resources: [],
    onRegister: vi.fn().mockResolvedValue(documentResource),
    onRemove: vi.fn().mockResolvedValue({
      selectedResourceId: documentResource.id,
      deletedRevision: documentResource.revision,
      deletedAt: "2026-08-19T08:05:00Z",
    }),
    onRefresh: vi.fn().mockResolvedValue(undefined),
    onClearError: vi.fn(),
    ...overrides,
  };
  render(<SelectedResourcePanel {...props} />);
  return props;
}

describe("SelectedResourcePanel", () => {
  it.each(["application", "window", "browser_surface", "document", "workspace", "screen_region"] as const)(
    "opens the native %s picker with only kind and a UUIDv7 request identity",
    async (kind) => {
      const onRegister = vi
        .fn<(input: RegisterSelectedResourceInput) => Promise<ResourceView>>()
        .mockResolvedValue(resourceFor(kind));
      const onRefresh = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      renderPanel({ onRegister, onRefresh });

      await user.click(screen.getByRole("button", { name: `Select ${kind}` }));

      await waitFor(() => expect(onRegister).toHaveBeenCalledOnce());
      const input = onRegister.mock.calls[0]?.[0];
      expect(input).toBeDefined();
      if (!input) throw new Error("The picker input was not recorded.");
      expect(Object.keys(input).sort()).toEqual(["idempotencyKey", "kind"]);
      expect(input.kind).toBe(kind);
      expect(input.idempotencyKey).toMatch(UUID_V7);
      await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
      expect(await screen.findByText(`Synthetic ${kind} is now selected.`)).toBeInTheDocument();
    },
  );

  it("offers only source-owned renderer pickers", () => {
    renderPanel();
    expect(screen.getAllByRole("button", { name: /^Select / })).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Select browser_surface" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Select screen_region" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /display/i })).not.toBeInTheDocument();
  });

  it("treats native picker cancellation as a neutral, conclusive outcome", async () => {
    const onRegister = vi
      .fn<(input: RegisterSelectedResourceInput) => Promise<ResourceView>>()
      .mockRejectedValue({
        code: "native_picker_cancelled",
        summary: "The native picker was cancelled.",
        retryable: false,
      });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const onClearError = vi.fn();
    const user = userEvent.setup();
    renderPanel({ onRegister, onRefresh, onClearError });

    await user.click(screen.getByRole("button", { name: "Select application" }));

    expect(await screen.findByText("Selection cancelled. No resource was added.")).toBeInTheDocument();
    expect(onClearError).toHaveBeenCalledOnce();
    expect(onRefresh).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Select application" }));
    await waitFor(() => expect(onRegister).toHaveBeenCalledTimes(2));
    expect(onRegister.mock.calls[1]?.[0].idempotencyKey).not.toBe(onRegister.mock.calls[0]?.[0].idempotencyKey);
  });

  it("reuses the UUIDv7 identity for a deliberate retry after failure", async () => {
    const onRegister = vi
      .fn<(input: RegisterSelectedResourceInput) => Promise<ResourceView>>()
      .mockRejectedValueOnce({
        code: "capability_unavailable",
        category: "unavailable",
        summary: "The picker is temporarily unavailable.",
        retryable: true,
      })
      .mockResolvedValueOnce(resourceFor("application"));
    const user = userEvent.setup();
    renderPanel({ onRegister });

    await user.click(screen.getByRole("button", { name: "Select application" }));
    expect(await screen.findByText(/retry the same request safely/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select application" }));

    await waitFor(() => expect(onRegister).toHaveBeenCalledTimes(2));
    expect(onRegister.mock.calls[1]?.[0].idempotencyKey).toBe(onRegister.mock.calls[0]?.[0].idempotencyKey);
  });

  it("prevents duplicate submission while a picker request is pending", async () => {
    let resolveSelection: ((resource: ResourceView) => void) | undefined;
    const onRegister = vi
      .fn<(input: RegisterSelectedResourceInput) => Promise<ResourceView>>()
      .mockReturnValue(new Promise<ResourceView>((resolve) => {
        resolveSelection = resolve;
      }));
    const user = userEvent.setup();
    renderPanel({ onRegister });
    const select = screen.getByRole("button", { name: "Select application" });

    await user.click(select);
    expect(screen.getByRole("button", { name: "Selecting application…" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Selecting application…" }));
    expect(onRegister).toHaveBeenCalledOnce();

    act(() => resolveSelection?.(resourceFor("application")));
    await waitFor(() => expect(screen.getByRole("button", { name: "Select application" })).toBeEnabled());
  });

  it("disables picker and deletion mutations without private admission", () => {
    renderPanel({ disabled: true, resources: [documentResource] });

    for (const button of screen.getAllByRole("button", { name: /^Select / })) {
      expect(button).toBeDisabled();
    }
    expect(screen.getByRole("button", { name: "Remove resource" })).toBeDisabled();
  });

  it("requires confirmation and submits the authoritative current revision for removal", async () => {
    const onRemove = vi.fn().mockResolvedValue({
      selectedResourceId: documentResource.id,
      deletedRevision: 7,
      deletedAt: "2026-08-19T08:05:00Z",
    });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ resources: [documentResource], onRemove, onRefresh });

    expect(screen.getByText("Revision 7", { exact: false })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove resource" }));
    expect(onRemove).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Confirm removal" }));

    await waitFor(() => expect(onRemove).toHaveBeenCalledWith({
      selectedResourceId: documentResource.id,
      expectedRevision: 7,
    }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText("Synthetic Atlas brief was removed.")).toBeInTheDocument();
  });

  it("refuses deletion without a reported revision", () => {
    renderPanel({ resources: [{ ...documentResource, revision: undefined }] });
    expect(screen.getByText(/revision not reported/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove resource" })).toBeDisabled();
  });

  it("refreshes the authoritative list after a removal revision conflict", async () => {
    const onRemove = vi.fn().mockRejectedValue({
      code: "conflict",
      category: "conflict",
      summary: "The resource revision changed.",
      retryable: true,
    });
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel({ resources: [documentResource], onRemove, onRefresh });

    await user.click(screen.getByRole("button", { name: "Remove resource" }));
    await user.click(screen.getByRole("button", { name: "Confirm removal" }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledOnce());
    expect(await screen.findByText(/authoritative list was refreshed/i)).toBeInTheDocument();
  });
});
