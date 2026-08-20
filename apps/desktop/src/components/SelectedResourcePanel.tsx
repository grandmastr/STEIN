import { useRef, useState } from "react";
import { displayMessageType, formatMoment } from "../lib/format";
import { newUuidV7 } from "../lib/uuid";
import {
  publicErrorFromUnknown,
  type PublicErrorView,
  type RegisterSelectedResourceInput,
  type RemoveSelectedResourceInput,
  type ResourceView,
  type SelectedResourceDeletionView,
  type SelectedResourceKind,
} from "../protocol";

const PICKER_KINDS = [
  "application",
  "window",
  "browser_surface",
  "document",
  "workspace",
  "screen_region",
] as const satisfies readonly SelectedResourceKind[];

type PickerKind = (typeof PICKER_KINDS)[number];
type Notice = { tone: "success" | "neutral" | "error"; text: string };

interface Props {
  disabled: boolean;
  resources: ResourceView[];
  onRegister: (input: RegisterSelectedResourceInput) => Promise<ResourceView>;
  onRemove: (input: RemoveSelectedResourceInput) => Promise<SelectedResourceDeletionView>;
  onRefresh: () => Promise<unknown>;
  onClearError?: () => void;
}

function pickerWasCancelled(error: PublicErrorView): boolean {
  const code = error.code.toLowerCase();
  return error.category === "cancelled" || code === "cancelled" || code.includes("cancel");
}

function isConflict(error: PublicErrorView): boolean {
  return error.category === "conflict" || error.code.toLowerCase().includes("conflict");
}

export function SelectedResourcePanel({
  disabled,
  resources,
  onRegister,
  onRemove,
  onRefresh,
  onClearError,
}: Props) {
  const [selectingKind, setSelectingKind] = useState<PickerKind | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const selectionInFlight = useRef(false);
  const removalInFlight = useRef(false);
  const pendingKeys = useRef<Partial<Record<PickerKind, string>>>({});
  const supportedResources = resources.filter((resource) =>
    PICKER_KINDS.some((kind) => kind === resource.kind),
  );
  const busy = selectingKind !== null || removingId !== null;

  async function reconcile(successText: string): Promise<void> {
    try {
      await onRefresh();
      setNotice({ tone: "success", text: successText });
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      setNotice({
        tone: "error",
        text: `${successText} CORE accepted the change, but the authoritative list could not refresh: ${error.summary}`,
      });
    }
  }

  async function selectResource(kind: PickerKind): Promise<void> {
    if (disabled || selectionInFlight.current || removalInFlight.current) return;

    selectionInFlight.current = true;
    setSelectingKind(kind);
    setConfirmingId(null);
    setNotice(null);
    const idempotencyKey = pendingKeys.current[kind] ?? newUuidV7();
    pendingKeys.current[kind] = idempotencyKey;

    try {
      const resource = await onRegister({ kind, idempotencyKey });
      delete pendingKeys.current[kind];
      await reconcile(`${resource.displayName} is now selected.`);
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (pickerWasCancelled(error)) {
        delete pendingKeys.current[kind];
        onClearError?.();
        setNotice({ tone: "neutral", text: "Selection cancelled. No resource was added." });
      } else {
        setNotice({
          tone: "error",
          text: `${error.summary} Select ${kind} again to retry the same request safely.`,
        });
      }
    } finally {
      selectionInFlight.current = false;
      setSelectingKind(null);
    }
  }

  async function removeResource(resource: ResourceView): Promise<void> {
    if (
      disabled ||
      resource.revision === undefined ||
      selectionInFlight.current ||
      removalInFlight.current
    ) return;

    removalInFlight.current = true;
    setRemovingId(resource.id);
    setNotice(null);
    try {
      await onRemove({
        selectedResourceId: resource.id,
        expectedRevision: resource.revision,
      });
      setConfirmingId(null);
      await reconcile(`${resource.displayName} was removed.`);
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (pickerWasCancelled(error)) {
        onClearError?.();
        setNotice({ tone: "neutral", text: "Removal cancelled. The resource remains selected." });
      } else if (isConflict(error)) {
        try {
          await onRefresh();
          setConfirmingId(null);
          setNotice({
            tone: "neutral",
            text: "The resource changed in CORE. The authoritative list was refreshed; review it before trying again.",
          });
        } catch (refreshError) {
          setNotice({ tone: "error", text: publicErrorFromUnknown(refreshError).summary });
        }
      } else {
        setNotice({ tone: "error", text: error.summary });
      }
    } finally {
      removalInFlight.current = false;
      setRemovingId(null);
    }
  }

  return (
    <section className="panel span-2" aria-labelledby="selected-resources-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Native selection · opaque bindings</p>
          <h2 id="selected-resources-title">Selected resources</h2>
        </div>
        <span className="panel__count">{supportedResources.length}</span>
      </div>

      <div className="selected-resource-layout">
        <div className="resource-picker">
          <p className="panel-note">
            Windows performs each selection outside the webview. The renderer sends only the resource kind and a retry-safe request identity; it never receives or submits paths, URLs, window handles, or native tokens.
          </p>
          <p className="panel-note">
            For an Edge tab, invoke the installed STEIN extension on that exact active tab first. The initial URL grant includes origin and path only; query, fragment, history, private pages, and background tabs remain excluded.
          </p>
          <div className="resource-picker__actions" aria-label="Native resource pickers">
            {PICKER_KINDS.map((kind) => (
              <button
                className="button button--ghost"
                disabled={disabled || busy}
                key={kind}
                type="button"
                onClick={() => void selectResource(kind)}
              >
                {selectingKind === kind ? `Selecting ${kind}…` : `Select ${kind}`}
              </button>
            ))}
          </div>
          {notice ? (
            <p className={`form-result form-result--${notice.tone}`} role="status">
              {notice.text}
            </p>
          ) : null}
        </div>

        <div className="record-stack" aria-label="Authoritative selected resources">
          {supportedResources.length === 0 ? (
            <p className="empty-inline">No native-selected application, window, Edge tab, document, workspace, or screen region exists.</p>
          ) : supportedResources.map((resource) => {
            const confirming = confirmingId === resource.id;
            const removing = removingId === resource.id;
            return (
              <article className="record-card" key={resource.id}>
                <div className="record-card__heading">
                  <strong>{resource.displayName}</strong>
                  <span className="status-chip">{displayMessageType(resource.kind)}</span>
                </div>
                <small>
                  {resource.revision === undefined ? "Revision not reported" : `Revision ${resource.revision}`}
                  {" · "}
                  {resource.createdAt ? `Selected ${formatMoment(resource.createdAt)}` : "Selection time not reported"}
                </small>
                {confirming ? (
                  <div className="resource-removal-confirmation" role="group" aria-label={`Confirm removal of ${resource.displayName}`}>
                    <p>Remove this exact binding? Grants or sessions that still reference it may need attention.</p>
                    <div className="button-row">
                      <button className="button button--danger button--small" disabled={disabled || busy} type="button" onClick={() => void removeResource(resource)}>
                        {removing ? "Removing…" : "Confirm removal"}
                      </button>
                      <button className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => setConfirmingId(null)}>Cancel</button>
                    </div>
                  </div>
                ) : (
                  <button
                    className="button button--danger button--small"
                    disabled={disabled || busy || resource.revision === undefined}
                    title={resource.revision === undefined ? "Refresh until CORE reports the current revision." : undefined}
                    type="button"
                    onClick={() => setConfirmingId(resource.id)}
                  >
                    Remove resource
                  </button>
                )}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
