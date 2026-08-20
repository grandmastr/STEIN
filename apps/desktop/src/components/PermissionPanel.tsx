import { useRef, useState, type FormEvent } from "react";
import { newUuidV7 } from "../lib/uuid";
import type {
  GoalView,
  GrantPermissionInput,
  PermissionScope,
  PublicErrorView,
  ResourceView,
  RevokePermissionInput,
  SessionGrantView,
} from "../protocol";

const SCOPES: Array<{ id: PermissionScope; label: string; offDevice: boolean }> = [
  { id: "observe.desktop.presence", label: "Presence / lock state (no input content)", offDevice: false },
  { id: "observe.desktop.foreground_application", label: "Foreground application identity", offDevice: false },
  { id: "observe.desktop.window_metadata", label: "Selected window metadata and title", offDevice: false },
  { id: "observe.browser.location", label: "Selected browser location", offDevice: false },
  { id: "observe.content.visible_text", label: "Redacted visible structured text", offDevice: false },
  { id: "observe.content.selected_document", label: "Exact selected-document content", offDevice: false },
  { id: "observe.screen.pixels", label: "Bounded transient screen pixels", offDevice: false },
  { id: "observe.workspace.activity", label: "Coarse selected-workspace activity", offDevice: false },
  { id: "reason.focus_context", label: "Send approved focus context to the selected model route", offDevice: true },
  { id: "intervene.desktop.notification", label: "Native desktop notifications", offDevice: false },
];

interface Props {
  disabled: boolean;
  currentDeviceId?: string;
  goals: GoalView[];
  resources: ResourceView[];
  grants: SessionGrantView[];
  onGrant: (input: GrantPermissionInput) => Promise<SessionGrantView>;
  onRevoke: (input: RevokePermissionInput) => Promise<void>;
}

function localExpiry(): string {
  const value = new Date(Date.now() + 8 * 60 * 60 * 1000);
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function PermissionPanel({ disabled, currentDeviceId, goals, resources, grants, onGrant, onRevoke }: Props) {
  const [goalId, setGoalId] = useState("");
  const [scope, setScope] = useState<PermissionScope>("observe.desktop.presence");
  const [resourceId, setResourceId] = useState("");
  const [expiresAt, setExpiresAt] = useState(localExpiry);
  const [whileDisconnected, setWhileDisconnected] = useState(true);
  const [afterRestart, setAfterRestart] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const pendingIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const selectedScope = SCOPES.find((item) => item.id === scope)!;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    if (!goalId || !expiresAt) {
      setMessage("Choose a goal and an expiry.");
      return;
    }
    const command = {
      goalId,
      scope,
      ...(resourceId ? { selectedResourceId: resourceId } : {}),
      purpose: "deadline_aware_focus",
      expiresAt: new Date(expiresAt).toISOString(),
      whileClientDisconnected: whileDisconnected,
      afterDaemonRestart: afterRestart,
      consentCopyVersion: "phase2-focus-consent-v1",
    };
    const fingerprint = JSON.stringify(command);
    if (pendingIdentity.current?.fingerprint !== fingerprint) {
      pendingIdentity.current = { fingerprint, key: newUuidV7() };
    }
    setSubmitting(true);
    try {
      const grant = await onGrant({ ...command, idempotencyKey: pendingIdentity.current.key });
      pendingIdentity.current = null;
      setMessage(`Granted ${grant.scope} until ${new Date(grant.expiresAt).toLocaleString()}.`);
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not create this grant.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel span-2" aria-labelledby="permissions-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Independent, revocable authority</p>
          <h2 id="permissions-title">Observation and delivery grants</h2>
        </div>
        <span className="panel__count">{grants.filter((grant) => grant.state === "active").length} active</span>
      </div>

      <div className="consent-layout">
        <form className="compact-form" onSubmit={submit} noValidate>
          <div className="form-row">
            <label>
              <span>Goal</span>
              <select aria-label="Grant goal" disabled={disabled || submitting} value={goalId} onChange={(event) => setGoalId(event.target.value)}>
                <option value="">Choose an active goal</option>
                {goals.filter((goal) => goal.state === "active").map((goal) => <option key={goal.id} value={goal.id}>{goal.title}</option>)}
              </select>
            </label>
            <p className="blocker-note">Device binding: {currentDeviceId ?? "CORE will bind this grant to its authenticated current device."}</p>
          </div>
          <label>
            <span>One exact scope</span>
            <select aria-label="Permission scope" disabled={disabled || submitting} value={scope} onChange={(event) => setScope(event.target.value as PermissionScope)}>
              {SCOPES.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </select>
          </label>
          <label>
            <span>Selected resource <i>when applicable</i></span>
            <select aria-label="Selected resource" disabled={disabled || submitting || resources.length === 0} value={resourceId} onChange={(event) => setResourceId(event.target.value)}>
              <option value="">No resource binding</option>
              {resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.displayName} · {resource.kind}</option>)}
            </select>
          </label>
          {resources.length === 0 ? (
            <p className="blocker-note">
              Protocol 1.2 supports daemon-owned resource registration, but this desktop does not yet surface the native picker control or invent a path/URL write. Existing bindings appear here.
            </p>
          ) : null}
          <label>
            <span>Grant expires (maximum eight hours)</span>
            <input aria-label="Grant expiry" disabled={disabled || submitting} type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          </label>
          <div className="check-list">
            <label><input checked={whileDisconnected} disabled={disabled || submitting} type="checkbox" onChange={(event) => setWhileDisconnected(event.target.checked)} /> Continue if this desktop closes</label>
            <label><input checked={afterRestart} disabled={disabled || submitting} type="checkbox" onChange={(event) => setAfterRestart(event.target.checked)} /> Recover after supervised daemon restart</label>
          </div>
          <div className="disclosure">
            <strong>{selectedScope.label}</strong>
            <p>
              Purpose: deadline-aware focus. {selectedScope.offDevice ? "Approved context may leave this device only through the separately approved exact model route." : "This scope is processed locally unless a separate model-route category permits its minimized result."}
              {" "}Normalized evidence is memory-only for at most ten minutes and is removed earlier on stop or revocation. Raw artifacts are destroyed immediately. Closing this desktop does not revoke the grant.
            </p>
            <p>Mute affects delivery only. Revoke/stop removes authority immediately; cleanup failure cannot restore it.</p>
          </div>
          {message ? <p className="form-result" role="status">{message}</p> : null}
          <button className="button button--primary button--wide" disabled={disabled || submitting}>{submitting ? "Granting…" : "Grant this scope"}</button>
        </form>

        <div className="record-stack" aria-label="Session grants">
          {grants.length === 0 ? <p className="empty-inline">No session grant exists.</p> : grants.map((grant) => (
            <article className="record-card" key={grant.id}>
              <div className="record-card__heading"><strong>{grant.scope}</strong><span className={`status-chip status-chip--${grant.state}`}>{grant.state}</span></div>
              <p>{grant.selectedResourceId ? `Resource ${grant.selectedResourceId}` : "No selected resource"}</p>
              <small>
                Desktop close: {grant.whileClientDisconnected ? "continues" : "stops"} · daemon restart: {grant.afterDaemonRestart ? "recovers" : "stops"}<br />
                Expires {new Date(grant.expiresAt).toLocaleString()} · revision {grant.revision}
              </small>
              {grant.state === "active" ? (
                <button className="button button--danger button--small" disabled={disabled} type="button" onClick={() => void onRevoke({
                  permissionType: "session_grant",
                  permissionId: grant.id,
                  expectedRevision: grant.revision,
                  reason: "user_requested",
                })}>Revoke grant</button>
              ) : null}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
