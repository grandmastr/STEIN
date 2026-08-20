import { useMemo, useRef, useState, type FormEvent } from "react";
import { newUuidV7 } from "../lib/uuid";
import type {
  CaptureView,
  EndFocusSessionInput,
  FocusSessionView,
  GoalView,
  ModelRouteView,
  PublicErrorView,
  ResourceView,
  SessionGrantView,
  SetMutedInput,
  StartFocusSessionInput,
} from "../protocol";

interface Props {
  disabled: boolean;
  goals: GoalView[];
  routes: ModelRouteView[];
  grants: SessionGrantView[];
  resources: ResourceView[];
  sessions: FocusSessionView[];
  captures: CaptureView[];
  onStart: (input: StartFocusSessionInput) => Promise<FocusSessionView>;
  onSetMuted: (input: SetMutedInput) => Promise<FocusSessionView>;
  onEnd: (input: EndFocusSessionInput) => Promise<FocusSessionView>;
}

const RUNNING_STATES = new Set(["requested", "starting", "active", "recovering", "stopping"]);

export function FocusPanel({ disabled, goals, routes, grants, resources, sessions, captures, onStart, onSetMuted, onEnd }: Props) {
  const [goalId, setGoalId] = useState("");
  const [routeId, setRouteId] = useState("");
  const [grantIds, setGrantIds] = useState<string[]>([]);
  const [resourceIds, setResourceIds] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const commandIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const selectedGoal = goals.find((goal) => goal.id === goalId);
  const eligibleGrants = useMemo(
    () => grants.filter((grant) => grant.state === "active" && (!goalId || grant.goalId === goalId)),
    [goalId, grants],
  );

  function toggle(value: string, values: string[], update: (next: string[]) => void) {
    update(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    if (!selectedGoal || !routeId || grantIds.length === 0) {
      setMessage("Choose an active goal, an active exact model route, and the complete grant set.");
      return;
    }
    const command = {
      goalId: selectedGoal.id,
      goalRevision: selectedGoal.revision,
      selectedResourceIds: resourceIds,
      permissionGrantIds: grantIds,
      modelRouteApprovalId: routeId,
    };
    const fingerprint = JSON.stringify(command);
    if (commandIdentity.current?.fingerprint !== fingerprint) {
      commandIdentity.current = { fingerprint, key: newUuidV7() };
    }
    setSubmitting(true);
    try {
      const session = await onStart({ ...command, idempotencyKey: commandIdentity.current.key });
      commandIdentity.current = null;
      setMessage(`Focus session accepted in ${session.state} state. Capture begins only after exact native-status acknowledgement.`);
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not start this focus session.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel span-2" aria-labelledby="focus-title">
      <div className="panel__header">
        <div><p className="eyebrow">Daemon-owned continuity</p><h2 id="focus-title">Focus sessions</h2></div>
        <span className="panel__count">{sessions.filter((session) => RUNNING_STATES.has(session.state)).length} running</span>
      </div>

      <div className="consent-layout">
        <form className="compact-form" onSubmit={submit} noValidate>
          <label>
            <span>Active goal</span>
            <select aria-label="Focus goal" disabled={disabled || submitting} value={goalId} onChange={(event) => { setGoalId(event.target.value); setGrantIds([]); }}>
              <option value="">Choose goal</option>
              {goals.filter((goal) => goal.state === "active").map((goal) => <option key={goal.id} value={goal.id}>{goal.title} · revision {goal.revision}</option>)}
            </select>
          </label>
          <label>
            <span>Approved exact model route</span>
            <select aria-label="Focus model route" disabled={disabled || submitting} value={routeId} onChange={(event) => setRouteId(event.target.value)}>
              <option value="">Choose route</option>
              {routes.filter((route) => route.state === "active").map((route) => <option key={route.id} value={route.id}>{route.providerId}/{route.routeId}</option>)}
            </select>
          </label>
          <fieldset className="selection-list">
            <legend>Exact permission grant set</legend>
            {eligibleGrants.length === 0 ? <p>No active grants match this goal.</p> : eligibleGrants.map((grant) => (
              <label key={grant.id}><input checked={grantIds.includes(grant.id)} disabled={disabled || submitting} type="checkbox" onChange={() => toggle(grant.id, grantIds, setGrantIds)} /> <span>{grant.scope}<small>{grant.selectedResourceId ?? "No resource"}</small></span></label>
            ))}
          </fieldset>
          <fieldset className="selection-list">
            <legend>Exact selected-resource set</legend>
            {resources.length === 0 ? <p>No native-selected binding is available. Protocol 1.2 registration is exposed through the bridge; the desktop picker control remains to be designed.</p> : resources.map((resource) => (
              <label key={resource.id}><input checked={resourceIds.includes(resource.id)} disabled={disabled || submitting} type="checkbox" onChange={() => toggle(resource.id, resourceIds, setResourceIds)} /> <span>{resource.displayName}<small>{resource.kind}</small></span></label>
            ))}
          </fieldset>
          <div className="disclosure">
            <strong>What continues without this window</strong>
            <p>CORE owns the session. The selected grants decide whether observation continues after desktop disconnect and whether it recovers after daemon restart. Native status and emergency stop remain the independent control path. Mute stops proactive delivery, not observation.</p>
          </div>
          {message ? <p className="form-result" role="status">{message}</p> : null}
          <button className="button button--primary button--wide" disabled={disabled || submitting}>{submitting ? "Requesting…" : "Start exact focus session"}</button>
        </form>

        <div className="record-stack" aria-label="Focus session status">
          {sessions.length === 0 ? <p className="empty-inline">No focus session exists.</p> : sessions.map((session) => {
            const capture = captures.find((item) => item.focusSessionId === session.id);
            return (
              <article className="record-card session-card" key={session.id}>
                <div className="record-card__heading"><strong>{goals.find((goal) => goal.id === session.goalId)?.title ?? "Focus session"}</strong><span className={`status-chip status-chip--${session.state}`}>{session.state}</span></div>
                <div className="session-flags">
                  <span className={session.interventionsMuted ? "flag flag--warn" : "flag flag--ok"}>Delivery {session.interventionsMuted ? "muted" : "enabled"}</span>
                  <span className={session.sourceDegraded ? "flag flag--bad" : "flag flag--ok"}>Sources {session.sourceDegraded ? "degraded" : "nominal"}</span>
                  <span className={capture?.nativeStatusVisible ? "flag flag--ok" : "flag flag--bad"}>Native status {capture?.nativeStatusVisible ? "visible" : "not acknowledged"}</span>
                  <span className={capture?.emergencyStopAvailable ? "flag flag--ok" : "flag flag--bad"}>Emergency stop {capture?.emergencyStopAvailable ? "available" : "unavailable"}</span>
                </div>
                {capture ? (
                  <div className="source-health">
                    <strong>Capture: {capture.state}</strong>
                    <div className="token-row">{capture.activeCategories.map((category) => <code key={category}>{category}</code>)}</div>
                    {capture.sources.map((source) => <span key={source.id}><i className={`health-dot health-dot--${source.health}`} /> {source.category}: {source.health}{source.lastCompleteAt ? ` · ${new Date(source.lastCompleteAt).toLocaleTimeString()}` : ""}</span>)}
                  </div>
                ) : <p>Capture view not available.</p>}
                <small>Revision {session.revision} · desktop close {session.whileClientDisconnected ? "allowed" : "not allowed"} · restart {session.afterDaemonRestart ? "allowed" : "not allowed"}</small>
                {RUNNING_STATES.has(session.state) ? (
                  <div className="button-row">
                    <button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => void onSetMuted({ focusSessionId: session.id, expectedRevision: session.revision, muted: !session.interventionsMuted })}>{session.interventionsMuted ? "Unmute delivery" : "Mute delivery"}</button>
                    <button className="button button--danger button--small" disabled={disabled} type="button" onClick={() => void onEnd({ focusSessionId: session.id, expectedRevision: session.revision })}>Stop observation</button>
                  </div>
                ) : null}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
