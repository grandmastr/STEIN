import { useMemo, useRef, useState, type FormEvent } from "react";
import { newUuidV7 } from "../lib/uuid";
import type {
  CaptureView,
  EndFocusSessionInput,
  FocusSessionView,
  GoalView,
  LatestModelRequestReceiptInput,
  ModelRequestReceiptView,
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
  onGetLatestModelRequestReceipt: (
    input: LatestModelRequestReceiptInput,
  ) => Promise<ModelRequestReceiptView | null>;
}

const RUNNING_STATES = new Set(["requested", "starting", "active", "recovering", "stopping"]);

export function FocusPanel({
  disabled,
  goals,
  routes,
  grants,
  resources,
  sessions,
  captures,
  onStart,
  onSetMuted,
  onEnd,
  onGetLatestModelRequestReceipt,
}: Props) {
  const [goalId, setGoalId] = useState("");
  const [routeId, setRouteId] = useState("");
  const [grantIds, setGrantIds] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [receiptPendingFor, setReceiptPendingFor] = useState<string | null>(null);
  const [receiptBySession, setReceiptBySession] = useState<
    Record<string, ModelRequestReceiptView | null>
  >({});
  const [receiptErrorBySession, setReceiptErrorBySession] = useState<Record<string, string>>({});
  const commandIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const selectedGoal = goals.find((goal) => goal.id === goalId);
  const eligibleGrants = useMemo(
    () => grants.filter((grant) => grant.state === "active" && (!goalId || grant.goalId === goalId)),
    [goalId, grants],
  );
  const derivedResourceIds = useMemo(
    () => Array.from(new Set(
      grantIds
        .map((grantId) => grants.find((grant) => grant.id === grantId)?.selectedResourceId)
        .filter((resourceId): resourceId is string => resourceId !== undefined),
    )),
    [grantIds, grants],
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
      selectedResourceIds: derivedResourceIds,
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

  async function getLatestModelRequestReceipt(focusSessionId: string) {
    setReceiptPendingFor(focusSessionId);
    setReceiptErrorBySession((current) => {
      const next = { ...current };
      delete next[focusSessionId];
      return next;
    });
    try {
      const receipt = await onGetLatestModelRequestReceipt({ focusSessionId });
      setReceiptBySession((current) => ({ ...current, [focusSessionId]: receipt }));
    } catch (caught) {
      setReceiptErrorBySession((current) => ({
        ...current,
        [focusSessionId]:
          (caught as PublicErrorView).summary ?? "CORE could not read the latest model request receipt.",
      }));
    } finally {
      setReceiptPendingFor(null);
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
          <div className="selection-list" aria-label="Derived selected-resource set">
            <strong>Exact selected-resource set</strong>
            {derivedResourceIds.length === 0 ? (
              <p>The chosen grants do not reference a selected resource.</p>
            ) : derivedResourceIds.map((resourceId) => {
              const resource = resources.find((candidate) => candidate.id === resourceId);
              return (
                <p key={resourceId}>
                  {resource?.displayName ?? "Selected resource"}
                  <small>{resource ? resource.kind : resourceId}</small>
                </p>
              );
            })}
            <small>This read-only set is derived exactly from the chosen grants.</small>
          </div>
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
            const receiptWasRead = Object.prototype.hasOwnProperty.call(receiptBySession, session.id);
            const receipt = receiptBySession[session.id];
            const receiptError = receiptErrorBySession[session.id];
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
                <div className="button-row">
                  <button
                    className="button button--ghost button--small"
                    disabled={disabled || receiptPendingFor !== null}
                    type="button"
                    onClick={() => void getLatestModelRequestReceipt(session.id)}
                  >
                    {receiptPendingFor === session.id ? "Checking…" : "Check latest model request receipt"}
                  </button>
                </div>
                <small>This read-only check reports an existing daemon request. It never starts a model request.</small>
                {receipt ? (
                  <div className="source-health" aria-label={`Latest model request receipt for ${session.id}`}>
                    <strong>Latest model request receipt</strong>
                    <span>Outcome: <code>{receipt.outcome}</code></span>
                    <span>Request: <code>{receipt.requestId}</code></span>
                    <span>Focus session: <code>{receipt.focusSessionId}</code></span>
                    <span>Model route approval: <code>{receipt.modelRouteApprovalId}</code> · revision {receipt.modelRouteRevision}</span>
                    <span>Started: <time dateTime={receipt.startedAt}>{receipt.startedAt}</time></span>
                    <span>Completed: {receipt.completedAt ? <time dateTime={receipt.completedAt}>{receipt.completedAt}</time> : "not completed"}</span>
                  </div>
                ) : receiptWasRead ? (
                  <p className="empty-inline" role="status">No model request receipt exists for this focus session.</p>
                ) : null}
                {receiptError ? <p className="form-result" role="alert">{receiptError}</p> : null}
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
