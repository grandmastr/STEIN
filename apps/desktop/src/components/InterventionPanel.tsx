import { useEffect, useRef, useState } from "react";
import type {
  InterventionExplanationView,
  InterventionFeedbackInput,
  InterventionHistoryInput,
  InterventionHistoryView,
  InterventionView,
  PublicErrorView,
  ResourceView,
} from "../protocol";

interface Props {
  disabled: boolean;
  interventions: InterventionView[];
  resources: ResourceView[];
  activatedExplanation?: InterventionExplanationView | null;
  onExplain: (input: { interventionId: string }) => Promise<InterventionExplanationView>;
  onFeedback: (input: InterventionFeedbackInput) => Promise<InterventionView>;
  onHistory: (input: InterventionHistoryInput) => Promise<InterventionHistoryView>;
}

export function InterventionPanel({ disabled, interventions, resources, activatedExplanation, onExplain, onFeedback, onHistory }: Props) {
  const [explanation, setExplanation] = useState<InterventionExplanationView | null>(null);
  const [selectedInterventionId, setSelectedInterventionId] = useState<string | null>(null);
  const [queriedHistory, setQueriedHistory] = useState<InterventionHistoryView | null>(null);
  const [correctionFor, setCorrectionFor] = useState<string | null>(null);
  const [correction, setCorrection] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [historyPending, setHistoryPending] = useState(false);
  const panelRef = useRef<HTMLElement>(null);
  const explanationRef = useRef<HTMLElement>(null);
  const visibleInterventions = queriedHistory?.entries ?? interventions;

  useEffect(() => {
    if (!activatedExplanation) return;
    setExplanation(activatedExplanation);
    setSelectedInterventionId(activatedExplanation.interventionId);
    setQueriedHistory(null);
    setCorrectionFor(null);
    setMessage(null);
    const focusTimer = window.setTimeout(() => {
      panelRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      explanationRef.current?.focus({ preventScroll: true });
    }, 0);
    return () => window.clearTimeout(focusTimer);
  }, [activatedExplanation]);

  async function loadHistory(before?: string) {
    setMessage(null);
    setHistoryPending(true);
    try {
      const history = await onHistory({ limit: 100, ...(before ? { before } : {}) });
      setQueriedHistory((current) => {
        if (!before || !current) return history;
        const known = new Set(current.entries.map((entry) => entry.id));
        return {
          asOf: history.asOf,
          entries: [...current.entries, ...history.entries.filter((entry) => !known.has(entry.id))],
        };
      });
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not query intervention history.");
    } finally {
      setHistoryPending(false);
    }
  }

  async function explain(interventionId: string) {
    setMessage(null);
    try {
      setExplanation(await onExplain({ interventionId }));
      setSelectedInterventionId(interventionId);
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not explain this intervention.");
    }
  }

  async function feedback(intervention: InterventionView, outcome: "accepted" | "dismissed") {
    setMessage(null);
    try {
      await onFeedback({
        interventionId: intervention.id,
        expectedRevision: intervention.revision,
        feedback: outcome,
      });
      setMessage(`Feedback recorded: ${outcome}. This does not learn a durable preference.`);
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not record feedback.");
    }
  }

  async function submitCorrection(intervention: InterventionView) {
    if (!correction.trim()) {
      setMessage("Enter the corrected session context.");
      return;
    }
    try {
      await onFeedback({
        interventionId: intervention.id,
        expectedRevision: intervention.revision,
        feedback: "corrected",
        correction: correction.trim(),
        ...(resourceId ? { associateResourceId: resourceId } : {}),
      });
      setCorrection("");
      setResourceId("");
      setCorrectionFor(null);
      setMessage("Correction recorded for current context. Historical policy facts were not rewritten and no preference was learned.");
    } catch (caught) {
      setMessage((caught as PublicErrorView).summary ?? "CORE could not record the correction.");
    }
  }

  return (
    <section className="panel span-2" aria-labelledby="interventions-title" ref={panelRef}>
      <div className="panel__header">
        <div><p className="eyebrow">Inspectable intervention decisions</p><h2 id="interventions-title">Intervention history</h2></div>
        <div className="button-row">
          <span className="panel__count">{visibleInterventions.length}</span>
          <button className="button button--ghost button--small" disabled={disabled || historyPending} type="button" onClick={() => void loadHistory()}>{historyPending ? "Loading…" : "Query latest"}</button>
        </div>
      </div>
      {queriedHistory ? <p className="panel-note">Authoritative history as of {new Date(queriedHistory.asOf).toLocaleString()}.</p> : null}
      {message ? <p className="form-result" role="status">{message}</p> : null}
      <div className="history-layout">
        <div className="record-stack">
          {visibleInterventions.length === 0 ? <p className="empty-inline">No intervention or missed-delivery history exists.</p> : visibleInterventions.map((intervention) => (
            <article className={selectedInterventionId === intervention.id ? "record-card record-card--selected" : "record-card"} aria-current={selectedInterventionId === intervention.id ? "true" : undefined} key={intervention.id}>
              <div className="record-card__heading"><strong>{intervention.userVisibleText ?? "Private text expired or unavailable"}</strong><span className={`status-chip status-chip--${intervention.state}`}>{intervention.state}</span></div>
              <p>{intervention.reasonCodes.join(" · ") || "No public reason code"}</p>
              <small>
                {intervention.urgency} urgency · outcome {intervention.outcome} · revision {intervention.revision}<br />
                {intervention.state === "accepted_by_channel" ? "Windows accepted submission; this does not prove displayed or seen." : `Updated ${new Date(intervention.updatedAt).toLocaleString()}`}
              </small>
              <div className="button-row">
                <button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => void explain(intervention.id)}>Why?</button>
                <button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => void feedback(intervention, "accepted")}>Useful</button>
                <button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => void feedback(intervention, "dismissed")}>Dismiss</button>
                <button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => setCorrectionFor(intervention.id)}>Correct context</button>
              </div>
              {correctionFor === intervention.id ? (
                <div className="correction-form">
                  <label><span>Correction</span><textarea aria-label="Context correction" disabled={disabled} maxLength={512} rows={3} value={correction} onChange={(event) => setCorrection(event.target.value)} /></label>
                  <label><span>Associate selected resource <i>optional</i></span><select aria-label="Correction resource" disabled={disabled} value={resourceId} onChange={(event) => setResourceId(event.target.value)}><option value="">No resource association</option>{resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.displayName}</option>)}</select></label>
                  <div className="button-row"><button className="button button--primary button--small" disabled={disabled} type="button" onClick={() => void submitCorrection(intervention)}>Record correction</button><button className="button button--ghost button--small" disabled={disabled} type="button" onClick={() => setCorrectionFor(null)}>Cancel</button></div>
                </div>
              ) : null}
            </article>
          ))}
        </div>

        <aside className="explanation" aria-label="Selected intervention explanation" aria-live="polite" ref={explanationRef} tabIndex={-1}>
          {explanation ? (
            <>
              <div className="record-card__heading"><strong>Why this occurred</strong><span className={`status-chip status-chip--${explanation.decision}`}>{explanation.decision}</span></div>
              <p>Policy {explanation.policyVersion} evaluated candidate revision {explanation.candidateRevision}.</p>
              {explanation.policyTrace ? (
                <div className="evidence-row" aria-label="Policy decision trace">
                  <strong>Policy trace</strong>
                  <span>
                    Profile {explanation.policyTrace.policyProfileId} · preferences revision {explanation.policyTrace.userPreferencesRevision} · input schema {explanation.policyTrace.inputSchemaVersion}
                  </span>
                  <small><code>{explanation.policyTrace.inputDigestSha256}</code></small>
                </div>
              ) : <p className="blocker-note">This legacy decision has no content-free policy trace.</p>}
              <div className="token-row">{explanation.decisionReasonCodes.map((reason) => <code key={reason}>{reason}</code>)}</div>
              <h3>Content-free evidence</h3>
              {explanation.evidence.length === 0 ? <p>No evidence summary is available.</p> : explanation.evidence.map((evidence, index) => (
                <div className="evidence-row" key={`${evidence.category}-${index}`}>
                  <strong>{evidence.category}</strong>
                  <span>{evidence.role} · {evidence.freshness} · {evidence.confidence} confidence</span>
                  <small>{new Date(evidence.observedFrom).toLocaleString()} – {new Date(evidence.observedUntil).toLocaleString()}</small>
                </div>
              ))}
              <p>Delivery: {explanation.deliveryState}. Outcome: {explanation.outcome}.</p>
              {explanation.correctionRecorded ? <p className="blocker-note">A later correction is recorded and takes precedence for current context.</p> : null}
            </>
          ) : (
            <><strong>Select “Why?”</strong><p>CORE will return the persisted policy decision, reason codes, evidence classes, freshness, and correction status—never raw observations or hidden model reasoning.</p></>
          )}
        </aside>
      </div>
      {queriedHistory && visibleInterventions.length > 0 ? (
        <button className="button button--ghost button--wide" disabled={disabled || historyPending} type="button" onClick={() => void loadHistory(visibleInterventions.at(-1)?.createdAt)}>Load older history</button>
      ) : null}
    </section>
  );
}
