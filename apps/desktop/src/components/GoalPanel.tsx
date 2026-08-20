import { useRef, useState, type FormEvent } from "react";
import { compactId, formatMoment } from "../lib/format";
import {
  publicErrorFromUnknown,
  type AbandonGoalInput,
  type GoalDeletionView,
  type GoalRevisionInput,
  type GoalView,
  type UpdateGoalInput,
} from "../protocol";
import { StatusPill } from "./StatusPill";

interface Props {
  goals: GoalView[];
  disabled: boolean;
  onUpdate: (input: UpdateGoalInput) => Promise<GoalView>;
  onDelete: (input: GoalRevisionInput) => Promise<GoalDeletionView>;
  onComplete: (input: GoalRevisionInput) => Promise<GoalView>;
  onAbandon: (input: AbandonGoalInput) => Promise<GoalView>;
  onRefresh: () => Promise<unknown>;
}

interface GoalDraft {
  title: string;
  successStatement: string;
  deadline: string;
}

type Notice = { tone: "success" | "neutral" | "error"; text: string };

function localDateTime(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function isConflict(error: ReturnType<typeof publicErrorFromUnknown>): boolean {
  return error.category === "conflict" || error.code.toLowerCase().includes("conflict");
}

export function GoalPanel({
  goals,
  disabled,
  onUpdate,
  onDelete,
  onComplete,
  onAbandon,
  onRefresh,
}: Props) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);
  const [draft, setDraft] = useState<GoalDraft | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState<Notice | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const inFlight = useRef(false);

  function startEditing(goal: GoalView): void {
    setEditingId(goal.id);
    setConfirmingDeleteId(null);
    setDraft({
      title: goal.title,
      successStatement: goal.successStatement,
      deadline: localDateTime(goal.deadline),
    });
    setFieldErrors({});
    setNotice(null);
  }

  async function refreshAfterSuccess(message: string): Promise<void> {
    try {
      await onRefresh();
      setNotice({ tone: "success", text: message });
    } catch (caught) {
      setNotice({ tone: "error", text: `${message} CORE accepted the change, but the authoritative goal list could not refresh: ${publicErrorFromUnknown(caught).summary}` });
    }
  }

  async function handleConflict(summary: string): Promise<void> {
    try {
      await onRefresh();
      setEditingId(null);
      setConfirmingDeleteId(null);
      setDraft(null);
      setNotice({ tone: "neutral", text: `${summary} The authoritative goal list was refreshed; review the current revision before trying again.` });
    } catch (caught) {
      setNotice({ tone: "error", text: `${summary} The authoritative refresh also failed: ${publicErrorFromUnknown(caught).summary}` });
    }
  }

  async function submitUpdate(event: FormEvent<HTMLFormElement>, goal: GoalView): Promise<void> {
    event.preventDefault();
    if (disabled || inFlight.current || !draft) return;

    const errors: Record<string, string> = {};
    const title = draft.title.trim();
    const successStatement = draft.successStatement.trim();
    if (!title) errors.title = "A goal title is required.";
    if ([...title].length > 200) errors.title = "Use 200 characters or fewer.";
    if (!successStatement) errors.successStatement = "A success statement is required.";
    if ([...successStatement].length > 2_000) errors.successStatement = "Use 2,000 characters or fewer.";

    const patch: UpdateGoalInput["patch"] = {};
    if (title !== goal.title) patch.title = title;
    if (successStatement !== goal.successStatement) patch.successStatement = successStatement;
    const originalDeadline = localDateTime(goal.deadline);
    if (draft.deadline !== originalDeadline) {
      if (!draft.deadline) patch.deadline = { operation: "clear" };
      else {
        const deadline = new Date(draft.deadline);
        if (Number.isNaN(deadline.getTime())) errors.deadline = "Choose a valid deadline or clear it.";
        else patch.deadline = { operation: "set", deadline: deadline.toISOString() };
      }
    }
    if (Object.keys(patch).length === 0 && Object.keys(errors).length === 0) {
      errors.form = "Change at least one field before saving.";
    }
    setFieldErrors(errors);
    setNotice(null);
    if (Object.keys(errors).length > 0) return;

    inFlight.current = true;
    setPendingId(goal.id);
    try {
      const updated = await onUpdate({ goalId: goal.id, expectedRevision: goal.revision, patch });
      setEditingId(null);
      setDraft(null);
      await refreshAfterSuccess(`“${updated.title}” was updated at revision ${updated.revision}.`);
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (isConflict(error)) await handleConflict(error.summary);
      else {
        setFieldErrors(error.fieldErrors ?? {});
        setNotice({ tone: "error", text: error.summary });
      }
    } finally {
      inFlight.current = false;
      setPendingId(null);
    }
  }

  async function deleteGoal(goal: GoalView): Promise<void> {
    if (disabled || inFlight.current) return;
    inFlight.current = true;
    setPendingId(goal.id);
    setNotice(null);
    try {
      const deletion = await onDelete({ goalId: goal.id, expectedRevision: goal.revision });
      setConfirmingDeleteId(null);
      const cascaded = deletion.focusSessionsDeleted + deletion.grantsDeleted + deletion.interventionsDeleted + deletion.pendingDeliveriesDeleted + deletion.privateAuditRecordsDeleted + deletion.resourceBindingsDeleted;
      await refreshAfterSuccess(`“${goal.title}” was deleted at revision ${deletion.deletedRevision}; ${cascaded} owned dependent record${cascaded === 1 ? "" : "s"} were removed.`);
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (isConflict(error)) await handleConflict(error.summary);
      else setNotice({ tone: "error", text: error.summary });
    } finally {
      inFlight.current = false;
      setPendingId(null);
    }
  }

  async function changeState(goal: GoalView, next: "completed" | "abandoned"): Promise<void> {
    if (disabled || inFlight.current) return;
    inFlight.current = true;
    setPendingId(goal.id);
    setNotice(null);
    try {
      const updated = next === "completed"
        ? await onComplete({ goalId: goal.id, expectedRevision: goal.revision })
        : await onAbandon({ goalId: goal.id, expectedRevision: goal.revision, reason: "user_requested" });
      await refreshAfterSuccess(`“${updated.title}” is ${updated.state} at revision ${updated.revision}.`);
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (isConflict(error)) await handleConflict(error.summary);
      else setNotice({ tone: "error", text: error.summary });
    } finally {
      inFlight.current = false;
      setPendingId(null);
    }
  }

  const busy = pendingId !== null;
  return (
    <section className="panel" aria-labelledby="goals-title">
      <div className="panel__header"><div><p className="eyebrow">Durable direct-user state</p><h2 id="goals-title">Goals</h2></div><span className="panel__count">{goals.length}</span></div>
      {notice ? <p className={`form-result goal-panel__notice form-result--${notice.tone}`} role="status">{notice.text}</p> : null}
      {goals.length === 0 ? <p className="empty-inline">No private goal view is available.</p> : (
        <ul className="goal-list">
          {goals.map((goal) => {
            const editing = editingId === goal.id && draft;
            const confirmingDelete = confirmingDeleteId === goal.id;
            const pending = pendingId === goal.id;
            return (
              <li key={goal.id}>
                <span className="goal-list__line" />
                <div className="goal-list__body">
                  <div className="goal-list__heading"><strong>{goal.title}</strong><StatusPill status={goal.state} /></div>
                  <p>{goal.successStatement}</p>
                  <span className="goal-list__meta"><span>{goal.deadline ? `Due ${formatMoment(goal.deadline)}` : "No deadline"}</span><span>Revision {goal.revision}</span><code title={goal.id}>{compactId(goal.id, 5)}</code></span>

                  {editing ? (
                    <form className="goal-edit-form" onSubmit={(event) => void submitUpdate(event, goal)} noValidate>
                      <label><span>Title</span><input aria-label={`Edit ${goal.title} title`} disabled={disabled || busy} maxLength={200} value={draft.title} onChange={(event) => setDraft((current) => current ? { ...current, title: event.target.value } : current)} />{fieldErrors.title ? <small className="field-error">{fieldErrors.title}</small> : null}</label>
                      <label><span>Success statement</span><textarea aria-label={`Edit ${goal.title} success statement`} disabled={disabled || busy} maxLength={2_000} rows={4} value={draft.successStatement} onChange={(event) => setDraft((current) => current ? { ...current, successStatement: event.target.value } : current)} />{fieldErrors.successStatement ? <small className="field-error">{fieldErrors.successStatement}</small> : null}</label>
                      <label><span>Deadline <i>optional</i></span><input aria-label={`Edit ${goal.title} deadline`} disabled={disabled || busy} type="datetime-local" value={draft.deadline} onChange={(event) => setDraft((current) => current ? { ...current, deadline: event.target.value } : current)} />{fieldErrors.deadline ? <small className="field-error">{fieldErrors.deadline}</small> : null}</label>
                      {fieldErrors.form ? <small className="field-error">{fieldErrors.form}</small> : null}
                      <div className="button-row"><button className="button button--primary button--small" disabled={disabled || busy} type="submit">{pending ? "Saving…" : "Save goal"}</button><button className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => { setEditingId(null); setDraft(null); setFieldErrors({}); }}>Cancel</button></div>
                    </form>
                  ) : confirmingDelete ? (
                    <div className="goal-delete-confirmation" role="group" aria-label={`Confirm deletion of ${goal.title}`}>
                      <strong>Delete this goal and its owned private state?</strong>
                      <p>CORE will cascade its focus sessions, grants, interventions, pending deliveries, private audit records, and resource bindings. This cannot be undone.</p>
                      <div className="button-row"><button className="button button--danger button--small" disabled={disabled || busy} type="button" onClick={() => void deleteGoal(goal)}>{pending ? "Deleting…" : "Confirm delete"}</button><button className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => setConfirmingDeleteId(null)}>Cancel</button></div>
                    </div>
                  ) : (
                    <div className="button-row goal-actions">
                      <button aria-label={`Edit ${goal.title}`} className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => startEditing(goal)}>Edit</button>
                      {goal.state === "active" ? <><button aria-label={`Complete ${goal.title}`} className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => void changeState(goal, "completed")}>Complete</button><button aria-label={`Abandon ${goal.title}`} className="button button--ghost button--small" disabled={disabled || busy} type="button" onClick={() => void changeState(goal, "abandoned")}>Abandon</button></> : null}
                      <button aria-label={`Delete ${goal.title}`} className="button button--danger button--small" disabled={disabled || busy} type="button" onClick={() => { setConfirmingDeleteId(goal.id); setEditingId(null); setDraft(null); setNotice(null); }}>Delete</button>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
