import { useMemo, useRef, useState, type FormEvent } from "react";
import type { CreateGoalInput, GoalView, PublicErrorView } from "../protocol";
import { newUuidV7 } from "../lib/uuid";
import { PlusIcon } from "./Icons";

interface CreateGoalFormProps {
  disabled: boolean;
  onCreate: (input: CreateGoalInput) => Promise<GoalView>;
}

interface DraftGoal {
  title: string;
  successStatement: string;
  deadline: string;
}

const emptyDraft: DraftGoal = {
  title: "",
  successStatement: "",
  deadline: "",
};

function validate(draft: DraftGoal): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!draft.title.trim()) errors.title = "Give this goal a short name.";
  if (draft.title.trim().length > 120) errors.title = "Keep the title under 120 characters.";
  if (!draft.successStatement.trim()) {
    errors.successStatement = "Describe what done looks like.";
  }
  if (draft.successStatement.trim().length > 500) {
    errors.successStatement = "Keep the success statement under 500 characters.";
  }
  if (draft.deadline && new Date(draft.deadline).getTime() <= Date.now()) {
    errors.deadline = "Choose a future deadline.";
  }
  return errors;
}

export function CreateGoalForm({ disabled, onCreate }: CreateGoalFormProps) {
  const [draft, setDraft] = useState(emptyDraft);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ tone: "success" | "error"; message: string } | null>(null);
  const pendingIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const remaining = useMemo(() => 500 - draft.successStatement.length, [draft.successStatement]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const errors = validate(draft);
    setFieldErrors(errors);
    setResult(null);
    if (Object.keys(errors).length > 0) return;

    const command = {
      title: draft.title.trim(),
      successStatement: draft.successStatement.trim(),
      ...(draft.deadline ? { deadline: new Date(draft.deadline).toISOString() } : {}),
    };
    const fingerprint = JSON.stringify(command);
    if (pendingIdentity.current?.fingerprint !== fingerprint) {
      pendingIdentity.current = { fingerprint, key: newUuidV7() };
    }
    const input: CreateGoalInput = {
      ...command,
      idempotencyKey: pendingIdentity.current.key,
    };

    setSubmitting(true);
    try {
      const goal = await onCreate(input);
      pendingIdentity.current = null;
      setDraft(emptyDraft);
      setResult({ tone: "success", message: `“${goal.title}” is now visible to CORE.` });
    } catch (error) {
      const publicError = error as PublicErrorView;
      setFieldErrors(publicError.fieldErrors ?? {});
      setResult({
        tone: "error",
        message: publicError.summary ?? "CORE could not create this goal.",
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel create-panel" aria-labelledby="create-goal-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Direct user command</p>
          <h2 id="create-goal-title">Create a goal</h2>
        </div>
        <span className="panel__glyph"><PlusIcon /></span>
      </div>

      <form className="goal-form" onSubmit={submit} noValidate>
        <label>
          <span>Title</span>
          <input
            aria-label="Title"
            autoComplete="off"
            disabled={disabled || submitting}
            maxLength={120}
            placeholder="Finish the product brief"
            value={draft.title}
            onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))}
            aria-invalid={Boolean(fieldErrors.title)}
            aria-describedby={fieldErrors.title ? "title-error" : undefined}
          />
          {fieldErrors.title ? <small id="title-error" className="field-error">{fieldErrors.title}</small> : null}
        </label>

        <label>
          <span>Success looks like</span>
          <textarea
            aria-label="Success looks like"
            disabled={disabled || submitting}
            maxLength={500}
            placeholder="A reviewed six-page brief ready to share with the team."
            rows={4}
            value={draft.successStatement}
            onChange={(event) =>
              setDraft((current) => ({ ...current, successStatement: event.target.value }))
            }
            aria-invalid={Boolean(fieldErrors.successStatement)}
            aria-describedby={fieldErrors.successStatement ? "success-error" : "success-count"}
          />
          <span className="field-meta" id="success-count">
            <span>{fieldErrors.successStatement ? <em id="success-error">{fieldErrors.successStatement}</em> : "Be concrete and observable."}</span>
            <span>{remaining}</span>
          </span>
        </label>

        <label>
          <span>Deadline <i>optional</i></span>
          <input
            aria-label="Deadline"
            disabled={disabled || submitting}
            type="datetime-local"
            value={draft.deadline}
            onChange={(event) => setDraft((current) => ({ ...current, deadline: event.target.value }))}
            aria-invalid={Boolean(fieldErrors.deadline)}
            aria-describedby={fieldErrors.deadline ? "deadline-error" : undefined}
          />
          {fieldErrors.deadline ? <small id="deadline-error" className="field-error">{fieldErrors.deadline}</small> : null}
        </label>

        {result ? (
          <p className={`form-result form-result--${result.tone}`} role="status">{result.message}</p>
        ) : null}

        <button className="button button--primary button--wide" disabled={disabled || submitting} type="submit">
          <PlusIcon />
          {submitting ? "Creating…" : disabled ? "Private admission required" : "Create goal"}
        </button>
      </form>
    </section>
  );
}
