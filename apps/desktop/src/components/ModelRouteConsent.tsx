import { useMemo, useRef, useState, type FormEvent } from "react";
import { newUuidV7 } from "../lib/uuid";
import type {
  ApproveModelRouteInput,
  ModelDataCategory,
  ModelRouteView,
  PublicErrorView,
  RevokePermissionInput,
} from "../protocol";

const CATEGORIES: Array<{ id: ModelDataCategory; label: string; detail: string }> = [
  { id: "goal", label: "Goal · required", detail: "Title, success statement, deadline, and revision." },
  { id: "focus_session", label: "Focus session", detail: "Session identity and elapsed state." },
  { id: "evidence_aggregates", label: "Evidence aggregates", detail: "Content-free freshness and progress summaries." },
  { id: "window_metadata", label: "Window metadata", detail: "Approved bounded titles and metadata." },
  { id: "browser_location", label: "Browser location", detail: "Only separately approved URL components." },
  { id: "visible_text", label: "Visible text", detail: "Locally redacted text from a selected surface." },
  { id: "selected_document", label: "Selected document", detail: "Bounded excerpts from an exact selected resource." },
  { id: "screen_pixels", label: "Screen pixels", detail: "A separate, bounded transient vision route." },
  { id: "workspace_activity", label: "Workspace activity", detail: "Opaque resource and coarse activity kind." },
  { id: "delivery_constraints", label: "Delivery constraints", detail: "Mute, cooldown, and channel suitability." },
];

interface Props {
  disabled: boolean;
  routes: ModelRouteView[];
  onSetup: (input: ApproveModelRouteInput) => Promise<ModelRouteView>;
  onRevoke: (input: RevokePermissionInput) => Promise<void>;
}

function localDate(days: number): string {
  const value = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  const offset = value.getTimezoneOffset() * 60_000;
  return new Date(value.getTime() - offset).toISOString().slice(0, 16);
}

export function ModelRouteConsent({ disabled, routes, onSetup, onRevoke }: Props) {
  const [routeId, setRouteId] = useState("");
  const [accountProfile, setAccountProfile] = useState("default");
  const [expiresAt, setExpiresAt] = useState(localDate(30));
  const [categories, setCategories] = useState<ModelDataCategory[]>([
    "goal",
    "focus_session",
    "evidence_aggregates",
    "delivery_constraints",
  ]);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const commandIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const activeRoutes = useMemo(() => routes.filter((route) => route.state === "active"), [routes]);

  function toggleCategory(category: ModelDataCategory) {
    if (category === "goal") return;
    setCategories((current) =>
      current.includes(category)
        ? current.filter((item) => item !== category)
        : [...current, category],
    );
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setResult(null);
    setError(null);
    const normalizedRoute = routeId.trim();
    if (!normalizedRoute || categories.length === 0) {
      setError("Enter an exact model identifier and choose at least one data category.");
      return;
    }

    const approval = {
      providerId: "openai",
      routeId: normalizedRoute,
      placement: "remote" as const,
      accountProfile: accountProfile.trim() || "default",
      allowedDataCategories: categories,
      retentionKind: "bounded" as const,
      retentionMaximumSeconds: 2_592_000,
      trainingUse: "excluded" as const,
      handlingProfileVersion: "openai-responses-default-2026-08",
      purpose: "reason.focus_context",
      maximumRequestTokens: 8_000,
      ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
      disclosureVersion: "phase2-openai-responses-v1",
    };
    const fingerprint = JSON.stringify(approval);
    if (commandIdentity.current?.fingerprint !== fingerprint) {
      commandIdentity.current = { fingerprint, key: newUuidV7() };
    }

    setSubmitting(true);
    try {
      // One invoke carries reviewed route metadata only. Rust validates it,
      // collects the credential through CredUI into zeroizing native memory,
      // approves the route, and only then writes Credential Manager under the
      // returned approval identity. No credential value exists in the DOM or
      // renderer DTO.
      const route = await onSetup({ ...approval, idempotencyKey: commandIdentity.current.key });
      commandIdentity.current = null;
      setResult(`Approved ${route.providerId}/${route.routeId}. The credential remains native-only.`);
    } catch (caught) {
      const failure = caught as PublicErrorView;
      // A post-approval store failure revokes that approval best-effort. Its
      // idempotency key must not replay the revoked result on the next attempt.
      if (failure.code === "model_route_setup_store_failed") commandIdentity.current = null;
      setError(failure.summary ?? "CORE could not configure this route.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel span-2" aria-labelledby="model-route-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Separate provider consent</p>
          <h2 id="model-route-title">Model route</h2>
        </div>
        <span className="panel__count">{activeRoutes.length} active</span>
      </div>

      <div className="consent-layout">
        <form className="compact-form" onSubmit={submit} noValidate>
          <label>
            <span>Exact OpenAI model identifier</span>
            <input
              aria-label="Exact OpenAI model identifier"
              autoComplete="off"
              disabled={disabled || submitting}
              value={routeId}
              onChange={(event) => setRouteId(event.target.value)}
              placeholder="Configured exact model ID"
            />
          </label>
          <label>
            <span>Account/project profile reference</span>
            <input
              aria-label="Account profile"
              autoComplete="off"
              disabled={disabled || submitting}
              value={accountProfile}
              onChange={(event) => setAccountProfile(event.target.value)}
            />
          </label>
          <div className="blocker-note">
            The provider credential is collected by a native Windows CredUI prompt after submit.
            No password field or credential value exists in this webview or its command DTO.
          </div>
          <label>
            <span>Approval expires</span>
            <input
              aria-label="Model approval expiry"
              disabled={disabled || submitting}
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </label>

          <fieldset className="choice-grid">
            <legend>Data allowed to leave this device</legend>
            {CATEGORIES.map((category) => (
              <label key={category.id} className="check-card">
                <input
                  checked={categories.includes(category.id)}
                  disabled={disabled || submitting || category.id === "goal"}
                  type="checkbox"
                  onChange={() => toggleCategory(category.id)}
                />
                <span><strong>{category.label}</strong><small>{category.detail}</small></span>
              </label>
            ))}
          </fieldset>

          <div className="disclosure">
            <strong>Remote processing disclosure</strong>
            <p>
              Requests use OpenAI Responses with <code>store: false</code>, strict structured output,
              and no tools, conversation state, background mode, or fallback. API data is excluded
              from training by default for this profile, but abuse-monitoring logs may retain input
              and output for up to 30 days. This is not a Zero Data Retention claim.
            </p>
          </div>
          {error ? <p className="form-result form-result--error" role="alert">{error}</p> : null}
          {result ? <p className="form-result form-result--success" role="status">{result}</p> : null}
          <button className="button button--primary button--wide" disabled={disabled || submitting}>
            {submitting ? "Waiting for Windows…" : "Open Windows prompt and approve exact route"}
          </button>
        </form>

        <div className="record-stack" aria-label="Approved model routes">
          {routes.length === 0 ? (
            <p className="empty-inline">No model route approval exists.</p>
          ) : routes.map((route) => (
            <article className="record-card" key={route.id}>
              <div className="record-card__heading">
                <strong>{route.providerId} / {route.routeId}</strong>
                <span className={`status-chip status-chip--${route.state}`}>{route.state}</span>
              </div>
              <p>{route.placement} · {route.retention} retention · training {route.trainingUse}</p>
              <div className="token-row">
                {route.allowedDataCategories.map((category) => <code key={category}>{category}</code>)}
              </div>
              <small>Expires {route.expiresAt ?? "only on explicit revocation"} · revision {route.revision}</small>
              {route.state === "active" ? (
                <button
                  className="button button--danger button--small"
                  disabled={disabled}
                  onClick={() => void onRevoke({
                    permissionType: "model_route_approval",
                    permissionId: route.id,
                    expectedRevision: route.revision,
                    reason: "user_requested",
                  })}
                  type="button"
                >
                  Revoke route
                </button>
              ) : null}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
