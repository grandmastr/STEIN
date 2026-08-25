import type { ConnectionView, PublicErrorView } from "../protocol";
import { CloseIcon, LinkIcon } from "./Icons";

interface ConnectionBannerProps {
  connection?: ConnectionView;
  error: PublicErrorView | null;
  busy: boolean;
  onReconnect: () => void;
  onDismiss: () => void;
}

export function ConnectionBanner({
  connection,
  error,
  busy,
  onReconnect,
  onDismiss,
}: ConnectionBannerProps) {
  const visibleError = error ?? connection?.error;
  if (!visibleError && connection?.phase !== "disconnected") {
    return null;
  }

  const heading = "CORE is out of reach";
  const detail =
    visibleError?.summary ??
    "The presentation is running, but its Rust bridge cannot reach the CORE daemon.";

  return (
    <section className="connection-banner" role="alert">
      <span className="connection-banner__icon">
        <LinkIcon />
      </span>
      <div className="connection-banner__copy">
        <strong>{heading}</strong>
        <span>{detail}</span>
        {visibleError?.correlationId ? (
          <code>Reference {visibleError.correlationId}</code>
        ) : null}
      </div>
      {visibleError?.retryable !== false ? (
        <button className="button button--small button--inverse" disabled={busy} onClick={onReconnect}>
          {busy ? "Connecting…" : "Reconnect"}
        </button>
      ) : null}
      {error ? (
        <button className="icon-button icon-button--inverse" aria-label="Dismiss error" onClick={onDismiss}>
          <CloseIcon />
        </button>
      ) : null}
    </section>
  );
}
