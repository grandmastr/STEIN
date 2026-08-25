import { compactId, displayMessageType, formatMoment } from "../lib/format";
import type {
  DoNotDisturbWindowView,
  EffectivePolicyView,
  SteinIdentityView,
} from "../protocol";

interface Props {
  identity?: SteinIdentityView;
  policy?: EffectivePolicyView;
}

function formatDuration(milliseconds: number): string {
  if (milliseconds % 60_000 === 0) return `${milliseconds / 60_000} min`;
  if (milliseconds % 1_000 === 0) return `${milliseconds / 1_000} sec`;
  return `${milliseconds} ms`;
}

function formatClockMinute(minute: number): string {
  const hours = Math.floor(minute / 60).toString().padStart(2, "0");
  const minutes = (minute % 60).toString().padStart(2, "0");
  return `${hours}:${minutes}`;
}

function formatOffset(minutes: number): string {
  const sign = minutes < 0 ? "−" : "+";
  const absolute = Math.abs(minutes);
  return `UTC${sign}${Math.floor(absolute / 60).toString().padStart(2, "0")}:${(absolute % 60).toString().padStart(2, "0")}`;
}

function formatDoNotDisturbWindow(window: DoNotDisturbWindowView): string {
  return `${formatClockMinute(window.startMinuteLocal)}–${formatClockMinute(window.endMinuteLocal)} ${formatOffset(window.utcOffsetMinutes)}`;
}

export function IdentityPolicyPanel({ identity, policy }: Props) {
  return (
    <section className="panel span-2" aria-labelledby="identity-policy-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Versioned, authoritative configuration</p>
          <h2 id="identity-policy-title">Identity and effective policy</h2>
        </div>
        <span className="panel__count">read only</span>
      </div>

      <div className="identity-policy-layout">
        <article className="identity-card" aria-labelledby="stein-identity-title">
          <p className="eyebrow">Product-owned invariants</p>
          <h3 id="stein-identity-title">STEIN identity</h3>
          {identity ? (
            <>
              <strong className="identity-card__name">{identity.displayName}</strong>
              <p>{identity.roleStatement}</p>
              <ul className="constraint-list">
                {identity.invariantBehavioralConstraints.map((constraint) => (
                  <li key={constraint}>{displayMessageType(constraint)}</li>
                ))}
              </ul>
              <dl className="policy-facts policy-facts--compact">
                <div><dt>Schema / revision</dt><dd>v{identity.schemaVersion} · {identity.revision}</dd></div>
                <div><dt>Owner</dt><dd title={identity.ownerId}>{compactId(identity.ownerId, 5)}</dd></div>
                <div><dt>Provenance</dt><dd>{displayMessageType(identity.provenance.source)} · {identity.provenance.version}</dd></div>
                <div><dt>Recorded</dt><dd>{formatMoment(identity.provenance.recordedAt)}</dd></div>
              </dl>
              <p className="panel-note">Identity constraints are shipped product behavior. Model output, observations, and feedback cannot edit them.</p>
            </>
          ) : <p className="empty-inline">No private identity view is available.</p>}
        </article>

        <article className="identity-card" aria-labelledby="effective-policy-title">
          <p className="eyebrow">Policy profile plus restrictive user choices</p>
          <h3 id="effective-policy-title">Effective policy</h3>
          {policy ? (
            <>
              <div className="record-card__heading">
                <strong>{policy.policyProfileId}</strong>
                <span className="status-chip">preferences r{policy.userPreferencesRevision}</span>
              </div>
              <dl className="policy-facts">
                <div><dt>Schema</dt><dd>v{policy.schemaVersion}</dd></div>
                <div><dt>Source stale</dt><dd>{formatDuration(policy.sourceStaleAfterMs)}</dd></div>
                <div><dt>Evidence age</dt><dd>{formatDuration(policy.maximumModelEvidenceAgeMs)}</dd></div>
                <div><dt>Model cooldown</dt><dd>{formatDuration(policy.modelRequestCooldownMs)}</dd></div>
                <div><dt>Model requests</dt><dd>{policy.maximumModelRequestsPerHour}/hour</dd></div>
                <div><dt>Intervention cooldown</dt><dd>{formatDuration(policy.interventionCooldownMs)}</dd></div>
                <div><dt>Intervention cap</dt><dd>{policy.maximumInterventionsPerSession}/session</dd></div>
                <div><dt>Proactive</dt><dd>{policy.proactiveEnabled ? (policy.proactiveMuted ? "enabled · muted" : "enabled") : "disabled"}</dd></div>
                <div><dt>Remote processing</dt><dd>{policy.remoteProcessingEnabled ? "allowed by preference" : "disabled"}</dd></div>
                <div><dt>Restart default</dt><dd>{policy.restartContinuityDefault ? "on" : "off"}</dd></div>
                <div><dt>Outbox capacity</dt><dd>{policy.outboxCapacityPerUser}/user · {policy.outboxCapacityPerSession}/session</dd></div>
              </dl>
              <div className="policy-list">
                <strong>Allowed delivery channels</strong>
                <p>{policy.allowedDeliveryChannels.length === 0 ? "None" : policy.allowedDeliveryChannels.map(displayMessageType).join(" · ")}</p>
              </div>
              <div className="policy-list">
                <strong>Do not disturb</strong>
                {policy.doNotDisturbWindows.length === 0 ? <p>None</p> : (
                  <ul>{policy.doNotDisturbWindows.map((window, index) => <li key={`${window.startMinuteLocal}-${window.endMinuteLocal}-${window.utcOffsetMinutes}-${index}`}>{formatDoNotDisturbWindow(window)}</li>)}</ul>
                )}
              </div>
              <p className="panel-note">This is the policy CORE enforces now. Preferences can make behavior quieter; they never create a grant, approve a model route, or bypass a hard ceiling.</p>
            </>
          ) : <p className="empty-inline">No private effective-policy view is available.</p>}
        </article>
      </div>
    </section>
  );
}
