import { useRef, useState, type FormEvent } from "react";
import { compactId, displayMessageType, formatMoment } from "../lib/format";
import {
  publicErrorFromUnknown,
  type DeliveryChannelClass,
  type InterventionStyle,
  type UpdateUserPreferencesInput,
  type UserPreferencesUpdateView,
  type UserPreferencesView,
} from "../protocol";

const DELIVERY_CHANNELS = [
  "native_desktop_notification",
  "connected_desktop",
] as const satisfies readonly DeliveryChannelClass[];

const INTERVENTION_STYLES = ["concise", "neutral", "reflective"] as const satisfies readonly InterventionStyle[];
const MINIMUM_COOLDOWN_SECONDS = 15 * 60;
const MAXIMUM_COOLDOWN_SECONDS = Math.floor(Number.MAX_SAFE_INTEGER / 1_000);
const MAXIMUM_INTERVENTIONS_PER_SESSION = 3;
const MAXIMUM_MODEL_REQUESTS_PER_HOUR = 12;
const MAXIMUM_DO_NOT_DISTURB_WINDOWS = 16;

interface DoNotDisturbDraft {
  start: string;
  end: string;
  utcOffsetMinutes: string;
}

interface PreferencesDraft {
  preferredFormOfAddress: string;
  interventionStyle: InterventionStyle;
  proactiveEnabled: boolean;
  proactiveMuted: boolean;
  maximumInterventionsPerSession: string;
  maximumModelRequestsPerHour: string;
  minimumInterventionCooldownSeconds: string;
  doNotDisturbWindows: DoNotDisturbDraft[];
  allowedDeliveryChannels: DeliveryChannelClass[];
  remoteProcessingEnabled: boolean;
  restartContinuityDefault: boolean;
}

interface Props {
  disabled: boolean;
  preferences?: UserPreferencesView;
  onUpdate: (input: UpdateUserPreferencesInput) => Promise<UserPreferencesUpdateView>;
  onRefresh: () => Promise<unknown>;
}

type Notice = { tone: "success" | "neutral" | "error"; text: string };

function minuteToClock(minute: number): string {
  return `${Math.floor(minute / 60).toString().padStart(2, "0")}:${(minute % 60).toString().padStart(2, "0")}`;
}

function clockToMinute(value: string): number | null {
  const match = /^(\d{2}):(\d{2})$/.exec(value);
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  if (hours > 23 || minutes > 59) return null;
  return hours * 60 + minutes;
}

function draftFrom(preferences: UserPreferencesView): PreferencesDraft {
  return {
    preferredFormOfAddress: preferences.preferredFormOfAddress ?? "",
    interventionStyle: preferences.interventionStyle,
    proactiveEnabled: preferences.proactiveEnabled,
    proactiveMuted: preferences.proactiveMuted,
    maximumInterventionsPerSession: String(preferences.maximumInterventionsPerSession),
    maximumModelRequestsPerHour: String(preferences.maximumModelRequestsPerHour),
    minimumInterventionCooldownSeconds: String(preferences.minimumInterventionCooldownMs / 1_000),
    doNotDisturbWindows: preferences.doNotDisturbWindows.map((window) => ({
      start: minuteToClock(window.startMinuteLocal),
      end: minuteToClock(window.endMinuteLocal),
      utcOffsetMinutes: String(window.utcOffsetMinutes),
    })),
    allowedDeliveryChannels: [...preferences.allowedDeliveryChannels],
    remoteProcessingEnabled: preferences.remoteProcessingEnabled,
    restartContinuityDefault: preferences.restartContinuityDefault,
  };
}

function integerInRange(value: string, minimum: number, maximum: number): number | null {
  if (!value.trim()) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

function isConflict(error: ReturnType<typeof publicErrorFromUnknown>): boolean {
  return error.category === "conflict" || error.code.toLowerCase().includes("conflict");
}

interface EditorProps extends Props {
  preferences: UserPreferencesView;
  notice: Notice | null;
  onNotice: (notice: Notice | null) => void;
}

function PreferencesEditor({ disabled, preferences, onUpdate, onRefresh, notice, onNotice }: EditorProps) {
  const [draft, setDraft] = useState(() => draftFrom(preferences));
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const inFlight = useRef(false);

  function toggleChannel(channel: DeliveryChannelClass): void {
    setDraft((current) => ({
      ...current,
      allowedDeliveryChannels: current.allowedDeliveryChannels.includes(channel)
        ? current.allowedDeliveryChannels.filter((item) => item !== channel)
        : DELIVERY_CHANNELS.filter((item) => item === channel || current.allowedDeliveryChannels.includes(item)),
    }));
  }

  function addDoNotDisturbWindow(): void {
    if (draft.doNotDisturbWindows.length >= MAXIMUM_DO_NOT_DISTURB_WINDOWS) return;
    setDraft((current) => ({
      ...current,
      doNotDisturbWindows: [
        ...current.doNotDisturbWindows,
        { start: "", end: "", utcOffsetMinutes: "" },
      ],
    }));
  }

  function updateDoNotDisturbWindow(index: number, patch: Partial<DoNotDisturbDraft>): void {
    setDraft((current) => ({
      ...current,
      doNotDisturbWindows: current.doNotDisturbWindows.map((window, currentIndex) =>
        currentIndex === index ? { ...window, ...patch } : window,
      ),
    }));
  }

  function removeDoNotDisturbWindow(index: number): void {
    setDraft((current) => ({
      ...current,
      doNotDisturbWindows: current.doNotDisturbWindows.filter((_, currentIndex) => currentIndex !== index),
    }));
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (disabled || inFlight.current) return;

    const errors: Record<string, string> = {};
    const address = draft.preferredFormOfAddress.trim();
    if ([...address].length > 80) errors.preferredFormOfAddress = "Use 80 characters or fewer.";
    const interventionCap = integerInRange(draft.maximumInterventionsPerSession, 0, MAXIMUM_INTERVENTIONS_PER_SESSION);
    if (interventionCap === null) errors.maximumInterventionsPerSession = "Choose a whole number from 0 to 3.";
    const modelCap = integerInRange(draft.maximumModelRequestsPerHour, 0, MAXIMUM_MODEL_REQUESTS_PER_HOUR);
    if (modelCap === null) errors.maximumModelRequestsPerHour = "Choose a whole number from 0 to 12.";
    const cooldownSeconds = Number(draft.minimumInterventionCooldownSeconds);
    if (
      !Number.isSafeInteger(cooldownSeconds) ||
      cooldownSeconds < MINIMUM_COOLDOWN_SECONDS ||
      cooldownSeconds > MAXIMUM_COOLDOWN_SECONDS
    ) {
      errors.minimumInterventionCooldownSeconds = "Use a whole number of seconds, at least 900 (15 minutes), within the protocol's exact integer range.";
    }

    const windows = draft.doNotDisturbWindows.map((window, index) => {
      const startMinuteLocal = clockToMinute(window.start);
      const endMinuteLocal = clockToMinute(window.end);
      const utcOffsetMinutes = integerInRange(window.utcOffsetMinutes, -1_439, 1_439);
      if (startMinuteLocal === null || endMinuteLocal === null || startMinuteLocal === endMinuteLocal || utcOffsetMinutes === null) {
        errors[`doNotDisturbWindows.${index}`] = "Choose different start/end times and a UTC offset from −1439 to 1439 minutes.";
      }
      return { startMinuteLocal, endMinuteLocal, utcOffsetMinutes };
    });

    setFieldErrors(errors);
    onNotice(null);
    if (Object.keys(errors).length > 0 || interventionCap === null || modelCap === null || !Number.isSafeInteger(cooldownSeconds)) return;

    const input: UpdateUserPreferencesInput = {
      expectedRevision: preferences.revision,
      preferences: {
        ...(address ? { preferredFormOfAddress: address } : {}),
        interventionStyle: draft.interventionStyle,
        proactiveEnabled: draft.proactiveEnabled,
        proactiveMuted: draft.proactiveMuted,
        maximumInterventionsPerSession: interventionCap,
        maximumModelRequestsPerHour: modelCap,
        minimumInterventionCooldownMs: cooldownSeconds * 1_000,
        doNotDisturbWindows: windows.map((window) => ({
          startMinuteLocal: window.startMinuteLocal!,
          endMinuteLocal: window.endMinuteLocal!,
          utcOffsetMinutes: window.utcOffsetMinutes!,
        })),
        allowedDeliveryChannels: [...draft.allowedDeliveryChannels],
        remoteProcessingEnabled: draft.remoteProcessingEnabled,
        restartContinuityDefault: draft.restartContinuityDefault,
      },
    };

    inFlight.current = true;
    setSubmitting(true);
    try {
      const result = await onUpdate(input);
      try {
        await onRefresh();
        onNotice({ tone: "success", text: `Preferences revision ${result.preferences.revision} is now authoritative.` });
      } catch (refreshError) {
        onNotice({
          tone: "error",
          text: `CORE accepted the preference update, but the authoritative view could not refresh: ${publicErrorFromUnknown(refreshError).summary}`,
        });
      }
    } catch (caught) {
      const error = publicErrorFromUnknown(caught);
      if (isConflict(error)) {
        try {
          await onRefresh();
          onNotice({ tone: "neutral", text: "CORE rejected the update because the preference revision changed. Authoritative values were refreshed; review them before saving again." });
        } catch (refreshError) {
          onNotice({ tone: "error", text: `${error.summary} The authoritative refresh also failed: ${publicErrorFromUnknown(refreshError).summary}` });
        }
      } else {
        setFieldErrors(error.fieldErrors ?? {});
        onNotice({ tone: "error", text: error.summary });
      }
    } finally {
      inFlight.current = false;
      setSubmitting(false);
    }
  }

  const controlsDisabled = disabled || submitting;
  return (
    <section className="panel span-2" aria-labelledby="user-preferences-title">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Direct-user configuration only</p>
          <h2 id="user-preferences-title">User preferences</h2>
        </div>
        <span className="panel__count">revision {preferences.revision}</span>
      </div>

      <form className="preferences-form" onSubmit={(event) => void submit(event)} noValidate>
        <div className="preferences-grid">
          <label>
            <span>Preferred form of address <i>optional</i></span>
            <input aria-label="Preferred form of address" autoComplete="off" disabled={controlsDisabled} maxLength={80} value={draft.preferredFormOfAddress} onChange={(event) => setDraft((current) => ({ ...current, preferredFormOfAddress: event.target.value }))} />
            {fieldErrors.preferredFormOfAddress ? <small className="field-error">{fieldErrors.preferredFormOfAddress}</small> : null}
          </label>
          <label>
            <span>Intervention style</span>
            <select aria-label="Intervention style" disabled={controlsDisabled} value={draft.interventionStyle} onChange={(event) => setDraft((current) => ({ ...current, interventionStyle: event.target.value as InterventionStyle }))}>
              {INTERVENTION_STYLES.map((style) => <option key={style} value={style}>{displayMessageType(style)}</option>)}
            </select>
          </label>
          <label>
            <span>Maximum interventions per session</span>
            <input aria-label="Maximum interventions per session" disabled={controlsDisabled} inputMode="numeric" max={3} min={0} step={1} type="number" value={draft.maximumInterventionsPerSession} onChange={(event) => setDraft((current) => ({ ...current, maximumInterventionsPerSession: event.target.value }))} />
            {fieldErrors.maximumInterventionsPerSession ? <small className="field-error">{fieldErrors.maximumInterventionsPerSession}</small> : <small>0 disables proactive interventions; the hard ceiling is 3.</small>}
          </label>
          <label>
            <span>Maximum model requests per hour</span>
            <input aria-label="Maximum model requests per hour" disabled={controlsDisabled} inputMode="numeric" max={12} min={0} step={1} type="number" value={draft.maximumModelRequestsPerHour} onChange={(event) => setDraft((current) => ({ ...current, maximumModelRequestsPerHour: event.target.value }))} />
            {fieldErrors.maximumModelRequestsPerHour ? <small className="field-error">{fieldErrors.maximumModelRequestsPerHour}</small> : <small>0 disables model requests; the hard ceiling is 12.</small>}
          </label>
          <label>
            <span>Minimum intervention cooldown (seconds)</span>
            <input aria-label="Minimum intervention cooldown" disabled={controlsDisabled} inputMode="numeric" max={MAXIMUM_COOLDOWN_SECONDS} min={MINIMUM_COOLDOWN_SECONDS} step={1} type="number" value={draft.minimumInterventionCooldownSeconds} onChange={(event) => setDraft((current) => ({ ...current, minimumInterventionCooldownSeconds: event.target.value }))} />
            {fieldErrors.minimumInterventionCooldownSeconds ? <small className="field-error">{fieldErrors.minimumInterventionCooldownSeconds}</small> : <small>At least 900 seconds (15 minutes); longer is quieter.</small>}
          </label>
        </div>

        <fieldset className="preference-toggle-grid">
          <legend>Behavior defaults</legend>
          <label><input checked={draft.proactiveEnabled} disabled={controlsDisabled} type="checkbox" onChange={(event) => setDraft((current) => ({ ...current, proactiveEnabled: event.target.checked }))} /><span><strong>Enable proactive suggestions</strong><small>Still requires an active focus session and every exact grant.</small></span></label>
          <label><input checked={draft.proactiveMuted} disabled={controlsDisabled} type="checkbox" onChange={(event) => setDraft((current) => ({ ...current, proactiveMuted: event.target.checked }))} /><span><strong>Mute proactive delivery</strong><small>Observation authority is separate; mute affects delivery only.</small></span></label>
          <label><input checked={draft.remoteProcessingEnabled} disabled={controlsDisabled} type="checkbox" onChange={(event) => setDraft((current) => ({ ...current, remoteProcessingEnabled: event.target.checked }))} /><span><strong>Allow remote processing preference</strong><small>Does not approve a provider, route, data category, or request.</small></span></label>
          <label><input checked={draft.restartContinuityDefault} disabled={controlsDisabled} type="checkbox" onChange={(event) => setDraft((current) => ({ ...current, restartContinuityDefault: event.target.checked }))} /><span><strong>Prefer restart continuity</strong><small>Does not modify existing grants; exact continuity consent remains required.</small></span></label>
        </fieldset>

        <fieldset className="preference-toggle-grid preference-toggle-grid--channels">
          <legend>Allowed delivery-channel preference</legend>
          {DELIVERY_CHANNELS.map((channel) => (
            <label key={channel}><input checked={draft.allowedDeliveryChannels.includes(channel)} disabled={controlsDisabled} type="checkbox" onChange={() => toggleChannel(channel)} /><span><strong>{displayMessageType(channel)}</strong><small>A channel preference cannot create notification authority.</small></span></label>
          ))}
        </fieldset>

        <fieldset className="dnd-editor">
          <legend>Do not disturb windows</legend>
          {draft.doNotDisturbWindows.length === 0 ? <p className="empty-inline">No do-not-disturb window is configured.</p> : draft.doNotDisturbWindows.map((window, index) => (
            <div className="dnd-row" key={index}>
              <label><span>Start</span><input aria-label={`Do not disturb ${index + 1} start`} disabled={controlsDisabled} type="time" value={window.start} onChange={(event) => updateDoNotDisturbWindow(index, { start: event.target.value })} /></label>
              <label><span>End</span><input aria-label={`Do not disturb ${index + 1} end`} disabled={controlsDisabled} type="time" value={window.end} onChange={(event) => updateDoNotDisturbWindow(index, { end: event.target.value })} /></label>
              <label><span>UTC offset (minutes)</span><input aria-label={`Do not disturb ${index + 1} UTC offset`} disabled={controlsDisabled} inputMode="numeric" max={1_439} min={-1_439} step={1} type="number" value={window.utcOffsetMinutes} onChange={(event) => updateDoNotDisturbWindow(index, { utcOffsetMinutes: event.target.value })} /></label>
              <button aria-label={`Remove do not disturb window ${index + 1}`} className="button button--ghost button--small" disabled={controlsDisabled} type="button" onClick={() => removeDoNotDisturbWindow(index)}>Remove</button>
              {fieldErrors[`doNotDisturbWindows.${index}`] ? <small className="field-error dnd-row__error">{fieldErrors[`doNotDisturbWindows.${index}`]}</small> : null}
            </div>
          ))}
          <button className="button button--ghost button--small" disabled={controlsDisabled || draft.doNotDisturbWindows.length >= MAXIMUM_DO_NOT_DISTURB_WINDOWS} type="button" onClick={addDoNotDisturbWindow}>Add do not disturb window</button>
        </fieldset>

        <div className="preferences-disclosure">
          <strong>Explicit configuration, not learned behavior</strong>
          <p>Only this direct capability-bound command can change durable preferences. Observations, model output, silence, timing, corrections, and accepted or dismissed interventions never update this record automatically.</p>
          <p>Preferences can make behavior quieter. They cannot grant observation, authorize off-device data, extend retention, bypass confirmation, or exceed CORE’s hard ceilings.</p>
          <small>Schema v{preferences.schemaVersion} · owner <span title={preferences.ownerId}>{compactId(preferences.ownerId, 5)}</span> · revision {preferences.revision}<br />Current provenance: {displayMessageType(preferences.provenance.source)} · {preferences.provenance.version} · {formatMoment(preferences.provenance.recordedAt)}</small>
        </div>

        {notice ? <p className={`form-result form-result--${notice.tone}`} role="status">{notice.text}</p> : null}
        <button className="button button--primary button--wide" disabled={controlsDisabled} type="submit">{submitting ? "Saving…" : "Save preferences"}</button>
      </form>
    </section>
  );
}

export function UserPreferencesPanel(props: Props) {
  const { preferences } = props;
  const [notice, setNotice] = useState<Notice | null>(null);
  if (!preferences) {
    return (
      <section className="panel span-2" aria-labelledby="user-preferences-title">
        <div className="panel__header"><div><p className="eyebrow">Direct-user configuration only</p><h2 id="user-preferences-title">User preferences</h2></div></div>
        <div className="preferences-form">
          <p className="empty-inline">No authoritative private preference record is available. The desktop will not invent defaults.</p>
          <button className="button button--primary button--wide" disabled type="button">Save preferences</button>
        </div>
      </section>
    );
  }
  return <PreferencesEditor key={`${preferences.ownerId}:${preferences.revision}`} {...props} preferences={preferences} notice={notice} onNotice={setNotice} />;
}
