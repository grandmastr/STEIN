import { ConnectionBanner } from "./components/ConnectionBanner";
import { CreateGoalForm } from "./components/CreateGoalForm";
import { FocusPanel } from "./components/FocusPanel";
import { InterventionPanel } from "./components/InterventionPanel";
import { ActivityIcon, GoalIcon, LinkIcon, PulseIcon, RefreshIcon } from "./components/Icons";
import { ModelRouteConsent } from "./components/ModelRouteConsent";
import { PermissionPanel } from "./components/PermissionPanel";
import { StatusPill } from "./components/StatusPill";
import { compactId, displayMessageType, formatMoment, formatRelative } from "./lib/format";
import { useCoreDashboard } from "./lib/useCoreDashboard";
import type {
  CapabilityView,
  CoreEventView,
  DeliveryChannelView,
  GoalView,
} from "./protocol";

function Header({ connected, refreshing, observedAt, onRefresh, onReconnect }: {
  connected: boolean;
  refreshing: boolean;
  observedAt?: string;
  onRefresh: () => void;
  onReconnect: () => void;
}) {
  return (
    <header className="app-header">
      <div className="brand" aria-label="STEIN CORE">
        <span className="brand__mark">S</span><span className="brand__wordmark">STEIN</span><span className="brand__divider" /><span className="brand__product">CORE</span>
      </div>
      <div className="header-actions">
        <span className="last-sync">Authoritative {formatRelative(observedAt)}</span>
        <button className="button button--ghost" disabled={refreshing} onClick={onRefresh}><RefreshIcon className={refreshing ? "spin" : undefined} />Refresh</button>
        {!connected ? <button className="button button--dark" disabled={refreshing} onClick={onReconnect}><LinkIcon />Reconnect</button> : null}
      </div>
    </header>
  );
}

function RuntimeHero({ snapshot }: { snapshot: NonNullable<ReturnType<typeof useCoreDashboard>["snapshot"]> }) {
  const healthy = snapshot.capabilities.filter((item) => item.state === "healthy").length;
  const activeSessions = snapshot.focusSessions.filter((session) => ["requested", "starting", "active", "recovering", "stopping"].includes(session.state)).length;
  return (
    <section className="runtime-hero">
      <div className="runtime-hero__signal" aria-hidden="true"><span /><span /><span /></div>
      <div className="runtime-hero__main">
        <p className="eyebrow eyebrow--light">Presentation-independent second-mind runtime</p>
        <div className="runtime-title-row"><h1>CORE is {snapshot.runtime.phase}</h1><StatusPill status={snapshot.connection.phase} /></div>
        <p>CORE owns canonical goals, grants, focus continuity, intervention policy, native status, and delivery. This desktop replaces its cache from an authoritative snapshot on every reconnect.</p>
        <dl className="runtime-identifiers">
          <div><dt>Instance</dt><dd title={snapshot.runtime.daemonInstanceId}>{compactId(snapshot.runtime.daemonInstanceId)}</dd></div>
          <div><dt>Protocol</dt><dd>v{snapshot.runtime.protocol.major}.{snapshot.runtime.protocol.minor}</dd></div>
          <div><dt>Build</dt><dd title={snapshot.runtime.buildId}>{compactId(snapshot.runtime.buildId, 6)}</dd></div>
          <div><dt>Started</dt><dd>{formatMoment(snapshot.runtime.startedAt)}</dd></div>
        </dl>
      </div>
      <div className="runtime-metrics" aria-label="CORE summary">
        <div className="metric"><span className="metric__icon"><PulseIcon /></span><span className="metric__value">{healthy}/{snapshot.capabilities.length}</span><span className="metric__label">Capabilities healthy</span></div>
        <div className="metric"><span className="metric__icon"><GoalIcon /></span><span className="metric__value">{snapshot.goals.filter((goal) => goal.state === "active").length}</span><span className="metric__label">Active goals</span></div>
        <div className="metric"><span className="metric__icon"><ActivityIcon /></span><span className="metric__value">{activeSessions}</span><span className="metric__label">Focus sessions</span></div>
        <div className="metric metric--cursor"><span className="metric__icon"><ActivityIcon /></span><span className="metric__value" title={snapshot.cursor}>{compactId(snapshot.cursor, 5)}</span><span className="metric__label">Event cursor</span></div>
      </div>
    </section>
  );
}

function AdmissionBanner({ reason }: { reason?: string }) {
  return (
    <section className="admission-banner" role="status">
      <div><p className="eyebrow">Diagnostic-only admission</p><h2>Private Phase 2 state is locked</h2></div>
      <p>{reason ?? "Signed-package broker admission is unavailable."}</p>
      <p>The dashboard shows only content-free runtime and capability health. Goals, routes, grants, subscriptions, history, and every mutation remain closed—there is no development or same-user bypass.</p>
    </section>
  );
}

function CapabilityList({ capabilities }: { capabilities: CapabilityView[] }) {
  return (
    <section className="panel" aria-labelledby="capabilities-title">
      <div className="panel__header"><div><p className="eyebrow">Content-free runtime surface</p><h2 id="capabilities-title">Capabilities</h2></div><span className="panel__count">{capabilities.length}</span></div>
      <ul className="capability-list">
        {capabilities.map((capability) => <li key={capability.id}><span className={`capability-icon capability-icon--${capability.state}`}><PulseIcon /></span><span className="capability-copy"><strong>{capability.label}</strong><small>{capability.detail ?? `Checked ${formatRelative(capability.checkedAt)}`}</small></span><StatusPill status={capability.state} /></li>)}
      </ul>
    </section>
  );
}

function GoalList({ goals, disabled, onComplete, onAbandon }: {
  goals: GoalView[];
  disabled: boolean;
  onComplete: (goal: GoalView) => void;
  onAbandon: (goal: GoalView) => void;
}) {
  return (
    <section className="panel" aria-labelledby="goals-title">
      <div className="panel__header"><div><p className="eyebrow">Durable direct-user state</p><h2 id="goals-title">Goals</h2></div><span className="panel__count">{goals.length}</span></div>
      {goals.length === 0 ? <p className="empty-inline">No private goal view is available.</p> : <ul className="goal-list">{goals.map((goal) => <li key={goal.id}><span className="goal-list__line" /><div className="goal-list__body"><div className="goal-list__heading"><strong>{goal.title}</strong><StatusPill status={goal.state} /></div><p>{goal.successStatement}</p><span className="goal-list__meta"><span>{goal.deadline ? `Due ${formatMoment(goal.deadline)}` : "No deadline"}</span><span>Revision {goal.revision}</span><code title={goal.id}>{compactId(goal.id, 5)}</code></span>{goal.state === "active" ? <div className="button-row"><button className="button button--ghost button--small" disabled={disabled} onClick={() => onComplete(goal)}>Complete</button><button className="button button--danger button--small" disabled={disabled} onClick={() => onAbandon(goal)}>Abandon</button></div> : null}</div></li>)}</ul>}
    </section>
  );
}

function ChannelStatus({ channels }: { channels: DeliveryChannelView[] }) {
  return (
    <section className="panel" aria-labelledby="channels-title">
      <div className="panel__header"><div><p className="eyebrow">Daemon-owned delivery</p><h2 id="channels-title">Native channels</h2></div><span className="panel__count">{channels.length}</span></div>
      {channels.length === 0 ? <p className="empty-inline">No private delivery-channel view is available.</p> : <div className="record-stack">{channels.map((channel) => <article className="record-card" key={channel.id}><div className="record-card__heading"><strong>{displayMessageType(channel.class)}</strong><span className={`status-chip status-chip--${channel.state}`}>{channel.state}</span></div><p>{channel.mayShowContentWhileLocked ? "Reports that content may show while locked" : "Private content is suppressed while locked"}</p><small>Observed {formatRelative(channel.observedAt)}{channel.statusCode ? ` · ${channel.statusCode}` : ""}</small></article>)}</div>}
      <p className="panel-note">Native notifications and capture controls are hosted by CORE. They continue when this Tauri window is closed. “Accepted by channel” never means displayed or seen.</p>
    </section>
  );
}

function EventTimeline({ events }: { events: CoreEventView[] }) {
  return (
    <section className="panel span-2" aria-labelledby="events-title">
      <div className="panel__header"><div><p className="eyebrow">Privacy-filtered private stream</p><h2 id="events-title">Recent view events</h2></div><span className="live-indicator"><span /> Live</span></div>
      {events.length === 0 ? <p className="empty-inline">No private event is available on this connection.</p> : <ol className="event-list">{events.map((event) => <li key={event.messageId}><span className="event-list__node" /><div><div className="event-list__heading"><strong>{displayMessageType(event.messageType)}</strong><time dateTime={event.occurredAt}>{formatRelative(event.occurredAt)}</time></div><p>{event.summary}</p><span className="event-list__meta">schema {event.schemaVersion} · cursor {compactId(event.cursor, 4)}</span></div></li>)}</ol>}
    </section>
  );
}

function LoadingDashboard() {
  return <main className="loading-state" aria-live="polite"><div className="loading-orbit"><span /></div><p className="eyebrow">Establishing local protocol session</p><h1>Connecting to CORE</h1><p>The Rust backend is negotiating protocol 1.2 and determining broker assurance.</p></main>;
}

export default function App() {
  const dashboard = useCoreDashboard();
  const { snapshot, error, loading, refreshing, commandPending } = dashboard;
  const connected = snapshot?.connection.phase === "connected";
  const privateAvailable = Boolean(snapshot?.access.privateProtocolAvailable);
  const controlsDisabled = !connected || !privateAvailable || commandPending;

  return (
    <div className="app-shell">
      <Header connected={connected} observedAt={snapshot?.observedAt} refreshing={refreshing} onRefresh={() => void dashboard.refresh()} onReconnect={() => void dashboard.reconnect()} />
      <ConnectionBanner busy={refreshing} connection={snapshot?.connection} error={error} onDismiss={dashboard.clearError} onReconnect={() => void dashboard.reconnect()} />
      {loading ? <LoadingDashboard /> : null}
      {!loading && !snapshot ? <main className="offline-state"><span className="offline-state__icon"><LinkIcon /></span><p className="eyebrow">Presentation available · daemon unavailable</p><h1>CORE is not connected</h1><p>Start the per-user daemon, then reconnect. Closing this window does not alter daemon-owned workflows or canonical state.</p><button className="button button--primary" disabled={refreshing} onClick={() => void dashboard.reconnect()}><LinkIcon />{refreshing ? "Connecting…" : "Reconnect to CORE"}</button></main> : null}

      {snapshot ? (
        <main className="dashboard">
          <RuntimeHero snapshot={snapshot} />
          {!privateAvailable ? <AdmissionBanner reason={snapshot.access.unavailableReason} /> : null}
          <div key={snapshot.access.assurance} className={!privateAvailable ? "private-workspace private-workspace--locked" : "private-workspace"} aria-disabled={!privateAvailable}>
            <div className="dashboard-grid dashboard-grid--phase2">
              <CreateGoalForm disabled={controlsDisabled} onCreate={dashboard.createGoal} />
              <GoalList goals={snapshot.goals} disabled={controlsDisabled} onComplete={(goal) => void dashboard.completeGoal({ goalId: goal.id, expectedRevision: goal.revision })} onAbandon={(goal) => void dashboard.abandonGoal({ goalId: goal.id, expectedRevision: goal.revision, reason: "user_requested" })} />
              <ModelRouteConsent disabled={controlsDisabled} routes={snapshot.modelRoutes} onStoreSecret={dashboard.storeModelSecret} onApprove={dashboard.approveModelRoute} onRevoke={dashboard.revokePermission} />
              <PermissionPanel currentDeviceId={snapshot.currentDeviceId} disabled={controlsDisabled} goals={snapshot.goals} resources={snapshot.selectedResources} grants={snapshot.sessionGrants} onGrant={dashboard.grantPermission} onRevoke={dashboard.revokePermission} />
              <FocusPanel disabled={controlsDisabled} goals={snapshot.goals} routes={snapshot.modelRoutes} grants={snapshot.sessionGrants} resources={snapshot.selectedResources} sessions={snapshot.focusSessions} captures={snapshot.captureStates} onStart={dashboard.startFocusSession} onSetMuted={dashboard.setInterventionsMuted} onEnd={dashboard.endFocusSession} />
              <ChannelStatus channels={snapshot.deliveryChannels} />
              <CapabilityList capabilities={snapshot.capabilities} />
              <InterventionPanel disabled={controlsDisabled} interventions={snapshot.interventionHistory} resources={snapshot.selectedResources} onExplain={dashboard.explainIntervention} onFeedback={dashboard.recordInterventionFeedback} onHistory={dashboard.getInterventionHistory} />
              <EventTimeline events={snapshot.recentEvents} />
            </div>
          </div>
        </main>
      ) : null}
      <footer className="app-footer"><span>STEIN Phase 2 · Windows-first</span><span>React → typed Tauri bridge → broker-assured IPC → daemon-owned CORE</span></footer>
    </div>
  );
}
