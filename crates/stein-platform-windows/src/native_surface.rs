use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use stein_core::{
    EmergencyCommand, EmergencyCommandAcknowledgement, EmergencyCommandEnvelope,
    EmergencyControlPort, FocusSessionId, NativeCaptureStatus, NativeStatusAcknowledgement,
    NativeStatusError, NativeStatusHeartbeat, NativeStatusPort, PermissionScope,
    PlatformPortAvailability,
};
use time::OffsetDateTime;
use tokio::sync::{Notify, oneshot};
use uuid::Uuid;

const STATUS_HEARTBEAT: Duration = Duration::from_secs(10);
const EMERGENCY_ACK_DEADLINE: Duration = Duration::from_secs(10);
const EMERGENCY_QUEUE_CAPACITY: usize = 8;
const MAX_RESOURCE_LABEL_SCALARS: usize = 128;

#[cfg(windows)]
mod native;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsNativeSurfaceError {
    pub summary: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SurfaceHealth {
    Starting,
    Healthy,
    ShellUnavailable,
    MessageLoopStopped,
    HeartbeatExpired,
    EmergencyAcknowledgementExpired,
}

impl SurfaceHealth {
    const fn availability(self) -> PlatformPortAvailability {
        match self {
            Self::Healthy => PlatformPortAvailability::Available,
            Self::Starting => PlatformPortAvailability::Unavailable {
                reason: "The Windows native status surface is starting.",
            },
            Self::ShellUnavailable => PlatformPortAvailability::Unavailable {
                reason: "The Windows notification-area status surface is unavailable.",
            },
            Self::MessageLoopStopped => PlatformPortAvailability::Unavailable {
                reason: "The Windows native status message loop stopped.",
            },
            Self::HeartbeatExpired => PlatformPortAvailability::Unavailable {
                reason: "The Windows native status heartbeat expired.",
            },
            Self::EmergencyAcknowledgementExpired => PlatformPortAvailability::Unavailable {
                reason: "A Windows emergency command was not acknowledged in time.",
            },
        }
    }
}

struct SharedSurface {
    health: Mutex<SurfaceHealthRecord>,
    heartbeats: Mutex<HeartbeatState>,
    heartbeat_notify: Notify,
    emergency: Mutex<EmergencyQueue>,
    emergency_notify: Notify,
}

impl SharedSurface {
    fn new() -> Self {
        Self {
            health: Mutex::new(SurfaceHealthRecord::default()),
            heartbeats: Mutex::new(HeartbeatState::default()),
            heartbeat_notify: Notify::new(),
            emergency: Mutex::new(EmergencyQueue::new(EMERGENCY_QUEUE_CAPACITY)),
            emergency_notify: Notify::new(),
        }
    }

    fn availability(&self) -> PlatformPortAvailability {
        let now = Instant::now();
        let emergency_expired = self
            .emergency
            .lock()
            .map_or(true, |queue| queue.has_expired_acknowledgement(now));
        let mut health = match self.health.lock() {
            Ok(health) => health,
            Err(_) => {
                return PlatformPortAvailability::Unavailable {
                    reason: "The Windows native status health state is unavailable.",
                };
            }
        };
        if emergency_expired {
            health.current = SurfaceHealth::EmergencyAcknowledgementExpired;
        } else if health
            .heartbeat_deadline
            .is_some_and(|deadline| deadline <= now)
            && health.current == SurfaceHealth::Healthy
        {
            health.current = SurfaceHealth::HeartbeatExpired;
        }
        health.current.availability()
    }

    fn mark_health(&self, current: SurfaceHealth, heartbeat_deadline: Option<Instant>) {
        if let Ok(mut health) = self.health.lock() {
            health.current = current;
            health.heartbeat_deadline = heartbeat_deadline;
        }
        if let Some(error) = heartbeat_loss(current)
            && let Ok(mut heartbeats) = self.heartbeats.lock()
        {
            heartbeats.loss = Some(error);
            heartbeats.pending.clear();
            self.heartbeat_notify.notify_waiters();
        }
    }

    /// Called only by the native window-owning thread after it successfully
    /// rendered/validated the current surface during a message-loop turn.
    fn record_message_loop_heartbeats(&self, state: &SurfaceState, emitted_at: OffsetDateTime) {
        let Ok(mut heartbeats) = self.heartbeats.lock() else {
            return;
        };
        heartbeats.loss = None;
        heartbeats
            .pending
            .retain(|session_id, _| state.sessions.contains_key(session_id));
        for stored in state.sessions.values() {
            heartbeats.pending.insert(
                stored.value.session_id,
                NativeStatusHeartbeat {
                    session_id: stored.value.session_id,
                    revision: stored.value.revision,
                    emitted_at,
                },
            );
        }
        self.heartbeat_notify.notify_waiters();
    }

    async fn next_heartbeat(
        &self,
        session_id: FocusSessionId,
    ) -> Result<NativeStatusHeartbeat, NativeStatusError> {
        loop {
            let notified = self.heartbeat_notify.notified();
            {
                let mut heartbeats = self.heartbeats.lock().map_err(|_| {
                    status_error("The Windows native heartbeat stream is unavailable.", true)
                })?;
                if let Some(error) = &heartbeats.loss {
                    return Err(error.clone());
                }
                if let Some(heartbeat) = heartbeats.pending.remove(&session_id) {
                    return Ok(heartbeat);
                }
            }
            notified.await;
        }
    }

    fn enqueue(&self, command: EmergencyCommand) {
        let queued = self
            .emergency
            .lock()
            .is_ok_and(|mut queue| queue.enqueue(command, OffsetDateTime::now_utc()));
        if queued {
            self.emergency_notify.notify_one();
        }
    }
}

#[derive(Default)]
struct HeartbeatState {
    pending: BTreeMap<FocusSessionId, NativeStatusHeartbeat>,
    loss: Option<NativeStatusError>,
}

fn heartbeat_loss(health: SurfaceHealth) -> Option<NativeStatusError> {
    let summary = match health {
        SurfaceHealth::Starting | SurfaceHealth::Healthy => return None,
        SurfaceHealth::ShellUnavailable => "The Windows native status shell registration was lost.",
        SurfaceHealth::MessageLoopStopped => "The Windows native status message loop stopped.",
        SurfaceHealth::HeartbeatExpired => "The Windows native status rendering heartbeat expired.",
        SurfaceHealth::EmergencyAcknowledgementExpired => {
            "The Windows emergency-control acknowledgement expired."
        }
    };
    Some(status_error(summary, true))
}

impl fmt::Debug for SharedSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedSurface")
            .field("availability", &self.availability())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct SurfaceHealthRecord {
    current: SurfaceHealth,
    heartbeat_deadline: Option<Instant>,
}

impl Default for SurfaceHealthRecord {
    fn default() -> Self {
        Self {
            current: SurfaceHealth::Starting,
            heartbeat_deadline: None,
        }
    }
}

enum SurfaceRequest {
    Publish {
        status: NativeCaptureStatus,
        response: oneshot::Sender<Result<NativeStatusAcknowledgement, NativeStatusError>>,
    },
    Clear {
        session_id: FocusSessionId,
        revision: u64,
        response: oneshot::Sender<Result<NativeStatusAcknowledgement, NativeStatusError>>,
    },
}

#[derive(Clone)]
struct StoredStatus {
    value: NativeCaptureStatus,
    expires_at: Instant,
}

#[derive(Clone, Default)]
struct SurfaceState {
    sessions: BTreeMap<FocusSessionId, StoredStatus>,
}

impl SurfaceState {
    fn prepare_publish(
        &self,
        status: &NativeCaptureStatus,
        now_utc: OffsetDateTime,
        now: Instant,
    ) -> Result<(Self, NativeStatusAcknowledgement), NativeStatusError> {
        validate_status(status, now_utc)?;
        if let Some(previous) = self.sessions.get(&status.session_id) {
            if status.revision < previous.value.revision {
                return Err(status_error(
                    "The Windows native status revision is stale.",
                    false,
                ));
            }
            if status.revision == previous.value.revision {
                if !same_status_semantics(status, &previous.value) {
                    return Err(status_error(
                        "The Windows native status revision conflicts with current state.",
                        false,
                    ));
                }
                if status.published_at < previous.value.published_at
                    || status.heartbeat_deadline < previous.value.heartbeat_deadline
                {
                    return Err(status_error(
                        "The Windows native status heartbeat refresh is stale.",
                        false,
                    ));
                }
            }
        }
        let remaining: Duration = (status.heartbeat_deadline - now_utc)
            .try_into()
            .map_err(|_| status_error("The native status heartbeat is invalid.", false))?;
        let mut next = self.clone();
        next.sessions.insert(
            status.session_id,
            StoredStatus {
                value: status.clone(),
                expires_at: now + remaining,
            },
        );
        Ok((
            next,
            NativeStatusAcknowledgement {
                session_id: status.session_id,
                revision: status.revision,
                acknowledged_at: now_utc,
                heartbeat_deadline: status.heartbeat_deadline,
            },
        ))
    }

    fn prepare_clear(
        &self,
        session_id: FocusSessionId,
        revision: u64,
        now_utc: OffsetDateTime,
    ) -> Result<(Self, NativeStatusAcknowledgement), NativeStatusError> {
        if let Some(previous) = self.sessions.get(&session_id)
            && revision < previous.value.revision
        {
            return Err(status_error(
                "The Windows native status clear revision is stale.",
                false,
            ));
        }
        let mut next = self.clone();
        next.sessions.remove(&session_id);
        Ok((
            next,
            NativeStatusAcknowledgement {
                session_id,
                revision,
                acknowledged_at: now_utc,
                heartbeat_deadline: now_utc
                    + time::Duration::try_from(STATUS_HEARTBEAT)
                        .expect("ten seconds is representable"),
            },
        ))
    }

    fn rendered(&self, private_labels_allowed: bool, now: Instant) -> RenderedSurface {
        let mut active_scopes = BTreeSet::new();
        let mut labels = BTreeSet::new();
        let mut muted = false;
        let mut degraded = false;
        let mut expired = false;
        let mut current_session = None;
        for stored in self.sessions.values() {
            active_scopes.extend(stored.value.active_scopes.iter().copied());
            muted |= stored.value.muted;
            degraded |= stored.value.source_degraded;
            expired |= stored.expires_at <= now;
            if current_session
                .as_ref()
                .is_none_or(|(_, published_at, _)| *published_at < stored.value.published_at)
            {
                current_session = Some((
                    stored.value.session_id,
                    stored.value.published_at,
                    stored.value.muted,
                ));
            }
            if private_labels_allowed {
                labels.extend(
                    stored
                        .value
                        .resources
                        .iter()
                        .map(|resource| resource.display_label.clone()),
                );
            }
        }
        let categories = active_scopes.into_iter().map(scope_display_name).collect();
        let mode = if expired {
            SurfaceMode::Unavailable
        } else if self.sessions.is_empty() {
            SurfaceMode::Inactive
        } else if degraded {
            SurfaceMode::Degraded
        } else if muted {
            SurfaceMode::Muted
        } else {
            SurfaceMode::Observing
        };
        RenderedSurface {
            mode,
            categories,
            resource_labels: labels.into_iter().collect(),
            current_session: current_session.map(|(session, _, _)| session),
            current_session_muted: current_session.is_some_and(|(_, _, muted)| muted),
        }
    }

    fn heartbeat_deadline(&self) -> Option<Instant> {
        self.sessions.values().map(|status| status.expires_at).min()
    }
}

/// A status revision identifies capture semantics, while CORE refreshes the
/// liveness timestamps for that same revision every five seconds. Keep those
/// two concerns separate so a refresh cannot smuggle in changed capture state.
fn same_status_semantics(left: &NativeCaptureStatus, right: &NativeCaptureStatus) -> bool {
    left.revision == right.revision
        && left.session_id == right.session_id
        && left.active_scopes == right.active_scopes
        && left.resources == right.resources
        && left.muted == right.muted
        && left.source_degraded == right.source_degraded
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SurfaceMode {
    Inactive,
    Observing,
    Degraded,
    Muted,
    Unavailable,
}

impl SurfaceMode {
    const fn tooltip(self) -> &'static str {
        match self {
            Self::Inactive => "STEIN: inactive",
            Self::Observing => "STEIN: observing",
            Self::Degraded => "STEIN: observation degraded",
            Self::Muted => "STEIN: interventions muted",
            Self::Unavailable => "STEIN: status unavailable",
        }
    }
}

#[derive(Clone)]
struct RenderedSurface {
    mode: SurfaceMode,
    categories: Vec<&'static str>,
    resource_labels: Vec<String>,
    current_session: Option<FocusSessionId>,
    current_session_muted: bool,
}

trait SurfaceBoundary {
    /// Returns true only when the native shell surface accepted this exact
    /// rendered state. Implementations must not retain the borrowed labels.
    fn render(&mut self, surface: &RenderedSurface) -> bool;
}

fn commit_surface_state(
    current: &mut SurfaceState,
    next: SurfaceState,
    boundary: &mut dyn SurfaceBoundary,
    now: Instant,
) -> Result<(), NativeStatusError> {
    if !boundary.render(&next.rendered(false, now)) {
        return Err(status_error(
            "The Windows notification-area status could not be updated.",
            true,
        ));
    }
    *current = next;
    Ok(())
}

fn recover_surface_state(
    current: &SurfaceState,
    boundary: &mut dyn SurfaceBoundary,
    now: Instant,
) -> bool {
    boundary.render(&current.rendered(false, now))
}

impl fmt::Debug for RenderedSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedSurface")
            .field("mode", &self.mode)
            .field("categories", &self.categories)
            .field("resource_label_count", &self.resource_labels.len())
            .field("has_current_session", &self.current_session.is_some())
            .field("current_session_muted", &self.current_session_muted)
            .finish()
    }
}

struct EmergencyQueue {
    capacity: usize,
    last_revision: u64,
    queued: VecDeque<EmergencyCommandEnvelope>,
    awaiting_acknowledgement: HashMap<(Uuid, u64), Instant>,
}

impl EmergencyQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            last_revision: 0,
            queued: VecDeque::new(),
            awaiting_acknowledgement: HashMap::new(),
        }
    }

    fn enqueue(&mut self, command: EmergencyCommand, issued_at: OffsetDateTime) -> bool {
        match command {
            EmergencyCommand::StopAllObservation => {
                if self
                    .queued
                    .iter()
                    .any(|queued| queued.command == EmergencyCommand::StopAllObservation)
                {
                    return false;
                }
                self.queued.clear();
            }
            EmergencyCommand::SetInterventionsMuted { session_id, .. } => {
                if self
                    .queued
                    .iter()
                    .any(|queued| queued.command == EmergencyCommand::StopAllObservation)
                {
                    return false;
                }
                self.queued.retain(|queued| {
                    !matches!(
                        queued.command,
                        EmergencyCommand::SetInterventionsMuted {
                            session_id: queued_session,
                            ..
                        } if queued_session == session_id
                    )
                });
                self.evict_open_if_full();
            }
            EmergencyCommand::OpenStein => {
                if self.queued.iter().any(|queued| {
                    matches!(
                        queued.command,
                        EmergencyCommand::OpenStein | EmergencyCommand::StopAllObservation
                    )
                }) {
                    return false;
                }
            }
        }
        if self.queued.len() >= self.capacity {
            return false;
        }
        let Some(revision) = self.last_revision.checked_add(1) else {
            return false;
        };
        self.last_revision = revision;
        self.queued.push_back(EmergencyCommandEnvelope {
            command_id: Uuid::now_v7(),
            revision,
            issued_at,
            command,
        });
        true
    }

    fn evict_open_if_full(&mut self) {
        if self.queued.len() < self.capacity {
            return;
        }
        if let Some(index) = self
            .queued
            .iter()
            .position(|queued| queued.command == EmergencyCommand::OpenStein)
        {
            self.queued.remove(index);
        }
    }

    fn pop(&mut self, now: Instant) -> Option<EmergencyCommandEnvelope> {
        let envelope = self.queued.pop_front()?;
        self.awaiting_acknowledgement.insert(
            (envelope.command_id, envelope.revision),
            now + EMERGENCY_ACK_DEADLINE,
        );
        Some(envelope)
    }

    fn acknowledge(
        &mut self,
        acknowledgement: EmergencyCommandAcknowledgement,
    ) -> Result<EmergencyCommandAcknowledgement, &'static str> {
        if self
            .awaiting_acknowledgement
            .remove(&(acknowledgement.command_id, acknowledgement.revision))
            .is_none()
        {
            return Err("The emergency command acknowledgement is unknown or duplicated.");
        }
        Ok(acknowledgement)
    }

    fn has_expired_acknowledgement(&self, now: Instant) -> bool {
        self.awaiting_acknowledgement
            .values()
            .any(|deadline| *deadline <= now)
    }
}

fn validate_status(
    status: &NativeCaptureStatus,
    now: OffsetDateTime,
) -> Result<(), NativeStatusError> {
    if status.revision == 0
        || status.published_at > now + time::Duration::seconds(1)
        || status.heartbeat_deadline <= now
        || status.heartbeat_deadline - status.published_at
            > time::Duration::try_from(STATUS_HEARTBEAT).expect("ten seconds is representable")
    {
        return Err(status_error(
            "The Windows native status timing or revision is invalid.",
            false,
        ));
    }
    if status
        .active_scopes
        .iter()
        .any(|scope| !scope.is_observation())
    {
        return Err(status_error(
            "The Windows native status contains a non-observation scope.",
            false,
        ));
    }
    let mut grants = BTreeSet::new();
    for resource in &status.resources {
        if !status.active_scopes.contains(&resource.scope)
            || !grants.insert(resource.grant_id)
            || !valid_display_label(&resource.display_label)
        {
            return Err(status_error(
                "The Windows native status resource mapping is invalid.",
                false,
            ));
        }
    }
    Ok(())
}

fn valid_display_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= MAX_RESOURCE_LABEL_SCALARS
        && !value.chars().any(|character| character.is_control())
}

const fn scope_display_name(scope: PermissionScope) -> &'static str {
    match scope {
        PermissionScope::ObserveDesktopPresence => "Desktop presence",
        PermissionScope::ObserveDesktopForegroundApplication => "Foreground application",
        PermissionScope::ObserveDesktopWindowMetadata => "Window metadata",
        PermissionScope::ObserveBrowserLocation => "Browser location",
        PermissionScope::ObserveContentVisibleText => "Visible text",
        PermissionScope::ObserveContentSelectedDocument => "Selected document",
        PermissionScope::ObserveScreenPixels => "Screen pixels",
        PermissionScope::ObserveWorkspaceActivity => "Workspace activity",
        PermissionScope::ReasonFocusContext | PermissionScope::InterveneDesktopNotification => {
            "Unavailable category"
        }
    }
}

fn status_error(summary: &'static str, retryable: bool) -> NativeStatusError {
    NativeStatusError { summary, retryable }
}

/// Daemon-owned Windows notification-area surface. One hidden message-window
/// thread owns both the shell icon and the direct emergency-control producer.
/// It has no dependency on the Tauri presentation process.
#[cfg(windows)]
pub struct WindowsNativeSurface {
    shared: Arc<SharedSurface>,
    native: native::NativeSurfaceThread,
}

#[cfg(windows)]
impl WindowsNativeSurface {
    pub fn start() -> Result<Self, WindowsNativeSurfaceError> {
        let shared = Arc::new(SharedSurface::new());
        let native = native::NativeSurfaceThread::start(Arc::clone(&shared))?;
        Ok(Self { shared, native })
    }
}

#[cfg(windows)]
impl fmt::Debug for WindowsNativeSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNativeSurface")
            .field("availability", &self.shared.availability())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl NativeStatusPort for WindowsNativeSurface {
    fn availability(&self) -> PlatformPortAvailability {
        self.shared.availability()
    }

    fn publish<'a>(
        &'a self,
        status: &'a NativeCaptureStatus,
    ) -> stein_core::PortFuture<'a, Result<NativeStatusAcknowledgement, NativeStatusError>> {
        let request = self.native.request_sender();
        let status = status.clone();
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            validate_status(&status, OffsetDateTime::now_utc())?;
            let (response, receiver) = oneshot::channel();
            request
                .send(SurfaceRequest::Publish { status, response })
                .map_err(|_| {
                    shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
                    status_error(
                        "The Windows native status request could not be queued.",
                        true,
                    )
                })?;
            receiver.await.map_err(|_| {
                shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
                status_error("The Windows native status acknowledgement was lost.", true)
            })?
        })
    }

    fn clear<'a>(
        &'a self,
        session_id: FocusSessionId,
        revision: u64,
    ) -> stein_core::PortFuture<'a, Result<NativeStatusAcknowledgement, NativeStatusError>> {
        let request = self.native.request_sender();
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let (response, receiver) = oneshot::channel();
            request
                .send(SurfaceRequest::Clear {
                    session_id,
                    revision,
                    response,
                })
                .map_err(|_| {
                    shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
                    status_error("The Windows native status clear could not be queued.", true)
                })?;
            receiver.await.map_err(|_| {
                shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
                status_error(
                    "The Windows native status clear acknowledgement was lost.",
                    true,
                )
            })?
        })
    }

    fn next_heartbeat<'a>(
        &'a self,
        session_id: FocusSessionId,
    ) -> stein_core::PortFuture<'a, Result<NativeStatusHeartbeat, NativeStatusError>> {
        Box::pin(self.shared.next_heartbeat(session_id))
    }
}

#[cfg(windows)]
impl EmergencyControlPort for WindowsNativeSurface {
    fn availability(&self) -> PlatformPortAvailability {
        self.shared.availability()
    }

    fn next_command<'a>(
        &'a self,
    ) -> stein_core::PortFuture<'a, Result<EmergencyCommandEnvelope, &'static str>> {
        Box::pin(async move {
            loop {
                let notified = self.shared.emergency_notify.notified();
                let command = self
                    .shared
                    .emergency
                    .lock()
                    .map_err(|_| "The Windows emergency-control queue is unavailable.")?
                    .pop(Instant::now());
                if let Some(command) = command {
                    return Ok(command);
                }
                if !self.shared.availability().is_available() {
                    return Err("The Windows emergency-control surface is unavailable.");
                }
                notified.await;
            }
        })
    }

    fn acknowledge<'a>(
        &'a self,
        acknowledgement: EmergencyCommandAcknowledgement,
    ) -> stein_core::PortFuture<'a, Result<EmergencyCommandAcknowledgement, &'static str>> {
        Box::pin(async move {
            self.shared
                .emergency
                .lock()
                .map_err(|_| "The Windows emergency-control queue is unavailable.")?
                .acknowledge(acknowledgement)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stein_core::{NativeResourceStatus, PermissionGrantId};
    use time::macros::datetime;

    fn status(revision: u64) -> NativeCaptureStatus {
        let published_at = datetime!(2026-08-19 12:00 UTC);
        NativeCaptureStatus {
            revision,
            session_id: FocusSessionId::new_v7(),
            active_scopes: BTreeSet::from([
                PermissionScope::ObserveDesktopPresence,
                PermissionScope::ObserveContentSelectedDocument,
            ]),
            resources: vec![NativeResourceStatus {
                grant_id: PermissionGrantId::new_v7(),
                scope: PermissionScope::ObserveContentSelectedDocument,
                display_label: "Synthetic plan".to_owned(),
            }],
            muted: false,
            source_degraded: false,
            published_at,
            heartbeat_deadline: published_at + time::Duration::seconds(10),
        }
    }

    #[test]
    fn exact_revision_and_category_state_is_committed_before_acknowledgement() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let current = SurfaceState::default();
        let value = status(7);
        let (next, acknowledgement) = current.prepare_publish(&value, now_utc, now).unwrap();

        assert_eq!(acknowledgement.session_id, value.session_id);
        assert_eq!(acknowledgement.revision, 7);
        assert_eq!(acknowledgement.heartbeat_deadline, value.heartbeat_deadline);
        assert_eq!(
            next.rendered(true, now).categories,
            vec!["Desktop presence", "Selected document"]
        );
    }

    #[test]
    fn equal_revision_with_different_state_and_stale_clear_fail_closed() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let original = status(7);
        let (state, _) = SurfaceState::default()
            .prepare_publish(&original, now_utc, now)
            .unwrap();
        let mut conflicting = original.clone();
        conflicting.muted = true;

        assert!(state.prepare_publish(&conflicting, now_utc, now).is_err());
        assert!(
            state
                .prepare_clear(original.session_id, 6, now_utc)
                .is_err()
        );
    }

    #[test]
    fn equal_revision_accepts_only_monotonic_liveness_refreshes() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let original = status(7);
        let (state, _) = SurfaceState::default()
            .prepare_publish(&original, now_utc, now)
            .unwrap();
        let mut refreshed = original.clone();
        refreshed.published_at += time::Duration::seconds(1);
        refreshed.heartbeat_deadline += time::Duration::seconds(1);

        let (refreshed_state, acknowledgement) = state
            .prepare_publish(
                &refreshed,
                now_utc + time::Duration::seconds(1),
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(acknowledgement.revision, original.revision);
        assert_eq!(
            refreshed_state
                .sessions
                .get(&original.session_id)
                .unwrap()
                .value,
            refreshed
        );

        let mut stale = original;
        stale.published_at -= time::Duration::milliseconds(1);
        stale.heartbeat_deadline -= time::Duration::milliseconds(1);
        assert!(
            refreshed_state
                .prepare_publish(
                    &stale,
                    now_utc + time::Duration::seconds(1),
                    now + Duration::from_secs(1),
                )
                .is_err()
        );
    }

    #[test]
    fn locked_or_ambiguous_surface_never_renders_resource_labels() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let (state, _) = SurfaceState::default()
            .prepare_publish(&status(1), now_utc, now)
            .unwrap();

        assert_eq!(state.rendered(true, now).resource_labels.len(), 1);
        assert!(state.rendered(false, now).resource_labels.is_empty());
        assert_eq!(state.rendered(false, now).categories.len(), 2);
    }

    #[test]
    fn tooltip_and_debug_output_are_content_free() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let (state, _) = SurfaceState::default()
            .prepare_publish(&status(1), now_utc, now)
            .unwrap();
        let rendered = state.rendered(true, now);

        assert_eq!(rendered.mode.tooltip(), "STEIN: observing");
        let debug = format!("{rendered:?}");
        assert!(!debug.contains("Synthetic plan"));
    }

    #[test]
    fn heartbeat_expiry_becomes_unavailable_instead_of_implying_capture() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let (state, _) = SurfaceState::default()
            .prepare_publish(&status(1), now_utc, now)
            .unwrap();

        assert_eq!(state.rendered(false, now).mode, SurfaceMode::Observing);
        assert_eq!(
            state.rendered(false, now + Duration::from_secs(10)).mode,
            SurfaceMode::Unavailable
        );
    }

    #[tokio::test]
    async fn adapter_heartbeat_stream_is_exact_coalesced_and_reports_loss_immediately() {
        let shared = SharedSurface::new();
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let value = status(7);
        let (state, _) = SurfaceState::default()
            .prepare_publish(&value, now_utc, now)
            .unwrap();
        shared.record_message_loop_heartbeats(&state, now_utc);
        shared.record_message_loop_heartbeats(&state, now_utc + time::Duration::milliseconds(1));

        let heartbeat = shared.next_heartbeat(value.session_id).await.unwrap();
        assert_eq!(heartbeat.session_id, value.session_id);
        assert_eq!(heartbeat.revision, value.revision);
        assert_eq!(
            heartbeat.emitted_at,
            now_utc + time::Duration::milliseconds(1)
        );

        shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
        let error = shared.next_heartbeat(value.session_id).await.unwrap_err();
        assert!(error.retryable);
        assert_eq!(
            error.summary,
            "The Windows native status message loop stopped."
        );
    }

    #[test]
    fn stop_has_precedence_and_clears_lower_priority_backpressure() {
        let mut queue = EmergencyQueue::new(2);
        let issued = datetime!(2026-08-19 12:00 UTC);
        assert!(queue.enqueue(EmergencyCommand::OpenStein, issued));
        assert!(queue.enqueue(
            EmergencyCommand::SetInterventionsMuted {
                session_id: FocusSessionId::new_v7(),
                muted: true,
            },
            issued,
        ));
        assert!(queue.enqueue(EmergencyCommand::StopAllObservation, issued));

        assert_eq!(queue.queued.len(), 1);
        let stop = queue.pop(Instant::now()).unwrap();
        assert_eq!(stop.command, EmergencyCommand::StopAllObservation);
        assert_eq!(stop.revision, 3, "evicted command revisions are not reused");
    }

    #[test]
    fn mute_coalesces_and_open_is_dropped_when_queue_is_full() {
        let mut queue = EmergencyQueue::new(1);
        let issued = datetime!(2026-08-19 12:00 UTC);
        let session = FocusSessionId::new_v7();
        assert!(queue.enqueue(EmergencyCommand::OpenStein, issued));
        assert!(queue.enqueue(
            EmergencyCommand::SetInterventionsMuted {
                session_id: session,
                muted: true,
            },
            issued,
        ));
        assert!(queue.enqueue(
            EmergencyCommand::SetInterventionsMuted {
                session_id: session,
                muted: false,
            },
            issued,
        ));
        assert_eq!(queue.queued.len(), 1);
        assert_eq!(queue.queued.front().unwrap().revision, 3);
        assert_eq!(
            queue.queued.front().unwrap().command,
            EmergencyCommand::SetInterventionsMuted {
                session_id: session,
                muted: false,
            }
        );
    }

    #[test]
    fn command_acknowledgement_is_correlated_and_expires() {
        let mut queue = EmergencyQueue::new(1);
        let issued = datetime!(2026-08-19 12:00 UTC);
        queue.enqueue(EmergencyCommand::OpenStein, issued);
        let now = Instant::now();
        let command = queue.pop(now).unwrap();
        assert_eq!(command.revision, 1);
        assert!(!queue.has_expired_acknowledgement(now));
        assert!(queue.has_expired_acknowledgement(now + EMERGENCY_ACK_DEADLINE));
        assert!(
            queue
                .acknowledge(EmergencyCommandAcknowledgement {
                    command_id: command.command_id,
                    revision: command.revision + 1,
                    status: stein_core::EmergencyCommandStatus::Accepted,
                    acknowledged_at: issued,
                })
                .is_err(),
            "a wrong revision must not consume the real pending acknowledgement"
        );
        let acknowledgement = EmergencyCommandAcknowledgement {
            command_id: command.command_id,
            revision: command.revision,
            status: stein_core::EmergencyCommandStatus::Accepted,
            acknowledged_at: issued,
        };
        assert_eq!(
            queue.acknowledge(acknowledgement.clone()).unwrap(),
            acknowledgement
        );
        assert!(
            queue
                .acknowledge(EmergencyCommandAcknowledgement {
                    command_id: command.command_id,
                    revision: command.revision,
                    status: stein_core::EmergencyCommandStatus::Accepted,
                    acknowledged_at: issued,
                })
                .is_err()
        );
    }

    #[test]
    fn emergency_queue_has_no_desktop_presentation_dependency() {
        let mut queue = EmergencyQueue::new(1);
        assert!(queue.enqueue(
            EmergencyCommand::StopAllObservation,
            datetime!(2026-08-19 12:00 UTC),
        ));
        assert_eq!(
            queue.pop(Instant::now()).unwrap().command,
            EmergencyCommand::StopAllObservation
        );
    }

    #[test]
    fn invalid_labels_and_non_observation_scopes_are_rejected() {
        let now = datetime!(2026-08-19 12:00:01 UTC);
        let mut value = status(1);
        value.resources[0].display_label = "private\nline".to_owned();
        assert!(validate_status(&value, now).is_err());

        let mut value = status(1);
        value
            .active_scopes
            .insert(PermissionScope::ReasonFocusContext);
        assert!(validate_status(&value, now).is_err());
    }

    struct RecordingBoundary {
        succeeds: bool,
        renders: Vec<RenderedSurface>,
    }

    impl SurfaceBoundary for RecordingBoundary {
        fn render(&mut self, surface: &RenderedSurface) -> bool {
            self.renders.push(surface.clone());
            self.succeeds
        }
    }

    #[test]
    fn failed_shell_commit_never_advances_acknowledgeable_state() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let current = SurfaceState::default();
        let value = status(3);
        let (next, _) = current.prepare_publish(&value, now_utc, now).unwrap();
        let mut committed = current;
        let mut boundary = RecordingBoundary {
            succeeds: false,
            renders: Vec::new(),
        };

        assert!(commit_surface_state(&mut committed, next, &mut boundary, now).is_err());
        assert!(committed.sessions.is_empty());
        assert_eq!(boundary.renders[0].categories.len(), 2);
        assert!(boundary.renders[0].resource_labels.is_empty());
    }

    #[test]
    fn explorer_recovery_replays_current_privacy_filtered_state() {
        let now_utc = datetime!(2026-08-19 12:00:01 UTC);
        let now = Instant::now();
        let (state, _) = SurfaceState::default()
            .prepare_publish(&status(4), now_utc, now)
            .unwrap();
        let mut unavailable = RecordingBoundary {
            succeeds: false,
            renders: Vec::new(),
        };
        assert!(!recover_surface_state(&state, &mut unavailable, now));

        let mut restored = RecordingBoundary {
            succeeds: true,
            renders: Vec::new(),
        };
        assert!(recover_surface_state(&state, &mut restored, now));
        assert_eq!(restored.renders[0].categories.len(), 2);
        assert!(restored.renders[0].resource_labels.is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "requires an interactive native Windows Explorer session"]
    async fn native_ports_ack_exact_status_and_route_emergency_control_without_tauri() {
        let surface = WindowsNativeSurface::start().unwrap();
        let published_at = OffsetDateTime::now_utc();
        let value = NativeCaptureStatus {
            revision: 9,
            session_id: FocusSessionId::new_v7(),
            active_scopes: BTreeSet::from([PermissionScope::ObserveDesktopPresence]),
            resources: Vec::new(),
            muted: false,
            source_degraded: false,
            published_at,
            heartbeat_deadline: published_at + time::Duration::seconds(10),
        };
        let acknowledgement = NativeStatusPort::publish(&surface, &value).await.unwrap();
        assert_eq!(acknowledgement.session_id, value.session_id);
        assert_eq!(acknowledgement.revision, value.revision);
        let heartbeat = NativeStatusPort::next_heartbeat(&surface, value.session_id)
            .await
            .unwrap();
        assert_eq!(heartbeat.session_id, value.session_id);
        assert_eq!(heartbeat.revision, value.revision);

        surface.shared.enqueue(EmergencyCommand::StopAllObservation);
        let command = EmergencyControlPort::next_command(&surface).await.unwrap();
        assert_eq!(command.command, EmergencyCommand::StopAllObservation);
        EmergencyControlPort::acknowledge(
            &surface,
            EmergencyCommandAcknowledgement {
                command_id: command.command_id,
                revision: command.revision,
                status: stein_core::EmergencyCommandStatus::Accepted,
                acknowledged_at: OffsetDateTime::now_utc(),
            },
        )
        .await
        .unwrap();

        let cleared = NativeStatusPort::clear(&surface, value.session_id, 10)
            .await
            .unwrap();
        assert_eq!(cleared.revision, 10);
        let shared = Arc::clone(&surface.shared);
        drop(surface);
        let error = shared.next_heartbeat(value.session_id).await.unwrap_err();
        assert_eq!(
            error.summary,
            "The Windows native status message loop stopped."
        );
    }
}
