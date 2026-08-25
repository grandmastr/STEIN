//! Dedicated one-way Microsoft Edge observation producer.
//!
//! This adapter does not expose CORE's client protocol. A package-admitted
//! native host may offer one explicitly selected tab, receive one capture plan
//! projected from fresh durable authority, and then write bounded observations.

use std::collections::HashSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use stein_core::{
    ActorId, BrowserLocationGranularity, DurableRepository, FocusSessionState, GrantState,
    NativeResourceBinding, NativeSelectedResource, NormalizedObservation,
    NormalizedObservationValue, ObservationAdapterEvent, ObservationPort, ObservationPortError,
    ObservationPortErrorKind, ObservationProvenance, ObservationRetention, ObservationSensitivity,
    ObservationSourceStatus, ObservationStartRequest, ObservationSubscription, PermissionScope,
    PlatformPortAvailability, ResourceKind, ResourceSelectionError, ResourceSelectionErrorKind,
    ResourceSelectionPort, SecondMindError, SourceHealth,
};
use stein_platform_windows::{
    BrowserAuthoritySnapshotPort, BrowserCaptureCancellation, BrowserCaptureScope,
    BrowserObservationProducerIngress, BrowserProducerAuthorityReference,
    BrowserProducerIngressError, BrowserProducerIngressErrorKind, BrowserProducerIngressEvent,
    BrowserProducerListener, CurrentBrowserProducerAuthority, EDGE_BROWSER_EXTRACTION_VERSION,
    EDGE_BROWSER_PRODUCER_SOURCE_ID, EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON,
    EDGE_BROWSER_REDACTION_VERSION, EdgeBrowserCapturePlan, EdgeBrowserCapturePolicy,
    EdgeBrowserSourcePauseReason, WindowsBrowserSurfaceBinding, WindowsObservationPort,
};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const PENDING_SELECTION_TIMEOUT: Duration = Duration::from_secs(120);
const SELECT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const CAPTURE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
const EVENT_CAPACITY: usize = 16;
const SAFE_BROWSER_LABEL: &str = "Selected Microsoft Edge tab";

struct PendingSelection {
    binding: WindowsBrowserSurfaceBinding,
    selected: bool,
    capture_sender: oneshot::Sender<PreparedCapture>,
}

struct ActiveCapture {
    session_id: stein_core::FocusSessionId,
    grant_id: stein_core::PermissionGrantId,
    binding: WindowsBrowserSurfaceBinding,
    cancellation: CancellationToken,
    stopped: Arc<CaptureStopped>,
}

struct PreparedCapture {
    reference: BrowserProducerAuthorityReference,
    sender: mpsc::Sender<ObservationAdapterEvent>,
    cancellation: CancellationToken,
    ready: oneshot::Sender<Result<(), ObservationPortError>>,
    stopped: Arc<CaptureStopped>,
}

struct CaptureStopped {
    complete: AtomicBool,
    notification: Notify,
}

impl CaptureStopped {
    fn new() -> Self {
        Self {
            complete: AtomicBool::new(false),
            notification: Notify::new(),
        }
    }

    fn finish(&self) {
        self.complete.store(true, Ordering::Release);
        self.notification.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notification.notified();
            if self.complete.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct ProducerState {
    admitted: AtomicBool,
    pending: Mutex<Option<PendingSelection>>,
    active: Mutex<Vec<ActiveCapture>>,
    selection_available: Notify,
}

impl Default for ProducerState {
    fn default() -> Self {
        Self {
            admitted: AtomicBool::new(false),
            pending: Mutex::new(None),
            active: Mutex::new(Vec::new()),
            selection_available: Notify::new(),
        }
    }
}

#[derive(Clone)]
struct RepositoryAuthority {
    repository: Arc<dyn DurableRepository>,
    owner: ActorId,
}

pub struct WindowsBrowserProducerPort {
    listener: BrowserProducerListener,
    authority: RepositoryAuthority,
    extension_id: &'static str,
    extension_version: &'static str,
    state: Arc<ProducerState>,
}

impl WindowsBrowserProducerPort {
    pub fn new(
        listener: BrowserProducerListener,
        repository: Arc<dyn DurableRepository>,
        owner: ActorId,
        extension_id: &'static str,
        extension_version: &'static str,
    ) -> Self {
        Self {
            listener,
            authority: RepositoryAuthority { repository, owner },
            extension_id,
            extension_version,
            state: Arc::new(ProducerState::default()),
        }
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), SecondMindError> {
        loop {
            let connection = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.listener.accept() => result,
            };
            let Ok(connection) = connection else {
                self.state.admitted.store(false, Ordering::Release);
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                continue;
            };
            self.state.admitted.store(true, Ordering::Release);
            let result = self.handle_connection(connection, &shutdown).await;
            self.state.admitted.store(false, Ordering::Release);
            self.clear_pending();
            if shutdown.is_cancelled() {
                return Ok(());
            }
            if result.is_err() {
                // Admission and wire failures are per-connection, content-free,
                // and must not stop the daemon or broaden fallback behavior.
                continue;
            }
        }
    }

    async fn handle_connection(
        &self,
        mut connection: stein_platform_windows::BrowserProducerConnectionAuthority,
        shutdown: &CancellationToken,
    ) -> Result<(), BrowserProducerIngressError> {
        let binding = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            result = connection.read_selection_offer(
                self.extension_id,
                self.extension_version,
                BrowserLocationGranularity {
                    origin: true,
                    path: true,
                    query: false,
                    fragment: false,
                },
            ) => result?,
        };
        let (capture_sender, capture_receiver) = oneshot::channel();
        {
            let mut pending = self.state.pending.lock().map_err(|_| ingress_internal())?;
            if pending.is_some() {
                return Err(ingress_error(
                    BrowserProducerIngressErrorKind::ConnectionChanged,
                ));
            }
            *pending = Some(PendingSelection {
                binding,
                selected: false,
                capture_sender,
            });
        }
        self.state.selection_available.notify_waiters();

        let prepared = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            result = tokio::time::timeout(PENDING_SELECTION_TIMEOUT, capture_receiver) => {
                result
                    .map_err(|_| ingress_error(BrowserProducerIngressErrorKind::AuthorityUnavailable))?
                    .map_err(|_| ingress_error(BrowserProducerIngressErrorKind::AuthorityUnavailable))?
            }
        };
        let plan = EdgeBrowserCapturePlan::from_policy(
            prepared.reference.policy(),
            self.extension_id,
            self.extension_version,
        )
        .map_err(|_| ingress_error(BrowserProducerIngressErrorKind::AuthorityChanged))?;
        let mut ingress = BrowserObservationProducerIngress::new(
            connection,
            prepared.reference.clone(),
            self.authority.clone(),
        )?;
        if let Err(failure) = ingress.send_capture_plan(&plan).await {
            let _ = prepared.ready.send(Err(boundary_lost()));
            return Err(failure);
        }
        if prepared.ready.send(Ok(())).is_err() {
            prepared.stopped.finish();
            self.remove_active(
                prepared.reference.session_id(),
                prepared.reference.grant_id(),
            );
            return Err(ingress_error(
                BrowserProducerIngressErrorKind::AuthorityChanged,
            ));
        }

        let session_id = prepared.reference.session_id();
        let grant_id = prepared.reference.grant_id();
        if let Err(failure) = self
            .wait_for_active_authority(&prepared.reference, &prepared.cancellation, shutdown)
            .await
        {
            ingress.cancel(BrowserCaptureCancellation::SourceLost);
            prepared.stopped.finish();
            self.remove_active(session_id, grant_id);
            return Err(failure);
        }
        let receive_result = loop {
            let received_at = now_unix_milliseconds();
            let event = tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                () = prepared.cancellation.cancelled() => break Ok(()),
                result = ingress.receive(received_at) => match result {
                    Ok(event) => event,
                    Err(failure) => break Err(failure),
                },
            };
            match event {
                BrowserProducerIngressEvent::Observation(Some(value)) => {
                    let observation = normalize(value, &prepared.reference, received_at)?;
                    if prepared
                        .sender
                        .send(ObservationAdapterEvent::Observation(Box::new(observation)))
                        .await
                        .is_err()
                    {
                        break Ok(());
                    }
                }
                BrowserProducerIngressEvent::Observation(None) => {}
                BrowserProducerIngressEvent::SourcePaused(reason) => {
                    if prepared
                        .sender
                        .send(ObservationAdapterEvent::SourceStatus(source_status(
                            &prepared.reference,
                            SourceHealth::Paused,
                            pause_detail(reason),
                            received_at,
                        )))
                        .await
                        .is_err()
                    {
                        break Ok(());
                    }
                }
            }
        };
        ingress.cancel(BrowserCaptureCancellation::SourceLost);
        let _ = prepared
            .sender
            .try_send(ObservationAdapterEvent::SourceStatus(source_status(
                &prepared.reference,
                SourceHealth::Unavailable,
                "The selected Edge producer connection ended.",
                now_unix_milliseconds(),
            )));
        prepared.stopped.finish();
        self.remove_active(session_id, grant_id);
        receive_result
    }

    fn has_pending_selection(&self) -> bool {
        self.state.admitted.load(Ordering::Acquire)
            && self
                .state
                .pending
                .lock()
                .is_ok_and(|pending| pending.is_some())
    }

    fn has_active_capture(&self) -> bool {
        self.state
            .active
            .lock()
            .is_ok_and(|active| !active.is_empty())
    }

    async fn wait_for_active_authority(
        &self,
        reference: &BrowserProducerAuthorityReference,
        cancellation: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<(), BrowserProducerIngressError> {
        let deadline = tokio::time::sleep(ACTIVE_AUTHORITY_TIMEOUT);
        tokio::pin!(deadline);
        loop {
            match self
                .authority
                .reload_current(reference, now_unix_milliseconds())
            {
                Ok(_) => return Ok(()),
                Err(failure)
                    if failure.kind == BrowserProducerIngressErrorKind::AuthorityChanged => {}
                Err(failure) => return Err(failure),
            }
            tokio::select! {
                () = shutdown.cancelled() => return Err(authority_changed()),
                () = cancellation.cancelled() => return Err(authority_changed()),
                () = &mut deadline => return Err(authority_changed()),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    fn clear_pending(&self) {
        if let Ok(mut pending) = self.state.pending.lock() {
            pending.take();
        }
    }

    fn remove_active(
        &self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) {
        if let Ok(mut active) = self.state.active.lock() {
            active.retain(|value| value.session_id != session_id || value.grant_id != grant_id);
        }
    }

    async fn stop_active(
        &self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> Result<(), ObservationPortError> {
        let capture = {
            let active = self.state.active.lock().map_err(|_| internal_error())?;
            active
                .iter()
                .find(|value| value.session_id == session_id && value.grant_id == grant_id)
                .map(|value| (value.cancellation.clone(), value.stopped.clone()))
        };
        let Some((cancellation, stopped)) = capture else {
            // The ingress loop may have already ended and removed the active
            // entry. That is already stopped, not a route change.
            return Ok(());
        };
        cancellation.cancel();
        tokio::time::timeout(CAPTURE_STOP_TIMEOUT, stopped.wait())
            .await
            .map_err(|_| boundary_lost())?;
        Ok(())
    }
}

#[derive(Default)]
struct BrowserRouteState(
    Mutex<HashSet<(stein_core::FocusSessionId, stein_core::PermissionGrantId)>>,
);

impl BrowserRouteState {
    fn insert(
        &self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> Result<(), ObservationPortError> {
        self.0
            .lock()
            .map_err(|_| internal_error())?
            .insert((session_id, grant_id));
        Ok(())
    }

    fn contains(
        &self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> Result<bool, ObservationPortError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| internal_error())?
            .contains(&(session_id, grant_id)))
    }

    fn remove(
        &self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> Result<(), ObservationPortError> {
        self.0
            .lock()
            .map_err(|_| internal_error())?
            .remove(&(session_id, grant_id));
        Ok(())
    }
}

/// Keeps existing Windows sources and the browser producer independently
/// dispatchable without changing CORE's platform-neutral observation contract.
pub struct WindowsObservationWithBrowser {
    native: Arc<WindowsObservationPort>,
    browser: Arc<WindowsBrowserProducerPort>,
    browser_routes: BrowserRouteState,
}

impl WindowsObservationWithBrowser {
    pub fn new(
        native: Arc<WindowsObservationPort>,
        browser: Arc<WindowsBrowserProducerPort>,
    ) -> Self {
        Self {
            native,
            browser,
            browser_routes: BrowserRouteState::default(),
        }
    }
}

impl ObservationPort for WindowsObservationWithBrowser {
    fn availability(&self, scope: PermissionScope) -> PlatformPortAvailability {
        if scope == PermissionScope::ObserveBrowserLocation {
            ObservationPort::availability(self.browser.as_ref(), scope)
        } else {
            ObservationPort::availability(self.native.as_ref(), scope)
        }
    }

    fn start<'a>(
        &'a self,
        request: &'a ObservationStartRequest,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<ObservationSubscription, ObservationPortError>> {
        if request
            .resource
            .as_ref()
            .is_some_and(|resource| resource.kind == ResourceKind::BrowserSurface)
            || request.grant.scope == PermissionScope::ObserveBrowserLocation
        {
            Box::pin(async move {
                let session_id = request
                    .grant
                    .focus_session_id
                    .ok_or_else(permission_denied)?;
                let subscription = self.browser.start(request, cancellation).await?;
                if let Err(failure) = self.native.mark_external_structured_source_active(
                    session_id,
                    request.grant.id,
                    request.grant.scope,
                ) {
                    let _ = self.browser.stop(session_id, request.grant.id).await;
                    return Err(failure);
                }
                if let Err(failure) = self.browser_routes.insert(session_id, request.grant.id) {
                    let _ = self.browser.stop_active(session_id, request.grant.id).await;
                    let _ = self
                        .native
                        .clear_external_structured_source(session_id, request.grant.id);
                    return Err(failure);
                }
                Ok(subscription)
            })
        } else {
            self.native.start(request, cancellation)
        }
    }

    fn stop<'a>(
        &'a self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> stein_core::PortFuture<'a, Result<(), ObservationPortError>> {
        Box::pin(async move {
            if self.browser_routes.contains(session_id, grant_id)? {
                // Keep the minimization marker until the producer loop has
                // actually stopped; otherwise pixels could race structured
                // browser evidence during cancellation.
                self.browser.stop_active(session_id, grant_id).await?;
                self.native
                    .clear_external_structured_source(session_id, grant_id)?;
                self.browser_routes.remove(session_id, grant_id)?;
                Ok(())
            } else {
                self.native.stop(session_id, grant_id).await
            }
        })
    }
}

impl ResourceSelectionPort for WindowsObservationWithBrowser {
    fn availability(&self) -> PlatformPortAvailability {
        ResourceSelectionPort::availability(self.native.as_ref())
    }

    fn select<'a>(
        &'a self,
        kind: ResourceKind,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<Option<NativeSelectedResource>, ResourceSelectionError>>
    {
        if kind == ResourceKind::BrowserSurface {
            self.browser.select(kind, cancellation)
        } else {
            self.native.select(kind, cancellation)
        }
    }

    fn release<'a>(
        &'a self,
        binding: NativeResourceBinding,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<(), ResourceSelectionError>> {
        if WindowsBrowserSurfaceBinding::parse(binding.as_str()).is_ok() {
            self.browser.release(binding, cancellation)
        } else {
            self.native.release(binding, cancellation)
        }
    }
}

impl ObservationPort for WindowsBrowserProducerPort {
    fn availability(&self, scope: PermissionScope) -> PlatformPortAvailability {
        if matches!(
            scope,
            PermissionScope::ObserveBrowserLocation | PermissionScope::ObserveContentVisibleText
        ) && (self.has_pending_selection() || self.has_active_capture())
        {
            PlatformPortAvailability::Available
        } else {
            PlatformPortAvailability::Unavailable {
                reason: EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON,
            }
        }
    }

    fn start<'a>(
        &'a self,
        request: &'a ObservationStartRequest,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<ObservationSubscription, ObservationPortError>> {
        Box::pin(async move {
            let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
            if resource.kind != ResourceKind::BrowserSurface
                || request.grant.selected_resource_id != Some(resource.id)
                || !browser_grant_is_connection_bound(
                    request.grant.scope,
                    request.grant.daemon_restart_allowed,
                )
            {
                return Err(permission_denied());
            }
            let binding = WindowsBrowserSurfaceBinding::parse(&resource.opaque_reference)
                .map_err(|_| permission_denied())?;
            let policy = EdgeBrowserCapturePolicy {
                binding: binding.clone(),
                scope: if request.grant.scope == PermissionScope::ObserveBrowserLocation {
                    BrowserCaptureScope::Location
                } else {
                    BrowserCaptureScope::VisibleText
                },
                authority_epoch: authority_epoch(),
                maximum_payload_bytes: request.limits.maximum_payload_bytes,
                minimum_interval: request.limits.minimum_interval,
            };
            policy.validate().map_err(|_| permission_denied())?;
            let reference = self
                .authority
                .prepare_reference(request, policy)
                .map_err(|_| permission_denied())?;
            let (sender, events) = mpsc::channel(EVENT_CAPACITY);
            let capture_sender = {
                let mut pending = self.state.pending.lock().map_err(|_| internal_error())?;
                let matches = pending
                    .as_ref()
                    .is_some_and(|pending| pending.selected && pending.binding == binding);
                if !matches {
                    return Err(boundary_lost());
                }
                pending
                    .take()
                    .expect("checked pending selection")
                    .capture_sender
            };
            let (ready, ready_receiver) = oneshot::channel();
            let stopped = Arc::new(CaptureStopped::new());
            let prepared = PreparedCapture {
                reference: reference.clone(),
                sender,
                cancellation: cancellation.clone(),
                ready,
                stopped: stopped.clone(),
            };
            {
                let mut active = self.state.active.lock().map_err(|_| internal_error())?;
                active.push(ActiveCapture {
                    session_id: reference.session_id(),
                    grant_id: reference.grant_id(),
                    binding,
                    cancellation: cancellation.clone(),
                    stopped: stopped.clone(),
                });
            }
            if capture_sender.send(prepared).is_err() {
                stopped.finish();
                self.remove_active(reference.session_id(), reference.grant_id());
                return Err(boundary_lost());
            }
            let ready = tokio::select! {
                () = cancellation.cancelled() => Err(cancelled()),
                result = tokio::time::timeout(CAPTURE_READY_TIMEOUT, ready_receiver) => {
                    result
                        .map_err(|_| boundary_lost())?
                        .map_err(|_| boundary_lost())?
                }
            };
            if let Err(failure) = ready {
                stopped.finish();
                self.remove_active(reference.session_id(), reference.grant_id());
                return Err(failure);
            }
            Ok(ObservationSubscription {
                initial_status: source_status(
                    &reference,
                    SourceHealth::Healthy,
                    "The selected Edge producer is admitted and active.",
                    now_unix_milliseconds(),
                ),
                events,
            })
        })
    }

    fn stop<'a>(
        &'a self,
        session_id: stein_core::FocusSessionId,
        grant_id: stein_core::PermissionGrantId,
    ) -> stein_core::PortFuture<'a, Result<(), ObservationPortError>> {
        Box::pin(async move { self.stop_active(session_id, grant_id).await })
    }
}

impl ResourceSelectionPort for WindowsBrowserProducerPort {
    fn availability(&self) -> PlatformPortAvailability {
        if self.has_pending_selection() {
            PlatformPortAvailability::Available
        } else {
            PlatformPortAvailability::Unavailable {
                reason: EDGE_BROWSER_PRODUCER_UNAVAILABLE_REASON,
            }
        }
    }

    fn select<'a>(
        &'a self,
        kind: ResourceKind,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<Option<NativeSelectedResource>, ResourceSelectionError>>
    {
        Box::pin(async move {
            if kind != ResourceKind::BrowserSurface {
                return Err(selection_unavailable());
            }
            let deadline = tokio::time::sleep(SELECT_WAIT_TIMEOUT);
            tokio::pin!(deadline);
            loop {
                if let Ok(mut pending) = self.state.pending.lock() {
                    if let Some(pending) = pending.as_mut().filter(|pending| !pending.selected) {
                        pending.selected = true;
                        return Ok(Some(NativeSelectedResource {
                            kind: ResourceKind::BrowserSurface,
                            binding: NativeResourceBinding::new(pending.binding.to_string()),
                            safe_display_label: SAFE_BROWSER_LABEL.to_owned(),
                        }));
                    }
                } else {
                    return Err(selection_internal());
                }
                tokio::select! {
                    () = cancellation.cancelled() => return Err(selection_cancelled()),
                    () = &mut deadline => return Err(selection_unavailable()),
                    () = self.state.selection_available.notified() => {}
                }
            }
        })
    }

    fn release<'a>(
        &'a self,
        binding: NativeResourceBinding,
        _cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<(), ResourceSelectionError>> {
        Box::pin(async move {
            let binding = WindowsBrowserSurfaceBinding::parse(binding.as_str())
                .map_err(|_| selection_internal())?;
            if let Ok(mut pending) = self.state.pending.lock() {
                if pending
                    .as_ref()
                    .is_some_and(|pending| pending.binding == binding)
                {
                    pending.take();
                }
            } else {
                return Err(selection_internal());
            }
            let captures = self
                .state
                .active
                .lock()
                .map_err(|_| selection_internal())?
                .iter()
                .filter(|capture| capture.binding == binding)
                .map(|capture| (capture.cancellation.clone(), capture.stopped.clone()))
                .collect();
            cancel_and_wait_for_cleanup(captures, CAPTURE_STOP_TIMEOUT).await
        })
    }
}

async fn cancel_and_wait_for_cleanup(
    captures: Vec<(CancellationToken, Arc<CaptureStopped>)>,
    timeout: Duration,
) -> Result<(), ResourceSelectionError> {
    for (cancellation, _) in &captures {
        cancellation.cancel();
    }
    tokio::time::timeout(timeout, async {
        for (_, stopped) in captures {
            stopped.wait().await;
        }
    })
    .await
    .map_err(|_| selection_cleanup_pending())?;
    Ok(())
}

impl RepositoryAuthority {
    fn prepare_reference(
        &self,
        request: &ObservationStartRequest,
        policy: EdgeBrowserCapturePolicy,
    ) -> Result<BrowserProducerAuthorityReference, BrowserProducerIngressError> {
        let state = self
            .repository
            .load_owner_state(self.owner)
            .map_err(|_| ingress_error(BrowserProducerIngressErrorKind::AuthorityUnavailable))?;
        let now = OffsetDateTime::now_utc();
        let resource = request.resource.as_ref().ok_or_else(authority_changed)?;
        let durable_resource = state
            .resources
            .iter()
            .find(|value| value.id == resource.id)
            .filter(|value| *value == resource)
            .ok_or_else(authority_changed)?;
        let grant = state
            .grants
            .iter()
            .find(|value| value.id == request.grant.id)
            .filter(|value| *value == &request.grant)
            .filter(|value| value.is_current_at(now))
            .ok_or_else(authority_changed)?;
        let session_id = grant.focus_session_id.ok_or_else(authority_changed)?;
        let session = state
            .focus_sessions
            .iter()
            .find(|value| value.id == session_id)
            .filter(|value| {
                matches!(
                    value.state,
                    FocusSessionState::Starting | FocusSessionState::Recovering
                ) && !value.muted
                    && !value.source_degraded
                    && value.permission_grant_ids.contains(&grant.id)
                    && value.selected_resource_ids.contains(&durable_resource.id)
            })
            .ok_or_else(authority_changed)?;
        let active_revision = anticipated_active_revision(session.state, session.revision)
            .ok_or_else(authority_changed)?;
        let current_device = state
            .current_device
            .as_ref()
            .filter(|value| value.device_id == grant.device_id)
            .ok_or_else(authority_changed)?;
        BrowserProducerAuthorityReference::new(
            session.id,
            active_revision,
            grant.id,
            grant.revision,
            durable_resource.id,
            durable_resource.revision,
            current_device.device_id,
            policy,
        )
    }
}

impl BrowserAuthoritySnapshotPort for RepositoryAuthority {
    fn reload_current(
        &self,
        reference: &BrowserProducerAuthorityReference,
        received_at_unix_ms: i64,
    ) -> Result<CurrentBrowserProducerAuthority, BrowserProducerIngressError> {
        let now =
            offset_from_unix_milliseconds(received_at_unix_ms).ok_or_else(authority_changed)?;
        let state = self
            .repository
            .load_owner_state(self.owner)
            .map_err(|_| ingress_error(BrowserProducerIngressErrorKind::AuthorityUnavailable))?;
        let session = state
            .focus_sessions
            .iter()
            .find(|value| value.id == reference.session_id())
            .filter(|value| {
                active_revision_matches(value.state, value.revision, reference.session_revision())
            })
            .filter(|value| {
                !value.muted
                    && !value.source_degraded
                    && value.permission_grant_ids.contains(&reference.grant_id())
                    && value
                        .selected_resource_ids
                        .contains(&reference.resource_id())
            })
            .ok_or_else(authority_changed)?;
        let grant = state
            .grants
            .iter()
            .find(|value| value.id == reference.grant_id())
            .filter(|value| {
                value.revision == reference.grant_revision()
                    && value.owner == self.owner
                    && value.state == GrantState::Active
                    && value.is_current_at(now)
                    && value.focus_session_id == Some(reference.session_id())
                    && value.selected_resource_id == Some(reference.resource_id())
                    && value.device_id == reference.device_id()
                    && scope_matches_policy(value.scope, reference.policy().scope)
            })
            .ok_or_else(authority_changed)?;
        let resource = state
            .resources
            .iter()
            .find(|value| value.id == reference.resource_id())
            .filter(|value| {
                value.revision == reference.resource_revision()
                    && value.owner == self.owner
                    && value.kind == ResourceKind::BrowserSurface
                    && WindowsBrowserSurfaceBinding::parse(&value.opaque_reference)
                        .is_ok_and(|binding| binding == reference.policy().binding)
            })
            .ok_or_else(authority_changed)?;
        state
            .current_device
            .as_ref()
            .filter(|value| value.device_id == reference.device_id())
            .ok_or_else(authority_changed)?;
        CurrentBrowserProducerAuthority::new(
            session.id,
            session.revision,
            grant.id,
            grant.revision,
            resource.id,
            resource.revision,
            reference.device_id(),
            reference.policy().clone(),
        )
    }
}

fn normalize(
    value: stein_platform_windows::AuthorizedBrowserObservation,
    reference: &BrowserProducerAuthorityReference,
    received_at_unix_ms: i64,
) -> Result<NormalizedObservation, BrowserProducerIngressError> {
    let received_at =
        offset_from_unix_milliseconds(received_at_unix_ms).ok_or_else(authority_changed)?;
    let observed_at = offset_from_unix_milliseconds(value.packet.observed_at_unix_ms)
        .ok_or_else(authority_changed)?;
    let normalized_value = match reference.policy().scope {
        BrowserCaptureScope::Location => NormalizedObservationValue::BrowserLocation {
            origin: value.packet.origin,
            path: value.packet.relative_location,
            query_included: value.packet.query_included,
            fragment_included: value.packet.fragment_included,
        },
        BrowserCaptureScope::VisibleText => NormalizedObservationValue::VisibleText {
            bounded_text: value
                .packet
                .visible_text
                .ok_or_else(|| ingress_error(BrowserProducerIngressErrorKind::PacketRejected))?,
        },
    };
    Ok(NormalizedObservation {
        observation_id: Uuid::now_v7(),
        session_id: value.session_id,
        grant_id: value.grant_id,
        grant_revision: value.grant_revision,
        device_id: value.device_id,
        value: normalized_value,
        provenance: ObservationProvenance {
            source_id: EDGE_BROWSER_PRODUCER_SOURCE_ID.to_owned(),
            source_event_id: Uuid::now_v7(),
            selected_resource_id: Some(value.resource_id),
            observed_at,
            received_at,
            extraction_version: EDGE_BROWSER_EXTRACTION_VERSION.to_owned(),
            redaction_version: EDGE_BROWSER_REDACTION_VERSION.to_owned(),
            normalization_schema_version: "browser-observation-v1".to_owned(),
            confidence_basis_points: 10_000,
            complete: true,
            sensitivity: ObservationSensitivity::Personal,
            retention: ObservationRetention::EphemeralSession,
            browser_granularity: Some(reference.policy().binding.granularity()),
        },
    })
}

fn source_status(
    reference: &BrowserProducerAuthorityReference,
    health: SourceHealth,
    detail: &'static str,
    observed_at_unix_ms: i64,
) -> ObservationSourceStatus {
    ObservationSourceStatus {
        source_id: EDGE_BROWSER_PRODUCER_SOURCE_ID.to_owned(),
        grant_id: reference.grant_id(),
        scope: match reference.policy().scope {
            BrowserCaptureScope::Location => PermissionScope::ObserveBrowserLocation,
            BrowserCaptureScope::VisibleText => PermissionScope::ObserveContentVisibleText,
        },
        resource_id: Some(reference.resource_id()),
        health,
        detail,
        observed_at: offset_from_unix_milliseconds(observed_at_unix_ms)
            .unwrap_or_else(OffsetDateTime::now_utc),
    }
}

const fn pause_detail(reason: EdgeBrowserSourcePauseReason) -> &'static str {
    match reason {
        EdgeBrowserSourcePauseReason::PausedBackground => {
            "The selected Edge tab is not the active focused surface."
        }
        EdgeBrowserSourcePauseReason::PausedProtected => {
            "The selected Edge surface does not permit the approved extraction."
        }
    }
}

const fn scope_matches_policy(scope: PermissionScope, policy: BrowserCaptureScope) -> bool {
    matches!(
        (scope, policy),
        (
            PermissionScope::ObserveBrowserLocation,
            BrowserCaptureScope::Location
        ) | (
            PermissionScope::ObserveContentVisibleText,
            BrowserCaptureScope::VisibleText
        )
    )
}

fn authority_epoch() -> u64 {
    let bytes = *Uuid::now_v7().as_bytes();
    u64::from_be_bytes(bytes[..8].try_into().expect("UUID prefix is eight bytes")).max(1)
}

fn anticipated_active_revision(state: FocusSessionState, revision: u64) -> Option<u64> {
    matches!(
        state,
        FocusSessionState::Starting | FocusSessionState::Recovering
    )
    .then(|| revision.checked_add(1))
    .flatten()
}

const fn browser_grant_is_connection_bound(
    scope: PermissionScope,
    daemon_restart_allowed: bool,
) -> bool {
    !daemon_restart_allowed
        && matches!(
            scope,
            PermissionScope::ObserveBrowserLocation | PermissionScope::ObserveContentVisibleText
        )
}

const fn active_revision_matches(
    state: FocusSessionState,
    revision: u64,
    anticipated_revision: u64,
) -> bool {
    matches!(state, FocusSessionState::Active) && revision == anticipated_revision
}

fn now_unix_milliseconds() -> i64 {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

fn offset_from_unix_milliseconds(value: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000).ok()
}

const fn ingress_error(kind: BrowserProducerIngressErrorKind) -> BrowserProducerIngressError {
    BrowserProducerIngressError {
        kind,
        summary: "The Edge browser producer ingress rejected the value.",
    }
}

const fn ingress_internal() -> BrowserProducerIngressError {
    ingress_error(BrowserProducerIngressErrorKind::AuthorityUnavailable)
}

const fn authority_changed() -> BrowserProducerIngressError {
    ingress_error(BrowserProducerIngressErrorKind::AuthorityChanged)
}

const fn permission_denied() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::PermissionDenied,
        summary: "The Edge observation request is outside current authority.",
    }
}

const fn boundary_lost() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::BoundaryLost,
        summary: "The selected Edge producer boundary is unavailable.",
    }
}

const fn internal_error() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Internal,
        summary: "The Edge observation adapter is unavailable.",
    }
}

const fn cancelled() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Cancelled,
        summary: "The Edge observation request was cancelled.",
    }
}

const fn selection_unavailable() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Unavailable,
        summary: "Invoke the STEIN Edge action on the exact tab before selecting this resource.",
        retryable: true,
    }
}

const fn selection_cancelled() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Cancelled,
        summary: "The Edge selection was cancelled.",
        retryable: false,
    }
}

const fn selection_internal() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Internal,
        summary: "The Edge selection boundary is unavailable.",
        retryable: true,
    }
}

const fn selection_cleanup_pending() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Internal,
        summary: "The Edge producer cleanup has not completed.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_stop_waiter_completes_only_after_ingress_finishes() {
        let stopped = Arc::new(CaptureStopped::new());
        let waiting = {
            let stopped = stopped.clone();
            tokio::spawn(async move { stopped.wait().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        stopped.finish();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("completion should wake the stop waiter")
            .expect("stop waiter should not panic");
    }

    #[tokio::test]
    async fn resource_cleanup_cancels_then_waits_and_times_out_retryably() {
        let cancellation = CancellationToken::new();
        let stopped = Arc::new(CaptureStopped::new());
        let completion = {
            let stopped = stopped.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                stopped.finish();
            })
        };
        cancel_and_wait_for_cleanup(
            vec![(cancellation.clone(), stopped)],
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        completion.await.unwrap();
        assert!(cancellation.is_cancelled());

        let stalled_cancellation = CancellationToken::new();
        let failure = cancel_and_wait_for_cleanup(
            vec![(
                stalled_cancellation.clone(),
                Arc::new(CaptureStopped::new()),
            )],
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();
        assert!(stalled_cancellation.is_cancelled());
        assert!(failure.retryable);
    }

    #[test]
    fn connection_end_keeps_browser_route_until_idempotent_stop_cleanup() {
        let routes = BrowserRouteState::default();
        let session_id = stein_core::FocusSessionId::new_v7();
        let grant_id = stein_core::PermissionGrantId::new_v7();

        routes.insert(session_id, grant_id).unwrap();
        // The ingress active entry may already be gone, but the composite route
        // remains so a later stop still clears pixel minimization.
        assert!(routes.contains(session_id, grant_id).unwrap());
        routes.remove(session_id, grant_id).unwrap();
        assert!(!routes.contains(session_id, grant_id).unwrap());
        routes.remove(session_id, grant_id).unwrap();
        assert!(!routes.contains(session_id, grant_id).unwrap());
    }

    #[test]
    fn starting_and_recovering_reference_only_the_next_active_revision() {
        for state in [FocusSessionState::Starting, FocusSessionState::Recovering] {
            let anticipated = anticipated_active_revision(state, 9).unwrap();
            assert_eq!(anticipated, 10);
            assert!(!active_revision_matches(state, 9, anticipated));
            assert!(active_revision_matches(
                FocusSessionState::Active,
                10,
                anticipated,
            ));
            assert!(!active_revision_matches(
                FocusSessionState::Active,
                11,
                anticipated,
            ));
        }
        assert_eq!(
            anticipated_active_revision(FocusSessionState::Starting, u64::MAX),
            None
        );
    }

    #[test]
    fn browser_adapter_rejects_restart_continuity_for_both_scopes() {
        for scope in [
            PermissionScope::ObserveBrowserLocation,
            PermissionScope::ObserveContentVisibleText,
        ] {
            assert!(browser_grant_is_connection_bound(scope, false));
            assert!(!browser_grant_is_connection_bound(scope, true));
        }
        assert!(!browser_grant_is_connection_bound(
            PermissionScope::ObserveDesktopWindowMetadata,
            false,
        ));
    }
}
