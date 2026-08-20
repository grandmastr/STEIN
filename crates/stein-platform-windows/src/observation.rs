use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stein_core::{
    Clock, FocusSessionId, ForegroundApplicationState, GrantState, NativeResourceBinding,
    NativeSelectedResource, NormalizedObservation, NormalizedObservationValue,
    ObservationAdapterEvent, ObservationPort, ObservationPortError, ObservationPortErrorKind,
    ObservationProvenance, ObservationRetention, ObservationSensitivity, ObservationSourceStatus,
    ObservationStartRequest, ObservationSubscription, PermissionGrant, PermissionGrantId,
    PermissionScope, PlatformPortAvailability, PresenceState, ResourceId, ResourceKind,
    ResourceSelectionError, ResourceSelectionErrorKind, ResourceSelectionPort, SensitiveText,
    SourceHealth, SystemClock, WorkspaceActivityKind,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::foreground::{
    ForegroundIdentityProbe, ForegroundMatch, ForegroundProbeError, ForegroundProbeErrorKind,
    NativeForegroundIdentityProbe,
};
use crate::selected_resource::{
    MAXIMUM_DOCUMENT_BYTES, NativeSelectedResourceFactory, SelectedDocumentRead,
    SelectedResourceError, SelectedResourceErrorKind, SelectedResourceEventSource,
    SelectedResourceFactory, SelectedResourceReceive,
};
use crate::uia::{
    MAXIMUM_UIA_TEXT_BYTES, NativeUiaTextSourceFactory, UiaError, UiaErrorKind, UiaInvocationError,
    UiaTextSource, UiaTextSourceFactory, VisibleTextSample, bounded_uia_read,
    bounded_uia_revalidate,
};
use crate::uia_binding::WindowsUiaWindowBinding;
use crate::{
    PresenceEvent, PresenceMonitorError, PresenceUpdateSource, WindowsApplicationBinding,
    WindowsPresenceMonitor, WindowsSelectedResourceBinding,
};

const PRESENCE_SOURCE_ID: &str = "windows:presence:wts-last-input:v1";
const FOREGROUND_SOURCE_ID: &str = "windows:foreground:exact-app-identity:v1";
const DOCUMENT_SOURCE_ID: &str = "windows:selected-document:file-id-128:v1";
const WORKSPACE_SOURCE_ID: &str = "windows:selected-workspace:directory-changes:v1";
const UIA_SOURCE_ID: &str = "windows:selected-window:uia-text-pattern-visible:v1";
const EVENT_BUFFER_CAPACITY: usize = 16;
const URGENT_EVENT_RESERVE: usize = 2;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MINIMUM_PRESENCE_INTERVAL: Duration = Duration::from_secs(1);
const MINIMUM_FOREGROUND_INTERVAL: Duration = Duration::from_secs(1);
const MINIMUM_SELECTED_RESOURCE_INTERVAL: Duration = Duration::from_secs(5);
const SELECTED_RESOURCE_COALESCE_INTERVAL: Duration = Duration::from_secs(2);
const UIA_COALESCE_INTERVAL: Duration = Duration::from_secs(2);
const MINIMUM_UIA_INTERVAL: Duration = Duration::from_secs(5);
const MAXIMUM_PENDING_NATIVE_SELECTIONS: usize = 16;
const NATIVE_PICKER_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);
const MAXIMUM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const MAXIMUM_STALE_AFTER: Duration = Duration::from_secs(30);

type SourceKey = (FocusSessionId, PermissionGrantId);

trait PresenceEventSource: Send {
    fn initial_event(&self) -> PresenceEvent;
    fn recv_timeout(&self, timeout: Duration) -> PresenceReceive;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresenceReceive {
    Event(PresenceEvent),
    Timeout,
    Closed,
}

trait PresenceSourceFactory: Send + Sync {
    fn start(
        &self,
        idle_threshold: Duration,
    ) -> Result<Box<dyn PresenceEventSource>, PresenceMonitorError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct NativePresenceFactory;

impl PresenceSourceFactory for NativePresenceFactory {
    fn start(
        &self,
        idle_threshold: Duration,
    ) -> Result<Box<dyn PresenceEventSource>, PresenceMonitorError> {
        let monitor = WindowsPresenceMonitor::start(idle_threshold)?;
        let mut initial = PresenceEvent {
            state: monitor.current_state(),
            source: PresenceUpdateSource::InitialSessionQuery,
        };
        while let Ok(event) = monitor.try_recv() {
            initial = event;
        }
        Ok(Box::new(NativePresenceSource { monitor, initial }))
    }
}

struct NativePresenceSource {
    monitor: WindowsPresenceMonitor,
    initial: PresenceEvent,
}

impl PresenceEventSource for NativePresenceSource {
    fn initial_event(&self) -> PresenceEvent {
        self.initial
    }

    fn recv_timeout(&self, timeout: Duration) -> PresenceReceive {
        match self.monitor.recv_timeout(timeout) {
            Ok(event) => PresenceReceive::Event(event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => PresenceReceive::Timeout,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => PresenceReceive::Closed,
        }
    }
}

struct ActiveSource {
    cancellation: CancellationToken,
    thread: Option<JoinHandle<()>>,
    native_selection_token: Option<String>,
}

struct ObservationInner {
    clock: Arc<dyn Clock>,
    presence_factory: Arc<dyn PresenceSourceFactory>,
    foreground_probe: Arc<dyn ForegroundIdentityProbe>,
    selected_factory: Arc<dyn SelectedResourceFactory>,
    uia_factory: Arc<dyn UiaTextSourceFactory>,
    uia_selections: Mutex<HashMap<String, WindowsUiaWindowBinding>>,
    idle_threshold: Duration,
    active: Mutex<HashMap<SourceKey, ActiveSource>>,
}

impl Drop for ObservationInner {
    fn drop(&mut self) {
        let active = self
            .active
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        let mut sources: Vec<_> = active.drain().map(|(_, source)| source).collect();
        for source in &sources {
            source.cancellation.cancel();
        }
        for source in &mut sources {
            if let Some(thread) = source.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

/// Windows implementation of CORE's observation port.
#[derive(Clone)]
pub struct WindowsObservationPort {
    inner: Arc<ObservationInner>,
}

impl WindowsObservationPort {
    /// Creates a port with an explicit active/idle threshold. There is no hidden
    /// product default because CORE policy does not yet define that threshold.
    pub fn new(idle_threshold: Duration) -> Result<Self, ObservationPortError> {
        crate::PresenceTracker::new(idle_threshold).map_err(|_| invalid_configuration())?;
        Ok(Self {
            inner: Arc::new(ObservationInner {
                clock: Arc::new(SystemClock::default()),
                presence_factory: Arc::new(NativePresenceFactory),
                foreground_probe: Arc::new(NativeForegroundIdentityProbe),
                selected_factory: Arc::new(NativeSelectedResourceFactory),
                uia_factory: Arc::new(NativeUiaTextSourceFactory),
                uia_selections: Mutex::new(HashMap::new()),
                idle_threshold,
                active: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[cfg(test)]
    fn with_components(
        idle_threshold: Duration,
        clock: Arc<dyn Clock>,
        presence_factory: Arc<dyn PresenceSourceFactory>,
    ) -> Self {
        Self {
            inner: Arc::new(ObservationInner {
                clock,
                presence_factory,
                foreground_probe: Arc::new(NativeForegroundIdentityProbe),
                selected_factory: Arc::new(NativeSelectedResourceFactory),
                uia_factory: Arc::new(NativeUiaTextSourceFactory),
                uia_selections: Mutex::new(HashMap::new()),
                idle_threshold,
                active: Mutex::new(HashMap::new()),
            }),
        }
    }

    #[cfg(test)]
    fn with_all_components(
        idle_threshold: Duration,
        clock: Arc<dyn Clock>,
        presence_factory: Arc<dyn PresenceSourceFactory>,
        foreground_probe: Arc<dyn ForegroundIdentityProbe>,
    ) -> Self {
        Self {
            inner: Arc::new(ObservationInner {
                clock,
                presence_factory,
                foreground_probe,
                selected_factory: Arc::new(NativeSelectedResourceFactory),
                uia_factory: Arc::new(NativeUiaTextSourceFactory),
                uia_selections: Mutex::new(HashMap::new()),
                idle_threshold,
                active: Mutex::new(HashMap::new()),
            }),
        }
    }

    #[cfg(test)]
    fn with_selected_components(
        idle_threshold: Duration,
        clock: Arc<dyn Clock>,
        selected_factory: Arc<dyn SelectedResourceFactory>,
    ) -> Self {
        Self {
            inner: Arc::new(ObservationInner {
                clock,
                presence_factory: Arc::new(NativePresenceFactory),
                foreground_probe: Arc::new(NativeForegroundIdentityProbe),
                selected_factory,
                uia_factory: Arc::new(NativeUiaTextSourceFactory),
                uia_selections: Mutex::new(HashMap::new()),
                idle_threshold,
                active: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Resolves the current foreground application into the canonical Windows
    /// resource reference used during an explicit, trusted selection flow.
    /// The returned value contains no title, path, or process identifier.
    pub fn resolve_current_foreground_binding(
        &self,
    ) -> Result<WindowsApplicationBinding, ObservationPortError> {
        self.inner
            .foreground_probe
            .resolve_current()
            .map_err(map_foreground_probe_error)
    }

    /// Opens the trusted native file picker and returns only the canonical,
    /// path-free identity of the exact selected UTF-8 `.txt` or `.md` file.
    pub fn select_document_binding(
        &self,
    ) -> Result<WindowsSelectedResourceBinding, ObservationPortError> {
        let cancellation = CancellationToken::new();
        self.inner
            .selected_factory
            .select_document(&cancellation)
            .map_err(map_selected_resource_error)
    }

    /// Opens the trusted native folder picker and returns only the canonical,
    /// path-free identity of the exact selected NTFS workspace.
    pub fn select_workspace_binding(
        &self,
    ) -> Result<WindowsSelectedResourceBinding, ObservationPortError> {
        let cancellation = CancellationToken::new();
        self.inner
            .selected_factory
            .select_workspace(&cancellation)
            .map_err(map_selected_resource_error)
    }

    /// Runs an explicit, daemon-owned native selection flow. The presentation
    /// requests only a semantic kind; the next deliberately clicked top-level
    /// window is resolved and revalidated in this adapter. Native identities
    /// and the opaque result never cross the renderer boundary.
    pub async fn select_native_resource(
        &self,
        kind: ResourceKind,
        cancellation: CancellationToken,
    ) -> Result<Option<NativeSelectedResource>, ResourceSelectionError> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        match kind {
            ResourceKind::Window => self.select_native_window(cancellation).await,
            ResourceKind::Document | ResourceKind::Workspace => {
                self.select_native_file_resource(kind, cancellation).await
            }
            _ => Err(resource_selection_unavailable()),
        }
    }

    async fn select_native_window(
        &self,
        cancellation: CancellationToken,
    ) -> Result<Option<NativeSelectedResource>, ResourceSelectionError> {
        let factory = Arc::clone(&self.inner.uia_factory);
        let picker_cancellation = cancellation.clone();
        let mut picker =
            tokio::task::spawn_blocking(move || factory.select_window(&picker_cancellation));
        let binding = tokio::select! {
            _ = cancellation.cancelled() => {
                if tokio::time::timeout(NATIVE_PICKER_CLEANUP_DEADLINE, &mut picker).await.is_err() {
                    picker.abort();
                    return Err(resource_selection_internal());
                }
                return Ok(None);
            }
            result = &mut picker => result
                .map_err(|_| resource_selection_internal())?
                .map_err(map_uia_selection_error)?,
        };
        let Some(binding) = binding else {
            return Ok(None);
        };
        let token = format!("winnative:v1:uia:{}", Uuid::now_v7());
        let mut selections = self
            .inner
            .uia_selections
            .lock()
            .map_err(|_| resource_selection_internal())?;
        if selections.len() >= MAXIMUM_PENDING_NATIVE_SELECTIONS {
            return Err(resource_selection_unavailable());
        }
        selections.insert(token.clone(), binding);
        Ok(Some(NativeSelectedResource {
            kind: ResourceKind::Window,
            binding: NativeResourceBinding::new(token),
            safe_display_label: "Selected window".to_owned(),
        }))
    }

    async fn select_native_file_resource(
        &self,
        kind: ResourceKind,
        cancellation: CancellationToken,
    ) -> Result<Option<NativeSelectedResource>, ResourceSelectionError> {
        let factory = Arc::clone(&self.inner.selected_factory);
        let picker_cancellation = cancellation.clone();
        let mut picker = tokio::task::spawn_blocking(move || match kind {
            ResourceKind::Document => factory.select_document(&picker_cancellation),
            ResourceKind::Workspace => factory.select_workspace(&picker_cancellation),
            _ => Err(SelectedResourceError {
                kind: SelectedResourceErrorKind::UnsupportedType,
            }),
        });
        let result = tokio::select! {
            result = &mut picker => result.map_err(|_| resource_selection_internal())?,
            _ = cancellation.cancelled() => {
                match tokio::time::timeout(NATIVE_PICKER_CLEANUP_DEADLINE, &mut picker).await {
                    Ok(result) => result.map_err(|_| resource_selection_internal())?,
                    Err(_) => {
                        picker.abort();
                        return Err(resource_selection_internal());
                    }
                }
            }
        };
        let binding = match result {
            Ok(binding) => binding,
            Err(error) if error.kind == SelectedResourceErrorKind::Cancelled => return Ok(None),
            Err(error) => return Err(map_selected_resource_selection_error(error)),
        };
        if binding.kind() != kind {
            return Err(resource_selection_internal());
        }
        Ok(Some(NativeSelectedResource {
            kind,
            binding: NativeResourceBinding::new(binding.to_string()),
            safe_display_label: match kind {
                ResourceKind::Document => "Selected document",
                ResourceKind::Workspace => "Selected workspace",
                _ => return Err(resource_selection_internal()),
            }
            .to_owned(),
        }))
    }

    /// Releases a native selection that CORE did not register or no longer
    /// needs. The exact HWND/process binding remains adapter-local and is
    /// discarded on restart in all cases.
    fn release_native_selection(
        &self,
        opaque_reference: &str,
    ) -> Result<(), ResourceSelectionError> {
        if canonical_uia_selection_token(opaque_reference) {
            self.inner
                .uia_selections
                .lock()
                .map_err(|_| resource_selection_internal())?
                .remove(opaque_reference);
            return Ok(());
        }
        let binding = WindowsSelectedResourceBinding::parse(opaque_reference)
            .map_err(|_| resource_selection_unavailable())?;
        if !matches!(
            binding.kind(),
            ResourceKind::Document | ResourceKind::Workspace
        ) || binding.to_string() != opaque_reference
        {
            return Err(resource_selection_unavailable());
        }
        // File/workspace bindings contain only canonical stable file identity;
        // the picker retains no live handle or private path after selection.
        Ok(())
    }

    fn start_presence(
        &self,
        request: &ObservationStartRequest,
        external_cancellation: CancellationToken,
    ) -> Result<ObservationSubscription, ObservationPortError> {
        validate_presence_request(request, self.inner.clock.now_utc())?;
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let session_id = request
            .grant
            .focus_session_id
            .ok_or_else(permission_denied)?;
        let key = (session_id, request.grant.id);
        {
            let active = self.inner.active.lock().map_err(|_| internal_error())?;
            if active.contains_key(&key) {
                return Err(ObservationPortError {
                    kind: ObservationPortErrorKind::BoundaryLost,
                    summary: "The Windows observation source is already active for this grant.",
                });
            }
        }

        let source = self
            .inner
            .presence_factory
            .start(self.inner.idle_threshold)
            .map_err(|_| unavailable())?;
        let now = self.inner.clock.now_utc();
        let initial_status = ObservationSourceStatus {
            source_id: PRESENCE_SOURCE_ID.to_owned(),
            grant_id: request.grant.id,
            scope: PermissionScope::ObserveDesktopPresence,
            resource_id: None,
            health: SourceHealth::Healthy,
            detail: "The Windows presence source is initialized.",
            observed_at: now,
        };
        let (events, receiver) = mpsc::channel(EVENT_BUFFER_CAPACITY);
        let stop_cancellation = CancellationToken::new();
        let worker_stop = stop_cancellation.clone();
        let worker_clock = Arc::clone(&self.inner.clock);
        let grant = request.grant.clone();
        let limits = request.limits.clone();
        let thread = thread::Builder::new()
            .name("stein-observation-presence".to_owned())
            .spawn(move || {
                run_presence_source(
                    source,
                    grant,
                    limits,
                    worker_clock,
                    external_cancellation,
                    worker_stop,
                    events,
                );
            })
            .map_err(|_| internal_error())?;

        let mut active = match self.inner.active.lock() {
            Ok(active) => active,
            Err(_) => {
                stop_cancellation.cancel();
                let _ = thread.join();
                return Err(internal_error());
            }
        };
        if active.contains_key(&key) {
            stop_cancellation.cancel();
            drop(active);
            let _ = thread.join();
            return Err(ObservationPortError {
                kind: ObservationPortErrorKind::BoundaryLost,
                summary: "The Windows observation source is already active for this grant.",
            });
        }
        active.insert(
            key,
            ActiveSource {
                cancellation: stop_cancellation,
                thread: Some(thread),
                native_selection_token: None,
            },
        );

        Ok(ObservationSubscription {
            initial_status,
            events: receiver,
        })
    }

    fn start_foreground(
        &self,
        request: &ObservationStartRequest,
        external_cancellation: CancellationToken,
    ) -> Result<ObservationSubscription, ObservationPortError> {
        let binding = validate_foreground_request(request, self.inner.clock.now_utc())?;
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let session_id = request
            .grant
            .focus_session_id
            .ok_or_else(permission_denied)?;
        let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
        let key = (session_id, request.grant.id);
        {
            let active = self.inner.active.lock().map_err(|_| internal_error())?;
            if active.contains_key(&key) {
                return Err(ObservationPortError {
                    kind: ObservationPortErrorKind::BoundaryLost,
                    summary: "The Windows observation source is already active for this grant.",
                });
            }
        }

        let initial_probe = self.inner.foreground_probe.classify_current(&binding);
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let initial_status = foreground_status(
            &request.grant,
            resource.id,
            foreground_health(&initial_probe),
            foreground_detail(&initial_probe),
            self.inner.clock.now_utc(),
        );
        let (events, receiver) = mpsc::channel(EVENT_BUFFER_CAPACITY);
        let stop_cancellation = CancellationToken::new();
        let worker_stop = stop_cancellation.clone();
        let worker_clock = Arc::clone(&self.inner.clock);
        let worker_probe = Arc::clone(&self.inner.foreground_probe);
        let grant = request.grant.clone();
        let limits = request.limits.clone();
        let resource_id = resource.id;
        let thread = thread::Builder::new()
            .name("stein-observation-foreground".to_owned())
            .spawn(move || {
                run_foreground_source(
                    worker_probe,
                    binding,
                    initial_probe,
                    grant,
                    resource_id,
                    limits,
                    worker_clock,
                    external_cancellation,
                    worker_stop,
                    events,
                );
            })
            .map_err(|_| internal_error())?;

        let mut active = match self.inner.active.lock() {
            Ok(active) => active,
            Err(_) => {
                stop_cancellation.cancel();
                let _ = thread.join();
                return Err(internal_error());
            }
        };
        if active.contains_key(&key) {
            stop_cancellation.cancel();
            drop(active);
            let _ = thread.join();
            return Err(ObservationPortError {
                kind: ObservationPortErrorKind::BoundaryLost,
                summary: "The Windows observation source is already active for this grant.",
            });
        }
        active.insert(
            key,
            ActiveSource {
                cancellation: stop_cancellation,
                thread: Some(thread),
                native_selection_token: None,
            },
        );

        Ok(ObservationSubscription {
            initial_status,
            events: receiver,
        })
    }

    fn start_selected_resource(
        &self,
        request: &ObservationStartRequest,
        external_cancellation: CancellationToken,
    ) -> Result<ObservationSubscription, ObservationPortError> {
        let binding = validate_selected_resource_request(request, self.inner.clock.now_utc())?;
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let session_id = request
            .grant
            .focus_session_id
            .ok_or_else(permission_denied)?;
        let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
        let key = (session_id, request.grant.id);
        {
            let active = self.inner.active.lock().map_err(|_| internal_error())?;
            if active.contains_key(&key) {
                return Err(ObservationPortError {
                    kind: ObservationPortErrorKind::BoundaryLost,
                    summary: "The Windows observation source is already active for this grant.",
                });
            }
        }

        let mut source = self
            .inner
            .selected_factory
            .open(&binding)
            .map_err(map_selected_resource_error)?;
        source.revalidate().map_err(map_selected_resource_error)?;
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let initial_status = selected_resource_status(
            &request.grant,
            resource.id,
            SourceHealth::Healthy,
            selected_resource_healthy_detail(request.grant.scope),
            self.inner.clock.now_utc(),
        );
        let (events, receiver) = mpsc::channel(EVENT_BUFFER_CAPACITY);
        let stop_cancellation = CancellationToken::new();
        let worker_stop = stop_cancellation.clone();
        let worker_clock = Arc::clone(&self.inner.clock);
        let grant = request.grant.clone();
        let limits = request.limits.clone();
        let resource_id = resource.id;
        let thread = thread::Builder::new()
            .name(match request.grant.scope {
                PermissionScope::ObserveContentSelectedDocument => {
                    "stein-observation-selected-document".to_owned()
                }
                PermissionScope::ObserveWorkspaceActivity => {
                    "stein-observation-selected-workspace".to_owned()
                }
                _ => return Err(permission_denied()),
            })
            .spawn(move || {
                run_selected_resource_source(
                    &mut *source,
                    grant,
                    resource_id,
                    limits,
                    worker_clock,
                    external_cancellation,
                    worker_stop,
                    events,
                );
            })
            .map_err(|_| internal_error())?;

        let mut active = match self.inner.active.lock() {
            Ok(active) => active,
            Err(_) => {
                stop_cancellation.cancel();
                let _ = thread.join();
                return Err(internal_error());
            }
        };
        if active.contains_key(&key) {
            stop_cancellation.cancel();
            drop(active);
            let _ = thread.join();
            return Err(ObservationPortError {
                kind: ObservationPortErrorKind::BoundaryLost,
                summary: "The Windows observation source is already active for this grant.",
            });
        }
        active.insert(
            key,
            ActiveSource {
                cancellation: stop_cancellation,
                thread: Some(thread),
                native_selection_token: None,
            },
        );

        Ok(ObservationSubscription {
            initial_status,
            events: receiver,
        })
    }

    fn start_uia_text(
        &self,
        request: &ObservationStartRequest,
        external_cancellation: CancellationToken,
    ) -> Result<ObservationSubscription, ObservationPortError> {
        let selection_token = validate_uia_request(request, self.inner.clock.now_utc())?;
        let binding = self
            .inner
            .uia_selections
            .lock()
            .map_err(|_| internal_error())?
            .get(&selection_token)
            .cloned()
            .ok_or_else(unavailable)?;
        if external_cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let session_id = request
            .grant
            .focus_session_id
            .ok_or_else(permission_denied)?;
        let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
        let key = (session_id, request.grant.id);
        {
            let active = self.inner.active.lock().map_err(|_| internal_error())?;
            if active.contains_key(&key) {
                return Err(ObservationPortError {
                    kind: ObservationPortErrorKind::BoundaryLost,
                    summary: "The Windows observation source is already active for this grant.",
                });
            }
        }

        let source = self
            .inner
            .uia_factory
            .open(&binding)
            .map_err(map_uia_error)?;
        let initial_status = uia_status(
            &request.grant,
            resource.id,
            SourceHealth::Unknown,
            "The exact selected-window UI Automation source is initializing.",
            self.inner.clock.now_utc(),
        );
        let (events, receiver) = mpsc::channel(EVENT_BUFFER_CAPACITY);
        let stop_cancellation = CancellationToken::new();
        let worker_stop = stop_cancellation.clone();
        let worker_clock = Arc::clone(&self.inner.clock);
        let grant = request.grant.clone();
        let limits = request.limits.clone();
        let resource_id = resource.id;
        let selection_cleanup = Arc::downgrade(&self.inner);
        let worker_selection_token = selection_token.clone();
        let thread = thread::Builder::new()
            .name("stein-observation-uia-visible-text".to_owned())
            .spawn(move || {
                run_uia_source(
                    source,
                    grant,
                    resource_id,
                    limits,
                    worker_clock,
                    external_cancellation,
                    worker_stop,
                    events,
                );
                if let Some(inner) = selection_cleanup.upgrade()
                    && let Ok(mut selections) = inner.uia_selections.lock()
                {
                    selections.remove(&worker_selection_token);
                }
            })
            .map_err(|_| internal_error())?;

        let mut active = match self.inner.active.lock() {
            Ok(active) => active,
            Err(_) => {
                stop_cancellation.cancel();
                let _ = thread.join();
                return Err(internal_error());
            }
        };
        if active.contains_key(&key) {
            stop_cancellation.cancel();
            drop(active);
            let _ = thread.join();
            return Err(ObservationPortError {
                kind: ObservationPortErrorKind::BoundaryLost,
                summary: "The Windows observation source is already active for this grant.",
            });
        }
        active.insert(
            key,
            ActiveSource {
                cancellation: stop_cancellation,
                thread: Some(thread),
                native_selection_token: Some(selection_token),
            },
        );

        Ok(ObservationSubscription {
            initial_status,
            events: receiver,
        })
    }
}

impl fmt::Debug for WindowsObservationPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsObservationPort")
            .finish_non_exhaustive()
    }
}

impl ObservationPort for WindowsObservationPort {
    fn availability(&self, scope: PermissionScope) -> PlatformPortAvailability {
        match scope {
            PermissionScope::ObserveDesktopPresence
            | PermissionScope::ObserveDesktopForegroundApplication
            | PermissionScope::ObserveContentVisibleText
            | PermissionScope::ObserveContentSelectedDocument
            | PermissionScope::ObserveWorkspaceActivity => PlatformPortAvailability::Available,
            _ => PlatformPortAvailability::Unavailable {
                reason: "This Windows observation source is not implemented.",
            },
        }
    }

    fn start<'a>(
        &'a self,
        request: &'a ObservationStartRequest,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<ObservationSubscription, ObservationPortError>> {
        Box::pin(async move {
            match request.grant.scope {
                PermissionScope::ObserveDesktopPresence => {
                    self.start_presence(request, cancellation)
                }
                PermissionScope::ObserveDesktopForegroundApplication => {
                    self.start_foreground(request, cancellation)
                }
                PermissionScope::ObserveContentVisibleText => {
                    self.start_uia_text(request, cancellation)
                }
                PermissionScope::ObserveContentSelectedDocument
                | PermissionScope::ObserveWorkspaceActivity => {
                    self.start_selected_resource(request, cancellation)
                }
                _ => Err(unavailable()),
            }
        })
    }

    fn stop<'a>(
        &'a self,
        session_id: FocusSessionId,
        grant_id: PermissionGrantId,
    ) -> stein_core::PortFuture<'a, Result<(), ObservationPortError>> {
        Box::pin(async move {
            let source = {
                let mut active = self.inner.active.lock().map_err(|_| internal_error())?;
                if active.keys().any(|(active_session, active_grant)| {
                    *active_grant == grant_id && *active_session != session_id
                }) {
                    return Err(ObservationPortError {
                        kind: ObservationPortErrorKind::BoundaryLost,
                        summary: "The observation grant belongs to another focus session.",
                    });
                }
                active.remove(&(session_id, grant_id))
            };
            if let Some(mut source) = source {
                source.cancellation.cancel();
                let join_failed = source
                    .thread
                    .take()
                    .is_some_and(|thread| thread.join().is_err());
                if let Some(token) = source.native_selection_token.take() {
                    self.inner
                        .uia_selections
                        .lock()
                        .map_err(|_| internal_error())?
                        .remove(&token);
                }
                if join_failed {
                    return Err(internal_error());
                }
            }
            Ok(())
        })
    }
}

impl ResourceSelectionPort for WindowsObservationPort {
    fn availability(&self) -> PlatformPortAvailability {
        PlatformPortAvailability::Available
    }

    fn select<'a>(
        &'a self,
        kind: ResourceKind,
        cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<Option<NativeSelectedResource>, ResourceSelectionError>>
    {
        Box::pin(async move { self.select_native_resource(kind, cancellation).await })
    }

    fn release<'a>(
        &'a self,
        binding: NativeResourceBinding,
        _cancellation: CancellationToken,
    ) -> stein_core::PortFuture<'a, Result<(), ResourceSelectionError>> {
        Box::pin(async move {
            // Cleanup is local and bounded, so rollback is honored even when
            // the operation cancellation that caused it is already set.
            self.release_native_selection(binding.as_str())
        })
    }
}

struct PresencePublisher {
    grant: PermissionGrant,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    events: mpsc::Sender<ObservationAdapterEvent>,
    health: SourceHealth,
    last_emitted_state: Option<PresenceState>,
    last_observation_elapsed: Option<Duration>,
    last_heartbeat: Instant,
}

impl PresencePublisher {
    fn process(&mut self, event: PresenceEvent) -> bool {
        match event.state {
            PresenceState::Active | PresenceState::Idle => {
                let recovering = self.health != SourceHealth::Healthy;
                if recovering && !self.status(SourceHealth::Healthy, healthy_detail()) {
                    return false;
                }
                self.observation(event, recovering)
            }
            PresenceState::Locked | PresenceState::SwitchedAway => {
                if self.health == SourceHealth::Healthy && !self.observation(event, true) {
                    return false;
                }
                self.status(
                    SourceHealth::Paused,
                    "The Windows session is locked or switched away.",
                )
            }
            PresenceState::Unknown => {
                if self.health == SourceHealth::Healthy && !self.observation(event, true) {
                    return false;
                }
                self.status(
                    SourceHealth::Unknown,
                    "Windows presence is awaiting fresh native session health.",
                )
            }
        }
    }

    fn observation(&mut self, event: PresenceEvent, bypass_rate: bool) -> bool {
        if self.last_emitted_state == Some(event.state) {
            return true;
        }
        let elapsed = self.clock.monotonic_elapsed();
        if !bypass_rate
            && self
                .last_observation_elapsed
                .is_some_and(|last| elapsed.saturating_sub(last) < self.limits.minimum_interval)
        {
            return true;
        }
        let now = self.clock.now_utc();
        let session_id = match self.grant.focus_session_id {
            Some(session_id) => session_id,
            None => return false,
        };
        let (confidence_basis_points, complete) = match event.state {
            PresenceState::Locked | PresenceState::SwitchedAway => (10_000, true),
            PresenceState::Active | PresenceState::Idle => (9_500, true),
            PresenceState::Unknown => (0, false),
        };
        let observation = NormalizedObservation {
            observation_id: Uuid::now_v7(),
            session_id,
            grant_id: self.grant.id,
            grant_revision: self.grant.revision,
            device_id: self.grant.device_id,
            value: NormalizedObservationValue::Presence(event.state),
            provenance: ObservationProvenance {
                source_id: PRESENCE_SOURCE_ID.to_owned(),
                source_event_id: Uuid::now_v7(),
                selected_resource_id: None,
                observed_at: now,
                received_at: now,
                extraction_version: match event.source {
                    PresenceUpdateSource::IdleSample => "windows-get-last-input-info-v1",
                    _ => "windows-wts-session-v1",
                }
                .to_owned(),
                redaction_version: "no-input-content-v1".to_owned(),
                normalization_schema_version: "stein-presence-v1".to_owned(),
                confidence_basis_points,
                complete,
                sensitivity: ObservationSensitivity::Personal,
                retention: ObservationRetention::EphemeralSession,
                browser_granularity: None,
            },
        };
        let required_reserve = if bypass_rate { 1 } else { URGENT_EVENT_RESERVE };
        if self.events.capacity() <= required_reserve {
            // Ordinary state changes are coalesced so two slots always remain
            // for an immediate lock/switch observation followed by Paused.
            return !bypass_rate;
        }
        if !self.send(ObservationAdapterEvent::Observation(Box::new(observation))) {
            return false;
        }
        self.last_emitted_state = Some(event.state);
        self.last_observation_elapsed = Some(elapsed);
        true
    }

    fn status(&mut self, health: SourceHealth, detail: &'static str) -> bool {
        let status = ObservationSourceStatus {
            source_id: PRESENCE_SOURCE_ID.to_owned(),
            grant_id: self.grant.id,
            scope: PermissionScope::ObserveDesktopPresence,
            resource_id: None,
            health,
            detail,
            observed_at: self.clock.now_utc(),
        };
        if !self.send(ObservationAdapterEvent::SourceStatus(status)) {
            return false;
        }
        self.health = health;
        self.last_heartbeat = Instant::now();
        true
    }

    fn heartbeat(&mut self) -> bool {
        if self.events.capacity() <= URGENT_EVENT_RESERVE {
            // A healthy heartbeat may be coalesced under backpressure; native
            // state transitions retain the reserved channel capacity.
            self.last_heartbeat = Instant::now();
            return true;
        }
        self.status(self.health, health_detail(self.health))
    }

    fn send(&self, event: ObservationAdapterEvent) -> bool {
        self.events.try_send(event).is_ok()
    }
}

fn run_presence_source(
    source: Box<dyn PresenceEventSource>,
    grant: PermissionGrant,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    external_cancellation: CancellationToken,
    stop_cancellation: CancellationToken,
    events: mpsc::Sender<ObservationAdapterEvent>,
) {
    let initial_event = source.initial_event();
    let mut publisher = PresencePublisher {
        grant,
        limits,
        clock,
        events,
        health: SourceHealth::Healthy,
        last_emitted_state: None,
        last_observation_elapsed: None,
        last_heartbeat: Instant::now(),
    };
    if !publisher.process(initial_event) {
        return;
    }
    let mut last_native_event = Instant::now();

    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The Windows presence source was cancelled.",
            );
            return;
        }
        if publisher.clock.now_utc() >= publisher.grant.expires_at
            || publisher.grant.state != GrantState::Active
        {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The Windows presence grant is no longer current.",
            );
            return;
        }
        let heartbeat_remaining = publisher
            .limits
            .heartbeat_interval
            .saturating_sub(publisher.last_heartbeat.elapsed());
        let wait = CANCELLATION_POLL_INTERVAL.min(heartbeat_remaining);
        match source.recv_timeout(wait) {
            PresenceReceive::Event(event) => {
                last_native_event = Instant::now();
                if !publisher.process(event) {
                    return;
                }
            }
            PresenceReceive::Timeout => {}
            PresenceReceive::Closed => {
                let _ = publisher.status(
                    SourceHealth::Unavailable,
                    "The Windows presence event source closed unexpectedly.",
                );
                return;
            }
        }
        if last_native_event.elapsed() > publisher.limits.stale_after
            && publisher.health != SourceHealth::Degraded
            && !publisher.status(
                SourceHealth::Degraded,
                "The Windows presence source missed its native freshness bound.",
            )
        {
            return;
        }
        if publisher.last_heartbeat.elapsed() >= publisher.limits.heartbeat_interval
            && !publisher.heartbeat()
        {
            return;
        }
    }
}

struct ForegroundPublisher {
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    events: mpsc::Sender<ObservationAdapterEvent>,
    extraction_version: &'static str,
    health: SourceHealth,
    failure: Option<ForegroundProbeErrorKind>,
    last_emitted_state: Option<ForegroundMatch>,
    last_observation_elapsed: Option<Duration>,
    last_heartbeat: Instant,
}

impl ForegroundPublisher {
    fn process(&mut self, result: Result<ForegroundMatch, ForegroundProbeError>) -> bool {
        match result {
            Ok(state) => {
                let recovering = self.health != SourceHealth::Healthy;
                if recovering
                    && !self.status(
                        SourceHealth::Healthy,
                        "The exact Windows foreground identity source is healthy.",
                    )
                {
                    return false;
                }
                self.failure = None;
                self.observation(state, recovering)
            }
            Err(error) => {
                self.last_emitted_state = None;
                let health = foreground_error_health(error.kind);
                if self.failure == Some(error.kind) && self.health == health {
                    return true;
                }
                if !self.status(health, foreground_error_detail(error.kind)) {
                    return false;
                }
                self.failure = Some(error.kind);
                true
            }
        }
    }

    fn observation(&mut self, state: ForegroundMatch, bypass_rate: bool) -> bool {
        if self.last_emitted_state == Some(state) {
            return true;
        }
        let elapsed = self.clock.monotonic_elapsed();
        if !bypass_rate
            && self
                .last_observation_elapsed
                .is_some_and(|last| elapsed.saturating_sub(last) < self.limits.minimum_interval)
        {
            return true;
        }
        if self.events.capacity() <= 1 {
            // Preserve one slot for a health transition. Foreground membership
            // is level-triggered and will be re-sampled after backpressure.
            return true;
        }
        let session_id = match self.grant.focus_session_id {
            Some(session_id) => session_id,
            None => return false,
        };
        let now = self.clock.now_utc();
        let value = match state {
            ForegroundMatch::Selected => NormalizedObservationValue::ForegroundApplication(
                ForegroundApplicationState::Selected {
                    application_id: self.resource_id.to_string(),
                },
            ),
            ForegroundMatch::OutsideSelectedScope => {
                NormalizedObservationValue::ForegroundApplication(
                    ForegroundApplicationState::OutsideSelectedScope,
                )
            }
        };
        let observation = NormalizedObservation {
            observation_id: Uuid::now_v7(),
            session_id,
            grant_id: self.grant.id,
            grant_revision: self.grant.revision,
            device_id: self.grant.device_id,
            value,
            provenance: ObservationProvenance {
                source_id: FOREGROUND_SOURCE_ID.to_owned(),
                source_event_id: Uuid::now_v7(),
                selected_resource_id: Some(self.resource_id),
                observed_at: now,
                received_at: now,
                extraction_version: self.extraction_version.to_owned(),
                redaction_version: "selected-resource-membership-only-v1".to_owned(),
                normalization_schema_version: "stein-foreground-application-v1".to_owned(),
                confidence_basis_points: 10_000,
                complete: true,
                sensitivity: ObservationSensitivity::Personal,
                retention: ObservationRetention::EphemeralSession,
                browser_granularity: None,
            },
        };
        if !self.send(ObservationAdapterEvent::Observation(Box::new(observation))) {
            return false;
        }
        self.last_emitted_state = Some(state);
        self.last_observation_elapsed = Some(elapsed);
        true
    }

    fn status(&mut self, health: SourceHealth, detail: &'static str) -> bool {
        let status = foreground_status(
            &self.grant,
            self.resource_id,
            health,
            detail,
            self.clock.now_utc(),
        );
        if !self.send(ObservationAdapterEvent::SourceStatus(status)) {
            return false;
        }
        self.health = health;
        self.last_heartbeat = Instant::now();
        true
    }

    fn heartbeat(&mut self) -> bool {
        if self.events.capacity() <= 1 {
            self.last_heartbeat = Instant::now();
            return true;
        }
        let detail = self.failure.map_or(
            "The exact Windows foreground identity source is healthy.",
            foreground_error_detail,
        );
        self.status(self.health, detail)
    }

    fn send(&self, event: ObservationAdapterEvent) -> bool {
        self.events.try_send(event).is_ok()
    }
}

#[allow(clippy::too_many_arguments)]
fn run_foreground_source(
    probe: Arc<dyn ForegroundIdentityProbe>,
    binding: WindowsApplicationBinding,
    initial_probe: Result<ForegroundMatch, ForegroundProbeError>,
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    external_cancellation: CancellationToken,
    stop_cancellation: CancellationToken,
    events: mpsc::Sender<ObservationAdapterEvent>,
) {
    let extraction_version = match binding {
        WindowsApplicationBinding::Packaged(_) => "windows-pfn-aumid-v1",
        WindowsApplicationBinding::Unpackaged(_) => {
            "windows-file-id-authenticode-publisher-sha256-v1"
        }
    };
    let initial_health = foreground_health(&initial_probe);
    let mut last_exact_probe = Instant::now();
    let mut publisher = ForegroundPublisher {
        grant,
        resource_id,
        limits,
        clock,
        events,
        extraction_version,
        health: initial_health,
        failure: initial_probe.as_ref().err().map(|error| error.kind),
        last_emitted_state: None,
        last_observation_elapsed: None,
        last_heartbeat: Instant::now(),
    };
    if !publisher.process(initial_probe) {
        return;
    }
    let mut next_probe = Instant::now() + publisher.limits.minimum_interval;

    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The Windows foreground identity source was cancelled.",
            );
            return;
        }
        if publisher.clock.now_utc() >= publisher.grant.expires_at
            || publisher.grant.state != GrantState::Active
        {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The Windows foreground observation grant is no longer current.",
            );
            return;
        }

        let now = Instant::now();
        let probe_remaining = next_probe.saturating_duration_since(now);
        let heartbeat_remaining = publisher
            .limits
            .heartbeat_interval
            .saturating_sub(publisher.last_heartbeat.elapsed());
        let wait = CANCELLATION_POLL_INTERVAL
            .min(probe_remaining)
            .min(heartbeat_remaining);
        if !wait.is_zero() {
            thread::sleep(wait);
        }

        if Instant::now() >= next_probe {
            let mut result = probe.classify_current(&binding);
            if result.is_ok() {
                last_exact_probe = Instant::now();
            } else if matches!(
                result,
                Err(ForegroundProbeError {
                    kind: ForegroundProbeErrorKind::BoundaryLost
                })
            ) && last_exact_probe.elapsed() > publisher.limits.stale_after
            {
                result = Err(ForegroundProbeError {
                    kind: ForegroundProbeErrorKind::Unavailable,
                });
            }
            if !publisher.process(result) {
                return;
            }
            next_probe = Instant::now() + publisher.limits.minimum_interval;
        }
        if publisher.last_heartbeat.elapsed() >= publisher.limits.heartbeat_interval
            && !publisher.heartbeat()
        {
            return;
        }
    }
}

struct SelectedResourcePublisher {
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    events: mpsc::Sender<ObservationAdapterEvent>,
    last_observation_elapsed: Option<Duration>,
    last_heartbeat: Instant,
}

impl SelectedResourcePublisher {
    fn ready_for_observation(&self) -> bool {
        self.last_observation_elapsed.is_none_or(|last| {
            self.clock.monotonic_elapsed().saturating_sub(last) >= self.limits.minimum_interval
        })
    }

    fn document(&mut self, sample: &crate::selected_resource::SelectedDocumentSample) -> bool {
        if sample.text.len() > self.limits.maximum_payload_bytes
            || sample.text.len() > MAXIMUM_DOCUMENT_BYTES
        {
            return false;
        }
        if self.events.capacity() <= 1 {
            return true;
        }
        let Some(session_id) = self.grant.focus_session_id else {
            return false;
        };
        let now = self.clock.now_utc();
        let observation = NormalizedObservation {
            observation_id: Uuid::now_v7(),
            session_id,
            grant_id: self.grant.id,
            grant_revision: self.grant.revision,
            device_id: self.grant.device_id,
            value: NormalizedObservationValue::SelectedDocument {
                bounded_text: SensitiveText::new(sample.text.clone()),
            },
            provenance: ObservationProvenance {
                source_id: DOCUMENT_SOURCE_ID.to_owned(),
                source_event_id: Uuid::now_v7(),
                selected_resource_id: Some(self.resource_id),
                observed_at: now,
                received_at: now,
                extraction_version: "windows-file-id-128-utf8-text-v1".to_owned(),
                redaction_version: "windows-selected-text-sensitive-lines-v1".to_owned(),
                normalization_schema_version: "stein-selected-document-v1".to_owned(),
                confidence_basis_points: 10_000,
                complete: sample.complete,
                sensitivity: ObservationSensitivity::Restricted,
                retention: ObservationRetention::EphemeralSession,
                browser_granularity: None,
            },
        };
        if self
            .events
            .try_send(ObservationAdapterEvent::Observation(Box::new(observation)))
            .is_err()
        {
            return false;
        }
        self.last_observation_elapsed = Some(self.clock.monotonic_elapsed());
        true
    }

    fn workspace(&mut self, activity: WorkspaceActivityKind) -> bool {
        if self.events.capacity() <= 1 {
            return true;
        }
        let Some(session_id) = self.grant.focus_session_id else {
            return false;
        };
        let now = self.clock.now_utc();
        let observation = NormalizedObservation {
            observation_id: Uuid::now_v7(),
            session_id,
            grant_id: self.grant.id,
            grant_revision: self.grant.revision,
            device_id: self.grant.device_id,
            value: NormalizedObservationValue::WorkspaceActivity { activity },
            provenance: ObservationProvenance {
                source_id: WORKSPACE_SOURCE_ID.to_owned(),
                source_event_id: Uuid::now_v7(),
                selected_resource_id: Some(self.resource_id),
                observed_at: now,
                received_at: now,
                extraction_version: "windows-read-directory-changes-action-only-v1".to_owned(),
                redaction_version: "no-file-or-directory-names-v1".to_owned(),
                normalization_schema_version: "stein-workspace-activity-v1".to_owned(),
                confidence_basis_points: 10_000,
                complete: true,
                sensitivity: ObservationSensitivity::Personal,
                retention: ObservationRetention::EphemeralSession,
                browser_granularity: None,
            },
        };
        if self
            .events
            .try_send(ObservationAdapterEvent::Observation(Box::new(observation)))
            .is_err()
        {
            return false;
        }
        self.last_observation_elapsed = Some(self.clock.monotonic_elapsed());
        true
    }

    fn status(&mut self, health: SourceHealth, detail: &'static str) -> bool {
        let status = selected_resource_status(
            &self.grant,
            self.resource_id,
            health,
            detail,
            self.clock.now_utc(),
        );
        if self
            .events
            .try_send(ObservationAdapterEvent::SourceStatus(status))
            .is_err()
        {
            return false;
        }
        self.last_heartbeat = Instant::now();
        true
    }

    fn heartbeat(&mut self) -> bool {
        if self.events.capacity() <= 1 {
            self.last_heartbeat = Instant::now();
            return true;
        }
        self.status(
            SourceHealth::Healthy,
            selected_resource_healthy_detail(self.grant.scope),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn run_selected_resource_source(
    source: &mut dyn SelectedResourceEventSource,
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    external_cancellation: CancellationToken,
    stop_cancellation: CancellationToken,
    events: mpsc::Sender<ObservationAdapterEvent>,
) {
    let kind = source.kind();
    let mut publisher = SelectedResourcePublisher {
        grant,
        resource_id,
        limits,
        clock,
        events,
        last_observation_elapsed: None,
        last_heartbeat: Instant::now(),
    };
    let mut pending_activity = None;
    let mut pending_since = None;

    if kind == ResourceKind::Document {
        match source.read_document(publisher.limits.maximum_payload_bytes, true) {
            Ok(SelectedDocumentRead::Sample(sample)) => {
                if publisher.document(&sample) {
                    source.commit_document(sample.fingerprint);
                } else {
                    return;
                }
            }
            Ok(SelectedDocumentRead::Retry) => {
                pending_since = Some(publisher.clock.monotonic_elapsed());
            }
            Ok(SelectedDocumentRead::Unchanged) => {}
            Err(error) => {
                let _ = selected_resource_failure_status(&mut publisher, error);
                return;
            }
        }
    }

    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The exact Windows selected-resource source was cancelled.",
            );
            return;
        }
        if publisher.clock.now_utc() >= publisher.grant.expires_at
            || publisher.grant.state != GrantState::Active
        {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The exact Windows selected-resource grant is no longer current.",
            );
            return;
        }

        let elapsed = publisher.clock.monotonic_elapsed();
        let coalesced = pending_since.is_some_and(|since| {
            elapsed.saturating_sub(since) >= SELECTED_RESOURCE_COALESCE_INTERVAL
        });
        if coalesced && publisher.ready_for_observation() && publisher.events.capacity() > 1 {
            if let Err(error) = source.revalidate() {
                let _ = selected_resource_failure_status(&mut publisher, error);
                return;
            }
            match kind {
                ResourceKind::Document => {
                    match source.read_document(publisher.limits.maximum_payload_bytes, false) {
                        Ok(SelectedDocumentRead::Sample(sample)) => {
                            if !publisher.document(&sample) {
                                return;
                            }
                            source.commit_document(sample.fingerprint);
                            pending_since = None;
                        }
                        Ok(SelectedDocumentRead::Unchanged) => pending_since = None,
                        Ok(SelectedDocumentRead::Retry) => {
                            pending_since = Some(publisher.clock.monotonic_elapsed());
                        }
                        Err(error) => {
                            let _ = selected_resource_failure_status(&mut publisher, error);
                            return;
                        }
                    }
                }
                ResourceKind::Workspace => {
                    if let Some(activity) = pending_activity.take()
                        && !publisher.workspace(activity)
                    {
                        return;
                    }
                    pending_since = None;
                }
                _ => {
                    let _ = selected_resource_failure_status(
                        &mut publisher,
                        SelectedResourceError {
                            kind: SelectedResourceErrorKind::UnsupportedType,
                        },
                    );
                    return;
                }
            }
        }

        if publisher.last_heartbeat.elapsed() >= publisher.limits.heartbeat_interval {
            if let Err(error) = source.revalidate() {
                let _ = selected_resource_failure_status(&mut publisher, error);
                return;
            }
            if !publisher.heartbeat() {
                return;
            }
        }

        let heartbeat_remaining = publisher
            .limits
            .heartbeat_interval
            .saturating_sub(publisher.last_heartbeat.elapsed());
        let wait = CANCELLATION_POLL_INTERVAL.min(heartbeat_remaining);
        match source.receive(wait) {
            Ok(SelectedResourceReceive::Activity(activity)) => {
                if let Err(error) = source.revalidate() {
                    let _ = selected_resource_failure_status(&mut publisher, error);
                    return;
                }
                pending_activity = coalesce_workspace_activity(pending_activity, activity);
                pending_since.get_or_insert_with(|| publisher.clock.monotonic_elapsed());
            }
            Ok(SelectedResourceReceive::Timeout) => {}
            Err(error) => {
                let _ = selected_resource_failure_status(&mut publisher, error);
                return;
            }
        }
    }
}

fn coalesce_workspace_activity(
    current: Option<WorkspaceActivityKind>,
    next: WorkspaceActivityKind,
) -> Option<WorkspaceActivityKind> {
    fn priority(value: WorkspaceActivityKind) -> u8 {
        match value {
            WorkspaceActivityKind::Modified => 0,
            WorkspaceActivityKind::Created => 1,
            WorkspaceActivityKind::Deleted => 2,
            WorkspaceActivityKind::Renamed => 3,
        }
    }
    match current {
        Some(current) if priority(current) >= priority(next) => Some(current),
        _ => Some(next),
    }
}

struct UiaPublisher {
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    events: mpsc::Sender<ObservationAdapterEvent>,
    last_observation_elapsed: Option<Duration>,
    last_fingerprint: Option<u64>,
    last_heartbeat: Instant,
}

impl UiaPublisher {
    fn ready_for_observation(&self) -> bool {
        self.last_observation_elapsed.is_none_or(|last| {
            self.clock.monotonic_elapsed().saturating_sub(last) >= self.limits.minimum_interval
        })
    }

    fn visible_text(&mut self, sample: VisibleTextSample) -> bool {
        if sample.text.len() > self.limits.maximum_payload_bytes
            || sample.text.len() > MAXIMUM_UIA_TEXT_BYTES
        {
            return false;
        }
        if sample.text.is_empty() {
            self.last_fingerprint = Some(sample.fingerprint);
            return true;
        }
        if self.events.capacity() <= 1 {
            return true;
        }
        let Some(session_id) = self.grant.focus_session_id else {
            return false;
        };
        let now = self.clock.now_utc();
        let observation = NormalizedObservation {
            observation_id: Uuid::now_v7(),
            session_id,
            grant_id: self.grant.id,
            grant_revision: self.grant.revision,
            device_id: self.grant.device_id,
            value: NormalizedObservationValue::VisibleText {
                // Keep the normalized value in its declared restricted,
                // ephemeral wrapper while the adapter-owned source buffer is
                // zeroed by `VisibleTextSample::drop` on every path.
                bounded_text: SensitiveText::new(sample.text.clone()),
            },
            provenance: ObservationProvenance {
                source_id: UIA_SOURCE_ID.to_owned(),
                source_event_id: Uuid::now_v7(),
                selected_resource_id: Some(self.resource_id),
                observed_at: now,
                received_at: now,
                extraction_version: "windows-uia-text-pattern-visible-ranges-v1".to_owned(),
                redaction_version: "windows-selected-text-sensitive-lines-v1".to_owned(),
                normalization_schema_version: "stein-visible-text-v1".to_owned(),
                confidence_basis_points: 9_500,
                complete: sample.complete,
                sensitivity: ObservationSensitivity::Restricted,
                retention: ObservationRetention::EphemeralSession,
                browser_granularity: None,
            },
        };
        if self
            .events
            .try_send(ObservationAdapterEvent::Observation(Box::new(observation)))
            .is_err()
        {
            return false;
        }
        self.last_fingerprint = Some(sample.fingerprint);
        self.last_observation_elapsed = Some(self.clock.monotonic_elapsed());
        true
    }

    fn status(&mut self, health: SourceHealth, detail: &'static str) -> bool {
        if self
            .events
            .try_send(ObservationAdapterEvent::SourceStatus(uia_status(
                &self.grant,
                self.resource_id,
                health,
                detail,
                self.clock.now_utc(),
            )))
            .is_err()
        {
            return false;
        }
        self.last_heartbeat = Instant::now();
        true
    }

    fn heartbeat(&mut self) -> bool {
        self.status(
            SourceHealth::Healthy,
            "The selected-window UI Automation source remains exactly bound.",
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn run_uia_source(
    source: Arc<dyn UiaTextSource>,
    grant: PermissionGrant,
    resource_id: ResourceId,
    limits: stein_core::ObservationLimits,
    clock: Arc<dyn Clock>,
    external_cancellation: CancellationToken,
    stop_cancellation: CancellationToken,
    events: mpsc::Sender<ObservationAdapterEvent>,
) {
    let mut publisher = UiaPublisher {
        grant,
        resource_id,
        limits,
        clock,
        events,
        last_observation_elapsed: None,
        last_fingerprint: None,
        last_heartbeat: Instant::now(),
    };
    if let Err(error) = bounded_uia_revalidate(
        Arc::clone(&source),
        &external_cancellation,
        &stop_cancellation,
    ) {
        let _ = uia_invocation_failure_status(&mut publisher, error);
        return;
    }
    if !publisher.status(
        SourceHealth::Healthy,
        "The exact selected-window UI Automation source is initialized.",
    ) {
        return;
    }

    match bounded_uia_read(
        Arc::clone(&source),
        publisher.limits.maximum_payload_bytes,
        &external_cancellation,
        &stop_cancellation,
    ) {
        Ok(sample) => {
            if external_cancellation.is_cancelled()
                || stop_cancellation.is_cancelled()
                || !publisher.visible_text(sample)
            {
                let _ = publisher.status(
                    SourceHealth::Paused,
                    "The selected-window UI Automation source was cancelled.",
                );
                return;
            }
        }
        Err(error) => {
            let _ = uia_invocation_failure_status(&mut publisher, error);
            return;
        }
    }
    let mut last_extraction = publisher.clock.monotonic_elapsed();

    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The selected-window UI Automation source was cancelled.",
            );
            return;
        }
        if publisher.clock.now_utc() >= publisher.grant.expires_at
            || publisher.grant.state != GrantState::Active
        {
            let _ = publisher.status(
                SourceHealth::Paused,
                "The selected-window visible-text grant is no longer current.",
            );
            return;
        }

        let elapsed = publisher.clock.monotonic_elapsed();
        if elapsed.saturating_sub(last_extraction) >= UIA_COALESCE_INTERVAL {
            match bounded_uia_read(
                Arc::clone(&source),
                publisher.limits.maximum_payload_bytes,
                &external_cancellation,
                &stop_cancellation,
            ) {
                Ok(sample) => {
                    last_extraction = elapsed;
                    if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
                        drop(sample);
                        let _ = publisher.status(
                            SourceHealth::Paused,
                            "The selected-window UI Automation source was cancelled.",
                        );
                        return;
                    }
                    if publisher.last_fingerprint != Some(sample.fingerprint)
                        && publisher.ready_for_observation()
                        && !publisher.visible_text(sample)
                    {
                        return;
                    }
                }
                Err(error) => {
                    let _ = uia_invocation_failure_status(&mut publisher, error);
                    return;
                }
            }
        }

        if publisher.last_heartbeat.elapsed() >= publisher.limits.heartbeat_interval {
            if let Err(error) = bounded_uia_revalidate(
                Arc::clone(&source),
                &external_cancellation,
                &stop_cancellation,
            ) {
                let _ = uia_invocation_failure_status(&mut publisher, error);
                return;
            }
            if !publisher.heartbeat() {
                return;
            }
        }
        thread::sleep(CANCELLATION_POLL_INTERVAL);
    }
}

fn uia_invocation_failure_status(publisher: &mut UiaPublisher, error: UiaInvocationError) -> bool {
    match error {
        UiaInvocationError::Cancelled => publisher.status(
            SourceHealth::Paused,
            "The selected-window UI Automation source was cancelled.",
        ),
        UiaInvocationError::TimedOut => publisher.status(
            SourceHealth::Unavailable,
            "The selected-window UI Automation provider exceeded its bounded deadline.",
        ),
        UiaInvocationError::WorkerLost => publisher.status(
            SourceHealth::Unavailable,
            "The isolated selected-window UI Automation worker was lost.",
        ),
        UiaInvocationError::Source(error) => uia_failure_status(publisher, error),
    }
}

fn uia_failure_status(publisher: &mut UiaPublisher, error: UiaError) -> bool {
    publisher.status(uia_error_health(error.kind), uia_error_detail(error.kind))
}

fn uia_status(
    grant: &PermissionGrant,
    resource_id: ResourceId,
    health: SourceHealth,
    detail: &'static str,
    observed_at: time::OffsetDateTime,
) -> ObservationSourceStatus {
    ObservationSourceStatus {
        source_id: UIA_SOURCE_ID.to_owned(),
        grant_id: grant.id,
        scope: PermissionScope::ObserveContentVisibleText,
        resource_id: Some(resource_id),
        health,
        detail,
        observed_at,
    }
}

fn uia_error_health(kind: UiaErrorKind) -> SourceHealth {
    match kind {
        UiaErrorKind::ProtectedSurface => SourceHealth::Paused,
        UiaErrorKind::BoundaryLost | UiaErrorKind::Unavailable => SourceHealth::Unavailable,
    }
}

fn uia_error_detail(kind: UiaErrorKind) -> &'static str {
    match kind {
        UiaErrorKind::BoundaryLost => {
            "The exact selected-window UI Automation identity could not be revalidated."
        }
        UiaErrorKind::ProtectedSurface => {
            "The selected window contains or became a protected UI Automation surface."
        }
        UiaErrorKind::Unavailable => {
            "Windows UI Automation visible-text extraction is unavailable."
        }
    }
}

fn selected_resource_failure_status(
    publisher: &mut SelectedResourcePublisher,
    error: SelectedResourceError,
) -> bool {
    publisher.status(
        selected_resource_error_health(error.kind),
        selected_resource_error_detail(error.kind),
    )
}

fn selected_resource_status(
    grant: &PermissionGrant,
    resource_id: ResourceId,
    health: SourceHealth,
    detail: &'static str,
    observed_at: time::OffsetDateTime,
) -> ObservationSourceStatus {
    ObservationSourceStatus {
        source_id: selected_resource_source_id(grant.scope).to_owned(),
        grant_id: grant.id,
        scope: grant.scope,
        resource_id: Some(resource_id),
        health,
        detail,
        observed_at,
    }
}

fn selected_resource_source_id(scope: PermissionScope) -> &'static str {
    match scope {
        PermissionScope::ObserveContentSelectedDocument => DOCUMENT_SOURCE_ID,
        PermissionScope::ObserveWorkspaceActivity => WORKSPACE_SOURCE_ID,
        _ => "windows:selected-resource:invalid",
    }
}

fn selected_resource_healthy_detail(scope: PermissionScope) -> &'static str {
    match scope {
        PermissionScope::ObserveContentSelectedDocument => {
            "The exact Windows selected-document source is healthy."
        }
        PermissionScope::ObserveWorkspaceActivity => {
            "The exact Windows selected-workspace source is healthy."
        }
        _ => "The Windows selected-resource source is unavailable.",
    }
}

fn selected_resource_error_health(kind: SelectedResourceErrorKind) -> SourceHealth {
    match kind {
        SelectedResourceErrorKind::BoundaryLost
        | SelectedResourceErrorKind::ProtectedSurface
        | SelectedResourceErrorKind::Cancelled => SourceHealth::Paused,
        SelectedResourceErrorKind::UnsupportedType | SelectedResourceErrorKind::Unavailable => {
            SourceHealth::Unavailable
        }
    }
}

fn selected_resource_error_detail(kind: SelectedResourceErrorKind) -> &'static str {
    match kind {
        SelectedResourceErrorKind::BoundaryLost => {
            "The exact Windows selected-resource identity or name changed."
        }
        SelectedResourceErrorKind::ProtectedSurface => {
            "The selected Windows resource is a protected or reparse surface."
        }
        SelectedResourceErrorKind::UnsupportedType => {
            "The selected Windows resource type or text encoding is unsupported."
        }
        SelectedResourceErrorKind::Cancelled => {
            "The trusted Windows resource selection was cancelled."
        }
        SelectedResourceErrorKind::Unavailable => {
            "The exact Windows selected-resource source is unavailable."
        }
    }
}

fn foreground_status(
    grant: &PermissionGrant,
    resource_id: ResourceId,
    health: SourceHealth,
    detail: &'static str,
    observed_at: time::OffsetDateTime,
) -> ObservationSourceStatus {
    ObservationSourceStatus {
        source_id: FOREGROUND_SOURCE_ID.to_owned(),
        grant_id: grant.id,
        scope: PermissionScope::ObserveDesktopForegroundApplication,
        resource_id: Some(resource_id),
        health,
        detail,
        observed_at,
    }
}

fn foreground_health(result: &Result<ForegroundMatch, ForegroundProbeError>) -> SourceHealth {
    result.as_ref().map_or_else(
        |error| foreground_error_health(error.kind),
        |_| SourceHealth::Healthy,
    )
}

fn foreground_detail(result: &Result<ForegroundMatch, ForegroundProbeError>) -> &'static str {
    result.as_ref().map_or_else(
        |error| foreground_error_detail(error.kind),
        |_| "The exact Windows foreground identity source is initialized.",
    )
}

fn foreground_error_health(kind: ForegroundProbeErrorKind) -> SourceHealth {
    match kind {
        ForegroundProbeErrorKind::BoundaryLost => SourceHealth::Degraded,
        ForegroundProbeErrorKind::ProtectedSurface => SourceHealth::Paused,
        ForegroundProbeErrorKind::Unavailable => SourceHealth::Unavailable,
    }
}

fn foreground_error_detail(kind: ForegroundProbeErrorKind) -> &'static str {
    match kind {
        ForegroundProbeErrorKind::BoundaryLost => {
            "The exact Windows foreground application identity could not be established."
        }
        ForegroundProbeErrorKind::ProtectedSurface => {
            "The Windows foreground surface is outside the daemon security boundary."
        }
        ForegroundProbeErrorKind::Unavailable => {
            "The Windows foreground application identity source is unavailable."
        }
    }
}

fn validate_foreground_request(
    request: &ObservationStartRequest,
    now: time::OffsetDateTime,
) -> Result<WindowsApplicationBinding, ObservationPortError> {
    let grant = &request.grant;
    let selected_resource = grant.selected_resource_id.ok_or_else(permission_denied)?;
    let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
    if grant.scope != PermissionScope::ObserveDesktopForegroundApplication
        || grant.focus_session_id.is_none()
        || !grant.is_current_at(now)
        || resource.id != selected_resource
        || resource.owner != grant.owner
        || resource.kind != ResourceKind::Application
    {
        return Err(permission_denied());
    }
    let binding = WindowsApplicationBinding::parse(&resource.opaque_reference)
        .map_err(|_| permission_denied())?;
    if binding.to_string() != resource.opaque_reference {
        return Err(permission_denied());
    }
    if request.limits.maximum_payload_bytes < resource.id.to_string().len()
        || request.limits.minimum_interval < MINIMUM_FOREGROUND_INTERVAL
        || request.limits.heartbeat_interval.is_zero()
        || request.limits.stale_after < request.limits.heartbeat_interval
    {
        return Err(invalid_configuration());
    }
    Ok(binding)
}

fn validate_selected_resource_request(
    request: &ObservationStartRequest,
    now: time::OffsetDateTime,
) -> Result<WindowsSelectedResourceBinding, ObservationPortError> {
    let grant = &request.grant;
    let selected_resource = grant.selected_resource_id.ok_or_else(permission_denied)?;
    let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
    let expected_kind = match grant.scope {
        PermissionScope::ObserveContentSelectedDocument => ResourceKind::Document,
        PermissionScope::ObserveWorkspaceActivity => ResourceKind::Workspace,
        _ => return Err(permission_denied()),
    };
    if grant.focus_session_id.is_none()
        || !grant.is_current_at(now)
        || resource.id != selected_resource
        || resource.owner != grant.owner
        || resource.kind != expected_kind
    {
        return Err(permission_denied());
    }
    let binding = WindowsSelectedResourceBinding::parse(&resource.opaque_reference)
        .map_err(|_| permission_denied())?;
    if binding.kind() != expected_kind || binding.to_string() != resource.opaque_reference {
        return Err(permission_denied());
    }
    if request.limits.maximum_payload_bytes == 0
        || request.limits.maximum_payload_bytes > MAXIMUM_DOCUMENT_BYTES
        || request.limits.minimum_interval < MINIMUM_SELECTED_RESOURCE_INTERVAL
        || request.limits.heartbeat_interval.is_zero()
        || request.limits.heartbeat_interval > MAXIMUM_HEARTBEAT_INTERVAL
        || request.limits.stale_after < request.limits.heartbeat_interval
        || request.limits.stale_after > MAXIMUM_STALE_AFTER
    {
        return Err(invalid_configuration());
    }
    Ok(binding)
}

fn validate_uia_request(
    request: &ObservationStartRequest,
    now: time::OffsetDateTime,
) -> Result<String, ObservationPortError> {
    let grant = &request.grant;
    let selected_resource = grant.selected_resource_id.ok_or_else(permission_denied)?;
    let resource = request.resource.as_ref().ok_or_else(permission_denied)?;
    if grant.scope != PermissionScope::ObserveContentVisibleText
        || grant.focus_session_id.is_none()
        || !grant.is_current_at(now)
        || resource.id != selected_resource
        || resource.owner != grant.owner
        || resource.kind != ResourceKind::Window
        || !canonical_uia_selection_token(&resource.opaque_reference)
        || request.limits.maximum_payload_bytes == 0
        || request.limits.maximum_payload_bytes > MAXIMUM_UIA_TEXT_BYTES
        || request.limits.minimum_interval < MINIMUM_UIA_INTERVAL
        || request.limits.heartbeat_interval.is_zero()
        || request.limits.heartbeat_interval > MAXIMUM_HEARTBEAT_INTERVAL
        || request.limits.stale_after < request.limits.heartbeat_interval
        || request.limits.stale_after > MAXIMUM_STALE_AFTER
    {
        return Err(permission_denied());
    }
    Ok(resource.opaque_reference.clone())
}

fn canonical_uia_selection_token(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("winnative:v1:uia:") else {
        return false;
    };
    Uuid::parse_str(uuid).is_ok_and(|parsed| parsed.to_string() == uuid)
}

fn validate_presence_request(
    request: &ObservationStartRequest,
    now: time::OffsetDateTime,
) -> Result<(), ObservationPortError> {
    let grant = &request.grant;
    if grant.scope != PermissionScope::ObserveDesktopPresence
        || grant.focus_session_id.is_none()
        || grant.selected_resource_id.is_some()
        || request.resource.is_some()
        || !grant.is_current_at(now)
    {
        return Err(permission_denied());
    }
    if request.limits.maximum_payload_bytes == 0
        || request.limits.minimum_interval < MINIMUM_PRESENCE_INTERVAL
        || request.limits.heartbeat_interval.is_zero()
        || request.limits.stale_after < request.limits.heartbeat_interval
    {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn healthy_detail() -> &'static str {
    "The Windows presence source is healthy."
}

fn health_detail(health: SourceHealth) -> &'static str {
    match health {
        SourceHealth::Healthy => healthy_detail(),
        SourceHealth::Paused => "The Windows presence source is paused.",
        SourceHealth::Unknown => "The Windows presence source health is unknown.",
        SourceHealth::Degraded => "The Windows presence source is degraded.",
        SourceHealth::Unavailable => "The Windows presence source is unavailable.",
    }
}

fn permission_denied() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::PermissionDenied,
        summary: "The Windows observation request is outside its exact grant or resource.",
    }
}

fn invalid_configuration() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Internal,
        summary: "The Windows observation limits are invalid.",
    }
}

fn map_foreground_probe_error(error: ForegroundProbeError) -> ObservationPortError {
    match error.kind {
        ForegroundProbeErrorKind::BoundaryLost => ObservationPortError {
            kind: ObservationPortErrorKind::BoundaryLost,
            summary: "The exact Windows foreground application identity could not be established.",
        },
        ForegroundProbeErrorKind::ProtectedSurface => ObservationPortError {
            kind: ObservationPortErrorKind::ProtectedSurface,
            summary: "The Windows foreground surface is outside the daemon security boundary.",
        },
        ForegroundProbeErrorKind::Unavailable => unavailable(),
    }
}

fn map_selected_resource_error(error: SelectedResourceError) -> ObservationPortError {
    match error.kind {
        SelectedResourceErrorKind::BoundaryLost => ObservationPortError {
            kind: ObservationPortErrorKind::BoundaryLost,
            summary: "The exact Windows selected-resource boundary was lost.",
        },
        SelectedResourceErrorKind::ProtectedSurface => ObservationPortError {
            kind: ObservationPortErrorKind::ProtectedSurface,
            summary: "The selected Windows resource is a protected or reparse surface.",
        },
        SelectedResourceErrorKind::UnsupportedType => ObservationPortError {
            kind: ObservationPortErrorKind::Unavailable,
            summary: "The selected Windows resource type or text encoding is unsupported.",
        },
        SelectedResourceErrorKind::Cancelled => cancelled(),
        SelectedResourceErrorKind::Unavailable => unavailable(),
    }
}

fn map_uia_error(error: UiaError) -> ObservationPortError {
    match error.kind {
        UiaErrorKind::BoundaryLost => ObservationPortError {
            kind: ObservationPortErrorKind::BoundaryLost,
            summary: "The exact selected Windows window identity could not be revalidated.",
        },
        UiaErrorKind::ProtectedSurface => ObservationPortError {
            kind: ObservationPortErrorKind::ProtectedSurface,
            summary: "The selected Windows window is locked, protected, or cross-integrity.",
        },
        UiaErrorKind::Unavailable => unavailable(),
    }
}

fn map_uia_selection_error(error: UiaError) -> ResourceSelectionError {
    let summary = match error.kind {
        UiaErrorKind::BoundaryLost => {
            "The selected Windows target could not be bound to one exact top-level window."
        }
        UiaErrorKind::ProtectedSurface => {
            "The selected Windows target is locked, protected, cross-integrity, or STEIN-owned."
        }
        UiaErrorKind::Unavailable => "The native Windows window picker is unavailable.",
    };
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Unavailable,
        summary,
        retryable: true,
    }
}

fn map_selected_resource_selection_error(error: SelectedResourceError) -> ResourceSelectionError {
    let (kind, summary, retryable) = match error.kind {
        SelectedResourceErrorKind::Cancelled => (
            ResourceSelectionErrorKind::Cancelled,
            "The native Windows resource picker was cancelled.",
            true,
        ),
        SelectedResourceErrorKind::ProtectedSurface => (
            ResourceSelectionErrorKind::Unavailable,
            "The selected Windows file resource is protected or outside the permitted boundary.",
            true,
        ),
        SelectedResourceErrorKind::BoundaryLost => (
            ResourceSelectionErrorKind::Unavailable,
            "The selected Windows file resource changed before it could be bound.",
            true,
        ),
        SelectedResourceErrorKind::UnsupportedType => (
            ResourceSelectionErrorKind::Unavailable,
            "The selected Windows file resource type is unsupported.",
            true,
        ),
        SelectedResourceErrorKind::Unavailable => (
            ResourceSelectionErrorKind::Unavailable,
            "The native Windows file resource picker is unavailable.",
            true,
        ),
    };
    ResourceSelectionError {
        kind,
        summary,
        retryable,
    }
}

fn resource_selection_unavailable() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Unavailable,
        summary: "The requested native Windows resource picker is unavailable.",
        retryable: true,
    }
}

fn resource_selection_internal() -> ResourceSelectionError {
    ResourceSelectionError {
        kind: ResourceSelectionErrorKind::Internal,
        summary: "The native Windows resource picker could not complete the operation.",
        retryable: true,
    }
}

fn cancelled() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Cancelled,
        summary: "The Windows observation request was cancelled.",
    }
}

fn unavailable() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Unavailable,
        summary: "The Windows observation source is unavailable.",
    }
}

fn internal_error() -> ObservationPortError {
    ObservationPortError {
        kind: ObservationPortErrorKind::Internal,
        summary: "The Windows observation source could not complete the operation.",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;

    use stein_core::{
        ActorId, ClientId, DeviceId, GoalId, ManualClock, ObservationLimits, ResourceBinding,
        ResourceId,
    };
    use time::macros::datetime;

    use super::*;

    struct ScriptedForegroundProbe {
        binding: WindowsApplicationBinding,
        results: Mutex<VecDeque<Result<ForegroundMatch, ForegroundProbeError>>>,
        fallback: Result<ForegroundMatch, ForegroundProbeError>,
        calls: AtomicUsize,
    }

    struct ScriptedSelectedState {
        binding: WindowsSelectedResourceBinding,
        kind: ResourceKind,
        receiver: Mutex<std_mpsc::Receiver<WorkspaceActivityKind>>,
        reads: Mutex<VecDeque<Result<SelectedDocumentRead, SelectedResourceError>>>,
        revalidations: Mutex<VecDeque<Result<(), SelectedResourceError>>>,
        commits: Mutex<Vec<crate::selected_resource::DocumentFingerprint>>,
        open_error: Mutex<Option<SelectedResourceError>>,
    }

    struct ScriptedSelectedSource {
        state: Arc<ScriptedSelectedState>,
    }

    impl SelectedResourceEventSource for ScriptedSelectedSource {
        fn kind(&self) -> ResourceKind {
            self.state.kind
        }

        fn revalidate(&mut self) -> Result<(), SelectedResourceError> {
            self.state
                .revalidations
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(()))
        }

        fn receive(
            &mut self,
            timeout: Duration,
        ) -> Result<SelectedResourceReceive, SelectedResourceError> {
            match self.state.receiver.lock().unwrap().recv_timeout(timeout) {
                Ok(activity) => Ok(SelectedResourceReceive::Activity(activity)),
                Err(std_mpsc::RecvTimeoutError::Timeout)
                | Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    Ok(SelectedResourceReceive::Timeout)
                }
            }
        }

        fn read_document(
            &mut self,
            _maximum_bytes: usize,
            _force: bool,
        ) -> Result<SelectedDocumentRead, SelectedResourceError> {
            self.state
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(SelectedDocumentRead::Unchanged))
        }

        fn commit_document(&mut self, fingerprint: crate::selected_resource::DocumentFingerprint) {
            self.state.commits.lock().unwrap().push(fingerprint);
        }
    }

    struct ScriptedSelectedFactory {
        state: Arc<ScriptedSelectedState>,
    }

    impl SelectedResourceFactory for ScriptedSelectedFactory {
        fn select_document(
            &self,
            cancellation: &CancellationToken,
        ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
            if cancellation.is_cancelled() {
                return Err(SelectedResourceError {
                    kind: SelectedResourceErrorKind::Cancelled,
                });
            }
            if self.state.kind == ResourceKind::Document {
                Ok(self.state.binding.clone())
            } else {
                Err(SelectedResourceError {
                    kind: SelectedResourceErrorKind::UnsupportedType,
                })
            }
        }

        fn select_workspace(
            &self,
            cancellation: &CancellationToken,
        ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
            if cancellation.is_cancelled() {
                return Err(SelectedResourceError {
                    kind: SelectedResourceErrorKind::Cancelled,
                });
            }
            if self.state.kind == ResourceKind::Workspace {
                Ok(self.state.binding.clone())
            } else {
                Err(SelectedResourceError {
                    kind: SelectedResourceErrorKind::UnsupportedType,
                })
            }
        }

        fn open(
            &self,
            binding: &WindowsSelectedResourceBinding,
        ) -> Result<Box<dyn SelectedResourceEventSource>, SelectedResourceError> {
            if let Some(error) = self.state.open_error.lock().unwrap().take() {
                return Err(error);
            }
            if binding != &self.state.binding {
                return Err(SelectedResourceError {
                    kind: SelectedResourceErrorKind::BoundaryLost,
                });
            }
            Ok(Box::new(ScriptedSelectedSource {
                state: Arc::clone(&self.state),
            }))
        }
    }

    impl ForegroundIdentityProbe for ScriptedForegroundProbe {
        fn resolve_current(&self) -> Result<WindowsApplicationBinding, ForegroundProbeError> {
            Ok(self.binding.clone())
        }

        fn classify_current(
            &self,
            _selected: &WindowsApplicationBinding,
        ) -> Result<ForegroundMatch, ForegroundProbeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(self.fallback)
        }
    }

    struct ChannelPresenceSource {
        initial: PresenceState,
        receiver: std_mpsc::Receiver<PresenceEvent>,
    }

    impl PresenceEventSource for ChannelPresenceSource {
        fn initial_event(&self) -> PresenceEvent {
            PresenceEvent {
                state: self.initial,
                source: PresenceUpdateSource::InitialSessionQuery,
            }
        }

        fn recv_timeout(&self, timeout: Duration) -> PresenceReceive {
            match self.receiver.recv_timeout(timeout) {
                Ok(event) => PresenceReceive::Event(event),
                Err(std_mpsc::RecvTimeoutError::Timeout) => PresenceReceive::Timeout,
                Err(std_mpsc::RecvTimeoutError::Disconnected) => PresenceReceive::Closed,
            }
        }
    }

    struct ChannelPresenceFactory {
        initial: PresenceState,
        receiver: Mutex<Option<std_mpsc::Receiver<PresenceEvent>>>,
    }

    impl PresenceSourceFactory for ChannelPresenceFactory {
        fn start(
            &self,
            _idle_threshold: Duration,
        ) -> Result<Box<dyn PresenceEventSource>, PresenceMonitorError> {
            let receiver = self
                .receiver
                .lock()
                .unwrap()
                .take()
                .ok_or(PresenceMonitorError {
                    summary: "The synthetic source was already consumed.",
                })?;
            Ok(Box::new(ChannelPresenceSource {
                initial: self.initial,
                receiver,
            }))
        }
    }

    struct Fixture {
        port: WindowsObservationPort,
        clock: Arc<ManualClock>,
        sender: std_mpsc::Sender<PresenceEvent>,
        request: ObservationStartRequest,
    }

    struct ForegroundFixture {
        port: WindowsObservationPort,
        clock: Arc<ManualClock>,
        probe: Arc<ScriptedForegroundProbe>,
        request: ObservationStartRequest,
        binding: WindowsApplicationBinding,
    }

    struct SelectedFixture {
        port: WindowsObservationPort,
        clock: Arc<ManualClock>,
        state: Arc<ScriptedSelectedState>,
        sender: std_mpsc::Sender<WorkspaceActivityKind>,
        request: ObservationStartRequest,
        binding: WindowsSelectedResourceBinding,
    }

    fn fixture(initial: PresenceState) -> Fixture {
        let now = datetime!(2026-08-19 12:00 UTC);
        let clock = Arc::new(ManualClock::new(now));
        let (sender, receiver) = std_mpsc::channel();
        let factory = Arc::new(ChannelPresenceFactory {
            initial,
            receiver: Mutex::new(Some(receiver)),
        });
        let session = FocusSessionId::new_v7();
        let grant = PermissionGrant {
            id: PermissionGrantId::new_v7(),
            revision: 4,
            owner: ActorId::new_v7(),
            goal_id: GoalId::from_uuid(Uuid::now_v7()),
            authenticated_client: ClientId::new_v7(),
            device_id: DeviceId::new_v7(),
            focus_session_id: Some(session),
            scope: PermissionScope::ObserveDesktopPresence,
            selected_resource_id: None,
            model_route_approval_id: None,
            purpose: "Synthetic presence fixture".to_owned(),
            placement: None,
            client_disconnect_allowed: true,
            daemon_restart_allowed: false,
            issued_at: now,
            effective_at: now,
            expires_at: now + time::Duration::hours(1),
            state: GrantState::Active,
            revoked_at: None,
            revocation_reason: None,
            consent_copy_version: "synthetic-v1".to_owned(),
        };
        let request = ObservationStartRequest {
            grant,
            resource: None,
            limits: ObservationLimits {
                maximum_payload_bytes: 1,
                minimum_interval: Duration::from_secs(1),
                heartbeat_interval: Duration::from_secs(10),
                stale_after: Duration::from_secs(30),
            },
        };
        let port = WindowsObservationPort::with_components(
            Duration::from_secs(60),
            clock.clone(),
            factory,
        );
        Fixture {
            port,
            clock,
            sender,
            request,
        }
    }

    fn foreground_fixture(
        initial: Result<ForegroundMatch, ForegroundProbeError>,
        subsequent: impl IntoIterator<Item = Result<ForegroundMatch, ForegroundProbeError>>,
    ) -> ForegroundFixture {
        let base = fixture(PresenceState::Active);
        let binding = WindowsApplicationBinding::packaged(
            "Synthetic.App_1234567890abc",
            "Synthetic.App_1234567890abc!Main",
        )
        .unwrap();
        let resource_id = ResourceId::new_v7();
        let mut request = base.request;
        request.grant.scope = PermissionScope::ObserveDesktopForegroundApplication;
        request.grant.selected_resource_id = Some(resource_id);
        request.limits.maximum_payload_bytes = 128;
        request.resource = Some(ResourceBinding {
            id: resource_id,
            owner: request.grant.owner,
            kind: ResourceKind::Application,
            opaque_reference: binding.to_string(),
            display_label: "Synthetic app".to_owned(),
            revision: 1,
            created_at: base.clock.now_utc(),
        });
        let mut results = VecDeque::from([initial]);
        results.extend(subsequent);
        let fallback = results
            .back()
            .copied()
            .unwrap_or(Ok(ForegroundMatch::OutsideSelectedScope));
        let probe = Arc::new(ScriptedForegroundProbe {
            binding: binding.clone(),
            results: Mutex::new(results),
            fallback,
            calls: AtomicUsize::new(0),
        });
        let (_unused_sender, unused_receiver) = std_mpsc::channel();
        let presence_factory = Arc::new(ChannelPresenceFactory {
            initial: PresenceState::Active,
            receiver: Mutex::new(Some(unused_receiver)),
        });
        let port = WindowsObservationPort::with_all_components(
            Duration::from_secs(60),
            base.clock.clone(),
            presence_factory,
            probe.clone(),
        );
        ForegroundFixture {
            port,
            clock: base.clock,
            probe,
            request,
            binding,
        }
    }

    fn selected_fixture(kind: ResourceKind) -> SelectedFixture {
        let base = fixture(PresenceState::Active);
        let resource_id = ResourceId::new_v7();
        let document_format =
            (kind == ResourceKind::Document).then_some(crate::WindowsDocumentFormat::Markdown);
        let binding = WindowsSelectedResourceBinding::from_selected_handle(
            0x1234,
            [0x56; 16],
            kind,
            document_format,
        )
        .unwrap();
        let mut request = base.request;
        request.grant.scope = match kind {
            ResourceKind::Document => PermissionScope::ObserveContentSelectedDocument,
            ResourceKind::Workspace => PermissionScope::ObserveWorkspaceActivity,
            _ => panic!("selected fixture requires a document or workspace"),
        };
        request.grant.selected_resource_id = Some(resource_id);
        request.limits = ObservationLimits {
            maximum_payload_bytes: MAXIMUM_DOCUMENT_BYTES,
            minimum_interval: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(10),
            stale_after: Duration::from_secs(30),
        };
        request.resource = Some(ResourceBinding {
            id: resource_id,
            owner: request.grant.owner,
            kind,
            opaque_reference: binding.to_string(),
            display_label: "Synthetic selected resource".to_owned(),
            revision: 1,
            created_at: base.clock.now_utc(),
        });
        let (sender, receiver) = std_mpsc::channel();
        let mut reads = VecDeque::new();
        if kind == ResourceKind::Document {
            reads.push_back(Ok(SelectedDocumentRead::Sample(
                crate::selected_resource::SelectedDocumentSample {
                    text: "Synthetic initial document".to_owned(),
                    complete: true,
                    fingerprint: crate::selected_resource::DocumentFingerprint {
                        change_time: 1,
                        last_write_time: 1,
                        end_of_file: 26,
                    },
                },
            )));
        }
        let state = Arc::new(ScriptedSelectedState {
            binding: binding.clone(),
            kind,
            receiver: Mutex::new(receiver),
            reads: Mutex::new(reads),
            revalidations: Mutex::new(VecDeque::new()),
            commits: Mutex::new(Vec::new()),
            open_error: Mutex::new(None),
        });
        let port = WindowsObservationPort::with_selected_components(
            Duration::from_secs(60),
            base.clock.clone(),
            Arc::new(ScriptedSelectedFactory {
                state: Arc::clone(&state),
            }),
        );
        SelectedFixture {
            port,
            clock: base.clock,
            state,
            sender,
            request,
            binding,
        }
    }

    async fn next_event(subscription: &mut ObservationSubscription) -> ObservationAdapterEvent {
        tokio::time::timeout(Duration::from_secs(2), subscription.events.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn is_presence_event(event: &ObservationAdapterEvent, expected: PresenceState) -> bool {
        matches!(
            event,
            ObservationAdapterEvent::Observation(observation)
                if observation.value == NormalizedObservationValue::Presence(expected)
        )
    }

    #[tokio::test]
    async fn presence_emits_exact_provenance_and_lock_pauses_immediately() {
        let fixture = fixture(PresenceState::Active);
        let cancellation = CancellationToken::new();
        let mut subscription = fixture
            .port
            .start(&fixture.request, cancellation.clone())
            .await
            .unwrap();
        assert_eq!(subscription.initial_status.health, SourceHealth::Healthy);
        let initial = next_event(&mut subscription).await;
        let ObservationAdapterEvent::Observation(initial) = initial else {
            panic!("expected initial presence observation");
        };
        assert_eq!(
            initial.value,
            NormalizedObservationValue::Presence(PresenceState::Active)
        );
        assert_eq!(
            initial.session_id,
            fixture.request.grant.focus_session_id.unwrap()
        );
        assert_eq!(initial.grant_id, fixture.request.grant.id);
        assert_eq!(initial.grant_revision, 4);
        assert_eq!(initial.device_id, fixture.request.grant.device_id);
        assert_eq!(initial.provenance.selected_resource_id, None);
        assert_eq!(initial.provenance.source_id, PRESENCE_SOURCE_ID);
        assert_eq!(initial.observation_id.get_version_num(), 7);
        assert_eq!(initial.provenance.source_event_id.get_version_num(), 7);
        assert_eq!(
            initial.provenance.observed_at,
            datetime!(2026-08-19 12:00 UTC)
        );
        assert_eq!(
            initial.provenance.received_at,
            initial.provenance.observed_at
        );
        assert_eq!(
            initial.provenance.retention,
            ObservationRetention::EphemeralSession
        );
        assert_eq!(
            initial.provenance.sensitivity,
            ObservationSensitivity::Personal
        );
        assert!(initial.provenance.complete);
        assert!(initial.provenance.browser_granularity.is_none());

        fixture
            .sender
            .send(PresenceEvent {
                state: PresenceState::Locked,
                source: PresenceUpdateSource::SessionNotification,
            })
            .unwrap();
        let locked = next_event(&mut subscription).await;
        assert!(is_presence_event(&locked, PresenceState::Locked));
        let paused = next_event(&mut subscription).await;
        assert!(matches!(
            paused,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));

        fixture
            .port
            .stop(
                fixture.request.grant.focus_session_id.unwrap(),
                fixture.request.grant.id,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unlock_requires_fresh_sample_before_health_and_observation_resume() {
        let fixture = fixture(PresenceState::Locked);
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        assert!(is_presence_event(
            &next_event(&mut subscription).await,
            PresenceState::Locked
        ));
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));

        fixture
            .sender
            .send(PresenceEvent {
                state: PresenceState::Unknown,
                source: PresenceUpdateSource::SessionNotification,
            })
            .unwrap();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Unknown,
                ..
            })
        ));
        fixture.clock.advance(Duration::from_secs(1));
        fixture
            .sender
            .send(PresenceEvent {
                state: PresenceState::Active,
                source: PresenceUpdateSource::IdleSample,
            })
            .unwrap();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Healthy,
                ..
            })
        ));
        assert!(is_presence_event(
            &next_event(&mut subscription).await,
            PresenceState::Active
        ));
    }

    #[tokio::test]
    async fn rate_limit_coalesces_nonurgent_state_but_never_lock() {
        let fixture = fixture(PresenceState::Active);
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        let _ = next_event(&mut subscription).await;
        fixture
            .sender
            .send(PresenceEvent {
                state: PresenceState::Idle,
                source: PresenceUpdateSource::IdleSample,
            })
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), subscription.events.recv())
                .await
                .is_err()
        );
        fixture
            .sender
            .send(PresenceEvent {
                state: PresenceState::Locked,
                source: PresenceUpdateSource::SessionNotification,
            })
            .unwrap();
        assert!(is_presence_event(
            &next_event(&mut subscription).await,
            PresenceState::Locked
        ));
    }

    #[test]
    fn bounded_channel_reserves_capacity_for_lock_and_pause() {
        let fixture = fixture(PresenceState::Active);
        let (events, mut receiver) = mpsc::channel(3);
        let mut publisher = PresencePublisher {
            grant: fixture.request.grant.clone(),
            limits: fixture.request.limits.clone(),
            clock: fixture.clock.clone(),
            events,
            health: SourceHealth::Healthy,
            last_emitted_state: None,
            last_observation_elapsed: None,
            last_heartbeat: Instant::now(),
        };
        assert!(publisher.process(PresenceEvent {
            state: PresenceState::Active,
            source: PresenceUpdateSource::IdleSample,
        }));
        fixture.clock.advance(Duration::from_secs(2));
        assert!(publisher.process(PresenceEvent {
            state: PresenceState::Idle,
            source: PresenceUpdateSource::IdleSample,
        }));
        assert!(publisher.process(PresenceEvent {
            state: PresenceState::Locked,
            source: PresenceUpdateSource::SessionNotification,
        }));

        assert!(is_presence_event(
            &receiver.try_recv().unwrap(),
            PresenceState::Active
        ));
        assert!(is_presence_event(
            &receiver.try_recv().unwrap(),
            PresenceState::Locked
        ));
        assert!(matches!(
            receiver.try_recv().unwrap(),
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancellation_closes_the_bounded_stream_and_stop_is_idempotent() {
        let fixture = fixture(PresenceState::Active);
        let cancellation = CancellationToken::new();
        let mut subscription = fixture
            .port
            .start(&fixture.request, cancellation.clone())
            .await
            .unwrap();
        let _ = next_event(&mut subscription).await;
        cancellation.cancel();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
                .await
                .unwrap()
                .is_none()
        );
        let session = fixture.request.grant.focus_session_id.unwrap();
        fixture
            .port
            .stop(session, fixture.request.grant.id)
            .await
            .unwrap();
        fixture
            .port
            .stop(session, fixture.request.grant.id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn grant_expiry_pauses_and_closes_the_source_without_an_external_signal() {
        let fixture = fixture(PresenceState::Active);
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        let _ = next_event(&mut subscription).await;
        fixture.clock.advance(Duration::from_secs(2 * 60 * 60));
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn heartbeats_are_bounded_and_missing_native_events_degrade_health() {
        let mut fixture = fixture(PresenceState::Active);
        fixture.request.limits.heartbeat_interval = Duration::from_millis(10);
        fixture.request.limits.stale_after = Duration::from_millis(30);
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        let _ = next_event(&mut subscription).await;
        let degraded = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(ObservationAdapterEvent::SourceStatus(status)) =
                    subscription.events.recv().await
                    && status.health == SourceHealth::Degraded
                {
                    break status;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(degraded.resource_id, None);
        assert_eq!(degraded.scope, PermissionScope::ObserveDesktopPresence);
    }

    #[tokio::test]
    async fn malformed_grant_limits_and_resource_fail_before_native_start() {
        let fixture = fixture(PresenceState::Active);
        let mut wrong = fixture.request.clone();
        wrong.grant.selected_resource_id = Some(ResourceId::new_v7());
        wrong.resource = Some(ResourceBinding {
            id: wrong.grant.selected_resource_id.unwrap(),
            owner: wrong.grant.owner,
            kind: ResourceKind::Device,
            opaque_reference: "synthetic-device".to_owned(),
            display_label: "Synthetic device".to_owned(),
            revision: 1,
            created_at: fixture.clock.now_utc(),
        });
        let error = match fixture.port.start(&wrong, CancellationToken::new()).await {
            Err(error) => error,
            Ok(_) => panic!("a resource-bound presence grant must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::PermissionDenied);

        let mut invalid_limits = fixture.request.clone();
        invalid_limits.limits.minimum_interval = Duration::ZERO;
        let error = match fixture
            .port
            .start(&invalid_limits, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an unsafe presence rate must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::Internal);
    }

    #[tokio::test]
    async fn foreground_emits_only_selected_membership_with_exact_provenance() {
        let fixture = foreground_fixture(Ok(ForegroundMatch::Selected), []);
        assert_eq!(
            ObservationPort::availability(
                &fixture.port,
                PermissionScope::ObserveDesktopForegroundApplication,
            ),
            PlatformPortAvailability::Available
        );
        assert_eq!(
            fixture.port.resolve_current_foreground_binding().unwrap(),
            fixture.binding
        );
        let cancellation = CancellationToken::new();
        let mut subscription = fixture
            .port
            .start(&fixture.request, cancellation.clone())
            .await
            .unwrap();
        let resource_id = fixture.request.resource.as_ref().unwrap().id;
        assert_eq!(subscription.initial_status.health, SourceHealth::Healthy);
        assert_eq!(subscription.initial_status.resource_id, Some(resource_id));
        let ObservationAdapterEvent::Observation(observation) = next_event(&mut subscription).await
        else {
            panic!("expected foreground observation");
        };
        assert_eq!(
            observation.value,
            NormalizedObservationValue::ForegroundApplication(
                ForegroundApplicationState::Selected {
                    application_id: resource_id.to_string(),
                }
            )
        );
        assert_eq!(observation.provenance.source_id, FOREGROUND_SOURCE_ID);
        assert_eq!(
            observation.provenance.selected_resource_id,
            Some(resource_id)
        );
        assert_eq!(
            observation.provenance.extraction_version,
            "windows-pfn-aumid-v1"
        );
        assert_eq!(observation.provenance.confidence_basis_points, 10_000);
        assert!(observation.provenance.complete);
        assert!(!format!("{observation:?}").contains("Synthetic.App"));

        cancellation.cancel();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn foreground_continuously_revalidates_and_recovers_from_protected_surface() {
        let fixture = foreground_fixture(
            Err(ForegroundProbeError {
                kind: ForegroundProbeErrorKind::ProtectedSurface,
            }),
            [
                Ok(ForegroundMatch::Selected),
                Ok(ForegroundMatch::OutsideSelectedScope),
            ],
        );
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(subscription.initial_status.health, SourceHealth::Paused);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), subscription.events.recv())
                .await
                .is_err()
        );

        let healthy = next_event(&mut subscription).await;
        assert!(matches!(
            healthy,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Healthy,
                ..
            })
        ));
        let selected = next_event(&mut subscription).await;
        assert!(matches!(
            selected,
            ObservationAdapterEvent::Observation(observation)
                if matches!(
                    observation.value,
                    NormalizedObservationValue::ForegroundApplication(
                        ForegroundApplicationState::Selected { .. }
                    )
                )
        ));
        fixture.clock.advance(Duration::from_secs(1));
        let outside = next_event(&mut subscription).await;
        assert!(matches!(
            outside,
            ObservationAdapterEvent::Observation(observation)
                if observation.value
                    == NormalizedObservationValue::ForegroundApplication(
                        ForegroundApplicationState::OutsideSelectedScope
                    )
        ));
        assert!(fixture.probe.calls.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn foreground_rejects_wrong_resource_and_unsafe_limits_before_native_probe() {
        let fixture = foreground_fixture(Ok(ForegroundMatch::Selected), []);
        let mut wrong_resource = fixture.request.clone();
        wrong_resource.resource.as_mut().unwrap().id = ResourceId::new_v7();
        let error = match fixture
            .port
            .start(&wrong_resource, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("a mismatched resource must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::PermissionDenied);
        assert_eq!(fixture.probe.calls.load(Ordering::SeqCst), 0);

        let mut unsafe_rate = fixture.request.clone();
        unsafe_rate.limits.minimum_interval = Duration::from_millis(999);
        let error = match fixture
            .port
            .start(&unsafe_rate, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an unsafe foreground rate must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::Internal);
        assert_eq!(fixture.probe.calls.load(Ordering::SeqCst), 0);

        let mut undersized = fixture.request.clone();
        undersized.limits.maximum_payload_bytes = 35;
        let error = match fixture
            .port
            .start(&undersized, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an undersized payload limit must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::Internal);
        assert_eq!(fixture.probe.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn foreground_rate_and_backpressure_preserve_status_capacity() {
        let fixture = foreground_fixture(Ok(ForegroundMatch::Selected), []);
        let resource_id = fixture.request.resource.as_ref().unwrap().id;
        let (events, mut receiver) = mpsc::channel(2);
        let mut publisher = ForegroundPublisher {
            grant: fixture.request.grant.clone(),
            resource_id,
            limits: fixture.request.limits.clone(),
            clock: fixture.clock.clone(),
            events,
            extraction_version: "synthetic-v1",
            health: SourceHealth::Healthy,
            failure: None,
            last_emitted_state: None,
            last_observation_elapsed: None,
            last_heartbeat: Instant::now(),
        };
        assert!(publisher.process(Ok(ForegroundMatch::Selected)));
        assert!(publisher.process(Ok(ForegroundMatch::OutsideSelectedScope)));
        assert!(publisher.process(Err(ForegroundProbeError {
            kind: ForegroundProbeErrorKind::BoundaryLost,
        })));
        assert!(matches!(
            receiver.try_recv().unwrap(),
            ObservationAdapterEvent::Observation(_)
        ));
        assert!(matches!(
            receiver.try_recv().unwrap(),
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Degraded,
                ..
            })
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn selected_document_is_bounded_coalesced_exact_and_revocation_safe() {
        let fixture = selected_fixture(ResourceKind::Document);
        assert_eq!(
            ObservationPort::availability(
                &fixture.port,
                PermissionScope::ObserveContentSelectedDocument,
            ),
            PlatformPortAvailability::Available
        );
        assert_eq!(
            fixture.port.select_document_binding().unwrap(),
            fixture.binding
        );
        let cancellation = CancellationToken::new();
        let mut subscription = fixture
            .port
            .start(&fixture.request, cancellation.clone())
            .await
            .unwrap();
        assert_eq!(subscription.initial_status.health, SourceHealth::Healthy);
        assert_eq!(
            subscription.initial_status.resource_id,
            fixture.request.grant.selected_resource_id
        );
        let ObservationAdapterEvent::Observation(initial) = next_event(&mut subscription).await
        else {
            panic!("expected initial selected-document observation");
        };
        let NormalizedObservationValue::SelectedDocument { bounded_text } = &initial.value else {
            panic!("expected selected-document value");
        };
        assert_eq!(bounded_text.expose(), "Synthetic initial document");
        assert_eq!(initial.provenance.source_id, DOCUMENT_SOURCE_ID);
        assert_eq!(
            initial.provenance.selected_resource_id,
            fixture.request.grant.selected_resource_id
        );
        assert_eq!(
            initial.provenance.sensitivity,
            ObservationSensitivity::Restricted
        );
        assert!(initial.provenance.complete);
        assert!(!format!("{initial:?}").contains("Synthetic initial document"));

        fixture
            .state
            .reads
            .lock()
            .unwrap()
            .push_back(Ok(SelectedDocumentRead::Sample(
                crate::selected_resource::SelectedDocumentSample {
                    text: "Synthetic coalesced document".to_owned(),
                    complete: false,
                    fingerprint: crate::selected_resource::DocumentFingerprint {
                        change_time: 2,
                        last_write_time: 2,
                        end_of_file: 30,
                    },
                },
            )));
        fixture
            .sender
            .send(WorkspaceActivityKind::Modified)
            .unwrap();
        fixture
            .sender
            .send(WorkspaceActivityKind::Modified)
            .unwrap();
        std::thread::sleep(Duration::from_millis(150));
        fixture.clock.advance(Duration::from_secs(5));
        let ObservationAdapterEvent::Observation(updated) = next_event(&mut subscription).await
        else {
            panic!("expected coalesced selected-document observation");
        };
        let NormalizedObservationValue::SelectedDocument { bounded_text } = &updated.value else {
            panic!("expected selected-document value");
        };
        assert_eq!(bounded_text.expose(), "Synthetic coalesced document");
        assert!(!updated.provenance.complete);
        assert_eq!(fixture.state.commits.lock().unwrap().len(), 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), subscription.events.recv())
                .await
                .is_err()
        );

        cancellation.cancel();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn selected_workspace_emits_only_coarse_activity_and_stops_at_expiry() {
        let mut fixture = selected_fixture(ResourceKind::Workspace);
        fixture.request.grant.expires_at = fixture.clock.now_utc() + time::Duration::seconds(20);
        assert_eq!(
            ObservationPort::availability(&fixture.port, PermissionScope::ObserveWorkspaceActivity,),
            PlatformPortAvailability::Available
        );
        assert_eq!(
            fixture.port.select_workspace_binding().unwrap(),
            fixture.binding
        );
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), subscription.events.recv())
                .await
                .is_err()
        );
        for activity in [
            WorkspaceActivityKind::Modified,
            WorkspaceActivityKind::Created,
            WorkspaceActivityKind::Renamed,
        ] {
            fixture.sender.send(activity).unwrap();
        }
        std::thread::sleep(Duration::from_millis(150));
        fixture.clock.advance(Duration::from_secs(5));
        let ObservationAdapterEvent::Observation(observation) = next_event(&mut subscription).await
        else {
            panic!("expected coarse workspace observation");
        };
        assert_eq!(
            observation.value,
            NormalizedObservationValue::WorkspaceActivity {
                activity: WorkspaceActivityKind::Renamed
            }
        );
        assert_eq!(observation.provenance.source_id, WORKSPACE_SOURCE_ID);
        assert_eq!(
            observation.provenance.selected_resource_id,
            fixture.request.grant.selected_resource_id
        );
        let debug = format!("{observation:?}");
        assert!(!debug.contains("private-workspace-name-739"));
        assert!(!debug.contains("private-document-name-739.md"));

        fixture.clock.advance(Duration::from_secs(30));
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn selected_resource_rejects_mismatch_reparse_and_weakened_bounds_before_capture() {
        let fixture = selected_fixture(ResourceKind::Document);

        let mut wrong_kind = fixture.request.clone();
        wrong_kind.resource.as_mut().unwrap().kind = ResourceKind::Workspace;
        let error = match fixture
            .port
            .start(&wrong_kind, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("a cross-kind selected resource must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::PermissionDenied);

        let mut unsafe_payload = fixture.request.clone();
        unsafe_payload.limits.maximum_payload_bytes = MAXIMUM_DOCUMENT_BYTES + 1;
        let error = match fixture
            .port
            .start(&unsafe_payload, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an oversized selected-document limit must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::Internal);

        let mut unsafe_rate = fixture.request.clone();
        unsafe_rate.limits.minimum_interval = Duration::from_millis(4_999);
        let error = match fixture
            .port
            .start(&unsafe_rate, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an unsafe selected-resource rate must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::Internal);

        *fixture.state.open_error.lock().unwrap() = Some(SelectedResourceError {
            kind: SelectedResourceErrorKind::ProtectedSurface,
        });
        let error = match fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("a reparse/protected selected resource must fail"),
        };
        assert_eq!(error.kind, ObservationPortErrorKind::ProtectedSurface);
    }

    #[tokio::test]
    async fn selected_resource_identity_loss_closes_without_a_late_observation() {
        let fixture = selected_fixture(ResourceKind::Workspace);
        fixture
            .state
            .revalidations
            .lock()
            .unwrap()
            .push_back(Ok(()));
        fixture
            .state
            .revalidations
            .lock()
            .unwrap()
            .push_back(Err(SelectedResourceError {
                kind: SelectedResourceErrorKind::BoundaryLost,
            }));
        let mut subscription = fixture
            .port
            .start(&fixture.request, CancellationToken::new())
            .await
            .unwrap();
        fixture
            .sender
            .send(WorkspaceActivityKind::Modified)
            .unwrap();
        assert!(matches!(
            next_event(&mut subscription).await,
            ObservationAdapterEvent::SourceStatus(ObservationSourceStatus {
                health: SourceHealth::Paused,
                ..
            })
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[ignore = "requires an interactive native Windows user session"]
    async fn native_presence_subscription_emits_a_bounded_observation() {
        let now = time::OffsetDateTime::now_utc();
        let session = FocusSessionId::new_v7();
        let request = ObservationStartRequest {
            grant: PermissionGrant {
                id: PermissionGrantId::new_v7(),
                revision: 1,
                owner: ActorId::new_v7(),
                goal_id: GoalId::from_uuid(Uuid::now_v7()),
                authenticated_client: ClientId::new_v7(),
                device_id: DeviceId::new_v7(),
                focus_session_id: Some(session),
                scope: PermissionScope::ObserveDesktopPresence,
                selected_resource_id: None,
                model_route_approval_id: None,
                purpose: "Synthetic native presence fixture".to_owned(),
                placement: None,
                client_disconnect_allowed: false,
                daemon_restart_allowed: false,
                issued_at: now,
                effective_at: now,
                expires_at: now + time::Duration::minutes(5),
                state: GrantState::Active,
                revoked_at: None,
                revocation_reason: None,
                consent_copy_version: "synthetic-v1".to_owned(),
            },
            resource: None,
            limits: ObservationLimits {
                maximum_payload_bytes: 1,
                minimum_interval: Duration::from_secs(1),
                heartbeat_interval: Duration::from_secs(10),
                stale_after: Duration::from_secs(30),
            },
        };
        let port = WindowsObservationPort::new(Duration::from_secs(60)).unwrap();
        let mut subscription = port
            .start(&request, CancellationToken::new())
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(2), subscription.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            ObservationAdapterEvent::Observation(observation)
                if matches!(observation.value, NormalizedObservationValue::Presence(_))
        ));
        port.stop(session, request.grant.id).await.unwrap();
    }
}
