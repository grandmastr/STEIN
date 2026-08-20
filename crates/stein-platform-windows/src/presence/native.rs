use std::fmt;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use stein_core::PresenceState;
use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK,
    WTS_SESSIONSTATE_UNLOCK, WTSActive, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW,
    WTSRegisterSessionNotification, WTSSessionInfoEx, WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA,
    GetMessageW, GetWindowLongPtrW, HWND_MESSAGE, KillTimer, MSG, PostMessageW, PostQuitMessage,
    RegisterClassW, SetTimer, SetWindowLongPtrW, TranslateMessage, WM_CLOSE, WM_DESTROY,
    WM_NCCREATE, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_CONSOLE_CONNECT,
    WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF, WTS_SESSION_LOGON, WTS_SESSION_UNLOCK,
};

use super::{PresenceEvent, PresenceSignal, PresenceTracker, PresenceUpdateSource};

const CLASS_NAME: &[u16] = &[
    b'S' as u16,
    b'T' as u16,
    b'E' as u16,
    b'I' as u16,
    b'N' as u16,
    b'_' as u16,
    b'P' as u16,
    b'r' as u16,
    b'e' as u16,
    b's' as u16,
    b'e' as u16,
    b'n' as u16,
    b'c' as u16,
    b'e' as u16,
    b'_' as u16,
    b'M' as u16,
    b'o' as u16,
    b'n' as u16,
    b'i' as u16,
    b't' as u16,
    b'o' as u16,
    b'r' as u16,
    0,
];
const SAMPLE_TIMER_ID: usize = 1;
const SAMPLE_INTERVAL_MILLISECONDS: u32 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresenceMonitorError {
    pub summary: &'static str,
}

/// WTS-backed current-session monitor. It owns a message-only window on a
/// dedicated thread and samples only elapsed idle time; it never captures keys,
/// pointer positions, window text, or other input content.
pub struct WindowsPresenceMonitor {
    receiver: Mutex<mpsc::Receiver<PresenceEvent>>,
    current: Arc<Mutex<PresenceState>>,
    window: usize,
    thread: Option<JoinHandle<()>>,
}

impl WindowsPresenceMonitor {
    pub fn start(idle_threshold: Duration) -> Result<Self, PresenceMonitorError> {
        PresenceTracker::new(idle_threshold).map_err(|_| PresenceMonitorError {
            summary: "The Windows presence monitor configuration is invalid.",
        })?;

        let (events_tx, events_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let current = Arc::new(Mutex::new(PresenceState::Unknown));
        let thread_current = Arc::clone(&current);
        let thread = thread::Builder::new()
            .name("stein-windows-presence".to_owned())
            .spawn(move || run_message_window(idle_threshold, events_tx, thread_current, ready_tx))
            .map_err(|_| PresenceMonitorError {
                summary: "The Windows presence monitor thread could not start.",
            })?;

        let window = match ready_rx.recv() {
            Ok(Ok(window)) => window,
            _ => {
                let _ = thread.join();
                return Err(PresenceMonitorError {
                    summary: "The Windows presence monitor could not initialize.",
                });
            }
        };

        Ok(Self {
            receiver: Mutex::new(events_rx),
            current,
            window,
            thread: Some(thread),
        })
    }

    pub fn current_state(&self) -> PresenceState {
        self.current
            .lock()
            .map(|state| *state)
            .unwrap_or(PresenceState::Unknown)
    }

    pub fn try_recv(&self) -> Result<PresenceEvent, mpsc::TryRecvError> {
        self.receiver
            .lock()
            .map_err(|_| mpsc::TryRecvError::Disconnected)?
            .try_recv()
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<PresenceEvent, mpsc::RecvTimeoutError> {
        self.receiver
            .lock()
            .map_err(|_| mpsc::RecvTimeoutError::Disconnected)?
            .recv_timeout(timeout)
    }
}

impl fmt::Debug for WindowsPresenceMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPresenceMonitor")
            .field("state", &self.current_state())
            .finish_non_exhaustive()
    }
}

impl Drop for WindowsPresenceMonitor {
    fn drop(&mut self) {
        let window = self.window as HWND;
        if !window.is_null() {
            // SAFETY: the numeric handle was returned by CreateWindowExW and is
            // used only to enqueue WM_CLOSE to its owning message-loop thread.
            unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct WindowContext {
    tracker: PresenceTracker,
    sender: mpsc::Sender<PresenceEvent>,
    current: Arc<Mutex<PresenceState>>,
    registered: bool,
}

fn run_message_window(
    idle_threshold: Duration,
    sender: mpsc::Sender<PresenceEvent>,
    current: Arc<Mutex<PresenceState>>,
    ready: mpsc::SyncSender<Result<usize, PresenceMonitorError>>,
) {
    let mut context = Box::new(WindowContext {
        tracker: PresenceTracker::new(idle_threshold).expect("validated before thread start"),
        sender,
        current,
        registered: false,
    });

    // SAFETY: null requests the module containing this code and has no lifetime
    // requirements.
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance.is_null() {
        let _ = ready.send(Err(initialization_error()));
        return;
    }
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_procedure),
        hInstance: instance,
        lpszClassName: CLASS_NAME.as_ptr(),
        ..Default::default()
    };
    // SAFETY: `class` and its static class-name pointer remain valid for this
    // synchronous registration call.
    let class_atom = unsafe { RegisterClassW(&class) };
    if class_atom == 0 {
        // SAFETY: read immediately after RegisterClassW failed.
        let error = unsafe { GetLastError() };
        if error != ERROR_CLASS_ALREADY_EXISTS {
            let _ = ready.send(Err(initialization_error()));
            return;
        }
    }

    let context_ptr = (&mut *context) as *mut WindowContext;
    // SAFETY: the registered class uses `window_procedure`; context points to a
    // stable Box allocation that outlives the window and message loop. The
    // window is message-only, has no UI surface, and receives no user content.
    let window = unsafe {
        CreateWindowExW(
            0,
            CLASS_NAME.as_ptr(),
            CLASS_NAME.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            ptr::null_mut(),
            instance,
            context_ptr.cast(),
        )
    };
    if window.is_null() {
        let _ = ready.send(Err(initialization_error()));
        return;
    }

    // SAFETY: `window` is a live HWND owned by this thread.
    if unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) } == 0 {
        // SAFETY: destroys the live window on its owning thread.
        unsafe { DestroyWindow(window) };
        let _ = ready.send(Err(initialization_error()));
        return;
    }
    context.registered = true;

    // SAFETY: sets a window-owned periodic timer. A null callback directs
    // WM_TIMER to this window procedure.
    if unsafe { SetTimer(window, SAMPLE_TIMER_ID, SAMPLE_INTERVAL_MILLISECONDS, None) } == 0 {
        // SAFETY: unregister and destroy the live owning-thread window.
        unsafe {
            WTSUnRegisterSessionNotification(window);
            DestroyWindow(window);
        }
        context.registered = false;
        let _ = ready.send(Err(initialization_error()));
        return;
    }

    initialize_presence(&mut context);
    if ready.send(Ok(window as usize)).is_err() {
        // No owner remains; close synchronously before entering the loop.
        // SAFETY: this is the window's owning thread, and the timer and WTS
        // registration were both established above.
        unsafe {
            KillTimer(window, SAMPLE_TIMER_ID);
            WTSUnRegisterSessionNotification(window);
            DestroyWindow(window);
        }
        context.registered = false;
        return;
    }

    let mut message = MaybeUninit::<MSG>::zeroed();
    loop {
        // SAFETY: `message` is writable and all messages for this thread are
        // accepted. Positive results fully initialize MSG.
        let result = unsafe { GetMessageW(message.as_mut_ptr(), ptr::null_mut(), 0, 0) };
        if result <= 0 {
            break;
        }
        // SAFETY: GetMessageW returned positive, so MSG is initialized for both
        // synchronous dispatch calls.
        unsafe {
            let message = message.assume_init_ref();
            TranslateMessage(message);
            DispatchMessageW(message);
        }
    }
    if context.registered {
        // GetMessageW failed rather than receiving the normal WM_DESTROY quit.
        // Clean up explicitly before the Box containing GWLP_USERDATA is freed.
        // SAFETY: this is still the window's owning thread.
        unsafe {
            KillTimer(window, SAMPLE_TIMER_ID);
            WTSUnRegisterSessionNotification(window);
            DestroyWindow(window);
        }
        context.registered = false;
    }
}

fn initialize_presence(context: &mut WindowContext) {
    match query_current_presence() {
        PresenceState::Locked => emit_signal(
            context,
            PresenceSignal::Locked,
            PresenceUpdateSource::InitialSessionQuery,
        ),
        PresenceState::Active => {
            emit_signal(
                context,
                PresenceSignal::Unlocked,
                PresenceUpdateSource::InitialSessionQuery,
            );
            sample_idle(context);
        }
        PresenceState::SwitchedAway => emit_signal(
            context,
            PresenceSignal::Disconnected,
            PresenceUpdateSource::InitialSessionQuery,
        ),
        PresenceState::Idle | PresenceState::Unknown => emit_signal(
            context,
            PresenceSignal::Ambiguous,
            PresenceUpdateSource::ProbeFailure,
        ),
    }
}

unsafe extern "system" fn window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // No panic may unwind through the Win32 callback ABI.
    std::panic::catch_unwind(|| {
        // SAFETY: all pointer access and window calls are contained and checked
        // by window_procedure_inner's invariants.
        unsafe { window_procedure_inner(window, message, wparam, lparam) }
    })
    .unwrap_or_else(|_| {
        // SAFETY: DefWindowProcW accepts the callback arguments unchanged.
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    })
}

unsafe fn window_procedure_inner(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = lparam as *const CREATESTRUCTW;
        if !create.is_null() {
            // SAFETY: WM_NCCREATE supplies a valid CREATESTRUCTW for this call;
            // lpCreateParams is the stable WindowContext pointer passed above.
            let context = unsafe { (*create).lpCreateParams as isize };
            // SAFETY: associates, but does not dereference, the stable pointer.
            unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, context) };
        }
    }

    // SAFETY: reads the pointer value associated during WM_NCCREATE.
    let context_ptr = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut WindowContext;
    if !context_ptr.is_null() {
        // SAFETY: the Box containing this context outlives the window and all
        // dispatched messages; dispatch is confined to the owning thread.
        let context = unsafe { &mut *context_ptr };
        match message {
            WM_WTSSESSION_CHANGE => {
                emit_signal(
                    context,
                    signal_from_wts(wparam as u32),
                    PresenceUpdateSource::SessionNotification,
                );
                return 0;
            }
            WM_TIMER if wparam == SAMPLE_TIMER_ID => {
                sample_idle(context);
                return 0;
            }
            WM_CLOSE => {
                // SAFETY: timer and registration belong to this live window.
                unsafe { KillTimer(window, SAMPLE_TIMER_ID) };
                if context.registered {
                    // SAFETY: this window was registered once and has not yet
                    // been unregistered.
                    unsafe { WTSUnRegisterSessionNotification(window) };
                    context.registered = false;
                }
                // SAFETY: destroys the window on its owning thread.
                unsafe { DestroyWindow(window) };
                return 0;
            }
            WM_DESTROY => {
                // SAFETY: terminates only this dedicated thread's message loop.
                unsafe { PostQuitMessage(0) };
                return 0;
            }
            _ => {}
        }
    }

    // SAFETY: default processing is required for unhandled messages.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn signal_from_wts(value: u32) -> PresenceSignal {
    match value {
        WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT => PresenceSignal::Connected,
        WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => PresenceSignal::Disconnected,
        WTS_SESSION_LOGON => PresenceSignal::Logon,
        WTS_SESSION_LOGOFF => PresenceSignal::Logoff,
        WTS_SESSION_LOCK => PresenceSignal::Locked,
        WTS_SESSION_UNLOCK => PresenceSignal::Unlocked,
        _ => PresenceSignal::Ambiguous,
    }
}

fn emit_signal(context: &mut WindowContext, signal: PresenceSignal, source: PresenceUpdateSource) {
    let state = context.tracker.apply_signal(signal);
    emit(context, PresenceEvent { state, source });
}

fn sample_idle(context: &mut WindowContext) {
    let idle_for = idle_duration().ok_or(());
    let state = context.tracker.apply_idle_sample(idle_for);
    let source = if idle_for.is_ok() {
        PresenceUpdateSource::IdleSample
    } else {
        PresenceUpdateSource::ProbeFailure
    };
    emit(context, PresenceEvent { state, source });
}

fn emit(context: &WindowContext, event: PresenceEvent) {
    if let Ok(mut current) = context.current.lock() {
        *current = event.state;
    }
    let _ = context.sender.send(event);
}

fn idle_duration() -> Option<Duration> {
    let mut input = LASTINPUTINFO {
        cbSize: mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: input points to a correctly sized writable LASTINPUTINFO.
    if unsafe { GetLastInputInfo(&mut input) } == 0 {
        return None;
    }
    // SAFETY: GetTickCount has no pointer or lifetime preconditions. Wrapping
    // subtraction is required for the documented 32-bit tick rollover.
    let now = unsafe { GetTickCount() };
    Some(Duration::from_millis(now.wrapping_sub(input.dwTime) as u64))
}

pub(crate) fn query_current_presence() -> PresenceState {
    let mut buffer = ptr::null_mut();
    let mut bytes = 0_u32;
    // SAFETY: out-pointers are writable. The current server/current session and
    // WTSSessionInfoEx form are documented for querying the caller's session.
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )
    } == 0
    {
        return PresenceState::Unknown;
    }
    struct WtsAllocation(*mut u16);
    impl Drop for WtsAllocation {
        fn drop(&mut self) {
            // SAFETY: WTSQuerySessionInformationW returned this allocation and
            // WTSFreeMemory is its required matching free.
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
    let allocation = WtsAllocation(buffer);
    if allocation.0.is_null() || (bytes as usize) < mem::size_of::<WTSINFOEXW>() {
        return PresenceState::Unknown;
    }
    // SAFETY: the successful query returned at least one complete WTSINFOEXW
    // that remains live through `allocation`.
    let info = unsafe { &*allocation.0.cast::<WTSINFOEXW>() };
    if info.Level != 1 {
        return PresenceState::Unknown;
    }
    // SAFETY: Level 1 makes WTSInfoExLevel1 the active union member.
    let level = unsafe { info.Data.WTSInfoExLevel1 };
    if level.SessionState != WTSActive {
        return PresenceState::SwitchedAway;
    }
    let flags = level.SessionFlags as u32;
    match flags {
        WTS_SESSIONSTATE_LOCK => PresenceState::Locked,
        WTS_SESSIONSTATE_UNLOCK => PresenceState::Active,
        _ => PresenceState::Unknown,
    }
}

fn initialization_error() -> PresenceMonitorError {
    PresenceMonitorError {
        summary: "The Windows session notification window is unavailable.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_handle_is_safe_to_move_and_share() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsPresenceMonitor>();
    }

    #[test]
    fn wts_mapping_fails_closed_for_unrecognized_events() {
        assert_eq!(signal_from_wts(WTS_SESSION_LOCK), PresenceSignal::Locked);
        assert_eq!(
            signal_from_wts(WTS_SESSION_UNLOCK),
            PresenceSignal::Unlocked
        );
        assert_eq!(signal_from_wts(u32::MAX), PresenceSignal::Ambiguous);
    }

    #[test]
    #[ignore = "requires an interactive native Windows user session"]
    fn native_monitor_reports_an_initial_content_free_state() {
        let monitor = WindowsPresenceMonitor::start(Duration::from_secs(60)).unwrap();
        let event = monitor.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            event.state,
            PresenceState::Active
                | PresenceState::Idle
                | PresenceState::Locked
                | PresenceState::Unknown
        ));
    }
}
