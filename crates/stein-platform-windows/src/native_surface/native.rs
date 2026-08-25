use std::mem::{self, MaybeUninit};
use std::ptr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use stein_core::{EmergencyCommand, PresenceState};
use time::OffsetDateTime;
use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION,
    NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, DispatchMessageW, GWLP_USERDATA, GetCursorPos, GetMessageW, GetWindowLongPtrW,
    IDI_APPLICATION, KillTimer, LoadIconW, MF_DISABLED, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
    PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow,
    SetTimer, SetWindowLongPtrW, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage,
    WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_NCCREATE, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};

use super::{
    RenderedSurface, SharedSurface, SurfaceBoundary, SurfaceHealth, SurfaceRequest, SurfaceState,
    WindowsNativeSurfaceError, commit_surface_state, recover_surface_state,
};

const CLASS_NAME: &[u16] = &[
    b'S' as u16,
    b'T' as u16,
    b'E' as u16,
    b'I' as u16,
    b'N' as u16,
    b'_' as u16,
    b'N' as u16,
    b'a' as u16,
    b't' as u16,
    b'i' as u16,
    b'v' as u16,
    b'e' as u16,
    b'_' as u16,
    b'S' as u16,
    b'u' as u16,
    b'r' as u16,
    b'f' as u16,
    b'a' as u16,
    b'c' as u16,
    b'e' as u16,
    0,
];
const ICON_ID: u32 = 1;
const ICON_CALLBACK_MESSAGE: u32 = WM_APP + 0x51;
const PROCESS_REQUESTS_MESSAGE: u32 = WM_APP + 0x52;
const HEALTH_TIMER_ID: usize = 1;
const HEALTH_TIMER_MILLISECONDS: u32 = 1_000;
const REQUEST_CAPACITY: usize = 16;
const MENU_MUTE: usize = 1_002;
const MENU_STOP: usize = 1_003;

#[derive(Clone)]
pub(super) struct NativeRequestSender {
    sender: mpsc::SyncSender<SurfaceRequest>,
    window: usize,
}

impl NativeRequestSender {
    pub(super) fn send(&self, request: SurfaceRequest) -> Result<(), ()> {
        self.sender.try_send(request).map_err(|_| ())?;
        let window = self.window as HWND;
        // SAFETY: `window` is the status thread's HWND. Posting does not borrow
        // the request; ownership remains in the bounded channel.
        if unsafe { PostMessageW(window, PROCESS_REQUESTS_MESSAGE, 0, 0) } == 0 {
            return Err(());
        }
        Ok(())
    }
}

pub(super) struct NativeSurfaceThread {
    request: NativeRequestSender,
    window: usize,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl NativeSurfaceThread {
    pub(super) fn start(shared: Arc<SharedSurface>) -> Result<Self, WindowsNativeSurfaceError> {
        let (request_tx, request_rx) = mpsc::sync_channel(REQUEST_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_shared = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("stein-windows-native-surface".to_owned())
            .spawn(move || run_message_window(request_rx, thread_shared, ready_tx))
            .map_err(|_| initialization_error())?;
        let window = match ready_rx.recv() {
            Ok(Ok(window)) => window,
            _ => {
                let _ = thread.join();
                return Err(initialization_error());
            }
        };
        Ok(Self {
            request: NativeRequestSender {
                sender: request_tx,
                window,
            },
            window,
            thread: Mutex::new(Some(thread)),
        })
    }

    pub(super) fn request_sender(&self) -> NativeRequestSender {
        self.request.clone()
    }
}

impl Drop for NativeSurfaceThread {
    fn drop(&mut self) {
        let window = self.window as HWND;
        if !window.is_null() {
            // SAFETY: the handle belongs to the live status message thread and
            // WM_CLOSE merely requests orderly owning-thread teardown.
            unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
        }
        if let Ok(thread) = self.thread.get_mut()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

struct WindowContext {
    receiver: mpsc::Receiver<SurfaceRequest>,
    shared: Arc<SharedSurface>,
    state: SurfaceState,
    taskbar_created: u32,
    icon_added: bool,
}

fn run_message_window(
    receiver: mpsc::Receiver<SurfaceRequest>,
    shared: Arc<SharedSurface>,
    ready: mpsc::SyncSender<Result<usize, WindowsNativeSurfaceError>>,
) {
    let taskbar_message_name = wide("TaskbarCreated");
    // SAFETY: the string is NUL-terminated and live for the synchronous call.
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar_message_name.as_ptr()) };
    if taskbar_created == 0 {
        shared.mark_health(SurfaceHealth::ShellUnavailable, None);
        let _ = ready.send(Err(initialization_error()));
        return;
    }

    let mut context = Box::new(WindowContext {
        receiver,
        shared: Arc::clone(&shared),
        state: SurfaceState::default(),
        taskbar_created,
        icon_added: false,
    });
    // SAFETY: null asks for the module containing this code.
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance.is_null() {
        shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
        let _ = ready.send(Err(initialization_error()));
        return;
    }
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_procedure),
        hInstance: instance,
        lpszClassName: CLASS_NAME.as_ptr(),
        ..Default::default()
    };
    // SAFETY: the WNDCLASS and static class-name storage remain valid for this
    // synchronous registration call.
    if unsafe { RegisterClassW(&class) } == 0 {
        // SAFETY: read immediately after RegisterClassW failed.
        let error = unsafe { GetLastError() };
        if error != ERROR_CLASS_ALREADY_EXISTS {
            shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
            let _ = ready.send(Err(initialization_error()));
            return;
        }
    }

    let context_ptr = (&mut *context) as *mut WindowContext;
    // SAFETY: context is a stable Box allocation that outlives the hidden
    // top-level window and its entire message loop.
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
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            context_ptr.cast(),
        )
    };
    let initial_surface = SurfaceState::default().rendered(false, Instant::now());
    if window.is_null()
        || !validate_menu_layout(&initial_surface)
        || !add_icon(window, initial_surface.mode.tooltip())
    {
        if !window.is_null() {
            // SAFETY: window was just created on this thread.
            unsafe { DestroyWindow(window) };
        }
        shared.mark_health(SurfaceHealth::ShellUnavailable, None);
        let _ = ready.send(Err(initialization_error()));
        return;
    }
    context.icon_added = true;
    // SAFETY: a null callback routes periodic WM_TIMER messages to this window.
    if unsafe { SetTimer(window, HEALTH_TIMER_ID, HEALTH_TIMER_MILLISECONDS, None) } == 0 {
        delete_icon(window);
        // SAFETY: window is live and owned by this thread.
        unsafe { DestroyWindow(window) };
        shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
        let _ = ready.send(Err(initialization_error()));
        return;
    }

    shared.mark_health(SurfaceHealth::Healthy, None);
    if ready.send(Ok(window as usize)).is_err() {
        // SAFETY: timer/window belong to this thread.
        unsafe { KillTimer(window, HEALTH_TIMER_ID) };
        delete_icon(window);
        // SAFETY: window is live and owned by this thread.
        unsafe { DestroyWindow(window) };
        return;
    }

    let mut message = MaybeUninit::<MSG>::zeroed();
    loop {
        // SAFETY: message is writable; positive results initialize it.
        let result = unsafe { GetMessageW(message.as_mut_ptr(), ptr::null_mut(), 0, 0) };
        if result <= 0 {
            break;
        }
        // SAFETY: a positive GetMessageW result initialized MSG.
        unsafe {
            let message = message.assume_init_ref();
            TranslateMessage(message);
            DispatchMessageW(message);
        }
    }
    if context.icon_added {
        delete_icon(window);
    }
    shared.mark_health(SurfaceHealth::MessageLoopStopped, None);
    shared.emergency_notify.notify_waiters();
}

unsafe extern "system" fn window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: all raw access is confined to the callback invariants below.
        unsafe { window_procedure_inner(window, message, wparam, lparam) }
    }))
    .unwrap_or_else(|_| {
        mark_callback_failure(window);
        // SAFETY: default processing accepts the original callback arguments.
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    })
}

fn mark_callback_failure(window: HWND) {
    // SAFETY: this only reads the pointer installed during WM_NCCREATE.
    let context = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut WindowContext;
    if !context.is_null() {
        // SAFETY: context lives through destruction of this window.
        unsafe { &*context }
            .shared
            .mark_health(SurfaceHealth::MessageLoopStopped, None);
    }
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
            // SAFETY: WM_NCCREATE provides a valid CREATESTRUCTW and the stable
            // WindowContext pointer was supplied as lpCreateParams.
            let context = unsafe { (*create).lpCreateParams as isize };
            // SAFETY: stores, but does not dereference, that stable pointer.
            unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, context) };
        }
    }
    // SAFETY: reads the pointer installed during WM_NCCREATE.
    let context_ptr = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut WindowContext;
    if !context_ptr.is_null() {
        // SAFETY: the owning Box outlives this window and dispatch is confined
        // to its dedicated thread.
        let context = unsafe { &mut *context_ptr };
        if message == context.taskbar_created {
            let mut boundary = AddIconBoundary { window };
            context.icon_added =
                recover_surface_state(&context.state, &mut boundary, Instant::now());
            if context.icon_added {
                refresh_health(context);
            } else {
                context
                    .shared
                    .mark_health(SurfaceHealth::ShellUnavailable, None);
            }
            return 0;
        }
        match message {
            PROCESS_REQUESTS_MESSAGE => {
                process_requests(window, context);
                return 0;
            }
            HEALTH_TIMER_ID_MESSAGE if wparam == HEALTH_TIMER_ID => {
                let rendered = context.state.rendered(false, Instant::now());
                if !modify_icon(window, rendered.mode.tooltip()) {
                    context.icon_added = false;
                    context
                        .shared
                        .mark_health(SurfaceHealth::ShellUnavailable, None);
                } else {
                    refresh_health(context);
                }
                return 0;
            }
            ICON_CALLBACK_MESSAGE => {
                let event = (lparam as u32) & 0xffff;
                if event == WM_CONTEXTMENU || event == WM_RBUTTONUP {
                    show_status_menu(window, context);
                }
                return 0;
            }
            WM_CLOSE => {
                // SAFETY: timer belongs to this live window.
                unsafe { KillTimer(window, HEALTH_TIMER_ID) };
                if context.icon_added {
                    delete_icon(window);
                    context.icon_added = false;
                }
                // SAFETY: destroys the window on its owning thread.
                unsafe { DestroyWindow(window) };
                return 0;
            }
            WM_DESTROY => {
                // SAFETY: exits only this dedicated message loop.
                unsafe { PostQuitMessage(0) };
                return 0;
            }
            _ => {}
        }
    }
    // SAFETY: required default handling for messages not consumed above.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

const HEALTH_TIMER_ID_MESSAGE: u32 = WM_TIMER;

fn process_requests(window: HWND, context: &mut WindowContext) {
    while let Ok(request) = context.receiver.try_recv() {
        let now_utc = OffsetDateTime::now_utc();
        let now = Instant::now();
        match request {
            SurfaceRequest::Publish { status, response } => {
                let result = context
                    .state
                    .prepare_publish(&status, now_utc, now)
                    .and_then(|(next, acknowledgement)| {
                        commit_surface(window, context, next)?;
                        Ok(acknowledgement)
                    });
                let _ = response.send(result);
            }
            SurfaceRequest::Clear {
                session_id,
                revision,
                response,
            } => {
                let result = context
                    .state
                    .prepare_clear(session_id, revision, now_utc)
                    .and_then(|(next, acknowledgement)| {
                        commit_surface(window, context, next)?;
                        Ok(acknowledgement)
                    });
                let _ = response.send(result);
            }
        }
    }
}

fn commit_surface(
    window: HWND,
    context: &mut WindowContext,
    next: SurfaceState,
) -> Result<(), stein_core::NativeStatusError> {
    let mut boundary = ModifyIconBoundary { window };
    if let Err(error) =
        commit_surface_state(&mut context.state, next, &mut boundary, Instant::now())
    {
        context.icon_added = false;
        context
            .shared
            .mark_health(SurfaceHealth::ShellUnavailable, None);
        return Err(error);
    }
    refresh_health(context);
    Ok(())
}

struct AddIconBoundary {
    window: HWND,
}

impl SurfaceBoundary for AddIconBoundary {
    fn render(&mut self, surface: &RenderedSurface) -> bool {
        validate_menu_layout(surface) && add_icon(self.window, surface.mode.tooltip())
    }
}

struct ModifyIconBoundary {
    window: HWND,
}

impl SurfaceBoundary for ModifyIconBoundary {
    fn render(&mut self, surface: &RenderedSurface) -> bool {
        validate_menu_layout(surface) && modify_icon(self.window, surface.mode.tooltip())
    }
}

fn refresh_health(context: &WindowContext) {
    if !context.icon_added {
        context
            .shared
            .mark_health(SurfaceHealth::ShellUnavailable, None);
        return;
    }
    let now = Instant::now();
    let deadline = context.state.heartbeat_deadline();
    let health = if deadline.is_some_and(|deadline| deadline <= now) {
        SurfaceHealth::HeartbeatExpired
    } else if context
        .shared
        .emergency
        .lock()
        .map_or(true, |queue| queue.has_expired_acknowledgement(now))
    {
        SurfaceHealth::EmergencyAcknowledgementExpired
    } else {
        SurfaceHealth::Healthy
    };
    context.shared.mark_health(health, deadline);
    if health == SurfaceHealth::Healthy {
        context
            .shared
            .record_message_loop_heartbeats(&context.state, OffsetDateTime::now_utc());
    }
}

fn show_status_menu(window: HWND, context: &WindowContext) {
    let labels_allowed = crate::presence::current_native_presence() == PresenceState::Active;
    let rendered = context.state.rendered(labels_allowed, Instant::now());
    // SAFETY: CreatePopupMenu returns an owning menu handle or null.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        context
            .shared
            .mark_health(SurfaceHealth::ShellUnavailable, None);
        return;
    }
    if !populate_status_menu(menu, &rendered) {
        // SAFETY: menu is owned by this function and was never displayed.
        unsafe { DestroyMenu(menu) };
        context
            .shared
            .mark_health(SurfaceHealth::ShellUnavailable, None);
        return;
    }

    let mut point = POINT::default();
    // SAFETY: point is writable and window/menu are live on this thread.
    let selected = unsafe {
        if GetCursorPos(&mut point) == 0 {
            0
        } else {
            SetForegroundWindow(window);
            TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                0,
                window,
                ptr::null(),
            ) as usize
        }
    };
    // SAFETY: menu is owned by this function and no longer displayed.
    unsafe { DestroyMenu(menu) };
    match selected {
        MENU_MUTE => {
            if let Some(session_id) = rendered.current_session {
                context
                    .shared
                    .enqueue(EmergencyCommand::SetInterventionsMuted {
                        session_id,
                        muted: !rendered.current_session_muted,
                    });
            }
        }
        MENU_STOP => context.shared.enqueue(EmergencyCommand::StopAllObservation),
        _ => {}
    }
}

fn validate_menu_layout(surface: &RenderedSurface) -> bool {
    // SAFETY: CreatePopupMenu returns an owning menu handle or null.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return false;
    }
    let valid = populate_status_menu(menu, surface);
    // SAFETY: menu is owned here and has never been displayed.
    unsafe { DestroyMenu(menu) };
    valid
}

fn populate_status_menu(
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    rendered: &RenderedSurface,
) -> bool {
    append_disabled(menu, rendered.mode.tooltip())
        && rendered
            .categories
            .iter()
            .all(|category| append_disabled(menu, &format!("Capturing: {category}")))
        && rendered
            .resource_labels
            .iter()
            .all(|label| append_disabled(menu, &format!("Resource: {}", escape_menu_label(label))))
        && append_separator(menu)
        && append_action(
            menu,
            MENU_MUTE,
            if rendered.current_session_muted {
                "Unmute interventions"
            } else {
                "Mute interventions"
            },
            rendered.current_session.is_some(),
        )
        && append_action(menu, MENU_STOP, "Stop all observation", true)
}

fn append_disabled(menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU, value: &str) -> bool {
    let value = wide(value);
    // SAFETY: menu is live and the NUL-terminated string remains valid for the
    // synchronous copy performed by AppendMenuW.
    unsafe { AppendMenuW(menu, MF_STRING | MF_GRAYED | MF_DISABLED, 0, value.as_ptr()) != 0 }
}

fn append_action(
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    id: usize,
    value: &str,
    enabled: bool,
) -> bool {
    let value = wide(value);
    let flags = if enabled {
        MF_STRING
    } else {
        MF_STRING | MF_GRAYED | MF_DISABLED
    };
    // SAFETY: menu is live and AppendMenuW copies the string synchronously.
    unsafe { AppendMenuW(menu, flags, id, value.as_ptr()) != 0 }
}

fn append_separator(menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU) -> bool {
    // SAFETY: menu is live; separators have no string pointer.
    unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null()) != 0 }
}

fn escape_menu_label(value: &str) -> String {
    value.replace('&', "&&")
}

fn add_icon(window: HWND, tooltip: &str) -> bool {
    let mut data = icon_data(window, tooltip);
    // SAFETY: the fully initialized NOTIFYICONDATAW is valid during both
    // synchronous shell calls. IDI_APPLICATION is a shared stock icon.
    if unsafe { Shell_NotifyIconW(NIM_ADD, &data) } == 0 {
        return false;
    }
    data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    // SAFETY: same live icon identity and initialized structure.
    if unsafe { Shell_NotifyIconW(NIM_SETVERSION, &data) } == 0 {
        // SAFETY: remove the icon that NIM_ADD just created.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
        return false;
    }
    true
}

fn modify_icon(window: HWND, tooltip: &str) -> bool {
    let data = icon_data(window, tooltip);
    // SAFETY: data describes the existing icon and lives through this call.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) != 0 }
}

fn delete_icon(window: HWND) {
    let data = icon_data(window, "STEIN: unavailable");
    // SAFETY: deletion is idempotent for this window/icon ID and data lives for
    // the synchronous call.
    unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
}

fn icon_data(window: HWND, tooltip: &str) -> NOTIFYICONDATAW {
    let mut data = NOTIFYICONDATAW {
        cbSize: mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: ICON_ID,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: ICON_CALLBACK_MESSAGE,
        // SAFETY: a null instance with IDI_APPLICATION loads a shared system
        // icon. The returned shared handle must not be destroyed by this code.
        hIcon: unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) },
        ..Default::default()
    };
    let tooltip = wide(tooltip);
    let copy_length = tooltip.len().saturating_sub(1).min(data.szTip.len() - 1);
    data.szTip[..copy_length].copy_from_slice(&tooltip[..copy_length]);
    data
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn initialization_error() -> WindowsNativeSurfaceError {
    WindowsNativeSurfaceError {
        summary: "The Windows native status surface could not initialize.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_escaping_does_not_create_accidental_mnemonics() {
        assert_eq!(escape_menu_label("R&D synthetic"), "R&&D synthetic");
    }

    #[test]
    fn native_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NativeSurfaceThread>();
    }

    #[test]
    #[ignore = "requires an interactive native Windows Explorer session"]
    fn native_surface_starts_and_recovers_through_taskbar_message_path() {
        let shared = Arc::new(SharedSurface::new());
        let surface = NativeSurfaceThread::start(Arc::clone(&shared)).unwrap();
        assert!(shared.availability().is_available());
        // Mirror Explorer's loss of all notification icons before broadcasting
        // TaskbarCreated; the owning thread still believes it must recover.
        delete_icon(surface.window as HWND);
        let taskbar_created = wide("TaskbarCreated");
        // SAFETY: string is valid for synchronous registration and the returned
        // registered message is posted to the live test surface window.
        let message = unsafe { RegisterWindowMessageW(taskbar_created.as_ptr()) };
        // SAFETY: this is a non-blocking post to a live HWND.
        let posted = unsafe { PostMessageW(surface.window as HWND, message, 0, 0) };
        assert_ne!(posted, 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(shared.availability().is_available());
    }
}
