//! Selected-window Windows UI Automation extraction.
//!
//! UIA elements and text ranges never escape this module. Public bindings are
//! path- and content-free, and every extraction revalidates HWND, PID, process
//! creation time, stable application identity, session state, and element
//! membership before and after reading visible TextPattern ranges.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use stein_core::PresenceState;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::foreground::{
    ForegroundProbeError, ForegroundProbeErrorKind, NativeWindowIdentity,
    reject_current_product_window, resolve_window_identity, revalidate_window_identity,
};
use crate::presence::current_native_presence;
use crate::selected_resource::redact_selected_text;
use crate::uia_binding::WindowsUiaWindowBinding;

pub(crate) const MAXIMUM_UIA_TEXT_BYTES: usize = 16 * 1024;
const MAXIMUM_UIA_ELEMENTS: i32 = 1_024;
const MAXIMUM_VISIBLE_RANGES: i32 = 256;
const MAXIMUM_RAW_UTF16_UNITS: usize = MAXIMUM_UIA_TEXT_BYTES / 4;
pub(crate) const UIA_OPERATION_DEADLINE: Duration = Duration::from_secs(2);
const UIA_SELECTION_DEADLINE: Duration = Duration::from_secs(30);
const UIA_CANCELLATION_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowPickerAction {
    Wait,
    Select,
    Cancel,
}

struct WindowPickerState {
    armed: bool,
}

impl WindowPickerState {
    const fn new(primary_button_down: bool) -> Self {
        Self {
            armed: !primary_button_down,
        }
    }

    fn update(&mut self, primary_button_down: bool, cancelled: bool) -> WindowPickerAction {
        if cancelled {
            return WindowPickerAction::Cancel;
        }
        if !self.armed {
            self.armed = !primary_button_down;
            return WindowPickerAction::Wait;
        }
        if primary_button_down {
            WindowPickerAction::Select
        } else {
            WindowPickerAction::Wait
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiaErrorKind {
    BoundaryLost,
    ProtectedSurface,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiaInvocationError {
    Cancelled,
    TimedOut,
    Source(UiaError),
    WorkerLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UiaError {
    pub(crate) kind: UiaErrorKind,
}

pub(crate) struct VisibleTextSample {
    pub(crate) text: String,
    pub(crate) complete: bool,
    pub(crate) fingerprint: u64,
}

impl Drop for VisibleTextSample {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl std::fmt::Debug for VisibleTextSample {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VisibleTextSample")
            .field("bytes", &self.text.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

pub(crate) trait UiaTextSource: Send + Sync {
    fn revalidate(&self) -> Result<(), UiaError>;
    fn read_visible_text(&self, maximum_bytes: usize) -> Result<VisibleTextSample, UiaError>;
}

pub(crate) trait UiaTextSourceFactory: Send + Sync {
    fn select_window(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<WindowsUiaWindowBinding>, UiaError>;
    fn open(&self, binding: &WindowsUiaWindowBinding) -> Result<Arc<dyn UiaTextSource>, UiaError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeUiaTextSourceFactory;

impl UiaTextSourceFactory for NativeUiaTextSourceFactory {
    fn select_window(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<WindowsUiaWindowBinding>, UiaError> {
        require_unlocked_session()?;
        let Some(window) = native::pick_window(cancellation, UIA_SELECTION_DEADLINE)? else {
            return Ok(None);
        };
        reject_current_product_window(window).map_err(map_foreground_error)?;
        let selected = resolve_window_identity(window).map_err(map_foreground_error)?;
        revalidate_window_identity(&selected).map_err(map_foreground_error)?;
        require_unlocked_session()?;
        WindowsUiaWindowBinding::new(
            selected.window,
            selected.process_id,
            selected.process_created_at_ticks,
            selected.application,
        )
        .map(Some)
        .map_err(|_| boundary_lost())
    }

    fn open(&self, binding: &WindowsUiaWindowBinding) -> Result<Arc<dyn UiaTextSource>, UiaError> {
        let source = NativeUiaTextSource {
            selected: NativeWindowIdentity {
                window: binding.window(),
                process_id: binding.process_id(),
                process_created_at_ticks: binding.process_created_at_ticks(),
                application: binding.application().clone(),
            },
        };
        Ok(Arc::new(source))
    }
}

enum UiaOperation {
    Revalidate,
    Read(usize),
}

enum UiaOperationResult {
    Revalidated(Result<(), UiaError>),
    Read(Result<VisibleTextSample, UiaError>),
}

pub(crate) fn bounded_uia_revalidate(
    source: Arc<dyn UiaTextSource>,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<(), UiaInvocationError> {
    match invoke_uia(
        source,
        UiaOperation::Revalidate,
        external_cancellation,
        stop_cancellation,
    )? {
        UiaOperationResult::Revalidated(result) => result.map_err(UiaInvocationError::Source),
        UiaOperationResult::Read(_) => Err(UiaInvocationError::WorkerLost),
    }
}

pub(crate) fn bounded_uia_read(
    source: Arc<dyn UiaTextSource>,
    maximum_bytes: usize,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<VisibleTextSample, UiaInvocationError> {
    match invoke_uia(
        source,
        UiaOperation::Read(maximum_bytes),
        external_cancellation,
        stop_cancellation,
    )? {
        UiaOperationResult::Read(result) => result.map_err(UiaInvocationError::Source),
        UiaOperationResult::Revalidated(_) => Err(UiaInvocationError::WorkerLost),
    }
}

fn invoke_uia(
    source: Arc<dyn UiaTextSource>,
    operation: UiaOperation,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<UiaOperationResult, UiaInvocationError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("stein-uia-disposable-operation".to_owned())
        .spawn(move || {
            let result = match operation {
                UiaOperation::Revalidate => UiaOperationResult::Revalidated(source.revalidate()),
                UiaOperation::Read(maximum_bytes) => {
                    UiaOperationResult::Read(source.read_visible_text(maximum_bytes))
                }
            };
            // A timed-out or cancelled caller has dropped its receiver. In
            // that case `result` (including any text) is destroyed here.
            let _ = sender.send(result);
        })
        .map_err(|_| UiaInvocationError::WorkerLost)?;

    let started = Instant::now();
    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            return Err(UiaInvocationError::Cancelled);
        }
        let remaining = UIA_OPERATION_DEADLINE.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(UiaInvocationError::TimedOut);
        }
        match receiver.recv_timeout(UIA_CANCELLATION_POLL.min(remaining)) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(UiaInvocationError::WorkerLost);
            }
        }
    }
}

struct NativeUiaTextSource {
    selected: NativeWindowIdentity,
}

impl UiaTextSource for NativeUiaTextSource {
    fn revalidate(&self) -> Result<(), UiaError> {
        require_unlocked_session()?;
        revalidate_window_identity(&self.selected).map_err(map_foreground_error)
    }

    fn read_visible_text(&self, maximum_bytes: usize) -> Result<VisibleTextSample, UiaError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_UIA_TEXT_BYTES {
            return Err(unavailable());
        }
        self.revalidate()?;
        let extracted = native::extract_visible_text(
            self.selected.window,
            self.selected.process_id,
            maximum_bytes,
        )?;
        self.revalidate()?;
        let (text, redaction_complete) = redact_selected_text(&extracted.text, maximum_bytes);
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        Ok(VisibleTextSample {
            text,
            complete: extracted.complete && redaction_complete,
            fingerprint: hasher.finish(),
        })
    }
}

fn require_unlocked_session() -> Result<(), UiaError> {
    match current_native_presence() {
        PresenceState::Active | PresenceState::Idle => Ok(()),
        PresenceState::Locked | PresenceState::SwitchedAway => Err(protected_surface()),
        PresenceState::Unknown => Err(boundary_lost()),
    }
}

fn map_foreground_error(error: ForegroundProbeError) -> UiaError {
    match error.kind {
        ForegroundProbeErrorKind::BoundaryLost => boundary_lost(),
        ForegroundProbeErrorKind::ProtectedSurface => protected_surface(),
        ForegroundProbeErrorKind::Unavailable => unavailable(),
    }
}

fn boundary_lost() -> UiaError {
    UiaError {
        kind: UiaErrorKind::BoundaryLost,
    }
}

fn protected_surface() -> UiaError {
    UiaError {
        kind: UiaErrorKind::ProtectedSurface,
    }
}

fn unavailable() -> UiaError {
    UiaError {
        kind: UiaErrorKind::Unavailable,
    }
}

mod native {
    use std::ffi::c_void;
    use std::thread;
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::UI::Accessibility::{
        CUIAutomation8, IUIAutomation, IUIAutomationElement, IUIAutomationTextPattern,
        IUIAutomationTextPattern2, TreeScope_Subtree, UIA_TextPattern2Id, UIA_TextPatternId,
    };
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_ESCAPE, VK_LBUTTON,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GA_ROOT, GetAncestor, GetCursorPos, WindowFromPoint,
    };
    use zeroize::Zeroize;

    use super::{
        MAXIMUM_RAW_UTF16_UNITS, MAXIMUM_UIA_ELEMENTS, MAXIMUM_VISIBLE_RANGES, UiaError,
        WindowPickerAction, WindowPickerState, boundary_lost, protected_surface, unavailable,
    };

    pub(super) struct ExtractedText {
        pub(super) text: String,
        pub(super) complete: bool,
    }

    impl Drop for ExtractedText {
        fn drop(&mut self) {
            self.text.zeroize();
        }
    }

    pub(super) fn pick_window(
        cancellation: &CancellationToken,
        timeout: Duration,
    ) -> Result<Option<usize>, UiaError> {
        if timeout.is_zero() {
            return Ok(None);
        }
        let started = Instant::now();
        // The click that invoked selection must be released before the picker
        // arms. Only the next deliberate primary-button press is sampled; no
        // pointer path, click history, or keyboard content is retained.
        let mut state = WindowPickerState::new(key_is_down(VK_LBUTTON));
        loop {
            if started.elapsed() >= timeout {
                return Ok(None);
            }
            let primary_down = key_is_down(VK_LBUTTON);
            match state.update(
                primary_down,
                cancellation.is_cancelled() || key_is_down(VK_ESCAPE),
            ) {
                WindowPickerAction::Cancel => return Ok(None),
                WindowPickerAction::Wait => {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                WindowPickerAction::Select => {}
            }
            {
                let mut point = POINT::default();
                // SAFETY: `point` is a valid writable POINT. Failure includes
                // secure-desktop/session transitions and therefore fails shut.
                if unsafe { GetCursorPos(&mut point) } == 0 {
                    return Err(protected_surface());
                }
                // SAFETY: the sampled point exists only for this explicit
                // picker action. User32 returns a borrowed HWND identity.
                let child = unsafe { WindowFromPoint(point) };
                if child.is_null() {
                    return Err(boundary_lost());
                }
                // SAFETY: the returned HWND is used only to resolve its exact
                // top-level selected boundary.
                let root = unsafe { GetAncestor(child, GA_ROOT) };
                if root.is_null() {
                    return Err(boundary_lost());
                }
                return Ok(Some(root as usize));
            }
        }
    }

    fn key_is_down(key: u16) -> bool {
        // SAFETY: GetAsyncKeyState accepts a virtual-key value. Only Escape and
        // the primary button are sampled during an explicit picker action.
        (unsafe { GetAsyncKeyState(i32::from(key)) } as u16 & 0x8000) != 0
    }

    struct ComApartment;

    impl ComApartment {
        fn initialize() -> Result<Self, UiaError> {
            // SAFETY: this dedicated observation worker initializes COM once
            // for the duration of the extraction and balances it in Drop.
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
                .ok()
                .map_err(|_| unavailable())?;
            Ok(Self)
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: this balances the successful CoInitializeEx on the same
            // worker thread after every COM interface has been dropped.
            unsafe { CoUninitialize() };
        }
    }

    #[cfg(test)]
    pub(super) fn probe_uia_client_without_reading_content() -> Result<(), UiaError> {
        let _apartment = ComApartment::initialize()?;
        // SAFETY: this instantiates only the local UIA COM client; it does not
        // request a root, HWND, element tree, pattern, or source text.
        let _automation: IUIAutomation =
            unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| unavailable())?;
        Ok(())
    }

    pub(super) fn extract_visible_text(
        selected_window: usize,
        selected_process_id: u32,
        maximum_bytes: usize,
    ) -> Result<ExtractedText, UiaError> {
        let _apartment = ComApartment::initialize()?;
        // SAFETY: CUIAutomation8 is an in-process COM class and no outer
        // aggregate is supplied. The interface stays on this worker thread.
        let automation: IUIAutomation =
            unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| unavailable())?;
        let hwnd = HWND(selected_window as *mut c_void);
        // SAFETY: the HWND was revalidated immediately before this call.
        let root = unsafe { automation.ElementFromHandle(hwnd) }.map_err(|_| boundary_lost())?;
        if !validate_element(&root, selected_window, selected_process_id, false)? {
            return Err(boundary_lost());
        }
        // SAFETY: the true condition and resulting bounded array stay local.
        let condition = unsafe { automation.CreateTrueCondition() }.map_err(|_| unavailable())?;
        // SAFETY: TreeScope_Subtree is bounded below before any content read.
        let elements =
            unsafe { root.FindAll(TreeScope_Subtree, &condition) }.map_err(|_| boundary_lost())?;
        // SAFETY: Length has no pointer inputs and is checked before iteration.
        let count = unsafe { elements.Length() }.map_err(|_| boundary_lost())?;
        if count <= 0 || count > MAXIMUM_UIA_ELEMENTS {
            return Err(boundary_lost());
        }

        // First validate the complete bounded element set. Rejecting the whole
        // read when any password or foreign element exists avoids parent-range
        // aggregation accidentally reintroducing protected text.
        for index in 0..count {
            // SAFETY: index is within the checked UIA element array length.
            let element = unsafe { elements.GetElement(index) }.map_err(|_| boundary_lost())?;
            let _ = validate_element(&element, selected_window, selected_process_id, true)?;
        }

        for index in 0..count {
            // SAFETY: index remains in the checked array range.
            let element = unsafe { elements.GetElement(index) }.map_err(|_| boundary_lost())?;
            if !validate_element(&element, selected_window, selected_process_id, true)? {
                continue;
            }
            // Prefer TextPattern2 but consume only its inherited TextPattern
            // visible-range contract. Unsupported elements are skipped.
            // SAFETY: the validated UIA element is queried only for a supported
            // COM pattern interface; no text is requested by this call.
            let text_pattern_2 = unsafe {
                element.GetCurrentPatternAs::<IUIAutomationTextPattern2>(UIA_TextPattern2Id)
            };
            let extracted = if let Ok(pattern) = text_pattern_2 {
                extract_pattern(
                    &pattern,
                    selected_window,
                    selected_process_id,
                    maximum_bytes,
                )?
            } else {
                // SAFETY: this is the same validated element and the fallback
                // query requests only the base TextPattern COM interface.
                let text_pattern = unsafe {
                    element.GetCurrentPatternAs::<IUIAutomationTextPattern>(UIA_TextPatternId)
                };
                let Ok(pattern) = text_pattern else {
                    continue;
                };
                extract_pattern(
                    &pattern,
                    selected_window,
                    selected_process_id,
                    maximum_bytes,
                )?
            };
            if !extracted.text.is_empty() {
                return Ok(extracted);
            }
        }
        Err(boundary_lost())
    }

    fn extract_pattern(
        pattern: &IUIAutomationTextPattern,
        selected_window: usize,
        selected_process_id: u32,
        maximum_bytes: usize,
    ) -> Result<ExtractedText, UiaError> {
        // SAFETY: only visible UIA ranges are requested; DocumentRange is never
        // used because it could include scrolled or otherwise hidden content.
        let ranges = unsafe { pattern.GetVisibleRanges() }.map_err(|_| boundary_lost())?;
        // SAFETY: the returned COM array owns its range interfaces.
        let count = unsafe { ranges.Length() }.map_err(|_| boundary_lost())?;
        if !(0..=MAXIMUM_VISIBLE_RANGES).contains(&count) {
            return Err(boundary_lost());
        }
        let mut raw = String::new();
        let mut complete = true;
        let mut remaining_units = MAXIMUM_RAW_UTF16_UNITS;
        for index in 0..count {
            if remaining_units == 0 || raw.len() >= maximum_bytes {
                complete = false;
                break;
            }
            // SAFETY: index is within the checked visible range array.
            let range = unsafe { ranges.GetElement(index) }.map_err(|_| boundary_lost())?;
            // SAFETY: the enclosing element is used only for boundary checks.
            let enclosing = unsafe { range.GetEnclosingElement() }.map_err(|_| boundary_lost())?;
            if !validate_element(&enclosing, selected_window, selected_process_id, true)? {
                return Err(boundary_lost());
            }
            let requested = i32::try_from(remaining_units).map_err(|_| unavailable())?;
            // SAFETY: GetText is explicitly bounded and the BSTR remains local.
            let value = unsafe { range.GetText(requested) }.map_err(|_| boundary_lost())?;
            let value = value.to_string();
            let units = value.encode_utf16().count();
            remaining_units = remaining_units.saturating_sub(units);
            if !raw.is_empty() && !value.is_empty() {
                raw.push('\n');
            }
            raw.push_str(&value);
            if units == requested as usize {
                complete = false;
            }
        }
        Ok(ExtractedText {
            text: raw,
            complete,
        })
    }

    fn validate_element(
        element: &IUIAutomationElement,
        selected_window: usize,
        selected_process_id: u32,
        reject_password: bool,
    ) -> Result<bool, UiaError> {
        // SAFETY: every property read is metadata-only and is checked before
        // any TextPattern text is requested.
        let process_id = unsafe { element.CurrentProcessId() }.map_err(|_| boundary_lost())?;
        if process_id <= 0 || process_id as u32 != selected_process_id {
            return Err(protected_surface());
        }
        let is_password = if reject_password {
            // SAFETY: password state is authoritative UIA metadata. A failure
            // is not treated as a non-password result.
            bool::from(unsafe { element.CurrentIsPassword() }.map_err(|_| protected_surface())?)
        } else {
            false
        };
        if is_password {
            return Err(protected_surface());
        }
        // SAFETY: native handles are metadata only. Zero denotes a virtual UIA
        // element; nonzero child HWNDs must remain under the selected root.
        let native = unsafe { element.CurrentNativeWindowHandle() }.map_err(|_| boundary_lost())?;
        if !native.0.is_null() {
            let raw = native.0 as windows_sys::Win32::Foundation::HWND;
            // SAFETY: GetAncestor performs an identity query on the UIA-provided
            // HWND. No target-process memory is accessed.
            if unsafe { GetAncestor(raw, GA_ROOT) } as usize != selected_window {
                return Err(protected_surface());
            }
        }
        // SAFETY: offscreen metadata is required before using a visible range.
        if bool::from(unsafe { element.CurrentIsOffscreen() }.map_err(|_| boundary_lost())?) {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    struct BlockingSource {
        delay: Duration,
    }

    impl UiaTextSource for BlockingSource {
        fn revalidate(&self) -> Result<(), UiaError> {
            thread::sleep(self.delay);
            Ok(())
        }

        fn read_visible_text(&self, _maximum_bytes: usize) -> Result<VisibleTextSample, UiaError> {
            thread::sleep(self.delay);
            Ok(VisibleTextSample {
                text: "synthetic-late-text".to_owned(),
                complete: true,
                fingerprint: 1,
            })
        }
    }

    #[test]
    fn debug_output_never_contains_visible_text() {
        let sample = VisibleTextSample {
            text: "synthetic-private-uia-text".to_owned(),
            complete: true,
            fingerprint: 7,
        };
        let debug = format!("{sample:?}");
        assert!(!debug.contains("synthetic-private-uia-text"));
        assert!(debug.contains("bytes"));
    }

    #[test]
    fn uia_redaction_and_utf8_ceiling_are_shared_with_selected_documents() {
        let input = format!(
            "password = synthetic-secret\n{}",
            "é".repeat(MAXIMUM_UIA_TEXT_BYTES)
        );
        let (text, complete) = redact_selected_text(&input, MAXIMUM_UIA_TEXT_BYTES);
        assert!(!text.contains("synthetic-secret"));
        assert!(text.contains("[REDACTED]"));
        assert!(text.len() <= MAXIMUM_UIA_TEXT_BYTES);
        assert!(!complete);
        assert!(text.is_char_boundary(text.len()));
    }

    #[test]
    fn picker_does_not_accept_the_button_press_that_invoked_it() {
        let mut state = WindowPickerState::new(true);
        assert_eq!(state.update(true, false), WindowPickerAction::Wait);
        assert_eq!(state.update(false, false), WindowPickerAction::Wait);
        assert_eq!(state.update(false, false), WindowPickerAction::Wait);
        assert_eq!(state.update(true, false), WindowPickerAction::Select);
    }

    #[test]
    fn picker_cancellation_wins_before_any_target_selection() {
        let mut state = WindowPickerState::new(false);
        assert_eq!(state.update(true, true), WindowPickerAction::Cancel);
    }

    #[test]
    fn cancellation_abandons_a_hung_provider_without_waiting_for_its_thread() {
        let source: Arc<dyn UiaTextSource> = Arc::new(BlockingSource {
            delay: Duration::from_secs(5),
        });
        let external = CancellationToken::new();
        let stop = CancellationToken::new();
        stop.cancel();
        let started = Instant::now();
        assert_eq!(
            bounded_uia_revalidate(source, &external, &stop),
            Err(UiaInvocationError::Cancelled)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn hung_provider_is_poisoned_at_the_two_second_deadline() {
        let source: Arc<dyn UiaTextSource> = Arc::new(BlockingSource {
            delay: Duration::from_secs(5),
        });
        let external = CancellationToken::new();
        let stop = CancellationToken::new();
        let started = Instant::now();
        assert!(matches!(
            bounded_uia_read(source, MAXIMUM_UIA_TEXT_BYTES, &external, &stop),
            Err(UiaInvocationError::TimedOut)
        ));
        assert!(started.elapsed() >= UIA_OPERATION_DEADLINE);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn uia_source_contains_no_logging_persistence_or_serde_path() {
        let source = include_str!("uia.rs");
        for forbidden in [
            concat!("print", "ln!"),
            concat!("eprint", "ln!"),
            concat!("tracing", "::"),
            concat!("log", "::"),
            concat!("File", "::create"),
            concat!("Open", "Options"),
            concat!("Serialize", ","),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden source path: {forbidden}"
            );
        }
    }

    #[test]
    #[ignore = "safe native COM activation probe; no picker, HWND, tree, or text read"]
    fn native_uia_client_activates_without_reading_any_surface() {
        native::probe_uia_client_without_reading_content().unwrap();
    }
}
