//! Exact, path-free selected document and workspace access.
//!
//! Full paths and directory-entry names exist only in short-lived private
//! native buffers. Public bindings contain only the volume identity, the
//! 128-bit file identity, the selected resource kind, and the document format.

use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use stein_core::{ResourceKind, WorkspaceActivityKind};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, GENERIC_READ,
    GetLastError, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ExtendedFileIdType, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED,
    FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_ID_128,
    FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    FILE_TYPE_DISK, FileAttributeTagInfo, FileBasicInfo, FileIdInfo, FileNameInfo,
    FileStandardInfo, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
    GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, OPEN_EXISTING, OpenFileById, ReadDirectoryChangesW, ReadFile,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, WaitForSingleObject,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetOpenFileNameW, OFN_DONTADDTORECENT, OFN_ENABLEHOOK, OFN_EXPLORER,
    OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_NODEREFERENCELINKS, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::{
    BFFM_INITIALIZED, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW, SHBrowseForFolderW,
    SHGetPathFromIDListW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetParent, IDCANCEL, KillTimer, PostMessageW, SetTimer, WM_CLOSE, WM_COMMAND, WM_INITDIALOG,
};
use zeroize::Zeroize;

use crate::{WindowsDocumentFormat, WindowsSelectedResourceBinding};

pub(crate) const MAXIMUM_DOCUMENT_BYTES: usize = 16 * 1024;
const RAW_READ_EXTRA_BYTES: usize = 4;
const MAXIMUM_PRIVATE_PATH_UTF16: usize = 32_768;
const VOLUME_NAME_UTF16: usize = 1_024;
const DIRECTORY_CHANGE_BUFFER_BYTES: usize = 16 * 1024;
const FILE_NAME_BUFFER_BYTES: usize = 64 * 1024;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const NATIVE_PICKER_DEADLINE: Duration = Duration::from_secs(30);
const PICKER_TIMER_ID: usize = 0x5354_4549;
const PICKER_TIMER_MILLISECONDS: u32 = 25;
const CHANGE_FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SelectedResourceErrorKind {
    BoundaryLost,
    ProtectedSurface,
    UnsupportedType,
    Cancelled,
    Unavailable,
}

/// Content-free native failure. It intentionally carries no path, file name,
/// document bytes, Win32 message, or raw OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectedResourceError {
    pub(crate) kind: SelectedResourceErrorKind,
}

#[derive(Clone, Copy)]
enum PickerDialogKind {
    Document,
    Workspace,
}

struct PickerCancellationState {
    cancellation: CancellationToken,
    deadline: Instant,
    window: HWND,
    kind: PickerDialogKind,
    timer_failed: bool,
}

thread_local! {
    static PICKER_CANCELLATION: std::cell::RefCell<Option<PickerCancellationState>> =
        const { std::cell::RefCell::new(None) };
}

struct PickerCancellationGuard;

impl PickerCancellationGuard {
    fn install(
        cancellation: CancellationToken,
        kind: PickerDialogKind,
    ) -> Result<Self, SelectedResourceError> {
        let installed = PICKER_CANCELLATION
            .try_with(|slot| {
                let mut state = slot.try_borrow_mut().map_err(|_| ())?;
                if state.is_some() {
                    return Err(());
                }
                *state = Some(PickerCancellationState {
                    cancellation,
                    deadline: Instant::now() + NATIVE_PICKER_DEADLINE,
                    window: null_mut(),
                    kind,
                    timer_failed: false,
                });
                Ok(())
            })
            .map_err(|_| unavailable())?;
        installed.map_err(|_| unavailable())?;
        Ok(Self)
    }

    fn cancelled(&self) -> Result<bool, SelectedResourceError> {
        PICKER_CANCELLATION
            .try_with(|slot| {
                let state = slot.try_borrow().map_err(|_| unavailable())?;
                let state = state.as_ref().ok_or_else(unavailable)?;
                if state.timer_failed {
                    return Err(unavailable());
                }
                Ok(state.cancellation.is_cancelled() || Instant::now() >= state.deadline)
            })
            .map_err(|_| unavailable())?
    }
}

impl Drop for PickerCancellationGuard {
    fn drop(&mut self) {
        let _ = PICKER_CANCELLATION.try_with(|slot| {
            let Ok(mut state) = slot.try_borrow_mut() else {
                return;
            };
            if let Some(state) = state.take()
                && !state.window.is_null()
            {
                // SAFETY: the timer was installed on this picker thread and
                // cleanup is idempotent after the modal dialog exits.
                unsafe { KillTimer(state.window, PICKER_TIMER_ID) };
            }
        });
    }
}

fn install_picker_timer(window: HWND, kind: PickerDialogKind) {
    let _ = PICKER_CANCELLATION.try_with(|slot| {
        let Ok(mut state) = slot.try_borrow_mut() else {
            return;
        };
        let Some(state) = state.as_mut() else {
            return;
        };
        state.window = window;
        state.kind = kind;
        // SAFETY: the modal common dialog owns this HWND and pumps timers on
        // the same thread. The callback retains no native or content pointer.
        if unsafe {
            SetTimer(
                window,
                PICKER_TIMER_ID,
                PICKER_TIMER_MILLISECONDS,
                Some(picker_timer),
            )
        } == 0
        {
            state.timer_failed = true;
            close_picker(window, kind);
        }
    });
}

unsafe extern "system" fn picker_timer(window: HWND, _message: u32, id: usize, _time: u32) {
    if id != PICKER_TIMER_ID {
        return;
    }
    let should_close = PICKER_CANCELLATION
        .try_with(|slot| {
            let Ok(state) = slot.try_borrow() else {
                return true;
            };
            state.as_ref().is_none_or(|state| {
                state.timer_failed
                    || state.cancellation.is_cancelled()
                    || Instant::now() >= state.deadline
            })
        })
        .unwrap_or(true);
    if should_close {
        let kind = PICKER_CANCELLATION
            .try_with(|slot| {
                slot.try_borrow()
                    .ok()
                    .and_then(|state| state.as_ref().map(|state| state.kind))
            })
            .ok()
            .flatten()
            .unwrap_or(PickerDialogKind::Workspace);
        // SAFETY: this callback is running on the modal dialog's own thread.
        unsafe { KillTimer(window, PICKER_TIMER_ID) };
        close_picker(window, kind);
    }
}

fn close_picker(window: HWND, kind: PickerDialogKind) {
    let (message, wparam) = match kind {
        PickerDialogKind::Document => (WM_COMMAND, IDCANCEL as WPARAM),
        PickerDialogKind::Workspace => (WM_CLOSE, 0),
    };
    // SAFETY: posting is non-blocking and the HWND is the current thread's
    // exact common-dialog window. No pointer crosses the callback boundary.
    let _ = unsafe { PostMessageW(window, message, wparam, 0 as LPARAM) };
}

unsafe extern "system" fn document_picker_hook(
    dialog: HWND,
    message: u32,
    _wparam: WPARAM,
    _lparam: LPARAM,
) -> usize {
    if message == WM_INITDIALOG {
        // SAFETY: the hook dialog is a child of the actual common dialog.
        let parent = unsafe { GetParent(dialog) };
        if !parent.is_null() {
            install_picker_timer(parent, PickerDialogKind::Document);
        }
    }
    0
}

unsafe extern "system" fn workspace_picker_callback(
    dialog: HWND,
    message: u32,
    _lparam: LPARAM,
    _data: LPARAM,
) -> i32 {
    if message == BFFM_INITIALIZED {
        install_picker_timer(dialog, PickerDialogKind::Workspace);
    }
    0
}

pub(crate) enum SelectedResourceReceive {
    Activity(WorkspaceActivityKind),
    Timeout,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DocumentFingerprint {
    pub(crate) change_time: i64,
    pub(crate) last_write_time: i64,
    pub(crate) end_of_file: i64,
}

/// A permitted normalized value. It has no Debug implementation so accidental
/// diagnostics cannot print its text.
pub(crate) struct SelectedDocumentSample {
    pub(crate) text: String,
    pub(crate) complete: bool,
    pub(crate) fingerprint: DocumentFingerprint,
}

impl Drop for SelectedDocumentSample {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

pub(crate) enum SelectedDocumentRead {
    Sample(SelectedDocumentSample),
    Unchanged,
    Retry,
}

pub(crate) trait SelectedResourceEventSource: Send {
    fn kind(&self) -> ResourceKind;

    fn revalidate(&mut self) -> Result<(), SelectedResourceError>;

    fn receive(
        &mut self,
        timeout: Duration,
    ) -> Result<SelectedResourceReceive, SelectedResourceError>;

    fn read_document(
        &mut self,
        maximum_bytes: usize,
        force: bool,
    ) -> Result<SelectedDocumentRead, SelectedResourceError>;

    fn commit_document(&mut self, fingerprint: DocumentFingerprint);
}

pub(crate) trait SelectedResourceFactory: Send + Sync {
    fn select_document(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError>;

    fn select_workspace(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError>;

    fn open(
        &self,
        binding: &WindowsSelectedResourceBinding,
    ) -> Result<Box<dyn SelectedResourceEventSource>, SelectedResourceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeSelectedResourceFactory;

impl SelectedResourceFactory for NativeSelectedResourceFactory {
    fn select_document(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
        select_document_with_native_picker(cancellation)
    }

    fn select_workspace(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
        select_workspace_with_native_picker(cancellation)
    }

    fn open(
        &self,
        binding: &WindowsSelectedResourceBinding,
    ) -> Result<Box<dyn SelectedResourceEventSource>, SelectedResourceError> {
        Ok(Box::new(NativeSelectedResourceSource::open(binding)?))
    }
}

pub(crate) fn redact_selected_text(value: &str, maximum_bytes: usize) -> (String, bool) {
    let normalized = value.strip_prefix('\u{feff}').unwrap_or(value);
    let mut output = String::with_capacity(normalized.len().min(maximum_bytes));
    let mut complete = true;
    let mut private_key_block = false;

    for segment in normalized.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let lower = line.to_ascii_lowercase();
        let starts_private_key = lower.contains("-----begin") && lower.contains("private key");
        let ends_private_key = lower.contains("-----end") && lower.contains("private key");
        let sensitive_assignment = [
            "password",
            "passwd",
            "credential",
            "api_key",
            "api-key",
            "access_token",
            "refresh_token",
            "authorization",
            "secret",
        ]
        .iter()
        .any(|marker| {
            lower.find(marker).is_some_and(|index| {
                lower[index + marker.len()..]
                    .chars()
                    .any(|character| matches!(character, ':' | '='))
            })
        });

        let replacement = if private_key_block || starts_private_key || sensitive_assignment {
            "[REDACTED]"
        } else {
            line
        };
        private_key_block = (private_key_block || starts_private_key) && !ends_private_key;

        if !append_utf8_bounded(&mut output, replacement, maximum_bytes) {
            complete = false;
            break;
        }
        if segment.ends_with('\n') && !append_utf8_bounded(&mut output, "\n", maximum_bytes) {
            complete = false;
            break;
        }
    }
    (output, complete)
}

fn append_utf8_bounded(output: &mut String, value: &str, maximum_bytes: usize) -> bool {
    let remaining = maximum_bytes.saturating_sub(output.len());
    if value.len() <= remaining {
        output.push_str(value);
        return true;
    }
    let mut boundary = remaining.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    output.push_str(&value[..boundary]);
    false
}

struct NativeSelectedResourceSource {
    binding: WindowsSelectedResourceBinding,
    volume: OwnedHandle,
    watcher: DirectoryWatcher,
    selected_name: PrivateWide,
    last_document: Option<DocumentFingerprint>,
}

impl NativeSelectedResourceSource {
    fn open(binding: &WindowsSelectedResourceBinding) -> Result<Self, SelectedResourceError> {
        let volume = find_bound_volume(binding.volume_identity())?;
        let selected = open_by_binding(&volume, binding, false)?;
        verify_bound_handle(selected.raw(), binding, None)?;
        let selected_name = query_private_file_name(selected.raw())?;

        let watch_handle = match binding.kind() {
            ResourceKind::Document => open_parent_watcher(selected.raw())?,
            ResourceKind::Workspace => {
                let watcher = open_exact_directory_watcher(selected.raw())?;
                verify_bound_handle(watcher.raw(), binding, Some(&selected_name))?;
                watcher
            }
            _ => return Err(unsupported_type()),
        };
        let watcher =
            DirectoryWatcher::new(watch_handle, binding.kind() == ResourceKind::Workspace)?;
        Ok(Self {
            binding: binding.clone(),
            volume,
            watcher,
            selected_name,
            last_document: None,
        })
    }

    fn current_handle(&self, overlapped: bool) -> Result<OwnedHandle, SelectedResourceError> {
        open_by_binding(&self.volume, &self.binding, overlapped)
    }

    fn verify_current(&self, handle: HANDLE) -> Result<FileSnapshot, SelectedResourceError> {
        verify_bound_handle(handle, &self.binding, Some(&self.selected_name))
    }
}

impl SelectedResourceEventSource for NativeSelectedResourceSource {
    fn kind(&self) -> ResourceKind {
        self.binding.kind()
    }

    fn revalidate(&mut self) -> Result<(), SelectedResourceError> {
        let selected = self.current_handle(false)?;
        self.verify_current(selected.raw())?;
        if self.binding.kind() == ResourceKind::Workspace {
            self.verify_current(self.watcher.handle.raw())?;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        timeout: Duration,
    ) -> Result<SelectedResourceReceive, SelectedResourceError> {
        self.watcher.receive(timeout)
    }

    fn read_document(
        &mut self,
        maximum_bytes: usize,
        force: bool,
    ) -> Result<SelectedDocumentRead, SelectedResourceError> {
        if self.binding.kind() != ResourceKind::Document
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_DOCUMENT_BYTES
        {
            return Err(unsupported_type());
        }
        let selected = self.current_handle(false)?;
        let before = self.verify_current(selected.raw())?;
        if !force && self.last_document == Some(before.fingerprint) {
            return Ok(SelectedDocumentRead::Unchanged);
        }

        let requested = maximum_bytes
            .checked_add(RAW_READ_EXTRA_BYTES)
            .ok_or_else(unsupported_type)?;
        let mut raw = PrivateBytes::new(requested);
        let mut bytes_read = 0_u32;
        // SAFETY: `selected` is a live file handle opened for GENERIC_READ,
        // `raw` is writable for exactly `requested` bytes, and bytes_read is a
        // valid output. This is a synchronous handle, so OVERLAPPED is null.
        if unsafe {
            ReadFile(
                selected.raw(),
                raw.as_mut_ptr(),
                u32::try_from(requested).map_err(|_| unsupported_type())?,
                &mut bytes_read,
                null_mut(),
            )
        } == 0
        {
            return Err(boundary_lost());
        }
        raw.truncate(usize::try_from(bytes_read).map_err(|_| unavailable())?);

        let after = self.verify_current(selected.raw())?;
        if before != after {
            return Ok(SelectedDocumentRead::Retry);
        }
        let text = std::str::from_utf8(raw.as_slice()).map_err(|_| unsupported_type())?;
        if text.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        }) {
            return Err(unsupported_type());
        }
        let (text, redaction_complete) = redact_selected_text(text, maximum_bytes);
        let raw_complete = before.fingerprint.end_of_file >= 0
            && u64::try_from(before.fingerprint.end_of_file)
                .is_ok_and(|size| size <= u64::from(bytes_read));
        Ok(SelectedDocumentRead::Sample(SelectedDocumentSample {
            text,
            complete: raw_complete && redaction_complete,
            fingerprint: before.fingerprint,
        }))
    }

    fn commit_document(&mut self, fingerprint: DocumentFingerprint) {
        self.last_document = Some(fingerprint);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileSnapshot {
    fingerprint: DocumentFingerprint,
}

struct DirectoryWatcher {
    handle: OwnedHandle,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u32]>,
    watch_subtree: bool,
    pending: bool,
}

// SAFETY: a watcher is moved to its dedicated worker before any overlapped I/O
// is queued and is not moved again while an operation is pending. Its handles,
// buffer, and OVERLAPPED have exclusive ownership for the worker lifetime.
unsafe impl Send for DirectoryWatcher {}

impl DirectoryWatcher {
    fn new(handle: OwnedHandle, watch_subtree: bool) -> Result<Self, SelectedResourceError> {
        // SAFETY: null security/name pointers request an unnamed, auto-reset,
        // initially nonsignaled event. The successful handle is owned below.
        let event = OwnedHandle::new(unsafe { CreateEventW(null(), 0, 0, null()) })
            .ok_or_else(unavailable)?;
        let mut overlapped = Box::<OVERLAPPED>::default();
        overlapped.hEvent = event.raw();
        Ok(Self {
            handle,
            event,
            overlapped,
            buffer: vec![0_u32; DIRECTORY_CHANGE_BUFFER_BYTES / size_of::<u32>()]
                .into_boxed_slice(),
            watch_subtree,
            pending: false,
        })
    }

    fn receive(
        &mut self,
        timeout: Duration,
    ) -> Result<SelectedResourceReceive, SelectedResourceError> {
        if !self.pending {
            self.start_read()?;
        }
        let milliseconds = timeout
            .as_millis()
            .min(u128::from(u32::MAX - 1))
            .try_into()
            .map_err(|_| unavailable())?;
        // SAFETY: the event belongs to this watcher and remains live while the
        // pinned-by-Box OVERLAPPED and change buffer remain allocated.
        match unsafe { WaitForSingleObject(self.event.raw(), milliseconds) } {
            WAIT_TIMEOUT => Ok(SelectedResourceReceive::Timeout),
            WAIT_OBJECT_0 => self.finish_read(),
            _ => Err(unavailable()),
        }
    }

    fn start_read(&mut self) -> Result<(), SelectedResourceError> {
        self.buffer.fill(0);
        *self.overlapped = OVERLAPPED::default();
        self.overlapped.hEvent = self.event.raw();
        // SAFETY: the event is exclusively owned by this watcher and there is
        // no outstanding read when pending is false.
        if unsafe { ResetEvent(self.event.raw()) } == 0 {
            return Err(unavailable());
        }
        // SAFETY: the directory handle was opened with FILE_LIST_DIRECTORY and
        // FILE_FLAG_OVERLAPPED. The DWORD-aligned boxed buffer and boxed
        // OVERLAPPED remain at stable addresses until completion/cancellation.
        let queued = unsafe {
            ReadDirectoryChangesW(
                self.handle.raw(),
                self.buffer.as_mut_ptr().cast::<c_void>(),
                u32::try_from(size_of_val(&*self.buffer)).map_err(|_| unavailable())?,
                i32::from(self.watch_subtree),
                CHANGE_FILTER,
                null_mut(),
                &mut *self.overlapped,
                None,
            )
        };
        if queued == 0 {
            // SAFETY: read immediately after the failed Win32 call.
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(unavailable());
            }
        }
        self.pending = true;
        Ok(())
    }

    fn finish_read(&mut self) -> Result<SelectedResourceReceive, SelectedResourceError> {
        let mut bytes = 0_u32;
        // SAFETY: the event signaled for this exact outstanding OVERLAPPED.
        let completed =
            unsafe { GetOverlappedResult(self.handle.raw(), &*self.overlapped, &mut bytes, 0) };
        self.pending = false;
        if completed == 0 {
            // SAFETY: read immediately after the failed Win32 call.
            let native_error = unsafe { GetLastError() };
            return if native_error == ERROR_OPERATION_ABORTED {
                Err(boundary_lost())
            } else {
                Err(unavailable())
            };
        }
        let bytes = usize::try_from(bytes).map_err(|_| unavailable())?;
        if bytes == 0 || bytes > size_of_val(&*self.buffer) {
            self.buffer.fill(0);
            return Err(boundary_lost());
        }
        let activity = parse_activity_without_names(self.buffer.as_ptr(), bytes)?;
        self.buffer.fill(0);
        Ok(SelectedResourceReceive::Activity(activity))
    }
}

impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        if self.pending {
            // SAFETY: the outstanding operation uses this watcher-owned handle
            // and OVERLAPPED. Cancellation is followed by a completion wait so
            // neither backing allocation is released while the kernel uses it.
            let _ = unsafe { CancelIoEx(self.handle.raw(), &*self.overlapped) };
            // SAFETY: the event is live until after this wait. Cancellation of
            // the one outstanding operation must signal its event.
            let _ = unsafe { WaitForSingleObject(self.event.raw(), INFINITE) };
            let mut ignored = 0_u32;
            // SAFETY: consumes the cancelled completion before allocations drop.
            let _ = unsafe {
                GetOverlappedResult(self.handle.raw(), &*self.overlapped, &mut ignored, 0)
            };
        }
        self.buffer.fill(0);
    }
}

fn parse_activity_without_names(
    words: *const u32,
    bytes: usize,
) -> Result<WorkspaceActivityKind, SelectedResourceError> {
    let mut offset = 0_usize;
    let mut selected = None;
    loop {
        if bytes.saturating_sub(offset) < 12 {
            return Err(boundary_lost());
        }
        // SAFETY: offset bounds were checked, the native buffer is DWORD
        // aligned, and only the three fixed u32 header values are read. The
        // private variable-length file-name field is deliberately never read.
        let header = unsafe { words.cast::<u8>().add(offset).cast::<u32>() };
        // SAFETY: all three u32 values are inside the checked fixed header.
        let next_offset = unsafe { *header } as usize;
        // SAFETY: second fixed u32 field is inside the checked header.
        let action = unsafe { *header.add(1) };
        // SAFETY: third fixed u32 field is inside the checked header.
        let name_bytes = unsafe { *header.add(2) } as usize;
        if !name_bytes.is_multiple_of(2) || name_bytes > bytes.saturating_sub(offset + 12) {
            return Err(boundary_lost());
        }
        selected = coalesce_activity(selected, action_to_activity(action)?);
        if next_offset == 0 {
            break;
        }
        if next_offset < 12 || !next_offset.is_multiple_of(size_of::<u32>()) {
            return Err(boundary_lost());
        }
        offset = offset
            .checked_add(next_offset)
            .filter(|next| *next < bytes)
            .ok_or_else(boundary_lost)?;
    }
    selected.ok_or_else(boundary_lost)
}

fn action_to_activity(action: u32) -> Result<WorkspaceActivityKind, SelectedResourceError> {
    match action {
        FILE_ACTION_ADDED => Ok(WorkspaceActivityKind::Created),
        FILE_ACTION_REMOVED => Ok(WorkspaceActivityKind::Deleted),
        FILE_ACTION_MODIFIED => Ok(WorkspaceActivityKind::Modified),
        FILE_ACTION_RENAMED_OLD_NAME | FILE_ACTION_RENAMED_NEW_NAME => {
            Ok(WorkspaceActivityKind::Renamed)
        }
        _ => Err(boundary_lost()),
    }
}

fn coalesce_activity(
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

fn select_document_with_native_picker(
    cancellation: &CancellationToken,
) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
    if cancellation.is_cancelled() {
        return Err(cancelled());
    }
    let cancellation_guard =
        PickerCancellationGuard::install(cancellation.clone(), PickerDialogKind::Document)?;
    let mut path = PrivateWide::zeroed(MAXIMUM_PRIVATE_PATH_UTF16);
    let filter: Vec<u16> = "Synthetic text documents (*.txt;*.md)\0*.txt;*.md\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = "Select the exact STEIN document\0".encode_utf16().collect();
    let mut picker = OPENFILENAMEW {
        lStructSize: u32::try_from(size_of::<OPENFILENAMEW>()).map_err(|_| unavailable())?,
        lpstrFilter: filter.as_ptr(),
        lpstrFile: path.as_mut_ptr(),
        nMaxFile: u32::try_from(path.len()).map_err(|_| unavailable())?,
        lpstrTitle: title.as_ptr(),
        Flags: OFN_DONTADDTORECENT
            | OFN_ENABLEHOOK
            | OFN_EXPLORER
            | OFN_FILEMUSTEXIST
            | OFN_NOCHANGEDIR
            | OFN_NODEREFERENCELINKS
            | OFN_PATHMUSTEXIST,
        lpfnHook: Some(document_picker_hook),
        ..OPENFILENAMEW::default()
    };
    // SAFETY: picker points to initialized fixed buffers that remain live for
    // the synchronous native dialog. The returned path never leaves this scope.
    if unsafe { GetOpenFileNameW(&mut picker) } == 0 {
        if cancellation_guard.cancelled()? {
            return Err(cancelled());
        }
        // SAFETY: this is the documented follow-up to a failed common dialog.
        return if unsafe { CommDlgExtendedError() } == 0 {
            Err(cancelled())
        } else {
            Err(unavailable())
        };
    }
    if cancellation_guard.cancelled()? {
        return Err(cancelled());
    }
    let format = selected_document_format(path.nul_terminated_slice())?;
    binding_from_selected_native_path(path.as_ptr(), ResourceKind::Document, Some(format))
}

fn select_workspace_with_native_picker(
    cancellation: &CancellationToken,
) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
    if cancellation.is_cancelled() {
        return Err(cancelled());
    }
    let cancellation_guard =
        PickerCancellationGuard::install(cancellation.clone(), PickerDialogKind::Workspace)?;
    let mut display_name = PrivateWide::zeroed(260);
    let title: Vec<u16> = "Select the exact STEIN workspace\0"
        .encode_utf16()
        .collect();
    let picker = BROWSEINFOW {
        pszDisplayName: display_name.as_mut_ptr(),
        lpszTitle: title.as_ptr(),
        ulFlags: BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS,
        lpfn: Some(workspace_picker_callback),
        ..BROWSEINFOW::default()
    };
    // SAFETY: the native picker synchronously uses the initialized structure;
    // the returned PIDL is owned by the shell allocator and freed below.
    let item = unsafe { SHBrowseForFolderW(&picker) };
    if item.is_null() {
        if cancellation_guard.cancelled()? {
            return Err(cancelled());
        }
        return Err(cancelled());
    }
    if cancellation_guard.cancelled()? {
        // SAFETY: the PIDL was allocated by the shell task allocator.
        unsafe { CoTaskMemFree(item.cast::<c_void>()) };
        return Err(cancelled());
    }
    let mut path = PrivateWide::zeroed(260);
    // SAFETY: item is a live shell PIDL and path is a MAX_PATH-sized writable
    // buffer as required by SHGetPathFromIDListW.
    let resolved = unsafe { SHGetPathFromIDListW(item, path.as_mut_ptr()) };
    // SAFETY: the PIDL was allocated by the shell task allocator.
    unsafe { CoTaskMemFree(item.cast::<c_void>()) };
    if resolved == 0 {
        return Err(unavailable());
    }
    binding_from_selected_native_path(path.as_ptr(), ResourceKind::Workspace, None)
}

fn selected_document_format(path: &[u16]) -> Result<WindowsDocumentFormat, SelectedResourceError> {
    let without_nul = path.strip_suffix(&[0]).unwrap_or(path);
    if ends_with_ascii_case_insensitive(without_nul, ".txt") {
        Ok(WindowsDocumentFormat::PlainText)
    } else if ends_with_ascii_case_insensitive(without_nul, ".md") {
        Ok(WindowsDocumentFormat::Markdown)
    } else {
        Err(unsupported_type())
    }
}

fn ends_with_ascii_case_insensitive(value: &[u16], suffix: &str) -> bool {
    value.len() >= suffix.len()
        && value[value.len() - suffix.len()..]
            .iter()
            .zip(suffix.bytes())
            .all(|(actual, expected)| {
                u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(&expected))
            })
}

fn binding_from_selected_native_path(
    path: *const u16,
    kind: ResourceKind,
    format: Option<WindowsDocumentFormat>,
) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if kind == ResourceKind::Workspace {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    // SAFETY: path is a live NUL-terminated private picker buffer. The handle
    // uses read/attribute-only rights and broad sharing to avoid changing the
    // selected resource or blocking its owner.
    let handle = OwnedHandle::new(unsafe {
        CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    })
    .ok_or_else(selection_open_error)?;
    verify_local_ntfs(handle.raw())?;
    let identity = query_file_id(handle.raw())?;
    let binding = WindowsSelectedResourceBinding::from_selected_handle(
        identity.VolumeSerialNumber,
        identity.FileId.Identifier,
        kind,
        format,
    )
    .map_err(|_| boundary_lost())?;
    verify_bound_handle(handle.raw(), &binding, None)?;
    Ok(binding)
}

fn find_bound_volume(volume_identity: u64) -> Result<OwnedHandle, SelectedResourceError> {
    let mut name = PrivateWide::zeroed(VOLUME_NAME_UTF16);
    // SAFETY: name is a writable UTF-16 buffer with the declared element count.
    let search = unsafe {
        FindFirstVolumeW(
            name.as_mut_ptr(),
            u32::try_from(name.len()).map_err(|_| unavailable())?,
        )
    };
    if search == INVALID_HANDLE_VALUE {
        return Err(unavailable());
    }
    let search = VolumeSearchHandle(search);

    loop {
        if let Some(handle) = open_volume_root(name.as_ptr())
            && verify_local_ntfs(handle.raw()).is_ok()
            && query_file_id(handle.raw())
                .is_ok_and(|identity| identity.VolumeSerialNumber == volume_identity)
        {
            return Ok(handle);
        }
        name.fill(0);
        // SAFETY: search remains live and name is the same writable buffer used
        // to begin enumeration.
        if unsafe {
            FindNextVolumeW(
                search.0,
                name.as_mut_ptr(),
                u32::try_from(name.len()).map_err(|_| unavailable())?,
            )
        } == 0
        {
            return Err(boundary_lost());
        }
    }
}

fn open_volume_root(path: *const u16) -> Option<OwnedHandle> {
    // SAFETY: path is a NUL-terminated volume name from FindFirst/NextVolumeW.
    // A volume root directory handle is sufficient as OpenFileById's hint.
    OwnedHandle::new(unsafe {
        CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    })
}

fn open_by_binding(
    volume: &OwnedHandle,
    binding: &WindowsSelectedResourceBinding,
    overlapped: bool,
) -> Result<OwnedHandle, SelectedResourceError> {
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: u32::try_from(size_of::<FILE_ID_DESCRIPTOR>()).map_err(|_| unavailable())?,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 {
                Identifier: *binding.file_id(),
            },
        },
    };
    let (access, mut flags) = match binding.kind() {
        ResourceKind::Document => (
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_FLAG_OPEN_REPARSE_POINT,
        ),
        ResourceKind::Workspace => (
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        ),
        _ => return Err(unsupported_type()),
    };
    if overlapped {
        flags |= FILE_FLAG_OVERLAPPED;
    }
    // SAFETY: volume is a live handle on the bound volume, descriptor contains
    // the exact FILE_ID_128, and no security-attribute pointer is supplied.
    OwnedHandle::new(unsafe {
        OpenFileById(volume.raw(), &descriptor, access, SHARE_ALL, null(), flags)
    })
    .ok_or_else(boundary_lost)
}

fn verify_bound_handle(
    handle: HANDLE,
    binding: &WindowsSelectedResourceBinding,
    expected_name: Option<&PrivateWide>,
) -> Result<FileSnapshot, SelectedResourceError> {
    // SAFETY: handle is live and GetFileType has no pointer parameters.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(unsupported_type());
    }
    verify_local_ntfs(handle)?;
    let identity = query_file_id(handle)?;
    if identity.VolumeSerialNumber != binding.volume_identity()
        || identity.FileId.Identifier != *binding.file_id()
    {
        return Err(boundary_lost());
    }

    let attributes: FILE_ATTRIBUTE_TAG_INFO = query_fixed(handle, FileAttributeTagInfo)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes.ReparseTag != 0 {
        return Err(protected_surface());
    }
    let standard: FILE_STANDARD_INFO = query_fixed(handle, FileStandardInfo)?;
    let is_directory =
        attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || standard.Directory;
    match binding.kind() {
        ResourceKind::Document if is_directory || standard.DeletePending => {
            return Err(boundary_lost());
        }
        ResourceKind::Workspace if !is_directory || standard.DeletePending => {
            return Err(boundary_lost());
        }
        ResourceKind::Document | ResourceKind::Workspace => {}
        _ => return Err(unsupported_type()),
    }

    let name = query_private_file_name(handle)?;
    if let Some(expected) = expected_name
        && name.as_slice() != expected.as_slice()
    {
        return Err(boundary_lost());
    }
    if let Some(format) = binding.document_format()
        && selected_document_format_for_name(name.as_slice()) != Some(format)
    {
        return Err(unsupported_type());
    }

    let basic: FILE_BASIC_INFO = query_fixed(handle, FileBasicInfo)?;
    Ok(FileSnapshot {
        fingerprint: DocumentFingerprint {
            change_time: basic.ChangeTime,
            last_write_time: basic.LastWriteTime,
            end_of_file: standard.EndOfFile,
        },
    })
}

fn selected_document_format_for_name(value: &[u16]) -> Option<WindowsDocumentFormat> {
    if ends_with_ascii_case_insensitive(value, ".txt") {
        Some(WindowsDocumentFormat::PlainText)
    } else if ends_with_ascii_case_insensitive(value, ".md") {
        Some(WindowsDocumentFormat::Markdown)
    } else {
        None
    }
}

fn verify_local_ntfs(handle: HANDLE) -> Result<(), SelectedResourceError> {
    let mut file_system = PrivateWide::zeroed(16);
    // SAFETY: handle is live and file_system is a writable UTF-16 buffer. All
    // other optional outputs are intentionally null.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            file_system.as_mut_ptr(),
            u32::try_from(file_system.len()).map_err(|_| unavailable())?,
        )
    } == 0
    {
        return Err(unavailable());
    }
    let value = file_system.nul_terminated_slice();
    if !value
        .strip_suffix(&[0])
        .unwrap_or(value)
        .iter()
        .copied()
        .eq("NTFS".encode_utf16())
    {
        return Err(unsupported_type());
    }
    Ok(())
}

fn query_file_id(handle: HANDLE) -> Result<FILE_ID_INFO, SelectedResourceError> {
    query_fixed(handle, FileIdInfo)
}

fn query_fixed<T: Default>(handle: HANDLE, class: i32) -> Result<T, SelectedResourceError> {
    let mut value = T::default();
    // SAFETY: value is a correctly sized writable instance for the requested
    // information class selected by each private call site.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (&mut value as *mut T).cast::<c_void>(),
            u32::try_from(size_of::<T>()).map_err(|_| unavailable())?,
        )
    } == 0
    {
        return Err(boundary_lost());
    }
    Ok(value)
}

fn query_private_file_name(handle: HANDLE) -> Result<PrivateWide, SelectedResourceError> {
    let mut words = PrivateWords::zeroed(FILE_NAME_BUFFER_BYTES / size_of::<u32>());
    // SAFETY: the DWORD-aligned private buffer is writable for its declared
    // size. It is zeroed on drop and never formatted or serialized.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileNameInfo,
            words.as_mut_ptr().cast::<c_void>(),
            u32::try_from(words.byte_len()).map_err(|_| unavailable())?,
        )
    } == 0
    {
        return Err(boundary_lost());
    }
    let bytes = words.as_bytes();
    if bytes.len() < size_of::<u32>() {
        return Err(boundary_lost());
    }
    let name_bytes = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| boundary_lost())?);
    let name_bytes = usize::try_from(name_bytes).map_err(|_| boundary_lost())?;
    if name_bytes % 2 != 0 || name_bytes > bytes.len().saturating_sub(4) {
        return Err(boundary_lost());
    }
    let mut name = PrivateWide::zeroed(name_bytes / 2);
    for (index, pair) in bytes[4..4 + name_bytes].chunks_exact(2).enumerate() {
        name.as_mut_slice()[index] = u16::from_ne_bytes([pair[0], pair[1]]);
    }
    Ok(name)
}

fn open_parent_watcher(document: HANDLE) -> Result<OwnedHandle, SelectedResourceError> {
    let mut path = final_private_path(document)?;
    let path_without_nul = path
        .as_slice()
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(path.len());
    let separator = path.as_slice()[..path_without_nul]
        .iter()
        .rposition(|value| *value == b'\\' as u16)
        .ok_or_else(boundary_lost)?;
    path.truncate(separator);
    path.push(0);
    // SAFETY: path is a private NUL-terminated parent path derived from the
    // selected document handle and remains live for this synchronous call.
    let parent = OwnedHandle::new(unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    })
    .ok_or_else(boundary_lost)?;
    verify_directory_handle(parent.raw())?;
    Ok(parent)
}

fn open_exact_directory_watcher(directory: HANDLE) -> Result<OwnedHandle, SelectedResourceError> {
    let mut path = final_private_path(directory)?;
    path.push(0);
    // SAFETY: path is a private NUL-terminated value derived from the already
    // reopened exact FILE_ID_128 handle and remains live for this call.
    let watcher = OwnedHandle::new(unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    })
    .ok_or_else(boundary_lost)?;
    verify_directory_handle(watcher.raw())?;
    Ok(watcher)
}

fn verify_directory_handle(handle: HANDLE) -> Result<(), SelectedResourceError> {
    let attributes: FILE_ATTRIBUTE_TAG_INFO = query_fixed(handle, FileAttributeTagInfo)?;
    let standard: FILE_STANDARD_INFO = query_fixed(handle, FileStandardInfo)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes.ReparseTag != 0 {
        return Err(protected_surface());
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 || !standard.Directory {
        return Err(boundary_lost());
    }
    verify_local_ntfs(handle)
}

fn final_private_path(handle: HANDLE) -> Result<PrivateWide, SelectedResourceError> {
    // SAFETY: a null output with zero capacity queries the required UTF-16 size.
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, 0) };
    let required = usize::try_from(required).map_err(|_| boundary_lost())?;
    if required == 0 || required >= MAXIMUM_PRIVATE_PATH_UTF16 {
        return Err(boundary_lost());
    }
    let mut path = PrivateWide::zeroed(required + 1);
    // SAFETY: path is writable for required+1 UTF-16 elements and handle is live.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            path.as_mut_ptr(),
            u32::try_from(path.len()).map_err(|_| unavailable())?,
            0,
        )
    };
    let written = usize::try_from(written).map_err(|_| boundary_lost())?;
    if written == 0 || written >= path.len() {
        return Err(boundary_lost());
    }
    path.truncate(written);
    Ok(path)
}

struct OwnedHandle(HANDLE);

// SAFETY: Windows kernel handles are process-wide values that may be used from
// another thread. OwnedHandle preserves exclusive close ownership when moved.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OwnedHandle is created only for a successful API handle and
        // closes that handle exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct VolumeSearchHandle(HANDLE);

impl Drop for VolumeSearchHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from FindFirstVolumeW and is closed once.
        let _ = unsafe { FindVolumeClose(self.0) };
    }
}

struct PrivateBytes(Vec<u8>);

impl PrivateBytes {
    fn new(length: usize) -> Self {
        Self(vec![0; length])
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn truncate(&mut self, length: usize) {
        self.0.truncate(length);
    }
}

impl Drop for PrivateBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct PrivateWide(Vec<u16>);

impl PrivateWide {
    fn zeroed(length: usize) -> Self {
        Self(vec![0; length])
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }

    fn as_slice(&self) -> &[u16] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u16] {
        &mut self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn fill(&mut self, value: u16) {
        self.0.fill(value);
    }

    fn truncate(&mut self, length: usize) {
        self.0.truncate(length);
    }

    fn push(&mut self, value: u16) {
        self.0.push(value);
    }

    fn nul_terminated_slice(&self) -> &[u16] {
        let length = self
            .0
            .iter()
            .position(|value| *value == 0)
            .map_or(self.0.len(), |index| index + 1);
        &self.0[..length]
    }
}

impl Drop for PrivateWide {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct PrivateWords(Vec<u32>);

impl PrivateWords {
    fn zeroed(length: usize) -> Self {
        Self(vec![0; length])
    }

    fn as_mut_ptr(&mut self) -> *mut u32 {
        self.0.as_mut_ptr()
    }

    fn byte_len(&self) -> usize {
        self.0.len() * size_of::<u32>()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the u32 allocation is live and may be viewed as its exact
        // initialized byte representation for parsing the native output.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), self.byte_len()) }
    }
}

impl Drop for PrivateWords {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn selection_open_error() -> SelectedResourceError {
    // SAFETY: read immediately after the failed native open call.
    if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
        protected_surface()
    } else {
        boundary_lost()
    }
}

fn boundary_lost() -> SelectedResourceError {
    SelectedResourceError {
        kind: SelectedResourceErrorKind::BoundaryLost,
    }
}

fn protected_surface() -> SelectedResourceError {
    SelectedResourceError {
        kind: SelectedResourceErrorKind::ProtectedSurface,
    }
}

fn unsupported_type() -> SelectedResourceError {
    SelectedResourceError {
        kind: SelectedResourceErrorKind::UnsupportedType,
    }
}

fn cancelled() -> SelectedResourceError {
    SelectedResourceError {
        kind: SelectedResourceErrorKind::Cancelled,
    }
}

fn unavailable() -> SelectedResourceError {
    SelectedResourceError {
        kind: SelectedResourceErrorKind::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::process::Command;
    use std::thread;

    use tempfile::tempdir;

    use super::*;

    fn private_native_path(path: &std::path::Path) -> PrivateWide {
        let mut value = PrivateWide(path.as_os_str().encode_wide().collect());
        value.push(0);
        value
    }

    fn bind_test_path(
        path: &std::path::Path,
        kind: ResourceKind,
        format: Option<WindowsDocumentFormat>,
    ) -> Result<WindowsSelectedResourceBinding, SelectedResourceError> {
        let path = private_native_path(path);
        binding_from_selected_native_path(path.as_ptr(), kind, format)
    }

    #[test]
    fn local_redaction_is_utf8_bounded_and_removes_sensitive_assignments() {
        let input = "# Synthetic\r\npassword = synthetic-secret\nchoice = alpha\n\
                     -----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\n";
        let (redacted, complete) = redact_selected_text(input, MAXIMUM_DOCUMENT_BYTES);
        assert!(complete);
        assert!(!redacted.contains("synthetic-secret"));
        assert!(!redacted.contains("secret-material"));
        assert!(redacted.contains("choice = alpha"));
        assert!(redacted.matches("[REDACTED]").count() >= 3);

        let (bounded, complete) = redact_selected_text(&"é".repeat(20_000), 16_383);
        assert!(!complete);
        assert!(bounded.len() <= 16_383);
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn directory_actions_coalesce_without_inspecting_private_names() {
        let entries = [
            FILE_ACTION_MODIFIED,
            FILE_ACTION_ADDED,
            FILE_ACTION_RENAMED_OLD_NAME,
        ];
        let mut buffer = vec![0_u32; entries.len() * 3];
        for (index, action) in entries.into_iter().enumerate() {
            let offset = index * 3;
            buffer[offset] = if index + 1 == entries.len() { 0 } else { 12 };
            buffer[offset + 1] = action;
            buffer[offset + 2] = 0;
        }
        assert_eq!(
            parse_activity_without_names(buffer.as_ptr(), buffer.len() * size_of::<u32>()).unwrap(),
            WorkspaceActivityKind::Renamed
        );
    }

    #[test]
    fn native_document_reopens_by_file_id_and_ignores_unrelated_sibling_activity() {
        let directory = tempdir().unwrap();
        let document = directory.path().join("synthetic-brief.md");
        let unrelated = directory.path().join("unrelated.txt");
        fs::write(
            &document,
            "# Project Atlas\npassword = synthetic-secret\nOption A\n",
        )
        .unwrap();
        let binding = bind_test_path(
            &document,
            ResourceKind::Document,
            Some(WindowsDocumentFormat::Markdown),
        )
        .unwrap();
        let encoded = binding.to_string();
        assert!(!encoded.contains("synthetic-brief"));
        assert!(!encoded.contains(directory.path().to_string_lossy().as_ref()));

        let mut source = NativeSelectedResourceSource::open(&binding).unwrap();
        let SelectedDocumentRead::Sample(initial) =
            source.read_document(MAXIMUM_DOCUMENT_BYTES, true).unwrap()
        else {
            panic!("expected the exact selected document sample");
        };
        assert!(initial.text.contains("Project Atlas"));
        assert!(!initial.text.contains("synthetic-secret"));
        source.commit_document(initial.fingerprint);

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::write(unrelated, "synthetic unrelated activity").unwrap();
        });
        assert!(matches!(
            source.receive(Duration::from_secs(2)).unwrap(),
            SelectedResourceReceive::Activity(_)
        ));
        writer.join().unwrap();
        assert!(matches!(
            source.read_document(MAXIMUM_DOCUMENT_BYTES, false).unwrap(),
            SelectedDocumentRead::Unchanged
        ));

        let changed_document = document.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::write(changed_document, "# Project Atlas\nOption B\n").unwrap();
        });
        assert!(matches!(
            source.receive(Duration::from_secs(2)).unwrap(),
            SelectedResourceReceive::Activity(_)
        ));
        writer.join().unwrap();
        let SelectedDocumentRead::Sample(updated) =
            source.read_document(MAXIMUM_DOCUMENT_BYTES, false).unwrap()
        else {
            panic!("expected an exact changed-document sample");
        };
        assert!(updated.text.contains("Option B"));
    }

    #[test]
    fn native_document_rename_and_path_replacement_fail_the_bound_identity() {
        let directory = tempdir().unwrap();
        let document = directory.path().join("selected.txt");
        let renamed = directory.path().join("renamed.txt");
        fs::write(&document, "synthetic selected content").unwrap();
        let binding = bind_test_path(
            &document,
            ResourceKind::Document,
            Some(WindowsDocumentFormat::PlainText),
        )
        .unwrap();
        let mut source = NativeSelectedResourceSource::open(&binding).unwrap();
        fs::rename(&document, &renamed).unwrap();
        let error = source.revalidate().unwrap_err();
        assert_eq!(error.kind, SelectedResourceErrorKind::BoundaryLost);

        fs::write(&document, "synthetic replacement content").unwrap();
        let error = source.revalidate().unwrap_err();
        assert_eq!(error.kind, SelectedResourceErrorKind::BoundaryLost);
    }

    #[test]
    fn native_workspace_watcher_does_not_cross_the_selected_handle_boundary() {
        let root = tempdir().unwrap();
        let workspace = root.path().join("selected-workspace");
        let outside = root.path().join("outside.txt");
        fs::create_dir(&workspace).unwrap();
        let binding = bind_test_path(&workspace, ResourceKind::Workspace, None).unwrap();
        let mut source = NativeSelectedResourceSource::open(&binding).unwrap();

        let outside_writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::write(outside, "synthetic outside activity").unwrap();
        });
        assert!(matches!(
            source.receive(Duration::from_millis(250)).unwrap(),
            SelectedResourceReceive::Timeout
        ));
        outside_writer.join().unwrap();

        let inside = workspace.join("inside.md");
        let inside_writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::write(inside, "synthetic selected activity").unwrap();
        });
        assert!(matches!(
            source.receive(Duration::from_secs(2)).unwrap(),
            SelectedResourceReceive::Activity(WorkspaceActivityKind::Created)
                | SelectedResourceReceive::Activity(WorkspaceActivityKind::Modified)
        ));
        inside_writer.join().unwrap();

        let renamed = root.path().join("renamed-workspace");
        fs::rename(&workspace, renamed).unwrap();
        let error = source.revalidate().unwrap_err();
        assert_eq!(error.kind, SelectedResourceErrorKind::BoundaryLost);
    }

    #[test]
    fn native_reparse_workspace_is_rejected_before_a_binding_is_created() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("target-workspace");
        let link = directory.path().join("selected-workspace");
        fs::create_dir(&target).unwrap();
        let mut output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic junction creation failed"
        );
        output.stdout.fill(0);
        output.stderr.fill(0);
        let error = bind_test_path(&link, ResourceKind::Workspace, None).unwrap_err();
        assert_eq!(error.kind, SelectedResourceErrorKind::ProtectedSurface);
    }
}
