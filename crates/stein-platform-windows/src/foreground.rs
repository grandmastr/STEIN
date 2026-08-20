//! Exact, content-free Windows foreground application identity.
//!
//! This module intentionally does not expose window titles, executable paths,
//! process identifiers, or identities for applications outside the selected
//! resource. Native values remain on the stack or behind private handle guards.

use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    APPMODEL_ERROR_NO_APPLICATION, APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_ACCESS_DENIED,
    ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, FILETIME, GENERIC_READ, GetLastError, HANDLE, HWND,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_SHA256_HASH_PROP_ID, CertGetCertificateContextProperty,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::Win32::Security::{
    EqualSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
};
use windows_sys::Win32::Storage::Packaging::Appx::{
    APPLICATION_USER_MODEL_ID_MAX_LENGTH, GetApplicationUserModelId, GetPackageFamilyName,
    PACKAGE_FAMILY_NAME_MAX_LENGTH,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessInformation, GetProcessTimes, OpenProcess,
    OpenProcessToken, PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROTECTION_LEVEL_NONE, ProcessProtectionLevelInfo, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GA_ROOT, GetAncestor, GetForegroundWindow, GetWindowThreadProcessId, IsWindow, IsWindowVisible,
};

use crate::WindowsApplicationBinding;

const MAXIMUM_PROCESS_IMAGE_PATH_UTF16: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForegroundMatch {
    Selected,
    OutsideSelectedScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForegroundProbeErrorKind {
    BoundaryLost,
    ProtectedSurface,
    Unavailable,
}

/// Deliberately content-free native failure. In particular, it carries no
/// Win32 error text because that can include a private executable path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForegroundProbeError {
    pub(crate) kind: ForegroundProbeErrorKind,
}

pub(crate) trait ForegroundIdentityProbe: Send + Sync {
    fn resolve_current(&self) -> Result<WindowsApplicationBinding, ForegroundProbeError>;

    fn classify_current(
        &self,
        selected: &WindowsApplicationBinding,
    ) -> Result<ForegroundMatch, ForegroundProbeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeForegroundIdentityProbe;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeWindowIdentity {
    pub(crate) window: usize,
    pub(crate) process_id: u32,
    pub(crate) process_created_at_ticks: u64,
    pub(crate) application: WindowsApplicationBinding,
}

pub(crate) fn resolve_window_identity(
    window: usize,
) -> Result<NativeWindowIdentity, ForegroundProbeError> {
    let process = ForegroundProcess::open_window(window as HWND)?;
    let application = process.resolve_binding()?;
    process.ensure_still_window()?;
    Ok(NativeWindowIdentity {
        window,
        process_id: process.process_id,
        process_created_at_ticks: process.process_created_at_ticks,
        application,
    })
}

pub(crate) fn revalidate_window_identity(
    selected: &NativeWindowIdentity,
) -> Result<(), ForegroundProbeError> {
    let process = ForegroundProcess::open_window(selected.window as HWND)?;
    if process.process_id != selected.process_id
        || process.process_created_at_ticks != selected.process_created_at_ticks
        || process.classify(&selected.application)? != ForegroundMatch::Selected
    {
        return Err(boundary_lost());
    }
    process.ensure_still_window()
}

pub(crate) fn reject_current_product_window(window: usize) -> Result<(), ForegroundProbeError> {
    let target = ForegroundProcess::open_window(window as HWND)?;
    // SAFETY: GetCurrentProcessId has no pointer inputs and the target PID was
    // sampled from the exact selected HWND.
    if target.process_id == unsafe { GetCurrentProcessId() } {
        return Err(protected_surface());
    }

    // Full-trust children and presentation executables in the same MSIX share
    // a package family even when only one declares an AUMID.
    // SAFETY: GetCurrentProcess returns the documented live pseudo-handle.
    let current = unsafe { GetCurrentProcess() };
    let target_package = query_process_identity(
        target.process.raw(),
        GetPackageFamilyName,
        PACKAGE_FAMILY_NAME_MAX_LENGTH,
        &[APPMODEL_ERROR_NO_PACKAGE],
    )?;
    let current_package = query_process_identity(
        current,
        GetPackageFamilyName,
        PACKAGE_FAMILY_NAME_MAX_LENGTH,
        &[APPMODEL_ERROR_NO_PACKAGE],
    )?;
    if target_package.is_some() && target_package == current_package {
        return Err(protected_surface());
    }

    // Unpackaged development/release processes are excluded by their pinned
    // Authenticode publisher. Failure to establish either publisher fails
    // closed instead of allowing STEIN to select its own surface.
    let target_image = ProcessImage::open(target.process.raw())?;
    let current_image = ProcessImage::open(current)?;
    if trusted_publisher_sha256(&target_image)? == trusted_publisher_sha256(&current_image)? {
        return Err(protected_surface());
    }
    target.ensure_still_window()
}

impl ForegroundIdentityProbe for NativeForegroundIdentityProbe {
    fn resolve_current(&self) -> Result<WindowsApplicationBinding, ForegroundProbeError> {
        let foreground = ForegroundProcess::open()?;
        let binding = foreground.resolve_binding()?;
        foreground.ensure_still_foreground()?;
        Ok(binding)
    }

    fn classify_current(
        &self,
        selected: &WindowsApplicationBinding,
    ) -> Result<ForegroundMatch, ForegroundProbeError> {
        let foreground = ForegroundProcess::open()?;
        let result = foreground.classify(selected)?;
        foreground.ensure_still_foreground()?;
        Ok(result)
    }
}

struct ForegroundProcess {
    window: HWND,
    process_id: u32,
    process_created_at_ticks: u64,
    process: OwnedHandle,
}

impl ForegroundProcess {
    fn open() -> Result<Self, ForegroundProbeError> {
        // SAFETY: GetForegroundWindow has no pointer parameters. A null result
        // is explicitly allowed during an activation transition and is treated
        // as a lost observation boundary.
        let window = unsafe { GetForegroundWindow() };
        if window.is_null() {
            return Err(boundary_lost());
        }

        Self::open_window(window)
    }

    fn open_window(window: HWND) -> Result<Self, ForegroundProbeError> {
        if window.is_null() {
            return Err(boundary_lost());
        }
        // SAFETY: these User32 queries do not dereference application memory.
        // A selected source must remain one visible top-level window.
        let (is_window, is_visible, root) = unsafe {
            (
                IsWindow(window),
                IsWindowVisible(window),
                GetAncestor(window, GA_ROOT),
            )
        };
        if is_window == 0 || is_visible == 0 || root != window {
            return Err(boundary_lost());
        }

        let mut process_id = 0;
        // SAFETY: `process_id` is a valid writable u32 and `window` was returned
        // by User32. A zero return or PID means the foreground changed/closed.
        let thread_id = unsafe { GetWindowThreadProcessId(window, &mut process_id) };
        if thread_id == 0 || process_id == 0 {
            return Err(boundary_lost());
        }

        // SAFETY: The PID came from User32 and no handle is inherited. The
        // minimum query right is used; a successful handle is owned below.
        let raw_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        let process = match OwnedHandle::new(raw_process) {
            Some(process) => process,
            None => {
                // SAFETY: GetLastError has no preconditions and is read
                // immediately after the failed OpenProcess call.
                return if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
                    Err(protected_surface())
                } else {
                    Err(boundary_lost())
                };
            }
        };

        ensure_unprotected_process(process.raw())?;
        ensure_same_user_and_integrity(process.raw())?;
        let process_created_at_ticks = process_creation_time(process.raw())?;

        let value = Self {
            window,
            process_id,
            process_created_at_ticks,
            process,
        };
        value.ensure_still_window()?;
        Ok(value)
    }

    fn resolve_binding(&self) -> Result<WindowsApplicationBinding, ForegroundProbeError> {
        if let Some(binding) = packaged_binding(self.process.raw())? {
            return Ok(binding);
        }
        let image = ProcessImage::open(self.process.raw())?;
        let publisher = trusted_publisher_sha256(&image)?;
        WindowsApplicationBinding::unpackaged(
            image.file_id.VolumeSerialNumber,
            image.file_id.FileId.Identifier,
            publisher,
        )
        .map_err(|_| boundary_lost())
    }

    fn classify(
        &self,
        selected: &WindowsApplicationBinding,
    ) -> Result<ForegroundMatch, ForegroundProbeError> {
        let packaged = packaged_binding(self.process.raw())?;
        match (selected, packaged) {
            (WindowsApplicationBinding::Packaged(selected), Some(actual)) => {
                let WindowsApplicationBinding::Packaged(actual) = actual else {
                    return Err(boundary_lost());
                };
                if selected == &actual {
                    Ok(ForegroundMatch::Selected)
                } else {
                    Ok(ForegroundMatch::OutsideSelectedScope)
                }
            }
            (WindowsApplicationBinding::Packaged(_), None)
            | (WindowsApplicationBinding::Unpackaged(_), Some(_)) => {
                Ok(ForegroundMatch::OutsideSelectedScope)
            }
            (WindowsApplicationBinding::Unpackaged(selected), None) => {
                let image = ProcessImage::open(self.process.raw())?;
                if image.file_id.VolumeSerialNumber != selected.volume_serial_number()
                    || image.file_id.FileId.Identifier != *selected.file_id()
                {
                    return Ok(ForegroundMatch::OutsideSelectedScope);
                }

                // Only the exact selected file is signature-inspected. This
                // avoids learning or retaining publisher identity for unrelated
                // foreground applications.
                let publisher = trusted_publisher_sha256(&image)?;
                if publisher != *selected.publisher_sha256() {
                    return Err(boundary_lost());
                }
                Ok(ForegroundMatch::Selected)
            }
        }
    }

    fn ensure_still_foreground(&self) -> Result<(), ForegroundProbeError> {
        // SAFETY: Both calls have the same conditions as in `open`. The second
        // PID sample closes the HWND-reuse/activation race before publication.
        let current = unsafe { GetForegroundWindow() };
        if current != self.window || current.is_null() {
            return Err(boundary_lost());
        }
        self.ensure_still_window()
    }

    fn ensure_still_window(&self) -> Result<(), ForegroundProbeError> {
        // SAFETY: the HWND is used only for identity queries. Rechecking the
        // root/visibility/PID closes the selection and HWND-reuse race.
        let (is_window, is_visible, root) = unsafe {
            (
                IsWindow(self.window),
                IsWindowVisible(self.window),
                GetAncestor(self.window, GA_ROOT),
            )
        };
        if is_window == 0 || is_visible == 0 || root != self.window {
            return Err(boundary_lost());
        }
        let mut process_id = 0;
        // SAFETY: `process_id` is writable and the HWND was just revalidated.
        let thread_id = unsafe { GetWindowThreadProcessId(self.window, &mut process_id) };
        if thread_id == 0 || process_id != self.process_id {
            return Err(boundary_lost());
        }
        if process_creation_time(self.process.raw())? != self.process_created_at_ticks {
            return Err(boundary_lost());
        }
        Ok(())
    }
}

fn process_creation_time(process: HANDLE) -> Result<u64, ForegroundProbeError> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME outputs are correctly sized and the process handle
    // has PROCESS_QUERY_LIMITED_INFORMATION rights.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(boundary_lost());
    }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if ticks == 0 {
        return Err(boundary_lost());
    }
    Ok(ticks)
}

fn ensure_unprotected_process(process: HANDLE) -> Result<(), ForegroundProbeError> {
    let mut protection = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
    // SAFETY: `process` is a live query handle and `protection` is a correctly
    // sized writable structure for ProcessProtectionLevelInfo.
    let succeeded = unsafe {
        GetProcessInformation(
            process,
            ProcessProtectionLevelInfo,
            (&raw mut protection).cast::<c_void>(),
            size_of_val(&protection) as u32,
        )
    };
    if succeeded == 0 {
        return Err(boundary_lost());
    }
    if protection.ProtectionLevel != PROTECTION_LEVEL_NONE {
        return Err(protected_surface());
    }
    Ok(())
}

fn ensure_same_user_and_integrity(process: HANDLE) -> Result<(), ForegroundProbeError> {
    let target_token = open_process_token(process)?;
    // SAFETY: GetCurrentProcess returns the documented pseudo-handle, which is
    // valid for OpenProcessToken and must not itself be closed.
    let current_process = unsafe { GetCurrentProcess() };
    let current_token = open_process_token(current_process).map_err(|_| unavailable())?;

    let target_user = token_information(target_token.raw(), TokenUser)?;
    let current_user = token_information(current_token.raw(), TokenUser)?;
    let target_user_sid = token_user_sid(&target_user)?;
    let current_user_sid = token_user_sid(&current_user)?;
    // SAFETY: Both SID pointers refer into live, kernel-populated token buffers
    // and were validated with IsValidSid immediately above.
    if unsafe { EqualSid(target_user_sid, current_user_sid) } == 0 {
        return Err(protected_surface());
    }

    let target_integrity = token_integrity_rid(target_token.raw())?;
    let current_integrity = token_integrity_rid(current_token.raw())?;
    if target_integrity > current_integrity {
        return Err(protected_surface());
    }
    Ok(())
}

fn open_process_token(process: HANDLE) -> Result<OwnedHandle, ForegroundProbeError> {
    let mut token = null_mut();
    // SAFETY: `process` is either the documented current-process pseudo-handle
    // or a live owned process handle, and `token` is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(protected_surface());
    }
    OwnedHandle::new(token).ok_or_else(boundary_lost)
}

struct AlignedTokenBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedTokenBuffer {
    fn new(byte_len: usize) -> Result<Self, ForegroundProbeError> {
        if byte_len == 0 || byte_len > 64 * 1024 {
            return Err(boundary_lost());
        }
        let word_count = byte_len.div_ceil(size_of::<usize>());
        Ok(Self {
            words: vec![0; word_count],
            byte_len,
        })
    }

    fn as_mut_void(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast::<c_void>()
    }

    fn as_ptr<T>(&self) -> Result<*const T, ForegroundProbeError> {
        if self.byte_len < size_of::<T>() {
            return Err(boundary_lost());
        }
        Ok(self.words.as_ptr().cast::<T>())
    }
}

fn token_information(
    token: HANDLE,
    information_class: i32,
) -> Result<AlignedTokenBuffer, ForegroundProbeError> {
    let mut required = 0;
    // SAFETY: This is the documented sizing call with a null output buffer.
    let _ = unsafe { GetTokenInformation(token, information_class, null_mut(), 0, &mut required) };
    if required == 0 {
        return Err(boundary_lost());
    }
    let mut buffer = AlignedTokenBuffer::new(required as usize)?;
    let mut written = required;
    // SAFETY: The buffer is aligned and at least `required` bytes long, and all
    // pointers remain valid for the duration of this call.
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_void(),
            required,
            &mut written,
        )
    } == 0
        || written > required
    {
        return Err(boundary_lost());
    }
    Ok(buffer)
}

fn token_user_sid(buffer: &AlignedTokenBuffer) -> Result<*mut c_void, ForegroundProbeError> {
    let user = buffer.as_ptr::<TOKEN_USER>()?;
    // SAFETY: `user` points at an aligned kernel-populated TOKEN_USER held by
    // `buffer`; its nested pointer is checked before being returned.
    let sid = unsafe { (*user).User.Sid };
    // SAFETY: `sid` is supplied by GetTokenInformation and remains live with
    // `buffer`; IsValidSid performs the native structure validation.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(boundary_lost());
    }
    Ok(sid)
}

fn token_integrity_rid(token: HANDLE) -> Result<u32, ForegroundProbeError> {
    let buffer = token_information(token, TokenIntegrityLevel)?;
    let label = buffer.as_ptr::<TOKEN_MANDATORY_LABEL>()?;
    // SAFETY: `label` points into a live, aligned buffer returned by the token
    // API; the SID is validated before any subauthority access.
    let sid = unsafe { (*label).Label.Sid };
    // SAFETY: The SID pointer remains live for the duration of this function.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(boundary_lost());
    }
    // SAFETY: IsValidSid succeeded, so the count pointer is readable.
    let count_pointer = unsafe { GetSidSubAuthorityCount(sid) };
    if count_pointer.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: `count_pointer` is part of the validated SID.
    let count = unsafe { *count_pointer };
    if count == 0 {
        return Err(boundary_lost());
    }
    // SAFETY: The requested index is strictly below the validated SID's count.
    let rid = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: `rid` addresses the requested subauthority in the live SID.
    Ok(unsafe { *rid })
}

type ProcessIdentityQuery = unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32;

fn packaged_binding(
    process: HANDLE,
) -> Result<Option<WindowsApplicationBinding>, ForegroundProbeError> {
    let package_family = query_process_identity(
        process,
        GetPackageFamilyName,
        PACKAGE_FAMILY_NAME_MAX_LENGTH,
        &[APPMODEL_ERROR_NO_PACKAGE],
    )?;
    let application_id = query_process_identity(
        process,
        GetApplicationUserModelId,
        APPLICATION_USER_MODEL_ID_MAX_LENGTH,
        &[APPMODEL_ERROR_NO_PACKAGE, APPMODEL_ERROR_NO_APPLICATION],
    )?;
    match (package_family, application_id) {
        (Some(package_family), Some(application_id)) => {
            WindowsApplicationBinding::packaged(package_family, application_id)
                .map(Some)
                .map_err(|_| boundary_lost())
        }
        (None, None) => Ok(None),
        // Half an app identity cannot be matched safely.
        _ => Err(boundary_lost()),
    }
}

fn query_process_identity(
    process: HANDLE,
    query: ProcessIdentityQuery,
    maximum_length: u32,
    absent_results: &[u32],
) -> Result<Option<String>, ForegroundProbeError> {
    let mut length = 0;
    // SAFETY: This is the API's documented sizing call. `length` is writable.
    let sizing_result = unsafe { query(process, &mut length, null_mut()) };
    if absent_results.contains(&sizing_result) {
        return Ok(None);
    }
    if sizing_result != ERROR_INSUFFICIENT_BUFFER || length < 2 || length > maximum_length {
        return Err(boundary_lost());
    }

    let mut value = vec![0u16; length as usize];
    let mut written = length;
    // SAFETY: `value` has `length` writable UTF-16 elements and the process
    // handle has query rights.
    let result = unsafe { query(process, &mut written, value.as_mut_ptr()) };
    if result != ERROR_SUCCESS || written != length || value.last() != Some(&0) {
        return Err(boundary_lost());
    }
    let text = &value[..value.len() - 1];
    if text.contains(&0) {
        return Err(boundary_lost());
    }
    String::from_utf16(text)
        .map(Some)
        .map_err(|_| boundary_lost())
}

pub(crate) struct ProcessImage {
    path: Vec<u16>,
    file: OwnedHandle,
    file_id: FILE_ID_INFO,
}

impl ProcessImage {
    pub(crate) fn open(process: HANDLE) -> Result<Self, ForegroundProbeError> {
        let mut path = vec![0u16; MAXIMUM_PROCESS_IMAGE_PATH_UTF16 + 1];
        let mut length = MAXIMUM_PROCESS_IMAGE_PATH_UTF16 as u32;
        // SAFETY: `path` is writable for `length` UTF-16 elements. The process
        // handle has PROCESS_QUERY_LIMITED_INFORMATION.
        if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) } == 0
            || length == 0
            || length as usize > MAXIMUM_PROCESS_IMAGE_PATH_UTF16
        {
            return Err(boundary_lost());
        }
        path.truncate(length as usize + 1);
        path[length as usize] = 0;

        // SAFETY: `path` is a live NUL-terminated UTF-16 path. The handle is
        // opened read-only for metadata and shared with the running image.
        let raw_file = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        let file = OwnedHandle::new(raw_file).ok_or_else(boundary_lost)?;
        let mut file_id = FILE_ID_INFO::default();
        // SAFETY: `file` is a live file handle and `file_id` is the exact output
        // structure required by FileIdInfo.
        if unsafe {
            GetFileInformationByHandleEx(
                file.raw(),
                FileIdInfo,
                (&raw mut file_id).cast::<c_void>(),
                size_of_val(&file_id) as u32,
            )
        } == 0
        {
            return Err(boundary_lost());
        }
        Ok(Self {
            path,
            file,
            file_id,
        })
    }

    pub(crate) fn path_without_nul(&self) -> &[u16] {
        &self.path[..self.path.len() - 1]
    }
}

pub(crate) fn trusted_publisher_sha256(
    image: &ProcessImage,
) -> Result<[u8; 32], ForegroundProbeError> {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: image.path.as_ptr(),
        hFile: image.file.raw(),
        pgKnownSubject: null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        // Do not let foreground observation initiate network access.
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: All WinTrust structures are correctly sized and remain live for
    // verification and the mandatory state-close call below. UI is disabled.
    let verification = unsafe {
        WinVerifyTrust(
            null_mut(),
            &raw mut action,
            (&raw mut trust_data).cast::<c_void>(),
        )
    };
    let publisher = if verification == 0 {
        extract_publisher_sha256(&trust_data)
    } else {
        Err(boundary_lost())
    };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: This closes the state created by the preceding WinVerifyTrust
    // call. The same live structures and action GUID must be passed back.
    let _ = unsafe {
        WinVerifyTrust(
            null_mut(),
            &raw mut action,
            (&raw mut trust_data).cast::<c_void>(),
        )
    };
    publisher
}

fn extract_publisher_sha256(trust_data: &WINTRUST_DATA) -> Result<[u8; 32], ForegroundProbeError> {
    if trust_data.hWVTStateData.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: `hWVTStateData` belongs to a successful, still-open WinTrust
    // verification state.
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: `provider` is live until WTD_STATEACTION_CLOSE. Multiple primary
    // signers are intentionally rejected as an ambiguous publisher identity.
    if unsafe { (*provider).csSigners } != 1 {
        return Err(boundary_lost());
    }
    // SAFETY: Provider signer zero exists because csSigners is exactly one.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: The signer remains live with the provider state. Index zero is the
    // leaf Authenticode publisher certificate.
    let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_certificate.is_null() {
        return Err(boundary_lost());
    }
    // SAFETY: The provider certificate and its context remain live until the
    // state-close call performed by the caller.
    let certificate = unsafe { (*provider_certificate).pCert };
    if certificate.is_null() {
        return Err(boundary_lost());
    }
    let mut publisher = [0u8; 32];
    let mut length = publisher.len() as u32;
    // SAFETY: `certificate` is live and `publisher` is a writable 32-byte
    // buffer for CERT_SHA256_HASH_PROP_ID.
    if unsafe {
        CertGetCertificateContextProperty(
            certificate,
            CERT_SHA256_HASH_PROP_ID,
            publisher.as_mut_ptr().cast::<c_void>(),
            &mut length,
        )
    } == 0
        || length != publisher.len() as u32
        || publisher.iter().all(|byte| *byte == 0)
    {
        return Err(boundary_lost());
    }
    Ok(publisher)
}

struct OwnedHandle(HANDLE);

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
        // SAFETY: OwnedHandle is constructed only from successful APIs that
        // transfer a closeable HANDLE, and it is closed exactly once here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn boundary_lost() -> ForegroundProbeError {
    ForegroundProbeError {
        kind: ForegroundProbeErrorKind::BoundaryLost,
    }
}

fn protected_surface() -> ForegroundProbeError {
    ForegroundProbeError {
        kind: ForegroundProbeErrorKind::ProtectedSurface,
    }
}

fn unavailable() -> ForegroundProbeError {
    ForegroundProbeError {
        kind: ForegroundProbeErrorKind::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "native Windows fixture: requires an interactive signed foreground application"]
    fn native_foreground_binding_is_exact_and_content_free() {
        let probe = NativeForegroundIdentityProbe;
        let binding = probe.resolve_current().unwrap();
        let encoded = binding.to_string();
        assert_eq!(WindowsApplicationBinding::parse(&encoded).unwrap(), binding);
        assert!(!encoded.contains(":\\"));
        assert!(!encoded.contains(".exe"));
        assert_eq!(
            probe.classify_current(&binding).unwrap(),
            ForegroundMatch::Selected
        );
    }

    #[test]
    #[ignore = "native Windows fixture: requires an interactive signed foreground application"]
    fn native_foreground_rejects_an_adversarial_near_match() {
        let probe = NativeForegroundIdentityProbe;
        let binding = probe.resolve_current().unwrap();
        let near_match = match &binding {
            WindowsApplicationBinding::Packaged(identity) => WindowsApplicationBinding::packaged(
                identity.package_family_name(),
                format!("{}!STEIN-Adversarial", identity.package_family_name()),
            )
            .unwrap(),
            WindowsApplicationBinding::Unpackaged(identity) => {
                let mut publisher = *identity.publisher_sha256();
                publisher[0] ^= 0xff;
                WindowsApplicationBinding::unpackaged(
                    identity.volume_serial_number(),
                    *identity.file_id(),
                    publisher,
                )
                .unwrap()
            }
        };
        let result = probe.classify_current(&near_match);
        match binding {
            WindowsApplicationBinding::Packaged(_) => {
                assert_eq!(result.unwrap(), ForegroundMatch::OutsideSelectedScope);
            }
            WindowsApplicationBinding::Unpackaged(_) => {
                assert_eq!(
                    result.unwrap_err().kind,
                    ForegroundProbeErrorKind::BoundaryLost
                );
            }
        }
    }
}
