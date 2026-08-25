//! Windows launch evidence for the Microsoft Edge native-messaging host.
//!
//! This is defense in depth, not CORE admission. Native-messaging argv,
//! ancestry, and a signed Edge image do not prove release-managed extension
//! code. The host must still obtain a distinct OS-bound browser-producer
//! capability before it reads or forwards content.

use std::ffi::{OsString, c_void};
use std::fmt;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use std::ptr::{NonNull, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindow};

use crate::foreground::{ProcessImage, trusted_publisher_sha256};

const EXTENSION_ID_BYTES: usize = 32;
const MAXIMUM_ARGUMENT_BYTES: usize = 256;
const MAXIMUM_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeLaunchErrorKind {
    InvalidConfiguration,
    WrongExtension,
    MalformedArguments,
    WrongParent,
    WrongUser,
    WrongEdgeImage,
    WrongEdgePublisher,
    WrongHostPublisher,
    InvalidStandardIo,
    BoundaryChanged,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeLaunchError {
    pub kind: EdgeLaunchErrorKind,
    pub summary: &'static str,
}

impl std::error::Error for EdgeLaunchError {}

impl fmt::Display for EdgeLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.summary)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EdgeNativeHostLaunchPolicy {
    expected_origin: String,
    edge_publisher_sha256: [u8; 32],
    host_publisher_sha256: [u8; 32],
}

impl fmt::Debug for EdgeNativeHostLaunchPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EdgeNativeHostLaunchPolicy([redacted])")
    }
}

impl EdgeNativeHostLaunchPolicy {
    pub fn new(
        extension_id: &str,
        edge_publisher_sha256: [u8; 32],
        host_publisher_sha256: [u8; 32],
    ) -> Result<Self, EdgeLaunchError> {
        if extension_id.len() != EXTENSION_ID_BYTES
            || !extension_id
                .bytes()
                .all(|byte| (b'a'..=b'p').contains(&byte))
            || edge_publisher_sha256.iter().all(|byte| *byte == 0)
            || host_publisher_sha256.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_configuration());
        }
        Ok(Self {
            expected_origin: format!("chrome-extension://{extension_id}/"),
            edge_publisher_sha256,
            host_publisher_sha256,
        })
    }
}

/// Opaque proof of launch evidence. It is neither cloneable nor serializable
/// and intentionally cannot be converted into a CORE connection capability.
pub struct VerifiedEdgeNativeHostLaunch {
    _private: (),
}

impl fmt::Debug for VerifiedEdgeNativeHostLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedEdgeNativeHostLaunch([redacted])")
    }
}

struct LaunchEvidence {
    origin: String,
    actual_parent_process_id: u32,
    rechecked_parent_process_id: u32,
    parent_window_process_id: Option<u32>,
    same_user: bool,
    parent_created_before_host: bool,
    parent_is_protected_edge_stable: bool,
    edge_publisher_sha256: [u8; 32],
    host_publisher_sha256: [u8; 32],
    standard_io_is_pipe: bool,
}

/// Verifies the current host launch before reading a native-message byte.
pub fn verify_current_edge_native_host_launch(
    policy: &EdgeNativeHostLaunchPolicy,
) -> Result<VerifiedEdgeNativeHostLaunch, EdgeLaunchError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let input = standard_handle(STD_INPUT_HANDLE)?;
    let output = standard_handle(STD_OUTPUT_HANDLE)?;
    // SAFETY: both values are live borrowed process standard handles.
    let standard_io_is_pipe = unsafe { GetFileType(input) } == FILE_TYPE_PIPE
        && unsafe { GetFileType(output) } == FILE_TYPE_PIPE;

    // SAFETY: GetCurrentProcess returns the live pseudo-handle for this process.
    let current_process = unsafe { GetCurrentProcess() };
    let host_image =
        ProcessImage::open(current_process).map_err(|_| error(EdgeLaunchErrorKind::Unavailable))?;
    let host_publisher_sha256 = trusted_publisher_sha256(&host_image)
        .map_err(|_| error(EdgeLaunchErrorKind::WrongHostPublisher))?;

    // SAFETY: GetCurrentProcessId has no preconditions.
    let current_process_id = unsafe { GetCurrentProcessId() };
    let first_parent_process_id = parent_process_id(current_process_id)?;
    if first_parent_process_id == 0 || first_parent_process_id == current_process_id {
        return Err(error(EdgeLaunchErrorKind::WrongParent));
    }
    // SAFETY: the PID came from a kernel process snapshot; query-only access is
    // requested and the returned handle is owned immediately.
    let parent = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            first_parent_process_id,
        )
    })
    .ok_or_else(|| error(EdgeLaunchErrorKind::Unavailable))?;
    let same_user = same_process_user(current_process, parent.raw())?;
    let parent_created_before_host =
        process_created_at(parent.raw())? <= process_created_at(current_process)?;
    let parent_image =
        ProcessImage::open(parent.raw()).map_err(|_| error(EdgeLaunchErrorKind::WrongEdgeImage))?;
    let parent_path = PathBuf::from(OsString::from_wide(parent_image.path_without_nul()));
    let parent_is_protected_edge_stable = is_protected_edge_stable_path(&parent_path)?;
    let edge_publisher_sha256 = trusted_publisher_sha256(&parent_image)
        .map_err(|_| error(EdgeLaunchErrorKind::WrongEdgePublisher))?;
    let rechecked_parent_process_id = parent_process_id(current_process_id)?;
    let parent_window_process_id = verify_parent_window(arguments.parent_window)?;

    validate_evidence(
        policy,
        &LaunchEvidence {
            origin: arguments.origin,
            actual_parent_process_id: first_parent_process_id,
            rechecked_parent_process_id,
            parent_window_process_id,
            same_user,
            parent_created_before_host,
            parent_is_protected_edge_stable,
            edge_publisher_sha256,
            host_publisher_sha256,
            standard_io_is_pipe,
        },
    )?;

    if standard_handle(STD_INPUT_HANDLE)? != input || standard_handle(STD_OUTPUT_HANDLE)? != output
    {
        return Err(error(EdgeLaunchErrorKind::BoundaryChanged));
    }
    Ok(VerifiedEdgeNativeHostLaunch { _private: () })
}

struct LaunchArguments {
    origin: String,
    parent_window: Option<HWND>,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<LaunchArguments, EdgeLaunchError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments
        .next()
        .ok_or_else(|| error(EdgeLaunchErrorKind::MalformedArguments))?;
    let origin = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty() && value.len() <= MAXIMUM_ARGUMENT_BYTES)
        .ok_or_else(|| error(EdgeLaunchErrorKind::MalformedArguments))?;
    let parent = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| value.len() <= MAXIMUM_ARGUMENT_BYTES)
        .ok_or_else(|| error(EdgeLaunchErrorKind::MalformedArguments))?;
    if arguments.next().is_some() {
        return Err(error(EdgeLaunchErrorKind::MalformedArguments));
    }
    let parent = parent
        .strip_prefix("--parent-window=")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| error(EdgeLaunchErrorKind::MalformedArguments))?
        .parse::<isize>()
        .map_err(|_| error(EdgeLaunchErrorKind::MalformedArguments))?;
    Ok(LaunchArguments {
        origin,
        parent_window: (parent != 0).then_some(parent as HWND),
    })
}

fn verify_parent_window(window: Option<HWND>) -> Result<Option<u32>, EdgeLaunchError> {
    let Some(window) = window else {
        // Microsoft documents zero for an MV3 service-worker caller.
        return Ok(None);
    };
    let mut process_id = 0_u32;
    // SAFETY: these User32 calls inspect the opaque HWND without dereferencing
    // target-process memory; process_id is a valid writable output.
    let (is_window, thread_id) = unsafe {
        (
            IsWindow(window),
            GetWindowThreadProcessId(window, &mut process_id),
        )
    };
    if is_window == 0 || thread_id == 0 || process_id == 0 {
        return Err(error(EdgeLaunchErrorKind::WrongParent));
    }
    Ok(Some(process_id))
}

fn validate_evidence(
    policy: &EdgeNativeHostLaunchPolicy,
    evidence: &LaunchEvidence,
) -> Result<(), EdgeLaunchError> {
    if evidence.origin != policy.expected_origin {
        return Err(error(EdgeLaunchErrorKind::WrongExtension));
    }
    if evidence.actual_parent_process_id == 0
        || evidence.actual_parent_process_id != evidence.rechecked_parent_process_id
        || evidence
            .parent_window_process_id
            .is_some_and(|process_id| process_id != evidence.actual_parent_process_id)
        || !evidence.parent_created_before_host
    {
        return Err(error(EdgeLaunchErrorKind::WrongParent));
    }
    if !evidence.same_user {
        return Err(error(EdgeLaunchErrorKind::WrongUser));
    }
    if !evidence.parent_is_protected_edge_stable {
        return Err(error(EdgeLaunchErrorKind::WrongEdgeImage));
    }
    if !constant_time_equal(
        &evidence.edge_publisher_sha256,
        &policy.edge_publisher_sha256,
    ) {
        return Err(error(EdgeLaunchErrorKind::WrongEdgePublisher));
    }
    if !constant_time_equal(
        &evidence.host_publisher_sha256,
        &policy.host_publisher_sha256,
    ) {
        return Err(error(EdgeLaunchErrorKind::WrongHostPublisher));
    }
    if !evidence.standard_io_is_pipe {
        return Err(error(EdgeLaunchErrorKind::InvalidStandardIo));
    }
    Ok(())
}

fn parent_process_id(process_id: u32) -> Result<u32, EdgeLaunchError> {
    // SAFETY: the snapshot is non-inheritable and wrapped on success.
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .ok_or_else(|| error(EdgeLaunchErrorKind::Unavailable))?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: snapshot is live and entry has the required initialized size.
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) } == 0 {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    loop {
        if entry.th32ProcessID == process_id {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: same live snapshot and initialized writable entry.
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
            return Err(error(EdgeLaunchErrorKind::Unavailable));
        }
    }
}

fn same_process_user(left: HANDLE, right: HANDLE) -> Result<bool, EdgeLaunchError> {
    let left = process_token(left)?;
    let right = process_token(right)?;
    let left_user = token_user(left.raw())?;
    let right_user = token_user(right.raw())?;
    // SAFETY: both SID pointers remain backed by live aligned token buffers.
    Ok(unsafe { EqualSid(left_user.sid, right_user.sid) } != 0)
}

fn process_token(process: HANDLE) -> Result<OwnedHandle, EdgeLaunchError> {
    let mut token = null_mut();
    // SAFETY: token is writable and only query access is requested.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    OwnedHandle::new(token).ok_or_else(|| error(EdgeLaunchErrorKind::Unavailable))
}

struct TokenUserBuffer {
    _buffer: AlignedBuffer,
    sid: *mut c_void,
}

fn token_user(token: HANDLE) -> Result<TokenUserBuffer, EdgeLaunchError> {
    let mut required = 0_u32;
    // SAFETY: documented sizing call and writable output length.
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 || required as usize > MAXIMUM_TOKEN_INFORMATION_BYTES {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    let mut buffer = AlignedBuffer::new(required as usize);
    let mut written = required;
    // SAFETY: buffer exposes exactly required writable bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr(),
            required,
            &mut written,
        )
    } == 0
        || written != required
    {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    let user = buffer.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: GetTokenInformation returned a complete TOKEN_USER.
    let sid = unsafe { (*user).User.Sid };
    // SAFETY: the SID points into the still-live token buffer.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    Ok(TokenUserBuffer {
        _buffer: buffer,
        sid,
    })
}

fn process_created_at(process: HANDLE) -> Result<u64, EdgeLaunchError> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME outputs are valid and writable.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn is_protected_edge_stable_path(path: &Path) -> Result<bool, EdgeLaunchError> {
    let roots = [
        known_folder(&FOLDERID_ProgramFiles)?,
        known_folder(&FOLDERID_ProgramFilesX86)?,
    ];
    Ok(roots.iter().any(|root| is_edge_path_below_root(path, root)))
}

fn is_edge_path_below_root(path: &Path, root: &Path) -> bool {
    let path_components: Vec<_> = path.components().collect();
    let root_components: Vec<_> = root.components().collect();
    if path_components.len() != root_components.len() + 5
        || !path_components
            .iter()
            .zip(&root_components)
            .all(|(left, right)| component_eq(left, right))
    {
        return false;
    }
    let tail = &path_components[root_components.len()..];
    component_text(&tail[0]).is_some_and(|value| value.eq_ignore_ascii_case("Microsoft"))
        && component_text(&tail[1]).is_some_and(|value| value.eq_ignore_ascii_case("Edge"))
        && component_text(&tail[2]).is_some_and(|value| value.eq_ignore_ascii_case("Application"))
        && component_text(&tail[3]).is_some_and(valid_edge_version)
        && component_text(&tail[4]).is_some_and(|value| value.eq_ignore_ascii_case("msedge.exe"))
}

fn component_eq(left: &Component<'_>, right: &Component<'_>) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn component_text<'a>(component: &'a Component<'a>) -> Option<&'a str> {
    match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    }
}

fn valid_edge_version(value: &str) -> bool {
    value.len() <= 64
        && value.split('.').count() == 4
        && value.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn known_folder(folder: &windows_sys::core::GUID) -> Result<PathBuf, EdgeLaunchError> {
    let mut path = null_mut();
    // SAFETY: path is a writable output and no impersonation token is supplied.
    let result =
        unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT as u32, null_mut(), &mut path) };
    if result < 0 {
        return Err(error(EdgeLaunchErrorKind::Unavailable));
    }
    let path = NonNull::new(path).ok_or_else(|| error(EdgeLaunchErrorKind::Unavailable))?;
    struct FolderPath(NonNull<u16>);
    impl Drop for FolderPath {
        fn drop(&mut self) {
            // SAFETY: SHGetKnownFolderPath transfers CoTaskMem ownership.
            unsafe { CoTaskMemFree(self.0.as_ptr().cast()) };
        }
    }
    let owned = FolderPath(path);
    let mut length = 0_usize;
    // SAFETY: the API returned a NUL-terminated allocation. The explicit bound
    // prevents an invalid result from causing an unbounded scan.
    unsafe {
        while *path.as_ptr().add(length) != 0 {
            length += 1;
            if length > 32_768 {
                return Err(error(EdgeLaunchErrorKind::Unavailable));
            }
        }
    }
    // SAFETY: the bounded scan found the terminator.
    let value = unsafe { std::slice::from_raw_parts(path.as_ptr(), length) };
    let result = PathBuf::from(OsString::from_wide(value));
    drop(owned);
    Ok(result)
}

fn standard_handle(kind: u32) -> Result<HANDLE, EdgeLaunchError> {
    // SAFETY: GetStdHandle has no pointer parameters.
    let handle = unsafe { GetStdHandle(kind) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(error(EdgeLaunchErrorKind::InvalidStandardIo))
    } else {
        Ok(handle)
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
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
        // SAFETY: this wrapper owns one closeable handle and closes it once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[repr(align(16))]
struct AlignedBuffer(Vec<u8>);

impl AlignedBuffer {
    fn new(length: usize) -> Self {
        Self(vec![0; length])
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

const fn error(kind: EdgeLaunchErrorKind) -> EdgeLaunchError {
    EdgeLaunchError {
        kind,
        summary: "The Edge native-messaging launch was rejected.",
    }
}

const fn invalid_configuration() -> EdgeLaunchError {
    EdgeLaunchError {
        kind: EdgeLaunchErrorKind::InvalidConfiguration,
        summary: "The Edge native-messaging launch policy is invalid.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EdgeNativeHostLaunchPolicy {
        EdgeNativeHostLaunchPolicy::new("abcdefghijklmnopabcdefghijklmnop", [0x11; 32], [0x22; 32])
            .unwrap()
    }

    fn evidence() -> LaunchEvidence {
        LaunchEvidence {
            origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_owned(),
            actual_parent_process_id: 41,
            rechecked_parent_process_id: 41,
            parent_window_process_id: None,
            same_user: true,
            parent_created_before_host: true,
            parent_is_protected_edge_stable: true,
            edge_publisher_sha256: [0x11; 32],
            host_publisher_sha256: [0x22; 32],
            standard_io_is_pipe: true,
        }
    }

    #[test]
    fn exact_origin_signed_edge_and_signed_host_evidence_is_required() {
        assert!(validate_evidence(&policy(), &evidence()).is_ok());

        type Mutator = fn(&mut LaunchEvidence);
        let cases: &[(Mutator, EdgeLaunchErrorKind)] = &[
            (
                |value| {
                    value.origin =
                        "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/".to_owned();
                },
                EdgeLaunchErrorKind::WrongExtension,
            ),
            (
                |value| value.edge_publisher_sha256 = [0x90; 32],
                EdgeLaunchErrorKind::WrongEdgePublisher,
            ),
            (
                |value| value.host_publisher_sha256 = [0x91; 32],
                EdgeLaunchErrorKind::WrongHostPublisher,
            ),
            (
                |value| value.parent_is_protected_edge_stable = false,
                EdgeLaunchErrorKind::WrongEdgeImage,
            ),
            (
                |value| value.same_user = false,
                EdgeLaunchErrorKind::WrongUser,
            ),
            (
                |value| value.standard_io_is_pipe = false,
                EdgeLaunchErrorKind::InvalidStandardIo,
            ),
        ];
        for (mutator, expected) in cases {
            let mut value = evidence();
            mutator(&mut value);
            assert_eq!(
                validate_evidence(&policy(), &value).unwrap_err().kind,
                *expected
            );
        }
    }

    #[test]
    fn parent_spoof_and_boundary_change_evidence_is_rejected() {
        let mut changed = evidence();
        changed.rechecked_parent_process_id = 99;
        assert_eq!(
            validate_evidence(&policy(), &changed).unwrap_err().kind,
            EdgeLaunchErrorKind::WrongParent
        );
        let mut wrong_window = evidence();
        wrong_window.parent_window_process_id = Some(99);
        assert_eq!(
            validate_evidence(&policy(), &wrong_window)
                .unwrap_err()
                .kind,
            EdgeLaunchErrorKind::WrongParent
        );
        let mut impossible_time = evidence();
        impossible_time.parent_created_before_host = false;
        assert_eq!(
            validate_evidence(&policy(), &impossible_time)
                .unwrap_err()
                .kind,
            EdgeLaunchErrorKind::WrongParent
        );
    }

    #[test]
    fn native_arguments_require_one_origin_and_one_parent_window() {
        let parsed = parse_arguments([
            OsString::from("host.exe"),
            OsString::from("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"),
            OsString::from("--parent-window=0"),
        ])
        .unwrap();
        assert!(parsed.parent_window.is_none());

        for values in [
            vec!["host.exe", "chrome-extension://id/"],
            vec!["host.exe", "chrome-extension://id/", "--parent-window=-1"],
            vec![
                "host.exe",
                "chrome-extension://id/",
                "--parent-window=0",
                "extra",
            ],
        ] {
            assert!(parse_arguments(values.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn only_protected_stable_edge_path_shape_is_accepted() {
        let root = Path::new(r"C:\Program Files (x86)");
        assert!(is_edge_path_below_root(
            Path::new(r"C:\Program Files (x86)\Microsoft\Edge\Application\140.0.1.2\msedge.exe"),
            root,
        ));
        for value in [
            r"C:\Users\Synthetic\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge Beta\Application\140.0.1.2\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\not-a-version\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\140.0.1.2\other.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\140.0.1.2\msedge.exe",
        ] {
            assert!(!is_edge_path_below_root(Path::new(value), root), "{value}");
        }
    }
}
