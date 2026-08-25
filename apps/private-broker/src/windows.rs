use std::{
    ffi::{OsString, c_void},
    io,
    mem::{align_of, size_of},
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, BorrowedHandle},
    },
    ptr::{NonNull, null_mut},
    time::{Duration, Instant},
};

use stein_broker_windows::{
    ExpectedCoreServer, ExpectedPackageIdentity, PackagePeerClass, PrivatePipeSecurity,
    admit_named_pipe_peer, verify_core_pipe_server,
};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    time::{sleep, timeout},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, ERROR_SUCCESS, HANDLE, LocalFree,
    },
    Security::{
        Authorization::ConvertSidToStringSidW,
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        GetTokenInformation, IsValidSid, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenIsAppContainer, TokenUser,
    },
    Storage::Packaging::Appx::{
        APPLICATION_USER_MODEL_ID_MAX_LENGTH, GetApplicationUserModelIdFromToken,
        GetPackageFamilyNameFromToken, PACKAGE_FAMILY_NAME_MAX_LENGTH,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{
    BROKER_APPLICATION_ID, BROKER_RELAY_PIPE, BrokerError, CORE_PRIVATE_PIPE,
    DESKTOP_APPLICATION_ID, PACKAGE_NAME, forward_frames, pinned_core_digest,
};

const DESKTOP_CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const CORE_CONNECT_DEADLINE: Duration = Duration::from_secs(5);
const ADMISSION_DEADLINE: Duration = Duration::from_secs(10);
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

pub(crate) async fn run() -> Result<(), BrokerError> {
    let runtime = RuntimeIdentity::current().map_err(|_| BrokerError::RuntimeIdentity)?;
    let expected_desktop = runtime
        .expected_desktop()
        .map_err(|_| BrokerError::RuntimeIdentity)?;
    let desktop = create_relay_server(&expected_desktop).map_err(|_| BrokerError::RelayEndpoint)?;

    timeout(DESKTOP_CONNECT_DEADLINE, desktop.connect())
        .await
        .map_err(|_| BrokerError::DesktopDeadline)?
        .map_err(|_| BrokerError::RelayEndpoint)?;

    let daemon_binding = random_daemon_binding().map_err(|_| BrokerError::DesktopAdmission)?;
    let admission_started = Instant::now();
    let authority = {
        let pipe = borrowed_handle(&desktop);
        admit_named_pipe_peer(
            pipe,
            &expected_desktop,
            PackagePeerClass::PackagedDesktop,
            daemon_binding,
            admission_started + ADMISSION_DEADLINE,
        )
        .map_err(|_| BrokerError::DesktopAdmission)?
    };

    let expected_core = ExpectedCoreServer::new(runtime.owner_sid, pinned_core_digest()?)
        .map_err(|_| BrokerError::CoreAdmission)?;
    let core = connect_verified_core(&expected_core).await?;
    if !authority.is_current_for(borrowed_handle(&desktop), &daemon_binding, Instant::now()) {
        return Err(BrokerError::AdmissionExpired);
    }

    relay_together(desktop, core).await
}

fn create_relay_server(expected: &ExpectedPackageIdentity) -> io::Result<NamedPipeServer> {
    let security = PrivatePipeSecurity::new(expected).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private pipe security unavailable",
        )
    })?;
    let mut attributes: SECURITY_ATTRIBUTES = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);

    // SAFETY: the descriptor and attributes remain live through this
    // synchronous CreateNamedPipe call. Windows copies the descriptor.
    unsafe {
        options.create_with_security_attributes_raw(
            BROKER_RELAY_PIPE,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

async fn connect_verified_core(
    expected: &ExpectedCoreServer,
) -> Result<NamedPipeClient, BrokerError> {
    let started = tokio::time::Instant::now();
    loop {
        match ClientOptions::new().open(CORE_PRIVATE_PIPE) {
            Ok(core) => {
                verify_core_pipe_server(borrowed_handle(&core), expected)
                    .map_err(|_| BrokerError::CoreAdmission)?;
                return Ok(core);
            }
            Err(error)
                if is_transient_connect_error(&error)
                    && started.elapsed() < CORE_CONNECT_DEADLINE =>
            {
                sleep(CONNECT_RETRY_DELAY).await;
            }
            Err(_) => return Err(BrokerError::CoreConnection),
        }
    }
}

fn is_transient_connect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) || error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
}

async fn relay_together(
    desktop: NamedPipeServer,
    core: NamedPipeClient,
) -> Result<(), BrokerError> {
    let (desktop_reader, desktop_writer) = tokio::io::split(desktop);
    let (core_reader, core_writer) = tokio::io::split(core);

    // Returning from either direction drops the other future and therefore all
    // four split halves. Neither peer can remain attached to a half-open relay.
    let result = tokio::select! {
        result = forward_frames(desktop_reader, core_writer) => result,
        result = forward_frames(core_reader, desktop_writer) => result,
    };
    result.map_err(|_| BrokerError::Relay)
}

fn borrowed_handle<T: AsRawHandle>(value: &T) -> BorrowedHandle<'_> {
    // SAFETY: the borrow cannot outlive `value`, and no ownership is transferred.
    unsafe { BorrowedHandle::borrow_raw(value.as_raw_handle()) }
}

fn random_daemon_binding() -> Result<[u8; 16], ()> {
    let mut value = [0_u8; 16];
    // SAFETY: `value` is a live writable buffer and the system-preferred RNG
    // accepts a null algorithm handle with the system-preferred RNG flag.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            value.as_mut_ptr(),
            value.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || value.iter().all(|byte| *byte == 0) {
        value.fill(0);
        return Err(());
    }
    Ok(value)
}

struct RuntimeIdentity {
    owner_sid: String,
    package_family_name: String,
}

impl RuntimeIdentity {
    fn current() -> Result<Self, ()> {
        let token = current_process_token()?;
        if token_u32(token.0, TokenIsAppContainer)? == 0 {
            return Err(());
        }

        let owner_sid = token_user_sid(token.0)?;
        let package_family_name = query_token_identity(
            token.0,
            GetPackageFamilyNameFromToken,
            PACKAGE_FAMILY_NAME_MAX_LENGTH,
        )?;
        let application_id = query_token_identity(
            token.0,
            GetApplicationUserModelIdFromToken,
            APPLICATION_USER_MODEL_ID_MAX_LENGTH,
        )?;

        if !package_family_name.starts_with(&format!("{PACKAGE_NAME}_"))
            || application_id != format!("{package_family_name}!{BROKER_APPLICATION_ID}")
        {
            return Err(());
        }

        Ok(Self {
            owner_sid,
            package_family_name,
        })
    }

    fn expected_desktop(&self) -> Result<ExpectedPackageIdentity, ()> {
        ExpectedPackageIdentity::new(
            self.owner_sid.clone(),
            self.package_family_name.clone(),
            format!("{}!{}", self.package_family_name, DESKTOP_APPLICATION_ID),
        )
        .map_err(|_| ())
    }
}

fn current_process_token() -> Result<OwnedHandle, ()> {
    let mut token = null_mut();
    // SAFETY: `token` is writable; TOKEN_QUERY is the only requested access.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(());
    }
    if token.is_null() {
        return Err(());
    }
    Ok(OwnedHandle(token))
}

fn token_user_sid(token: HANDLE) -> Result<String, ()> {
    let buffer = token_information(token, TokenUser)?;
    let user = buffer.read::<TOKEN_USER>()?;
    // SAFETY: the nested SID remains backed by the live token buffer.
    let sid = unsafe { (*user).User.Sid };
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(());
    }
    sid_to_string(sid)
}

fn sid_to_string(sid: *mut c_void) -> Result<String, ()> {
    let mut text = null_mut();
    // SAFETY: `sid` was validated and `text` is a writable output pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(());
    }
    let text = NonNull::new(text).ok_or(())?;
    let owned = OwnedLocal(text.cast());
    let mut length = 0_usize;
    // SAFETY: the API returned a NUL-terminated UTF-16 allocation. The bound
    // prevents an invalid result from causing an unbounded scan.
    unsafe {
        while *text.as_ptr().add(length) != 0 {
            length += 1;
            if length > 256 {
                return Err(());
            }
        }
    }
    // SAFETY: the bounded scan found the terminator.
    let value = unsafe { std::slice::from_raw_parts(text.as_ptr(), length) };
    let result = OsString::from_wide(value).into_string().map_err(|_| ());
    drop(owned);
    result
}

type TokenIdentityQuery = unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32;

fn query_token_identity(
    token: HANDLE,
    query: TokenIdentityQuery,
    maximum_length: u32,
) -> Result<String, ()> {
    let mut length = 0_u32;
    // SAFETY: documented sizing call and writable length.
    if unsafe { query(token, &mut length, null_mut()) } != ERROR_INSUFFICIENT_BUFFER
        || length < 2
        || length > maximum_length
    {
        return Err(());
    }
    let mut value = vec![0_u16; length as usize];
    let mut written = length;
    // SAFETY: the buffer has `length` writable UTF-16 elements.
    if unsafe { query(token, &mut written, value.as_mut_ptr()) } != ERROR_SUCCESS
        || written != length
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        return Err(());
    }
    String::from_utf16(&value[..value.len() - 1]).map_err(|_| ())
}

fn token_u32(token: HANDLE, information_class: i32) -> Result<u32, ()> {
    let buffer = token_information(token, information_class)?;
    let value = buffer.read::<u32>()?;
    // SAFETY: the aligned buffer contains a complete u32.
    Ok(unsafe { *value })
}

fn token_information(token: HANDLE, information_class: i32) -> Result<AlignedBuffer, ()> {
    let mut required = 0_u32;
    // SAFETY: documented sizing call and writable length.
    unsafe {
        GetTokenInformation(token, information_class, null_mut(), 0, &mut required);
    }
    if required == 0 || required > 64 * 1024 {
        return Err(());
    }
    let mut buffer = AlignedBuffer::new(required as usize);
    let mut written = required;
    // SAFETY: `buffer` has at least `required` writable bytes.
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr(),
            required,
            &mut written,
        )
    } == 0
        || written > required
    {
        return Err(());
    }
    buffer.written = written as usize;
    Ok(buffer)
}

struct AlignedBuffer {
    words: Vec<usize>,
    written: usize,
}

impl AlignedBuffer {
    fn new(bytes: usize) -> Self {
        Self {
            words: vec![0; bytes.div_ceil(size_of::<usize>())],
            written: 0,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn read<T>(&self) -> Result<*const T, ()> {
        if self.written < size_of::<T>()
            || !(self.words.as_ptr() as usize).is_multiple_of(align_of::<T>())
        {
            return Err(());
        }
        Ok(self.words.as_ptr().cast())
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        self.words.fill(0);
        self.written = 0;
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns a valid kernel handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct OwnedLocal(NonNull<c_void>);

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocated this pointer with LocalAlloc.
        unsafe { LocalFree(self.0.as_ptr()) };
    }
}
