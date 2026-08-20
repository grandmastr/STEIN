//! Trusted Windows activation and admission for the private transport broker.
//!
//! Nothing in this module is renderer-callable. The installed package identity
//! is read from the current process token, the broker is activated by its exact
//! AUMID, and the connected pipe server is verified before IPC writes a byte.

use std::{
    ffi::c_void,
    fmt, io,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    ptr::null_mut,
    time::{Duration, Instant},
};

use stein_broker_windows::{
    BROKER_APPLICATION_ID, BROKER_RELAY_PIPE, DESKTOP_APPLICATION_ID, ExpectedPackageIdentity,
    PRODUCTION_PACKAGE_NAME, PackagePeerClass, PackageServerConnectionAuthority,
    admit_package_pipe_server,
};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time::sleep,
};
use windows::{
    Win32::{
        Foundation::RPC_E_CHANGED_MODE,
        System::Com::{
            CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
        UI::Shell::{AO_NONE, ApplicationActivationManager, IApplicationActivationManager},
    },
    core::HSTRING,
};
use windows_sys::Win32::{
    Foundation::{
        APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY,
        ERROR_SUCCESS, HANDLE,
    },
    Security::{GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer},
    Storage::Packaging::Appx::{
        APPLICATION_USER_MODEL_ID_MAX_LENGTH, GetApplicationUserModelIdFromToken,
        GetPackageFamilyNameFromToken, PACKAGE_FAMILY_NAME_MAX_LENGTH,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateBrokerError {
    /// Development/legacy unpackaged desktop: diagnostic IPC remains allowed.
    Unpackaged,
    /// A packaged process did not have the exact production desktop identity.
    WrongDesktopIdentity,
    ActivationUnavailable,
    ConnectionUnavailable,
    BrokerAdmissionFailed,
}

/// Connected broker stream plus the non-transferable native proof for this
/// exact handle. Debug output deliberately reveals neither handle nor identity.
pub(crate) struct VerifiedBrokerTransport {
    pipe: NamedPipeClient,
    authority: PackageServerConnectionAuthority,
}

impl fmt::Debug for VerifiedBrokerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedBrokerTransport([redacted])")
    }
}

impl VerifiedBrokerTransport {
    pub(crate) fn into_parts(self) -> (NamedPipeClient, PackageServerConnectionAuthority) {
        (self.pipe, self.authority)
    }
}

pub(crate) async fn connect() -> Result<VerifiedBrokerTransport, PrivateBrokerError> {
    let expected_broker = expected_broker_identity()?;
    let broker_aumid = current_broker_aumid()?;
    tokio::task::spawn_blocking(move || activate_broker(&broker_aumid))
        .await
        .map_err(|_| PrivateBrokerError::ActivationUnavailable)??;

    let pipe = connect_pipe().await?;
    let authority = admit_package_pipe_server(
        borrowed_handle(&pipe),
        &expected_broker,
        PackagePeerClass::AppContainerBroker,
        Instant::now() + HANDSHAKE_DEADLINE,
    )
    .map_err(|_| PrivateBrokerError::BrokerAdmissionFailed)?;
    if !authority.is_current_for(borrowed_handle(&pipe), Instant::now()) {
        return Err(PrivateBrokerError::BrokerAdmissionFailed);
    }
    Ok(VerifiedBrokerTransport { pipe, authority })
}

fn expected_broker_identity() -> Result<ExpectedPackageIdentity, PrivateBrokerError> {
    let identity = current_package_identity()?;
    ExpectedPackageIdentity::new(
        stein_ipc::current_user_sid().map_err(|_| PrivateBrokerError::WrongDesktopIdentity)?,
        identity.package_family_name.clone(),
        format!("{}!{}", identity.package_family_name, BROKER_APPLICATION_ID),
    )
    .map_err(|_| PrivateBrokerError::WrongDesktopIdentity)
}

fn current_broker_aumid() -> Result<String, PrivateBrokerError> {
    let identity = current_package_identity()?;
    Ok(format!(
        "{}!{}",
        identity.package_family_name, BROKER_APPLICATION_ID
    ))
}

struct CurrentPackageIdentity {
    package_family_name: String,
}

fn current_package_identity() -> Result<CurrentPackageIdentity, PrivateBrokerError> {
    let token = current_process_token()?;
    if token_u32(token.0, TokenIsAppContainer)? != 0 {
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }
    let package_family_name = match query_token_identity(
        token.0,
        GetPackageFamilyNameFromToken,
        PACKAGE_FAMILY_NAME_MAX_LENGTH,
    )? {
        TokenIdentity::Unpackaged => return Err(PrivateBrokerError::Unpackaged),
        TokenIdentity::Value(value) => value,
    };
    let application_user_model_id = match query_token_identity(
        token.0,
        GetApplicationUserModelIdFromToken,
        APPLICATION_USER_MODEL_ID_MAX_LENGTH,
    )? {
        TokenIdentity::Unpackaged => return Err(PrivateBrokerError::WrongDesktopIdentity),
        TokenIdentity::Value(value) => value,
    };

    if !package_family_name.starts_with(&format!("{PRODUCTION_PACKAGE_NAME}_"))
        || application_user_model_id != format!("{package_family_name}!{DESKTOP_APPLICATION_ID}")
    {
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }
    Ok(CurrentPackageIdentity {
        package_family_name,
    })
}

fn current_process_token() -> Result<OwnedHandle, PrivateBrokerError> {
    let mut token = null_mut();
    // SAFETY: `token` is writable and only query access is requested.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }
    Ok(OwnedHandle(token))
}

fn token_u32(token: HANDLE, information_class: i32) -> Result<u32, PrivateBrokerError> {
    let mut value = 0_u32;
    let mut written = 0_u32;
    // SAFETY: `value` is a writable u32 buffer and `written` is writable.
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            (&mut value as *mut u32).cast::<c_void>(),
            std::mem::size_of::<u32>() as u32,
            &mut written,
        )
    } == 0
        || written != std::mem::size_of::<u32>() as u32
    {
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }
    Ok(value)
}

type TokenIdentityQuery = unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32;

enum TokenIdentity {
    Unpackaged,
    Value(String),
}

fn query_token_identity(
    token: HANDLE,
    query: TokenIdentityQuery,
    maximum_length: u32,
) -> Result<TokenIdentity, PrivateBrokerError> {
    let mut length = 0_u32;
    // SAFETY: this is the documented sizing call and `length` is writable.
    let sizing_result = unsafe { query(token, &mut length, null_mut()) };
    if sizing_result == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(TokenIdentity::Unpackaged);
    }
    if sizing_result != ERROR_INSUFFICIENT_BUFFER || length < 2 || length > maximum_length {
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }

    let mut value = vec![0_u16; length as usize];
    let mut written = length;
    // SAFETY: `value` contains `length` writable UTF-16 elements and the token
    // remains live with TOKEN_QUERY access.
    if unsafe { query(token, &mut written, value.as_mut_ptr()) } != ERROR_SUCCESS
        || written != length
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        value.fill(0);
        return Err(PrivateBrokerError::WrongDesktopIdentity);
    }
    let identity = String::from_utf16(&value[..value.len() - 1])
        .map_err(|_| PrivateBrokerError::WrongDesktopIdentity);
    value.fill(0);
    identity.map(TokenIdentity::Value)
}

fn activate_broker(application_user_model_id: &str) -> Result<(), PrivateBrokerError> {
    // SAFETY: the blocking worker owns this COM apartment for the duration of
    // activation. RPC_E_CHANGED_MODE means the thread already has a usable
    // apartment and therefore must not be uninitialized by this function.
    let initialization = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let uninitialize = if initialization.is_ok() {
        true
    } else if initialization == RPC_E_CHANGED_MODE {
        false
    } else {
        return Err(PrivateBrokerError::ActivationUnavailable);
    };
    let _apartment = ComApartment { uninitialize };

    // SAFETY: COM is initialized on this thread and the class/interface pair is
    // the operating-system Application Activation Manager.
    let manager: IApplicationActivationManager =
        unsafe { CoCreateInstance(&ApplicationActivationManager, None, CLSCTX_LOCAL_SERVER) }
            .map_err(|_| PrivateBrokerError::ActivationUnavailable)?;
    let application_user_model_id = HSTRING::from(application_user_model_id);
    let arguments = HSTRING::new();
    // SAFETY: both HSTRING values remain live through the synchronous call.
    let process_id =
        unsafe { manager.ActivateApplication(&application_user_model_id, &arguments, AO_NONE) }
            .map_err(|_| PrivateBrokerError::ActivationUnavailable)?;
    if process_id == 0 {
        return Err(PrivateBrokerError::ActivationUnavailable);
    }
    Ok(())
}

async fn connect_pipe() -> Result<NamedPipeClient, PrivateBrokerError> {
    let started = tokio::time::Instant::now();
    loop {
        match ClientOptions::new().open(BROKER_RELAY_PIPE) {
            Ok(pipe) => return Ok(pipe),
            Err(error)
                if transient_connect_error(&error) && started.elapsed() < CONNECT_DEADLINE =>
            {
                sleep(CONNECT_RETRY_DELAY).await;
            }
            Err(_) => return Err(PrivateBrokerError::ConnectionUnavailable),
        }
    }
}

fn transient_connect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) || error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
}

fn borrowed_handle<T: AsRawHandle>(value: &T) -> BorrowedHandle<'_> {
    // SAFETY: the borrow cannot outlive `value`, and ownership is not moved.
    unsafe { BorrowedHandle::borrow_raw(value.as_raw_handle()) }
}

struct ComApartment {
    uninitialize: bool,
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this guard exists only after successful CoInitializeEx on
            // the same blocking worker thread.
            unsafe { CoUninitialize() };
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns the process-token handle exclusively.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unpacked_test_process_cannot_construct_broker_expectations() {
        assert!(matches!(
            current_package_identity(),
            Err(PrivateBrokerError::Unpackaged)
        ));
    }

    #[test]
    fn errors_and_transport_debug_are_content_free() {
        assert_eq!(
            format!("{:?}", PrivateBrokerError::BrokerAdmissionFailed),
            "BrokerAdmissionFailed"
        );
        assert!(!format!("{:?}", PrivateBrokerError::WrongDesktopIdentity).contains("STEIN."));
    }
}
