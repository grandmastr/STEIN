//! Windows package-identity admission for STEIN's private client broker.
//!
//! This crate proves identity from kernel-owned process and token state. It
//! does not trust package names, AUMIDs, process IDs, paths, or capability
//! material supplied over the protocol. The verified authority is deliberately
//! opaque, non-cloneable, non-serializable, and scoped to one daemon instance.

use std::{fmt, time::Instant};

use thiserror::Error;

/// Stable production package and application identities shared by the signed
/// desktop, the AppContainer relay, and CORE's private endpoint configuration.
pub const PRODUCTION_PACKAGE_NAME: &str = "STEIN.PersonalIntelligence";
pub const DESKTOP_APPLICATION_ID: &str = "Desktop";
pub const BROKER_APPLICATION_ID: &str = "PrivateBroker";
pub const BROWSER_PRODUCER_APPLICATION_ID: &str = "BrowserObservationProducer";
pub const BROKER_RELAY_PIPE: &str = r"\\.\pipe\LOCAL\stein-private-broker-v1";
pub const CORE_PRIVATE_PIPE: &str = r"\\.\pipe\LOCAL\stein-core-private-v1";

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::PrivatePipeSecurity;

/// The package identities accepted by STEIN's narrow Windows broker topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackagePeerClass {
    /// The sandboxed broker admitted by CORE's private endpoint.
    AppContainerBroker,
    /// The packaged full-trust Tauri backend admitted by the broker relay.
    PackagedDesktop,
    /// The packaged full-trust, write-only Edge observation producer admitted
    /// by CORE's dedicated browser endpoint.
    BrowserObservationProducer,
}

/// Resolves the current process token's owner SID without trusting environment
/// variables or command-line input.
#[cfg(windows)]
pub fn current_process_user_sid() -> Result<String, AdmissionError> {
    native::current_process_user_sid()
}

#[cfg(not(windows))]
pub fn current_process_user_sid() -> Result<String, AdmissionError> {
    Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
}

/// Exact, installation-pinned Windows package identity.
///
/// Debug output is intentionally content-free so an error path cannot disclose
/// installation identity or accidentally train callers to log it.
#[derive(Clone, Eq, PartialEq)]
pub struct ExpectedPackageIdentity {
    #[cfg(windows)]
    owner_sid: String,
    #[cfg(windows)]
    package_family_name: String,
    #[cfg(windows)]
    app_user_model_id: String,
    #[cfg(windows)]
    app_container_sid: String,
}

/// Exact identity of the unpackaged, signed CORE binary the AppContainer
/// broker is allowed to relay to. The SHA-256 digest is compiled into the
/// signed package build, so a same-user process cannot replace it through a
/// writable configuration file.
#[derive(Clone, Eq, PartialEq)]
pub struct ExpectedCoreServer {
    #[cfg(windows)]
    owner_sid: String,
    #[cfg(windows)]
    executable_sha256: [u8; 32],
}

impl fmt::Debug for ExpectedCoreServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedCoreServer([redacted])")
    }
}

impl ExpectedCoreServer {
    #[cfg(windows)]
    pub fn new(
        owner_sid: impl Into<String>,
        executable_sha256: [u8; 32],
    ) -> Result<Self, AdmissionError> {
        native::expected_core_server(owner_sid.into(), executable_sha256)
    }

    #[cfg(not(windows))]
    pub fn new(
        _owner_sid: impl Into<String>,
        _executable_sha256: [u8; 32],
    ) -> Result<Self, AdmissionError> {
        Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
    }
}

impl fmt::Debug for ExpectedPackageIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedPackageIdentity([redacted])")
    }
}

impl ExpectedPackageIdentity {
    /// Validates an exact package identity and derives its AppContainer SID
    /// through the operating system. The caller cannot substitute a claimed
    /// SID that is unrelated to the pinned PFN.
    #[cfg(windows)]
    pub fn new(
        owner_sid: impl Into<String>,
        package_family_name: impl Into<String>,
        app_user_model_id: impl Into<String>,
    ) -> Result<Self, AdmissionError> {
        native::expected_identity(
            owner_sid.into(),
            package_family_name.into(),
            app_user_model_id.into(),
        )
    }

    #[cfg(not(windows))]
    pub fn new(
        _owner_sid: impl Into<String>,
        _package_family_name: impl Into<String>,
        _app_user_model_id: impl Into<String>,
    ) -> Result<Self, AdmissionError> {
        Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
    }

    #[cfg(windows)]
    pub(crate) fn from_validated_parts(
        owner_sid: String,
        package_family_name: String,
        app_user_model_id: String,
        app_container_sid: String,
    ) -> Self {
        Self {
            owner_sid,
            package_family_name,
            app_user_model_id,
            app_container_sid,
        }
    }
}

/// An opaque single-connection authority created only after native peer proof.
///
/// There is intentionally no accessor for its random bytes and no `Clone`,
/// `Serialize`, or wire representation. The IPC layer moves this value into one
/// connection's session state and drops it when that connection ends.
pub struct ConnectionAuthority {
    #[cfg(windows)]
    secret: [u8; 32],
    #[cfg(windows)]
    daemon_instance: [u8; 16],
    #[cfg(windows)]
    connection_handle: usize,
    #[cfg(windows)]
    expires_at: Instant,
}

/// Opaque proof that a connected client-side pipe is attached to the exact
/// package server identity verified by the operating system.
///
/// This is the desktop-side counterpart to [`ConnectionAuthority`]. It is
/// non-cloneable, non-serializable, bound to one raw pipe handle, and useful
/// only during the short protocol-handshake window. IPC consumes it before
/// writing the first private frame, so callers cannot upgrade an arbitrary
/// named-pipe connection by choosing an assurance enum.
pub struct PackageServerConnectionAuthority {
    #[cfg(windows)]
    secret: [u8; 32],
    #[cfg(windows)]
    connection_handle: usize,
    #[cfg(windows)]
    expires_at: Instant,
}

impl fmt::Debug for ConnectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionAuthority([redacted])")
    }
}

impl fmt::Debug for PackageServerConnectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PackageServerConnectionAuthority([redacted])")
    }
}

impl ConnectionAuthority {
    /// Whether the authority is still bound to this exact pipe handle, daemon,
    /// and handshake window.
    #[cfg(windows)]
    pub fn is_current_for(
        &self,
        pipe: std::os::windows::io::BorrowedHandle<'_>,
        daemon_instance: &[u8; 16],
        now: Instant,
    ) -> bool {
        use std::os::windows::io::AsRawHandle;

        constant_time_equal(&self.daemon_instance, daemon_instance)
            && pipe.as_raw_handle() as usize == self.connection_handle
            && now <= self.expires_at
    }

    #[cfg(windows)]
    fn from_native(
        daemon_instance: [u8; 16],
        connection_handle: usize,
        expires_at: Instant,
    ) -> Result<Self, AdmissionError> {
        let secret = native::random_authority()?;
        Ok(Self {
            secret,
            daemon_instance,
            connection_handle,
            expires_at,
        })
    }
}

impl PackageServerConnectionAuthority {
    /// Whether this proof is still bound to the exact connected client-side
    /// named-pipe handle and has not exceeded its handshake deadline.
    #[cfg(windows)]
    pub fn is_current_for(
        &self,
        pipe: std::os::windows::io::BorrowedHandle<'_>,
        now: Instant,
    ) -> bool {
        use std::os::windows::io::AsRawHandle;

        pipe.as_raw_handle() as usize == self.connection_handle && now <= self.expires_at
    }

    #[cfg(windows)]
    fn from_native(connection_handle: usize, expires_at: Instant) -> Result<Self, AdmissionError> {
        let secret = native::random_authority()?;
        Ok(Self {
            secret,
            connection_handle,
            expires_at,
        })
    }
}

impl Drop for ConnectionAuthority {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            self.secret.fill(0);
            self.daemon_instance.fill(0);
            self.connection_handle = 0;
        }
    }
}

impl Drop for PackageServerConnectionAuthority {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            self.secret.fill(0);
            self.connection_handle = 0;
        }
    }
}

#[cfg(windows)]
fn constant_time_equal(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Content-free failure classes suitable for diagnostic health reporting.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdmissionErrorKind {
    #[error("invalid package admission configuration")]
    InvalidConfiguration,
    #[error("the package admission boundary is unavailable")]
    BoundaryUnavailable,
    #[error("the named-pipe peer changed during verification")]
    BoundaryChanged,
    #[error("the peer belongs to a different operating-system user")]
    WrongUser,
    #[error("the peer does not have the required package identity")]
    WrongPackage,
    #[error("the peer does not have the required application identity")]
    WrongApplication,
    #[error("the peer does not have the required AppContainer identity")]
    WrongAppContainer,
    #[error("the peer is not in the required Windows execution class")]
    WrongExecutionClass,
    #[error("the CORE endpoint is not owned by the pinned signed binary")]
    WrongCoreImage,
    #[error("cryptographic authority generation failed")]
    RandomnessUnavailable,
    #[error("Windows package admission is unavailable on this platform")]
    Unsupported,
}

/// A content-free admission error. Native error strings are never retained
/// because they may contain private paths or package details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{kind}")]
pub struct AdmissionError {
    kind: AdmissionErrorKind,
}

impl AdmissionError {
    pub const fn new(kind: AdmissionErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> AdmissionErrorKind {
        self.kind
    }
}

/// Verifies the client attached to a named-pipe server handle and creates a
/// one-use, one-daemon authority for that exact connection.
///
/// The pipe handle is borrowed and must identify a connected server endpoint.
/// Windows supplies the peer PID and impersonation token; no protocol field is
/// involved in admission.
#[cfg(windows)]
pub fn admit_named_pipe_peer(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
    daemon_instance: [u8; 16],
    expires_at: Instant,
) -> Result<ConnectionAuthority, AdmissionError> {
    use std::os::windows::io::AsRawHandle;

    native::verify_named_pipe_peer(pipe, expected, class)?;
    ConnectionAuthority::from_native(daemon_instance, pipe.as_raw_handle() as usize, expires_at)
}

/// Verifies that the server behind a connected broker-side named-pipe client
/// is the exact unpackaged CORE binary pinned into this signed package build.
/// This prevents a same-user fake server from racing CORE and receiving private
/// desktop payloads from an otherwise correctly admitted broker.
#[cfg(windows)]
pub fn verify_core_pipe_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expected: &ExpectedCoreServer,
) -> Result<(), AdmissionError> {
    native::verify_core_pipe_server(pipe, expected)
}

/// Verifies the exact packaged process serving a connected named-pipe client.
/// The desktop uses this after connecting to the relay, before sending a byte,
/// so a same-user process cannot pre-create the broker pipe and harvest private
/// commands. For the production relay `class` is `AppContainerBroker`.
#[cfg(windows)]
pub fn verify_package_pipe_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
) -> Result<(), AdmissionError> {
    native::verify_package_pipe_server(pipe, expected, class)
}

/// Verifies the package server behind a connected client-side pipe and returns
/// a short-lived, handle-bound proof for the IPC handshake.
///
/// `expected` must be built from the trusted desktop backend's installed
/// package identity, never renderer input or a wire field. The returned value
/// has no authority beyond this one pipe handle and deadline.
#[cfg(windows)]
pub fn admit_package_pipe_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
    expires_at: Instant,
) -> Result<PackageServerConnectionAuthority, AdmissionError> {
    use std::os::windows::io::AsRawHandle;

    native::verify_package_pipe_server(pipe, expected, class)?;
    PackageServerConnectionAuthority::from_native(pipe.as_raw_handle() as usize, expires_at)
}

#[cfg(not(windows))]
pub fn verify_package_pipe_server(
    _pipe: (),
    _expected: &ExpectedPackageIdentity,
    _class: PackagePeerClass,
) -> Result<(), AdmissionError> {
    Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
}

#[cfg(not(windows))]
pub fn admit_package_pipe_server(
    _pipe: (),
    _expected: &ExpectedPackageIdentity,
    _class: PackagePeerClass,
    _expires_at: Instant,
) -> Result<PackageServerConnectionAuthority, AdmissionError> {
    Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
}

#[cfg(not(windows))]
pub fn verify_core_pipe_server(
    _pipe: (),
    _expected: &ExpectedCoreServer,
) -> Result<(), AdmissionError> {
    Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
}

#[cfg(not(windows))]
pub fn admit_named_pipe_peer(
    _pipe: (),
    _expected: &ExpectedPackageIdentity,
    _class: PackagePeerClass,
    _daemon_instance: [u8; 16],
    _expires_at: Instant,
) -> Result<ConnectionAuthority, AdmissionError> {
    Err(AdmissionError::new(AdmissionErrorKind::Unsupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn comparison_checks_every_daemon_byte() {
        let value = [7_u8; 16];
        assert!(constant_time_equal(&value, &value));
        for index in 0..value.len() {
            let mut changed = value;
            changed[index] ^= 1;
            assert!(!constant_time_equal(&value, &changed));
        }
    }

    #[test]
    fn errors_and_debug_output_are_content_free() {
        let error = AdmissionError::new(AdmissionErrorKind::WrongPackage);
        assert_eq!(
            error.to_string(),
            "the peer does not have the required package identity"
        );
        assert!(!format!("{error:?}").contains("family"));
    }

    #[cfg(windows)]
    #[test]
    fn authority_is_scoped_to_pipe_daemon_and_deadline() {
        use std::{
            os::windows::io::{AsRawHandle, BorrowedHandle},
            time::Duration,
        };

        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

        // SAFETY: Win32 pseudo-handles remain valid for the process lifetime.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: see above.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: each raw value is a live Win32 pseudo-handle during the test.
        let process = unsafe { BorrowedHandle::borrow_raw(process) };
        // SAFETY: see above.
        let thread = unsafe { BorrowedHandle::borrow_raw(thread) };
        let daemon = [3_u8; 16];
        let now = Instant::now();
        let authority = ConnectionAuthority::from_native(
            daemon,
            process.as_raw_handle() as usize,
            now + Duration::from_secs(3),
        )
        .expect("authority");

        assert!(authority.is_current_for(process, &daemon, now));
        assert!(!authority.is_current_for(thread, &daemon, now));
        assert!(!authority.is_current_for(process, &[4; 16], now));
        assert!(!authority.is_current_for(process, &daemon, now + Duration::from_secs(4)));
    }

    #[cfg(windows)]
    #[test]
    fn package_server_authority_is_scoped_to_pipe_and_deadline() {
        use std::{
            os::windows::io::{AsRawHandle, BorrowedHandle},
            time::Duration,
        };

        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

        // SAFETY: Win32 pseudo-handles remain valid for the process lifetime.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: same contract as above for the current-thread pseudo-handle.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: these borrows do not outlive the pseudo-handle validity.
        let process = unsafe { BorrowedHandle::borrow_raw(process) };
        // SAFETY: see above.
        let thread = unsafe { BorrowedHandle::borrow_raw(thread) };
        let now = Instant::now();
        let authority = PackageServerConnectionAuthority::from_native(
            process.as_raw_handle() as usize,
            now + Duration::from_secs(3),
        )
        .expect("authority");

        assert!(authority.is_current_for(process, now));
        assert!(!authority.is_current_for(thread, now));
        assert!(!authority.is_current_for(process, now + Duration::from_secs(4)));
    }
}
