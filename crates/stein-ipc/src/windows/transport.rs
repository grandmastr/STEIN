use std::{ffi::c_void, io, time::Duration};

use stein_broker_windows::{ExpectedPackageIdentity, PrivatePipeSecurity};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    time::sleep,
};
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use super::{PipeSecurity, ensure_pipe_server_is_current_user};

pub(crate) fn create_pipe_server(name: &str, first_instance: bool) -> io::Result<NamedPipeServer> {
    let security = PipeSecurity::current_user_only()?;
    let mut attributes: SECURITY_ATTRIBUTES = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        // Leave the operating-system pipe-instance capacity at Tokio's
        // unlimited default. The server's semaphore owns the application
        // connection limit and an always-open replacement listener needs one
        // additional pipe instance beyond that limit.
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);

    // SAFETY: attributes and its descriptor remain valid for this synchronous
    // CreateNamedPipe call. Windows copies the security descriptor to the object.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

pub(crate) fn create_private_pipe_server(
    name: &str,
    first_instance: bool,
    expected: &ExpectedPackageIdentity,
) -> io::Result<NamedPipeServer> {
    let security = PrivatePipeSecurity::new(expected).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private named-pipe security is unavailable",
        )
    })?;
    let mut attributes: SECURITY_ATTRIBUTES = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);

    // SAFETY: attributes and its descriptor remain valid for this synchronous
    // CreateNamedPipe call. Windows copies the security descriptor.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

pub(crate) async fn connect_pipe(name: &str, timeout: Duration) -> io::Result<NamedPipeClient> {
    let started = tokio::time::Instant::now();
    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => {
                ensure_pipe_server_is_current_user(&client)?;
                return Ok(client);
            }
            Err(error)
                if (matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) || error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32))
                    && started.elapsed() < timeout =>
            {
                sleep(Duration::from_millis(75)).await;
            }
            Err(error) => return Err(error),
        }
    }
}
