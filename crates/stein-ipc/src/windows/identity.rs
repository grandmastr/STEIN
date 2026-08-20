use std::{ffi::c_void, io, os::windows::io::AsRawHandle, ptr};

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns a valid Win32 handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this call.
    unsafe { sid_for_process_handle(GetCurrentProcess()) }
}

pub fn default_pipe_name() -> io::Result<String> {
    let sid = current_user_sid()?;
    let safe_sid: String = sid
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect();
    Ok(format!(r"\\.\pipe\stein-core-v1-{safe_sid}"))
}

pub(crate) fn ensure_pipe_client_is_current_user(server: &NamedPipeServer) -> io::Result<String> {
    let mut pid = 0_u32;
    // SAFETY: the handle is a connected named-pipe server and pid is writable.
    let ok = unsafe {
        GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid as *mut u32)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    ensure_process_is_current_user(pid)
}

pub(crate) fn ensure_pipe_server_is_current_user(client: &NamedPipeClient) -> io::Result<String> {
    let mut pid = 0_u32;
    // SAFETY: the handle is a connected named-pipe client and pid is writable.
    let ok = unsafe {
        GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid as *mut u32)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    ensure_process_is_current_user(pid)
}

fn ensure_process_is_current_user(pid: u32) -> io::Result<String> {
    let actual = sid_for_process_id(pid)?;
    let expected = current_user_sid()?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe peer belongs to a different operating-system user",
        ));
    }
    Ok(actual)
}

fn sid_for_process_id(pid: u32) -> io::Result<String> {
    // SAFETY: requested access is read-only and pid came from the kernel.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = OwnedHandle(process);
    // SAFETY: process handle remains live for the duration of the call.
    unsafe { sid_for_process_handle(process.0) }
}

unsafe fn sid_for_process_handle(process: HANDLE) -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: token is writable and process is a valid process handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut required = 0_u32;
    // SAFETY: null buffer query obtains the required TOKEN_USER size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = vec![0_u8; required as usize];
    // SAFETY: buffer is at least the required size and pointers are valid.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: GetTokenInformation initialized a TOKEN_USER at the buffer start.
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_text = ptr::null_mut();
    // SAFETY: the SID belongs to the live token buffer and output pointer is valid.
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let result = wide_ptr_to_string(sid_text);
    // SAFETY: ConvertSidToStringSidW allocates with LocalAlloc.
    unsafe { LocalFree(sid_text as *mut c_void) };
    result
}

fn wide_ptr_to_string(value: *const u16) -> io::Result<String> {
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "null SID string",
        ));
    }
    let mut length = 0_usize;
    // SAFETY: value is a NUL-terminated string allocated by Win32.
    unsafe {
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(value, length))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SID string"))
    }
}
