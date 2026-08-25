use std::{io, ptr};

use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
};

use super::current_user_sid;

pub(crate) struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl PipeSecurity {
    pub(crate) fn current_user_only() -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: wide is NUL-terminated and descriptor is a valid output pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }

    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: the descriptor was allocated by LocalAlloc through the SDDL API.
            unsafe { LocalFree(self.descriptor) };
        }
    }
}
