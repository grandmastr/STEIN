//! Windows-native credential collection for the desktop bridge.
//!
//! Secret text never crosses the Tauri invoke boundary. CredUI writes into a
//! native UTF-16 buffer owned by this module; the module immediately converts
//! it into CORE's non-serializable `SecretValue`, writes it to Credential
//! Manager, and wipes the native buffer on every return path.

use stein_core::SecretStoreError;

#[derive(Debug)]
pub enum NativeCredentialPromptError {
    Cancelled,
    InvalidReference,
    Unavailable,
    Internal,
    Store(SecretStoreError),
}

#[cfg(windows)]
pub fn prompt_and_store(
    route_id: String,
    parent_window: isize,
) -> Result<(), NativeCredentialPromptError> {
    windows::prompt_and_store(route_id, parent_window)
}

#[cfg(not(windows))]
pub fn prompt_and_store(
    _route_id: String,
    _parent_window: isize,
) -> Result<(), NativeCredentialPromptError> {
    Err(NativeCredentialPromptError::Unavailable)
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        mem::size_of,
        ptr::{null, write_volatile},
        sync::atomic::{Ordering, compiler_fence},
    };

    use stein_core::{SecretKey, SecretStore, SecretValue};
    use stein_platform_windows::WindowsCredentialSecretStore;
    use windows_sys::Win32::{
        Foundation::{ERROR_CANCELLED, ERROR_SUCCESS},
        Security::Credentials::{
            CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST,
            CREDUI_FLAGS_EXCLUDE_CERTIFICATES, CREDUI_FLAGS_GENERIC_CREDENTIALS,
            CREDUI_FLAGS_PASSWORD_ONLY_OK, CREDUI_INFOW, CredUIPromptForCredentialsW,
        },
    };

    use super::NativeCredentialPromptError;

    const MAX_ROUTE_ID_BYTES: usize = 128;
    const CREDUI_PASSWORD_CODE_UNITS: usize = 257;
    const CREDUI_USERNAME_CODE_UNITS: usize = 513;

    struct SensitiveWideBuffer(Vec<u16>);

    impl SensitiveWideBuffer {
        fn zeroed(length: usize) -> Self {
            Self(vec![0; length])
        }

        fn as_mut_ptr(&mut self) -> *mut u16 {
            self.0.as_mut_ptr()
        }

        fn secret_bytes(&self) -> Result<Vec<u8>, NativeCredentialPromptError> {
            let length = self
                .0
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(self.0.len());
            if length == 0 {
                return Err(NativeCredentialPromptError::Internal);
            }
            String::from_utf16(&self.0[..length])
                .map(String::into_bytes)
                .map_err(|_| NativeCredentialPromptError::Internal)
        }

        fn wipe(&mut self) {
            secure_zero_wide(&mut self.0);
        }
    }

    impl Drop for SensitiveWideBuffer {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    pub(super) fn prompt_and_store(
        route_id: String,
        parent_window: isize,
    ) -> Result<(), NativeCredentialPromptError> {
        if !valid_route_id(&route_id) {
            return Err(NativeCredentialPromptError::InvalidReference);
        }

        let target = wide_null(&format!("STEIN:model-route:{route_id}"));
        let caption = wide_null("Store provider credential");
        let message = wide_null(&format!(
            "Enter the provider credential for exact route {route_id}. STEIN stores it directly in Windows Credential Manager; the desktop webview cannot read it."
        ));
        let mut username = SensitiveWideBuffer::zeroed(CREDUI_USERNAME_CODE_UNITS);
        let mut password = SensitiveWideBuffer::zeroed(CREDUI_PASSWORD_CODE_UNITS);
        let mut save = 0;
        let info = CREDUI_INFOW {
            cbSize: size_of::<CREDUI_INFOW>() as u32,
            hwndParent: parent_window as *mut c_void,
            pszMessageText: message.as_ptr(),
            pszCaptionText: caption.as_ptr(),
            hbmBanner: null_mut_handle(),
        };

        // SAFETY: every pointer is valid for the duration of the synchronous
        // call, both output buffers advertise their actual allocation length,
        // and all strings are NUL-terminated UTF-16.
        let result = unsafe {
            CredUIPromptForCredentialsW(
                &info,
                target.as_ptr(),
                null(),
                ERROR_SUCCESS,
                username.as_mut_ptr(),
                CREDUI_USERNAME_CODE_UNITS as u32,
                password.as_mut_ptr(),
                CREDUI_PASSWORD_CODE_UNITS as u32,
                &mut save,
                CREDUI_FLAGS_ALWAYS_SHOW_UI
                    | CREDUI_FLAGS_DO_NOT_PERSIST
                    | CREDUI_FLAGS_EXCLUDE_CERTIFICATES
                    | CREDUI_FLAGS_GENERIC_CREDENTIALS
                    | CREDUI_FLAGS_PASSWORD_ONLY_OK,
            )
        };
        if result == ERROR_CANCELLED {
            return Err(NativeCredentialPromptError::Cancelled);
        }
        if result != ERROR_SUCCESS {
            return Err(NativeCredentialPromptError::Unavailable);
        }

        let secret = SecretValue::new(password.secret_bytes()?);
        WindowsCredentialSecretStore::new()
            .write(&SecretKey::new(route_id), &secret)
            .map_err(NativeCredentialPromptError::Store)
    }

    fn valid_route_id(route_id: &str) -> bool {
        !route_id.is_empty()
            && route_id.len() <= MAX_ROUTE_ID_BYTES
            && route_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    fn null_mut_handle() -> *mut c_void {
        std::ptr::null_mut()
    }

    fn secure_zero_wide(buffer: &mut [u16]) {
        for unit in buffer {
            // SAFETY: `unit` is a valid, uniquely borrowed element. Volatile
            // writes prevent the compiler from eliding this final wipe.
            unsafe { write_volatile(unit, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(test)]
    mod tests {
        use super::{secure_zero_wide, valid_route_id};

        #[test]
        fn route_reference_accepts_only_credential_store_safe_identifiers() {
            assert!(valid_route_id("gpt-5.4_exact.route"));
            assert!(!valid_route_id(""));
            assert!(!valid_route_id("route/with/path"));
            assert!(!valid_route_id(&"x".repeat(129)));
        }

        #[test]
        fn native_secret_buffer_wipe_overwrites_every_code_unit() {
            let mut buffer = vec![0x41, 0x42, 0x43, 0];
            secure_zero_wide(&mut buffer);
            assert_eq!(buffer, vec![0, 0, 0, 0]);
        }
    }
}
