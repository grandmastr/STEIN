//! Windows-native credential collection for the desktop bridge.
//!
//! Secret text never crosses the Tauri invoke boundary. CredUI writes into a
//! native UTF-16 buffer owned by this module and converts it into a
//! non-serializable `NativeSecret`. The caller keeps that zeroizing value only
//! long enough to approve the exact route, then asks this module to write it to
//! Credential Manager under the returned approval identity. The native UTF-16
//! buffer is wiped on every return path.

use stein_core::{SecretStoreError, SecretValue};
use zeroize::Zeroizing;

const MAX_ROUTE_ID_BYTES: usize = 128;

/// Native-only credential bytes. The type has no formatting or serialization
/// implementation and uses `zeroize`'s compiler-fenced drop behavior while the
/// daemon approval is in flight.
pub(crate) struct NativeSecret(Zeroizing<Vec<u8>>);

impl NativeSecret {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    fn into_secret_value(mut self) -> SecretValue {
        SecretValue::new(std::mem::take(&mut *self.0))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(value: Vec<u8>) -> Self {
        Self::new(value)
    }

    #[cfg(test)]
    pub(crate) fn expose_for_test(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub enum NativeCredentialPromptError {
    Cancelled,
    InvalidReference,
    Unavailable,
    Internal,
    Store(SecretStoreError),
}

#[cfg(windows)]
pub fn prompt_for_secret(
    route_id: String,
    parent_window: isize,
) -> Result<NativeSecret, NativeCredentialPromptError> {
    windows::prompt_for_secret(route_id, parent_window)
}

#[cfg(not(windows))]
pub fn prompt_for_secret(
    _route_id: String,
    _parent_window: isize,
) -> Result<NativeSecret, NativeCredentialPromptError> {
    Err(NativeCredentialPromptError::Unavailable)
}

#[cfg(windows)]
pub fn store_secret(
    approval_id: String,
    secret: NativeSecret,
) -> Result<(), NativeCredentialPromptError> {
    windows::store_secret(approval_id, secret)
}

#[cfg(not(windows))]
pub fn store_secret(
    _approval_id: String,
    _secret: NativeSecret,
) -> Result<(), NativeCredentialPromptError> {
    Err(NativeCredentialPromptError::Unavailable)
}

pub fn validate_approval_id(approval_id: &str) -> Result<(), NativeCredentialPromptError> {
    let parsed = uuid::Uuid::parse_str(approval_id)
        .map_err(|_| NativeCredentialPromptError::InvalidReference)?;
    if parsed.hyphenated().to_string() == approval_id {
        Ok(())
    } else {
        Err(NativeCredentialPromptError::InvalidReference)
    }
}

pub fn validate_route_id(route_id: &str) -> Result<(), NativeCredentialPromptError> {
    if !route_id.is_empty()
        && route_id.len() <= MAX_ROUTE_ID_BYTES
        && route_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(NativeCredentialPromptError::InvalidReference)
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        mem::size_of,
        ptr::{null, write_volatile},
        sync::atomic::{Ordering, compiler_fence},
    };

    use stein_core::{SecretKey, SecretStore};
    use stein_platform_windows::WindowsCredentialSecretStore;
    use windows_sys::Win32::{
        Foundation::{ERROR_CANCELLED, ERROR_SUCCESS},
        Security::Credentials::{
            CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST,
            CREDUI_FLAGS_EXCLUDE_CERTIFICATES, CREDUI_FLAGS_GENERIC_CREDENTIALS,
            CREDUI_FLAGS_PASSWORD_ONLY_OK, CREDUI_INFOW, CredUIPromptForCredentialsW,
        },
    };

    use super::{NativeCredentialPromptError, NativeSecret};

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

    pub(super) fn prompt_for_secret(
        route_id: String,
        parent_window: isize,
    ) -> Result<NativeSecret, NativeCredentialPromptError> {
        super::validate_route_id(&route_id)?;

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

        Ok(NativeSecret::new(password.secret_bytes()?))
    }

    pub(super) fn store_secret(
        approval_id: String,
        secret: NativeSecret,
    ) -> Result<(), NativeCredentialPromptError> {
        super::validate_approval_id(&approval_id)?;
        let secret = secret.into_secret_value();
        WindowsCredentialSecretStore::new()
            .write(&SecretKey::new(approval_id), &secret)
            .map_err(NativeCredentialPromptError::Store)
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
        use super::secure_zero_wide;
        use crate::native_credential_prompt::{validate_approval_id, validate_route_id};

        #[test]
        fn route_reference_accepts_only_credential_store_safe_identifiers() {
            assert!(validate_route_id("gpt-5.4_exact.route").is_ok());
            assert!(validate_route_id("").is_err());
            assert!(validate_route_id("route/with/path").is_err());
            assert!(validate_route_id(&"x".repeat(129)).is_err());
        }

        #[test]
        fn credential_target_requires_a_canonically_formatted_approval_uuid() {
            assert!(validate_approval_id("0198c083-f38b-7000-8000-000000000020").is_ok());
            assert!(validate_approval_id("exact-model").is_err());
            assert!(validate_approval_id("0198C083-F38B-7000-8000-000000000020").is_err());
            assert!(validate_approval_id("{0198c083-f38b-7000-8000-000000000020}").is_err());
        }

        #[test]
        fn native_secret_buffer_wipe_overwrites_every_code_unit() {
            let mut buffer = vec![0x41, 0x42, 0x43, 0];
            secure_zero_wide(&mut buffer);
            assert_eq!(buffer, vec![0, 0, 0, 0]);
        }
    }
}
