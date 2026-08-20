use std::fmt;

use stein_core::{SecretKey, SecretStore, SecretStoreError, SecretStoreErrorKind, SecretValue};

/// Native target prefix for model-route credentials.
pub const MODEL_ROUTE_TARGET_PREFIX: &str = "STEIN:model-route:";
const MAX_ROUTE_ID_BYTES: usize = 128;
const MAX_SECRET_BYTES: usize = 2_560;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendError {
    AccessDenied,
    Unavailable,
    Internal,
}

trait CredentialBackend: Send + Sync {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>, BackendError>;
    fn write(&self, target: &str, value: &[u8]) -> Result<(), BackendError>;
    fn delete(&self, target: &str) -> Result<bool, BackendError>;
}

struct CredentialStoreAdapter<B> {
    backend: B,
}

impl<B: CredentialBackend> CredentialStoreAdapter<B> {
    fn read(&self, key: &SecretKey) -> Result<Option<SecretValue>, SecretStoreError> {
        let target = target_for(key)?;
        self.backend
            .read(&target)
            .map(|value| value.map(SecretValue::new))
            .map_err(store_error)
    }

    fn write(&self, key: &SecretKey, value: &SecretValue) -> Result<(), SecretStoreError> {
        let target = target_for(key)?;
        let exposed = value.expose();
        if exposed.is_empty() || exposed.len() > MAX_SECRET_BYTES {
            return Err(invalid_secret());
        }
        self.backend.write(&target, exposed).map_err(store_error)
    }

    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError> {
        let target = target_for(key)?;
        self.backend.delete(&target).map_err(store_error)
    }
}

/// Current-user Windows Credential Manager implementation of CORE's secret
/// store. The value deliberately has no fields and its `Debug` output contains
/// no credential target or secret material.
#[derive(Clone, Copy, Default)]
pub struct WindowsCredentialSecretStore;

impl WindowsCredentialSecretStore {
    pub const fn new() -> Self {
        Self
    }
}

impl fmt::Debug for WindowsCredentialSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsCredentialSecretStore")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl SecretStore for WindowsCredentialSecretStore {
    fn is_available(&self) -> bool {
        native::is_available()
    }

    fn read(&self, key: &SecretKey) -> Result<Option<SecretValue>, SecretStoreError> {
        CredentialStoreAdapter { backend: NativeApi }.read(key)
    }

    fn write(&self, key: &SecretKey, value: &SecretValue) -> Result<(), SecretStoreError> {
        CredentialStoreAdapter { backend: NativeApi }.write(key, value)
    }

    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError> {
        CredentialStoreAdapter { backend: NativeApi }.delete(key)
    }
}

#[cfg(not(windows))]
impl SecretStore for WindowsCredentialSecretStore {
    fn is_available(&self) -> bool {
        false
    }

    fn read(&self, _key: &SecretKey) -> Result<Option<SecretValue>, SecretStoreError> {
        Err(unavailable_store())
    }

    fn write(&self, _key: &SecretKey, _value: &SecretValue) -> Result<(), SecretStoreError> {
        Err(unavailable_store())
    }

    fn delete(&self, _key: &SecretKey) -> Result<bool, SecretStoreError> {
        Err(unavailable_store())
    }
}

fn target_for(key: &SecretKey) -> Result<String, SecretStoreError> {
    let route_id = key.as_str();
    let valid = !route_id.is_empty()
        && route_id.len() <= MAX_ROUTE_ID_BYTES
        && route_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(invalid_reference());
    }

    Ok(format!("{MODEL_ROUTE_TARGET_PREFIX}{route_id}"))
}

fn invalid_reference() -> SecretStoreError {
    SecretStoreError {
        kind: SecretStoreErrorKind::Internal,
        summary: "The secret reference is malformed.",
    }
}

fn invalid_secret() -> SecretStoreError {
    SecretStoreError {
        kind: SecretStoreErrorKind::Internal,
        summary: "The secret value is invalid for the platform store.",
    }
}

#[cfg(not(windows))]
fn unavailable_store() -> SecretStoreError {
    SecretStoreError {
        kind: SecretStoreErrorKind::Unavailable,
        summary: "Windows Credential Manager is unavailable on this platform.",
    }
}

fn store_error(error: BackendError) -> SecretStoreError {
    match error {
        BackendError::AccessDenied => SecretStoreError {
            kind: SecretStoreErrorKind::AccessDenied,
            summary: "Windows Credential Manager denied the operation.",
        },
        BackendError::Unavailable => SecretStoreError {
            kind: SecretStoreErrorKind::Unavailable,
            summary: "Windows Credential Manager is unavailable for this user session.",
        },
        BackendError::Internal => SecretStoreError {
            kind: SecretStoreErrorKind::Internal,
            summary: "Windows Credential Manager could not complete the operation.",
        },
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct NativeApi;

#[cfg(windows)]
impl CredentialBackend for NativeApi {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>, BackendError> {
        native::read(target)
    }

    fn write(&self, target: &str, value: &[u8]) -> Result<(), BackendError> {
        native::write(target, value)
    }

    fn delete(&self, target: &str) -> Result<bool, BackendError> {
        native::delete(target)
    }
}

#[cfg(windows)]
mod native {
    use std::ptr;
    use std::slice;
    use std::sync::atomic::{Ordering, compiler_fence};

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    use super::BackendError;

    struct CredentialAllocation(*mut CREDENTIALW);

    impl Drop for CredentialAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: CredReadW returned a writable CREDENTIALW allocation.
                // Credential Manager bounds generic blobs to 2,560 bytes; the
                // additional check prevents following a malformed size. Scrub
                // the native copy before releasing the allocation.
                unsafe {
                    let credential = &mut *self.0;
                    let size = credential.CredentialBlobSize as usize;
                    if !credential.CredentialBlob.is_null() && size <= super::MAX_SECRET_BYTES {
                        secure_zero(credential.CredentialBlob, size);
                    }
                }
                // SAFETY: CredReadW returned this allocation and ownership has
                // not been transferred. CredFree is the required matching free.
                unsafe { CredFree(self.0.cast()) };
            }
        }
    }

    pub(super) fn is_available() -> bool {
        // This reserved target is outside the model-route namespace, so the
        // read-only probe cannot collide with a configured provider secret.
        let target = wide("STEIN:credential-manager:availability-probe");
        let mut raw = ptr::null_mut();
        // SAFETY: `target` is NUL terminated and `raw` is a writable out-pointer.
        let succeeded = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if succeeded != 0 {
            drop(CredentialAllocation(raw));
            return true;
        }
        // SAFETY: read immediately after the failed Win32 call.
        (unsafe { GetLastError() }) == ERROR_NOT_FOUND
    }

    pub(super) fn read(target: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let target = wide(target);
        let mut raw = ptr::null_mut();
        // SAFETY: `target` is NUL terminated for this call and `raw` points to a
        // writable out-parameter. A successful allocation is guarded below.
        let succeeded = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if succeeded == 0 {
            // SAFETY: GetLastError has no pointer preconditions and is read
            // immediately after the failed Win32 call.
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(map_native_error(error))
            };
        }

        if raw.is_null() {
            return Err(BackendError::Internal);
        }
        let allocation = CredentialAllocation(raw);
        // SAFETY: a successful CredReadW returns a valid CREDENTIALW allocation
        // for the lifetime of `allocation`.
        let credential = unsafe { &*allocation.0 };
        let size = credential.CredentialBlobSize as usize;
        if size == 0 || size > super::MAX_SECRET_BYTES || credential.CredentialBlob.is_null() {
            return Err(BackendError::Internal);
        }
        // SAFETY: Credential Manager owns a readable blob of exactly the
        // advertised size until CredFree runs. We copy once into SecretValue's
        // eventual owned buffer and never format or log it.
        let bytes = unsafe { slice::from_raw_parts(credential.CredentialBlob, size) };
        Ok(Some(bytes.to_vec()))
    }

    pub(super) fn write(target: &str, value: &[u8]) -> Result<(), BackendError> {
        let mut target = wide(target);
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: value.len() as u32,
            CredentialBlob: value.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: every pointer in `credential` is either null or remains valid
        // for the synchronous call. CredWriteW copies the supplied credential.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            // SAFETY: read immediately after the failed Win32 call.
            Err(map_native_error(unsafe { GetLastError() }))
        } else {
            Ok(())
        }
    }

    pub(super) fn delete(target: &str) -> Result<bool, BackendError> {
        let target = wide(target);
        // SAFETY: `target` is a valid NUL-terminated string for this call.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(true);
        }
        // SAFETY: read immediately after the failed Win32 call.
        let error = unsafe { GetLastError() };
        if error == ERROR_NOT_FOUND {
            Ok(false)
        } else {
            Err(map_native_error(error))
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    unsafe fn secure_zero(buffer: *mut u8, length: usize) {
        for index in 0..length {
            // SAFETY: the caller provides a writable buffer spanning `length`
            // bytes. Volatile stores prevent dead-store elimination before the
            // native allocation is released.
            unsafe { buffer.add(index).write_volatile(0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    fn map_native_error(error: u32) -> BackendError {
        match error {
            ERROR_ACCESS_DENIED => BackendError::AccessDenied,
            ERROR_NO_SUCH_LOGON_SESSION => BackendError::Unavailable,
            _ => BackendError::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl CredentialBackend for FakeBackend {
        fn read(&self, target: &str) -> Result<Option<Vec<u8>>, BackendError> {
            Ok(self.values.lock().unwrap().get(target).cloned())
        }

        fn write(&self, target: &str, value: &[u8]) -> Result<(), BackendError> {
            self.values
                .lock()
                .unwrap()
                .insert(target.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, target: &str) -> Result<bool, BackendError> {
            Ok(self.values.lock().unwrap().remove(target).is_some())
        }
    }

    #[test]
    fn deterministic_target_is_scoped_to_model_routes() {
        let key = SecretKey::new("route_01.example");
        assert_eq!(
            target_for(&key).unwrap(),
            "STEIN:model-route:route_01.example"
        );
    }

    #[test]
    fn malformed_references_fail_before_backend_access() {
        for value in ["", "../route", "route:name", "route/name", "route name"] {
            let error = target_for(&SecretKey::new(value)).unwrap_err();
            assert_eq!(error.kind, SecretStoreErrorKind::Internal);
            assert_eq!(error.summary, "The secret reference is malformed.");
        }
        assert!(target_for(&SecretKey::new("x".repeat(MAX_ROUTE_ID_BYTES))).is_ok());
        assert!(target_for(&SecretKey::new("x".repeat(MAX_ROUTE_ID_BYTES + 1))).is_err());
    }

    #[test]
    fn debug_output_is_content_free() {
        assert_eq!(
            format!("{:?}", WindowsCredentialSecretStore::new()),
            "WindowsCredentialSecretStore { .. }"
        );
        for (native, expected) in [
            (
                BackendError::AccessDenied,
                SecretStoreErrorKind::AccessDenied,
            ),
            (BackendError::Unavailable, SecretStoreErrorKind::Unavailable),
            (BackendError::Internal, SecretStoreErrorKind::Internal),
        ] {
            let error = store_error(native);
            assert_eq!(error.kind, expected);
            assert!(!error.summary.contains("route"));
        }
    }

    #[test]
    fn fake_lifecycle_covers_missing_replace_and_delete() {
        let store = CredentialStoreAdapter {
            backend: FakeBackend::default(),
        };
        let key = SecretKey::new("synthetic-route");
        assert!(store.read(&key).unwrap().is_none());

        store
            .write(&key, &SecretValue::new(b"first".to_vec()))
            .unwrap();
        assert_eq!(store.read(&key).unwrap().unwrap().expose(), b"first");

        store
            .write(&key, &SecretValue::new(b"replacement".to_vec()))
            .unwrap();
        assert_eq!(store.read(&key).unwrap().unwrap().expose(), b"replacement");
        assert!(store.delete(&key).unwrap());
        assert!(!store.delete(&key).unwrap());
        assert!(store.read(&key).unwrap().is_none());
    }

    #[test]
    fn empty_and_oversized_values_fail_closed() {
        let store = CredentialStoreAdapter {
            backend: FakeBackend::default(),
        };
        let key = SecretKey::new("synthetic-route");
        for value in [Vec::new(), vec![0_u8; MAX_SECRET_BYTES + 1]] {
            let error = store.write(&key, &SecretValue::new(value)).unwrap_err();
            assert_eq!(error.kind, SecretStoreErrorKind::Internal);
        }
        assert!(store.read(&key).unwrap().is_none());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "mutates a synthetic current-user Credential Manager entry"]
    fn native_current_user_credential_lifecycle() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = SecretKey::new(format!("native-test-{}-{suffix}", std::process::id()));
        let store = WindowsCredentialSecretStore::new();

        // Best-effort pre-clean and guaranteed cleanup keep the fixture scoped
        // to its unique synthetic target even if a prior assertion failed.
        let _ = store.delete(&key);
        struct Cleanup<'a>(&'a WindowsCredentialSecretStore, &'a SecretKey);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.0.delete(self.1);
            }
        }
        let _cleanup = Cleanup(&store, &key);

        assert!(store.read(&key).unwrap().is_none());
        store
            .write(&key, &SecretValue::new(b"synthetic-first".to_vec()))
            .unwrap();
        let restarted_store = WindowsCredentialSecretStore::new();
        assert_eq!(
            restarted_store.read(&key).unwrap().unwrap().expose(),
            b"synthetic-first"
        );
        store
            .write(&key, &SecretValue::new(b"synthetic-second".to_vec()))
            .unwrap();
        assert_eq!(
            store.read(&key).unwrap().unwrap().expose(),
            b"synthetic-second"
        );
        assert!(store.delete(&key).unwrap());
        assert!(store.read(&key).unwrap().is_none());
    }
}
