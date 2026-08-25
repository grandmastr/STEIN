use std::{
    ffi::OsString,
    ffi::c_void,
    fs::File,
    io::Read,
    mem::{align_of, size_of},
    os::windows::ffi::OsStringExt,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    path::PathBuf,
    ptr::{NonNull, null_mut},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
        LocalFree,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, SDDL_REVISION_1,
        },
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        FreeSid, GetTokenInformation, IsValidSid,
        Isolation::DeriveAppContainerSidFromAppContainerName,
        PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_APPCONTAINER_INFORMATION,
        TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenIsAppContainer, TokenUser,
    },
    Storage::Packaging::Appx::{
        APPLICATION_USER_MODEL_ID_MAX_LENGTH, GetApplicationUserModelIdFromToken,
        GetPackageFamilyName, GetPackageFamilyNameFromToken, PACKAGE_FAMILY_NAME_MAX_LENGTH,
        VerifyApplicationUserModelId, VerifyPackageFamilyName,
    },
    System::{
        Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient},
        Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    },
};

use crate::{
    AdmissionError, AdmissionErrorKind, ExpectedCoreServer, ExpectedPackageIdentity,
    PackagePeerClass,
};

const MAXIMUM_CORE_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAXIMUM_PROCESS_IMAGE_UTF16: usize = 32_768;

/// Security descriptor for CORE's private AppContainer named-pipe endpoint.
///
/// The DACL contains only the owning user and the exact package SID. The low
/// mandatory label lets the low-integrity AppContainer exercise the DACL; it
/// does not grant access by itself. Every accepted handle is still subjected to
/// the kernel-token proof in [`crate::admit_named_pipe_peer`].
pub struct PrivatePipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl std::fmt::Debug for PrivatePipeSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivatePipeSecurity([redacted])")
    }
}

impl PrivatePipeSecurity {
    pub fn new(expected: &ExpectedPackageIdentity) -> Result<Self, AdmissionError> {
        let descriptor = security_descriptor_sddl(expected);
        let descriptor = wide(&descriptor);
        let mut native = null_mut();
        // SAFETY: the SDDL is NUL-terminated and `native` is a writable output
        // pointer. The returned descriptor uses LocalAlloc ownership.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut native,
                null_mut(),
            )
        } == 0
            || native.is_null()
        {
            return Err(invalid_configuration());
        }
        Ok(Self { descriptor: native })
    }

    /// Returns security attributes borrowing this descriptor. The caller must
    /// keep `self` alive through the synchronous named-pipe creation call.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PrivatePipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: the SDDL conversion allocated this descriptor with
            // LocalAlloc and this wrapper owns it exclusively.
            unsafe { LocalFree(self.descriptor) };
        }
    }
}

fn security_descriptor_sddl(expected: &ExpectedPackageIdentity) -> String {
    // The AppContainer access check intersects the user's and package's grants;
    // both principals therefore receive only the access needed for a duplex
    // pipe. `P` protects the DACL from inherited broad grants. `LW` is required
    // for a low-integrity AppContainer to write; the exact DACL remains the
    // discretionary admission boundary.
    format!(
        "D:P(A;;GRGW;;;{})(A;;GRGW;;;{})S:(ML;;NW;;;LW)",
        expected.owner_sid, expected.app_container_sid
    )
}

pub(crate) fn expected_identity(
    owner_sid: String,
    package_family_name: String,
    app_user_model_id: String,
) -> Result<ExpectedPackageIdentity, AdmissionError> {
    validate_sid_text(&owner_sid)?;
    validate_package_identity(&package_family_name, &app_user_model_id)?;
    let app_container_sid = derive_app_container_sid(&package_family_name)?;
    Ok(ExpectedPackageIdentity::from_validated_parts(
        owner_sid,
        package_family_name,
        app_user_model_id,
        app_container_sid,
    ))
}

pub(crate) fn expected_core_server(
    owner_sid: String,
    executable_sha256: [u8; 32],
) -> Result<ExpectedCoreServer, AdmissionError> {
    validate_sid_text(&owner_sid)?;
    if executable_sha256.iter().all(|byte| *byte == 0) {
        return Err(invalid_configuration());
    }
    Ok(ExpectedCoreServer {
        owner_sid,
        executable_sha256,
    })
}

fn validate_package_identity(
    package_family_name: &str,
    app_user_model_id: &str,
) -> Result<(), AdmissionError> {
    if package_family_name.is_empty()
        || app_user_model_id.is_empty()
        || package_family_name.encode_utf16().count() + 1 > PACKAGE_FAMILY_NAME_MAX_LENGTH as usize
        || app_user_model_id.encode_utf16().count() + 1
            > APPLICATION_USER_MODEL_ID_MAX_LENGTH as usize
        || package_family_name.contains('\0')
        || app_user_model_id.contains('\0')
    {
        return Err(invalid_configuration());
    }

    let family = wide(package_family_name);
    let application = wide(app_user_model_id);
    // SAFETY: both buffers are NUL-terminated and remain live for these
    // validation calls. These APIs perform no writes through their pointers.
    let family_result = unsafe { VerifyPackageFamilyName(family.as_ptr()) };
    // SAFETY: see above.
    let application_result = unsafe { VerifyApplicationUserModelId(application.as_ptr()) };
    if family_result != ERROR_SUCCESS || application_result != ERROR_SUCCESS {
        return Err(invalid_configuration());
    }

    let required_prefix = format!("{package_family_name}!");
    if !app_user_model_id.starts_with(&required_prefix)
        || app_user_model_id.len() == required_prefix.len()
    {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn validate_sid_text(value: &str) -> Result<(), AdmissionError> {
    let _sid = sid_from_text(value)?;
    Ok(())
}

fn derive_app_container_sid(package_family_name: &str) -> Result<String, AdmissionError> {
    let package_family_name = wide(package_family_name);
    let mut sid = null_mut();
    // SAFETY: input is a live NUL-terminated PFN and `sid` is a writable output
    // pointer. The API allocates the returned SID with FreeSid ownership.
    let result = unsafe {
        DeriveAppContainerSidFromAppContainerName(package_family_name.as_ptr(), &mut sid)
    };
    if result < 0 || sid.is_null() {
        return Err(invalid_configuration());
    }
    let sid = OwnedFreeSid(sid);
    sid_to_text(sid.0)
}

pub(crate) fn verify_named_pipe_peer(
    pipe: BorrowedHandle<'_>,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
) -> Result<(), AdmissionError> {
    let pipe = pipe.as_raw_handle() as HANDLE;
    // SAFETY: the borrowed handle remains live for this call and must be a
    // connected server-side named-pipe endpoint by the public API contract.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(boundary_unavailable());
    }
    let guard = ImpersonationGuard;

    let mut token = null_mut();
    // SAFETY: the current thread is impersonating the connected pipe peer;
    // `token` is writable and requests query-only access.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        guard.revert_or_abort();
        return Err(boundary_unavailable());
    }
    let token = OwnedHandle(token);

    let result = verify_token(token.0, expected, class);
    guard.revert_or_abort();
    result
}

pub(crate) fn verify_core_pipe_server(
    pipe: BorrowedHandle<'_>,
    expected: &ExpectedCoreServer,
) -> Result<(), AdmissionError> {
    let pipe = pipe.as_raw_handle() as HANDLE;
    let mut first_pid = 0_u32;
    // SAFETY: the borrowed handle is a connected client-side named pipe and
    // `first_pid` is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut first_pid) } == 0 || first_pid == 0 {
        return Err(boundary_unavailable());
    }

    // SAFETY: the PID came from the kernel pipe endpoint and only query access
    // is requested.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, first_pid) };
    if process.is_null() {
        return Err(boundary_unavailable());
    }
    let process = OwnedHandle(process);

    let mut token = null_mut();
    // SAFETY: `token` is writable and the live process handle has query access.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(boundary_unavailable());
    }
    let token = OwnedHandle(token);
    let user = token_information(token.0, TokenUser)?;
    let user = user.read::<TOKEN_USER>()?;
    // SAFETY: the nested SID is backed by the live token-information buffer.
    let user_sid = unsafe { (*user).User.Sid };
    if user_sid.is_null() || unsafe { IsValidSid(user_sid) } == 0 {
        return Err(boundary_unavailable());
    }
    if sid_to_text(user_sid)? != expected.owner_sid {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongUser));
    }
    if token_u32(token.0, TokenIsAppContainer)? != 0 {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongExecutionClass));
    }

    let mut package_length = 0_u32;
    // SAFETY: this is the package-identity sizing call and length is writable.
    // CORE is intentionally unpackaged; any package identity is rejected.
    if unsafe { GetPackageFamilyName(process.0, &mut package_length, null_mut()) }
        != APPMODEL_ERROR_NO_PACKAGE
    {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongExecutionClass));
    }

    let path = process_image_path(process.0)?;
    let digest = digest_file(&path)?;
    if !constant_time_digest_equal(&digest, &expected.executable_sha256) {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongCoreImage));
    }

    let mut second_pid = 0_u32;
    // Re-read the kernel-owned pipe endpoint after verification to close the
    // observable PID-reuse/process-replacement race.
    // SAFETY: same live pipe handle and writable output as the first call.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut second_pid) } == 0 || second_pid != first_pid
    {
        return Err(AdmissionError::new(AdmissionErrorKind::BoundaryChanged));
    }
    Ok(())
}

pub(crate) fn verify_package_pipe_server(
    pipe: BorrowedHandle<'_>,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
) -> Result<(), AdmissionError> {
    let pipe = pipe.as_raw_handle() as HANDLE;
    let mut first_pid = 0_u32;
    // SAFETY: the borrowed handle is a connected client-side named pipe and
    // `first_pid` is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut first_pid) } == 0 || first_pid == 0 {
        return Err(boundary_unavailable());
    }

    // SAFETY: the PID is kernel-derived and only query access is requested.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, first_pid) };
    if process.is_null() {
        return Err(boundary_unavailable());
    }
    let process = OwnedHandle(process);
    let token = open_process_token(process.0)?;
    verify_token(token.0, expected, class)?;

    let mut second_pid = 0_u32;
    // SAFETY: same live pipe handle and writable output as the first call.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut second_pid) } == 0 || second_pid != first_pid
    {
        return Err(AdmissionError::new(AdmissionErrorKind::BoundaryChanged));
    }
    Ok(())
}

fn open_process_token(process: HANDLE) -> Result<OwnedHandle, AdmissionError> {
    let mut token = null_mut();
    // SAFETY: `token` is writable and the live process handle has query access.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return Err(boundary_unavailable());
    }
    Ok(OwnedHandle(token))
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, AdmissionError> {
    let mut buffer = vec![0_u16; MAXIMUM_PROCESS_IMAGE_UTF16];
    let mut length = buffer.len() as u32;
    // SAFETY: the process handle has query access and `buffer` exposes `length`
    // writable UTF-16 elements.
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0
        || length == 0
        || length as usize >= buffer.len()
        || buffer[..length as usize].contains(&0)
    {
        return Err(boundary_unavailable());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn digest_file(path: &PathBuf) -> Result<[u8; 32], AdmissionError> {
    let mut file =
        File::open(path).map_err(|_| AdmissionError::new(AdmissionErrorKind::WrongCoreImage))?;
    let metadata = file
        .metadata()
        .map_err(|_| AdmissionError::new(AdmissionErrorKind::WrongCoreImage))?;
    if metadata.len() == 0 || metadata.len() > MAXIMUM_CORE_IMAGE_BYTES {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongCoreImage));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AdmissionError::new(AdmissionErrorKind::WrongCoreImage))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| AdmissionError::new(AdmissionErrorKind::WrongCoreImage))?;
        if total > MAXIMUM_CORE_IMAGE_BYTES {
            return Err(AdmissionError::new(AdmissionErrorKind::WrongCoreImage));
        }
        hasher.update(&buffer[..read]);
    }
    buffer.fill(0);
    if total != metadata.len() {
        return Err(AdmissionError::new(AdmissionErrorKind::BoundaryChanged));
    }
    Ok(hasher.finalize().into())
}

fn constant_time_digest_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn verify_token(
    token: HANDLE,
    expected: &ExpectedPackageIdentity,
    class: PackagePeerClass,
) -> Result<(), AdmissionError> {
    let user = token_information(token, TokenUser)?;
    let user = user.read::<TOKEN_USER>()?;
    // SAFETY: the TOKEN_USER and nested SID remain backed by `user` and are
    // validated before conversion.
    let user_sid = unsafe { (*user).User.Sid };
    if user_sid.is_null() || unsafe { IsValidSid(user_sid) } == 0 {
        return Err(boundary_unavailable());
    }
    if sid_to_text(user_sid)? != expected.owner_sid {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongUser));
    }

    let is_app_container = token_u32(token, TokenIsAppContainer)? != 0;
    match class {
        PackagePeerClass::AppContainerBroker if !is_app_container => {
            return Err(AdmissionError::new(AdmissionErrorKind::WrongExecutionClass));
        }
        PackagePeerClass::PackagedDesktop | PackagePeerClass::BrowserObservationProducer
            if is_app_container =>
        {
            return Err(AdmissionError::new(AdmissionErrorKind::WrongExecutionClass));
        }
        PackagePeerClass::AppContainerBroker
        | PackagePeerClass::PackagedDesktop
        | PackagePeerClass::BrowserObservationProducer => {}
    }

    if is_app_container {
        let app_container = token_information(token, TokenAppContainerSid)?;
        let app_container = app_container.read::<TOKEN_APPCONTAINER_INFORMATION>()?;
        // SAFETY: the nested SID is backed by the live token-information
        // buffer and is validated before conversion.
        let app_container_sid = unsafe { (*app_container).TokenAppContainer };
        if app_container_sid.is_null() || unsafe { IsValidSid(app_container_sid) } == 0 {
            return Err(boundary_unavailable());
        }
        if sid_to_text(app_container_sid)? != expected.app_container_sid {
            return Err(AdmissionError::new(AdmissionErrorKind::WrongAppContainer));
        }
    }

    let package_family = query_token_identity(
        token,
        GetPackageFamilyNameFromToken,
        PACKAGE_FAMILY_NAME_MAX_LENGTH,
        AdmissionErrorKind::WrongPackage,
    )?;
    if package_family != expected.package_family_name {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongPackage));
    }

    let application_id = query_token_identity(
        token,
        GetApplicationUserModelIdFromToken,
        APPLICATION_USER_MODEL_ID_MAX_LENGTH,
        AdmissionErrorKind::WrongApplication,
    )?;
    if application_id != expected.app_user_model_id {
        return Err(AdmissionError::new(AdmissionErrorKind::WrongApplication));
    }

    Ok(())
}

pub(crate) fn current_process_user_sid() -> Result<String, AdmissionError> {
    // SAFETY: GetCurrentProcess returns a live pseudo-handle and the token is
    // immediately wrapped with exclusive ownership on success.
    let process = unsafe { GetCurrentProcess() };
    let mut token = null_mut();
    // SAFETY: `token` is writable and only query access is requested.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(boundary_unavailable());
    }
    let token = OwnedHandle(token);
    let user = token_information(token.0, TokenUser)?;
    let user = user.read::<TOKEN_USER>()?;
    // SAFETY: the TOKEN_USER and nested SID remain backed by `user` here.
    let sid = unsafe { (*user).User.Sid };
    sid_to_text(sid)
}

type TokenIdentityQuery = unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32;

fn query_token_identity(
    token: HANDLE,
    query: TokenIdentityQuery,
    maximum_length: u32,
    mismatch: AdmissionErrorKind,
) -> Result<String, AdmissionError> {
    let mut length = 0_u32;
    // SAFETY: this is the documented sizing call and `length` is writable.
    let sizing_result = unsafe { query(token, &mut length, null_mut()) };
    if sizing_result != ERROR_INSUFFICIENT_BUFFER || length < 2 || length > maximum_length {
        return Err(AdmissionError::new(mismatch));
    }

    let mut value = vec![0_u16; length as usize];
    let mut written = length;
    // SAFETY: `value` contains `length` writable UTF-16 elements and the token
    // remains live with TOKEN_QUERY access.
    let result = unsafe { query(token, &mut written, value.as_mut_ptr()) };
    if result != ERROR_SUCCESS
        || written != length
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        return Err(AdmissionError::new(mismatch));
    }
    String::from_utf16(&value[..value.len() - 1]).map_err(|_| AdmissionError::new(mismatch))
}

pub(crate) fn random_authority() -> Result<[u8; 32], AdmissionError> {
    let mut authority = [0_u8; 32];
    // SAFETY: `authority` is a live writable buffer; a null algorithm handle is
    // required with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            authority.as_mut_ptr(),
            authority.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || authority.iter().all(|byte| *byte == 0) {
        authority.fill(0);
        return Err(AdmissionError::new(
            AdmissionErrorKind::RandomnessUnavailable,
        ));
    }
    Ok(authority)
}

fn token_u32(token: HANDLE, information_class: i32) -> Result<u32, AdmissionError> {
    let buffer = token_information(token, information_class)?;
    let value = buffer.read::<u32>()?;
    // SAFETY: `value` points to an aligned u32 fully contained by `buffer`.
    Ok(unsafe { *value })
}

fn token_information(
    token: HANDLE,
    information_class: i32,
) -> Result<AlignedBuffer, AdmissionError> {
    let mut required = 0_u32;
    // SAFETY: the null-buffer call obtains the required byte count.
    unsafe {
        GetTokenInformation(token, information_class, null_mut(), 0, &mut required);
    }
    if required == 0 || required > 64 * 1024 {
        return Err(boundary_unavailable());
    }
    let mut buffer = AlignedBuffer::new(required as usize);
    let mut written = required;
    // SAFETY: `buffer` is aligned and contains at least `required` writable
    // bytes; the token remains live for this synchronous call.
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
        return Err(boundary_unavailable());
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
        let words = bytes.div_ceil(size_of::<usize>());
        Self {
            words: vec![0; words],
            written: 0,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn read<T>(&self) -> Result<*const T, AdmissionError> {
        if self.written < size_of::<T>()
            || !(self.words.as_ptr() as usize).is_multiple_of(align_of::<T>())
        {
            return Err(boundary_unavailable());
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

struct OwnedLocalSid(NonNull<c_void>);

impl Drop for OwnedLocalSid {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSidToSidW allocated this pointer with LocalAlloc.
        unsafe { LocalFree(self.0.as_ptr()) };
    }
}

struct OwnedFreeSid(*mut c_void);

impl Drop for OwnedFreeSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: DeriveAppContainerSidFromAppContainerName allocated this
            // SID and documents FreeSid ownership.
            unsafe { FreeSid(self.0) };
        }
    }
}

struct ImpersonationGuard;

impl ImpersonationGuard {
    fn revert_or_abort(self) {
        // A thread that cannot leave client impersonation must not continue
        // running CORE or the broker under the client's security context.
        // SAFETY: the current thread is impersonating the pipe client.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        std::mem::forget(self);
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: this is the emergency unwind path. Continuing after failure
        // would retain attacker-controlled impersonation, so abort instead.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn sid_from_text(value: &str) -> Result<OwnedLocalSid, AdmissionError> {
    if value.is_empty() || value.len() > 256 || value.contains('\0') {
        return Err(invalid_configuration());
    }
    let value = wide(value);
    let mut sid = null_mut();
    // SAFETY: `value` is NUL-terminated and `sid` is a writable output pointer.
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) } == 0 {
        return Err(invalid_configuration());
    }
    let sid = NonNull::new(sid).ok_or_else(invalid_configuration)?;
    // SAFETY: ConvertStringSidToSidW returned this SID.
    if unsafe { IsValidSid(sid.as_ptr()) } == 0 {
        // Preserve ownership so the invalid allocation is still freed.
        drop(OwnedLocalSid(sid));
        return Err(invalid_configuration());
    }
    Ok(OwnedLocalSid(sid))
}

fn sid_to_text(sid: *mut c_void) -> Result<String, AdmissionError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(boundary_unavailable());
    }
    let mut text = null_mut();
    // SAFETY: `sid` is valid for the call and `text` is a writable output
    // pointer. The returned string uses LocalAlloc ownership.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(boundary_unavailable());
    }
    let text = NonNull::new(text).ok_or_else(boundary_unavailable)?;
    let owned = OwnedLocalSid(text.cast());
    let mut length = 0_usize;
    // SAFETY: ConvertSidToStringSidW returned a NUL-terminated UTF-16 string.
    unsafe {
        while *text.as_ptr().add(length) != 0 {
            length += 1;
            if length > 256 {
                return Err(boundary_unavailable());
            }
        }
    }
    // SAFETY: the scan found the terminating NUL within the defensive bound.
    let value = unsafe { std::slice::from_raw_parts(text.as_ptr(), length) };
    let result = String::from_utf16(value).map_err(|_| boundary_unavailable());
    drop(owned);
    result
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

const fn invalid_configuration() -> AdmissionError {
    AdmissionError::new(AdmissionErrorKind::InvalidConfiguration)
}

const fn boundary_unavailable() -> AdmissionError {
    AdmissionError::new(AdmissionErrorKind::BoundaryUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::BorrowedHandle;

    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn package_identity_requires_matching_family_prefix() {
        let error = validate_package_identity(
            "Stein.Test_1234567890abc",
            "Different.Test_1234567890abc!Desktop",
        )
        .expect_err("mismatched AUMID must fail");
        assert_eq!(error.kind(), AdmissionErrorKind::InvalidConfiguration);
    }

    #[test]
    fn app_container_sid_is_derived_from_a_valid_family() {
        let identity = expected_identity(
            "S-1-5-21-1-2-3-1001".to_owned(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe".to_owned(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App".to_owned(),
        )
        .expect("valid package identity");
        assert!(identity.app_container_sid.starts_with("S-1-15-2-"));
        assert_ne!(identity.app_container_sid, identity.owner_sid);
    }

    #[test]
    fn private_pipe_descriptor_names_only_owner_and_exact_package() {
        let identity = expected_identity(
            "S-1-5-21-1-2-3-1001".to_owned(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe".to_owned(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App".to_owned(),
        )
        .expect("valid package identity");
        let sddl = security_descriptor_sddl(&identity);
        assert!(sddl.contains(&identity.owner_sid));
        assert!(sddl.contains(&identity.app_container_sid));
        assert!(!sddl.contains(";;;AC"));
        assert!(!sddl.contains(";;;WD"));
        assert!(sddl.ends_with("S:(ML;;NW;;;LW)"));
        let descriptor = PrivatePipeSecurity::new(&identity).expect("valid native descriptor");
        assert!(!descriptor.attributes().lpSecurityDescriptor.is_null());
    }

    #[test]
    fn authority_uses_system_rng() {
        let first = random_authority().expect("system RNG");
        let second = random_authority().expect("system RNG");
        assert_ne!(first, second);
        assert!(first.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn core_identity_rejects_an_unpinned_digest() {
        let error = expected_core_server("S-1-5-21-1-2-3-1001".to_owned(), [0; 32])
            .expect_err("an all-zero digest cannot pin CORE");
        assert_eq!(error.kind(), AdmissionErrorKind::InvalidConfiguration);
    }

    #[test]
    fn core_image_digest_covers_the_exact_executable() {
        let executable = std::env::current_exe().expect("test executable path");
        let first = digest_file(&executable).expect("digest current test executable");
        let second = digest_file(&executable).expect("repeat digest");
        assert!(constant_time_digest_equal(&first, &second));
        let mut changed = second;
        changed[31] ^= 1;
        assert!(!constant_time_digest_equal(&first, &changed));
    }

    #[tokio::test]
    async fn kernel_pipe_tokens_reject_unpacked_client_and_pin_core_server() {
        let nonce = random_authority().expect("pipe nonce");
        let suffix: String = nonce[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name = format!(
            r"\\.\pipe\LOCAL\stein-broker-native-{}-{suffix}",
            std::process::id()
        );
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)
            .expect("create test server");
        let client = ClientOptions::new()
            .open(&name)
            .expect("connect test client");
        server.connect().await.expect("accept test client");

        // SAFETY: these Tokio pipe objects own their handles for the entire
        // verification calls below.
        let server_handle = unsafe { BorrowedHandle::borrow_raw(server.as_raw_handle()) };
        // SAFETY: same as above for the client-side handle.
        let client_handle = unsafe { BorrowedHandle::borrow_raw(client.as_raw_handle()) };

        // SAFETY: GetCurrentProcess returns a pseudo-handle valid for token
        // queries in this process.
        let token = open_process_token(unsafe { GetCurrentProcess() }).expect("current token");
        let user = token_information(token.0, TokenUser).expect("token user");
        let user = user.read::<TOKEN_USER>().expect("TOKEN_USER");
        // SAFETY: the SID remains backed by the live token-information buffer.
        let owner = sid_to_text(unsafe { (*user).User.Sid }).expect("current owner SID");

        let package = expected_identity(
            owner.clone(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe".to_owned(),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App".to_owned(),
        )
        .expect("valid expected package");
        let rejection =
            verify_named_pipe_peer(server_handle, &package, PackagePeerClass::PackagedDesktop)
                .expect_err("an unpackaged same-user client must not be admitted");
        assert_eq!(rejection.kind(), AdmissionErrorKind::WrongPackage);

        let executable = std::env::current_exe().expect("test executable path");
        let core = expected_core_server(
            owner,
            digest_file(&executable).expect("pinned test executable"),
        )
        .expect("valid CORE pin");
        verify_core_pipe_server(client_handle, &core).expect("exact server binary is accepted");
    }
}
