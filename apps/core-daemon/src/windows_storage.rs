use std::ffi::{OsStr, c_void};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

pub const DATABASE_FILE_NAME: &str = "stein.db";

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: each value wrapped here was allocated by a Windows API
            // whose documented matching release function is LocalFree.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub fn prepare_repository_path(owner_sid: &str) -> io::Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the current-user local application-data directory is unavailable",
        )
    })?;
    let local_app_data = PathBuf::from(local_app_data);
    if !local_app_data.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the current-user local application-data directory is invalid",
        ));
    }
    prepare_repository_at(&local_app_data, owner_sid)
}

pub fn verify_repository_artifacts(database: &Path, owner_sid: &str) -> io::Result<()> {
    if database.file_name() != Some(OsStr::new(DATABASE_FILE_NAME)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the STEIN repository path is not canonical",
        ));
    }
    let data_directory = database.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the STEIN repository directory is unavailable",
        )
    })?;
    ensure_directory(data_directory)?;
    apply_and_verify_private_dacl(data_directory, owner_sid, true)?;
    protect_existing_children(data_directory, owner_sid)
}

fn prepare_repository_at(local_app_data: &Path, owner_sid: &str) -> io::Result<PathBuf> {
    let stein_root = local_app_data.join("STEIN");
    ensure_directory(&stein_root)?;
    apply_and_verify_private_dacl(&stein_root, owner_sid, true)?;

    let data_directory = stein_root.join("data");
    ensure_directory(&data_directory)?;
    apply_and_verify_private_dacl(&data_directory, owner_sid, true)?;
    protect_existing_children(&data_directory, owner_sid)?;

    let database = data_directory.join(DATABASE_FILE_NAME);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&database)
    {
        Ok(file) => drop(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    ensure_plain_file(&database)?;
    apply_and_verify_private_dacl(&database, owner_sid, false)?;
    Ok(database)
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a protected STEIN data directory is not a plain directory",
        ));
    }
    Ok(())
}

fn ensure_plain_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a protected STEIN data artifact is not a plain file",
        ));
    }
    Ok(())
}

fn protect_existing_children(directory: &Path, owner_sid: &str) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        ensure_plain_file(&path)?;
        apply_and_verify_private_dacl(&path, owner_sid, false)?;
    }
    Ok(())
}

fn apply_and_verify_private_dacl(path: &Path, owner_sid: &str, directory: bool) -> io::Result<()> {
    let inheritance = if directory { "OICI" } else { "" };
    let descriptor_text = format!("D:P(A;{inheritance};FA;;;{owner_sid})");
    let descriptor_text = wide_nul(OsStr::new(&descriptor_text))?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the SDDL buffer is NUL terminated and both output pointers are
    // writable. The returned allocation is owned by `descriptor` below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor_allocation` owns a valid self-relative security
    // descriptor for the duration of this call and output pointers are valid.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor_allocation.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(io::Error::last_os_error());
    }

    let path = wide_nul(path.as_os_str())?;
    // SAFETY: the path and descriptor remain live and NUL terminated. The DACL
    // pointer refers into the live descriptor allocation and no owner/group/SACL
    // update is requested.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    verify_private_dacl(path.as_slice(), owner_sid, directory)
}

fn verify_private_dacl(path: &[u16], owner_sid: &str, directory: bool) -> io::Result<()> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the path is NUL terminated, all requested output pointers are
    // writable, and the returned descriptor is released below with LocalFree.
    let result = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(private_acl_error());
    }

    let owner_sid = wide_nul(OsStr::new(owner_sid))?;
    let mut expected_owner: PSID = ptr::null_mut();
    // SAFETY: the SID string is NUL terminated and the output pointer is valid.
    if unsafe { ConvertStringSidToSidW(owner_sid.as_ptr(), &mut expected_owner) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let expected_owner_allocation = LocalAllocation(expected_owner);
    // SAFETY: both SID pointers remain live for this comparison.
    if unsafe { EqualSid(owner, expected_owner_allocation.0) } == 0 {
        return Err(private_acl_error());
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the security descriptor is live and outputs are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor_allocation.0, &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(private_acl_error());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the live descriptor and the information buffer
    // has the exact size required for AclSizeInformation.
    if unsafe {
        GetAclInformation(
            dacl,
            ptr::addr_of_mut!(information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(private_acl_error());
    }

    let mut raw_ace: *mut c_void = ptr::null_mut();
    // SAFETY: the verified ACL contains exactly one ACE and the output pointer
    // is writable. The ACE remains owned by the live descriptor.
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(private_acl_error());
    }
    // SAFETY: GetAce returned a pointer to the first ACE; its type is checked
    // before any fields beyond the common header are trusted.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let expected_flags = if directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || ace.Header.AceFlags != expected_flags
        || ace.Mask != FILE_ALL_ACCESS
    {
        return Err(private_acl_error());
    }
    let ace_sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
    // SAFETY: ACCESS_ALLOWED_ACE stores its SID starting at SidStart, and both
    // allocations remain live for the comparison.
    if unsafe { EqualSid(ace_sid, expected_owner_allocation.0) } == 0 {
        return Err(private_acl_error());
    }
    Ok(())
}

fn wide_nul(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a Windows path or identity contains an embedded NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

fn private_acl_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "a STEIN data artifact is not restricted to its owning Windows user",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_path_and_existing_artifacts_receive_exact_private_acls() {
        let temporary = tempfile::tempdir().unwrap();
        let owner_sid = stein_ipc::current_user_sid().unwrap();
        let data = temporary.path().join("STEIN").join("data");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("stein.db.recovery"), b"synthetic").unwrap();

        let path = prepare_repository_at(temporary.path(), &owner_sid).unwrap();

        assert_eq!(path, data.join(DATABASE_FILE_NAME));
        verify_private_dacl(&wide_nul(path.as_os_str()).unwrap(), &owner_sid, false).unwrap();
        verify_private_dacl(&wide_nul(data.as_os_str()).unwrap(), &owner_sid, true).unwrap();
        verify_private_dacl(
            &wide_nul(data.join("stein.db.recovery").as_os_str()).unwrap(),
            &owner_sid,
            false,
        )
        .unwrap();
    }

    #[test]
    fn non_directory_data_paths_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let owner_sid = stein_ipc::current_user_sid().unwrap();
        fs::create_dir(temporary.path().join("STEIN")).unwrap();
        fs::write(
            temporary.path().join("STEIN").join("data"),
            b"not a directory",
        )
        .unwrap();

        let error = prepare_repository_at(temporary.path(), &owner_sid).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
