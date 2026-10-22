// SPDX-License-Identifier: Apache-2.0 OR MIT

use landlock::Errno;
use landlock_policy::{Policy, PolicyFormat};
use libc::c_char;
use std::ffi::{c_int, CStr};
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::unix::io::{BorrowedFd, IntoRawFd, OwnedFd, RawFd};

fn unwrap_errno<T>(err: T) -> c_int
where
    T: Into<Errno>,
{
    let mut errno = *err.into();
    // TODO: Filter all error codes to document them, see libseccomp's _rc_filter().
    if errno <= 0 {
        // This should never happen.
        eprintln!("Error: Invalid errno value: {errno}");
        errno = libc::EIO;
    }
    -errno
}

/// Convert std::io::Error to Errno while preserving raw OS error codes.
/// This ensures that errno values like ENOTDIR and ENOENT are preserved correctly.
///
/// TODO: Remove once From<Error> for Errno is fixed in the Landlock crate.
fn io_error_to_errno(err: Error) -> Errno {
    match err.raw_os_error() {
        Some(errno) => Errno::new(errno),
        None => Errno::from(err),
    }
}

fn parse_file<F>(policy_fd: RawFd, flags: u32, parser: F) -> Result<*mut Policy, Errno>
where
    F: FnOnce(File) -> Result<Policy, Error>,
{
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    let fd = unsafe { BorrowedFd::borrow_raw(policy_fd) };
    // Checks if it is a valid file descriptor.
    let file = File::from(fd.try_clone_to_owned()?);
    Ok(Box::into_raw(Box::new(parser(file)?)))
}

// TODO: Pass a set of buffers for warnings and errors.

// TODO: Return NULL if the ruleset is not supported.

// TODO: Add a flag to accept unknown JSON entries (e.g. for OCI specification).

/// Parses a JSON policy file
///
/// # Parameters
///
/// * `policy_fd`: A file descriptor referring to a JSON policy file.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_json_file(policy_fd: RawFd, flags: u32) -> *mut Policy {
    parse_file(policy_fd, flags, |file| {
        Policy::parse_json(file).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

/// Parses a TOML policy file
///
/// # Parameters
///
/// * `policy_fd`: A file descriptor referring to a TOML policy file.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_toml_file(policy_fd: RawFd, flags: u32) -> *mut Policy {
    parse_file(policy_fd, flags, |mut file| {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut file, &mut buffer)?;
        Policy::parse_toml(&buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

fn parse_buffer<F>(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
    parser: F,
) -> Result<*mut Policy, Errno>
where
    F: FnOnce(&[u8]) -> Result<Policy, Error>,
{
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    if buffer_ptr.is_null() {
        return Err(Errno::new(libc::EFAULT));
    }

    let buffer = if buffer_size == 0 {
        // Treat 0-sized buffer as null-terminated string.
        let c_str = unsafe { std::ffi::CStr::from_ptr(buffer_ptr as *const std::ffi::c_char) };
        c_str.to_bytes()
    } else {
        unsafe { std::slice::from_raw_parts(buffer_ptr, buffer_size) }
    };

    let policy = parser(buffer).map_err(Errno::from)?;
    Ok(Box::into_raw(Box::new(policy)))
}

/// Parses a JSON policy from a memory buffer
///
/// # Parameters
///
/// * `buffer_ptr`: Pointer to the buffer containing JSON data.
/// * `buffer_size`: Size of the buffer in bytes, or 0 if `buffer_ptr` is null-terminated.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_json_buffer(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
) -> *mut Policy {
    parse_buffer(buffer_ptr, buffer_size, flags, |buffer| {
        Policy::parse_json(std::io::Cursor::new(buffer))
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

/// Parses a TOML policy from a memory buffer
///
/// # Parameters
///
/// * `buffer_ptr`: Pointer to the buffer containing TOML data.
/// * `buffer_size`: Size of the buffer in bytes, or 0 if `buffer_ptr` is null-terminated.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_toml_buffer(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
) -> *mut Policy {
    parse_buffer(buffer_ptr, buffer_size, flags, |buffer| {
        let data =
            std::str::from_utf8(buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Policy::parse_toml(data).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

fn parse_directory(
    dir_path: *const c_char,
    flags: u32,
    format: PolicyFormat,
) -> Result<*mut Policy, Errno> {
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    if dir_path.is_null() {
        return Err(Errno::new(libc::EFAULT));
    }

    let path = unsafe { CStr::from_ptr(dir_path) }.to_str()?;
    let policy =
        Policy::parse_directory(path, format).map_err(|e| io_error_to_errno(Error::from(e)))?;
    Ok(Box::into_raw(Box::new(policy)))
}

/// Parses all JSON policy files in a directory
///
/// # Parameters
///
/// * `dir_path`: A pointer to a null-terminated string containing the directory path.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_json_directory(
    dir_path: *const c_char,
    flags: u32,
) -> *mut Policy {
    parse_directory(dir_path, flags, PolicyFormat::Json)
        .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

/// Parses all TOML policy files in a directory
///
/// # Parameters
///
/// * `dir_path`: A pointer to a null-terminated string containing the directory path.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlock_policy object on success. This object must be freed
///   with landlock_policy_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlock_policy_parse_toml_directory(
    dir_path: *const c_char,
    flags: u32,
) -> *mut Policy {
    parse_directory(dir_path, flags, PolicyFormat::Toml)
        .unwrap_or_else(|e| unwrap_errno(e) as *mut Policy)
}

/// Frees a landlock_policy object
///
/// # Safety
///
/// The pointer must have been returned by landlock_policy_parse_*().
#[no_mangle]
pub unsafe extern "C" fn landlock_policy_free(policy: *mut Policy) {
    if !policy.is_null() {
        drop(Box::from_raw(policy));
    }
}

// TODO: Also return RestrictionStatus

/// Creates a ruleset from a landlock_policy object
///
/// # Parameters
///
/// * `policy`: A pointer to a landlock_policy object.
/// * `flags`: Must be 0.
///
/// # Safety
///
/// `policy` must have been returned by landlock_policy_parse_json() or
/// landlock_policy_parse_toml().
///
/// # Returns
///
/// * The ruleset file descriptor on success.
/// * -errno on error.
#[no_mangle]
pub unsafe extern "C" fn landlock_policy_build_ruleset(policy: *const Policy, flags: u32) -> RawFd {
    if flags != 0 {
        return unwrap_errno(Errno::new(libc::EINVAL));
    }

    if policy.is_null() {
        return unwrap_errno(Errno::new(libc::EFAULT));
    }

    // TODO: Avoid cloning the policy.
    let resolved = match unsafe { &*policy }.clone().resolve() {
        Ok(resolved) => resolved,
        Err(e) => return unwrap_errno(e),
    };
    resolved
        .build_ruleset()
        .map(|(r, _)| {
            let fd: Option<OwnedFd> = r.into();
            fd.map(|fd| fd.into_raw_fd()).unwrap_or(-1)
        })
        .unwrap_or_else(unwrap_errno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_parse_directory_enotdir() {
        let file_path =
            CString::new(std::env::current_exe().unwrap().as_path().to_str().unwrap()).unwrap();
        let result = parse_directory(file_path.as_ptr(), 0, PolicyFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::ENOTDIR);
    }

    #[test]
    fn test_parse_directory_null_path() {
        let result = parse_directory(std::ptr::null(), 0, PolicyFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::EFAULT);
    }

    #[test]
    fn test_parse_directory_invalid_flags() {
        let file_path =
            CString::new(std::env::current_exe().unwrap().as_path().to_str().unwrap()).unwrap();
        let result = parse_directory(file_path.as_ptr(), 1, PolicyFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::EINVAL);
    }

    #[test]
    fn test_parse_directory_nonexistent() {
        let nonexistent_path = CString::new("/nonexistent/directory/").unwrap();

        let result = parse_directory(nonexistent_path.as_ptr(), 0, PolicyFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::ENOENT);
    }
}
