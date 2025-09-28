// SPDX-License-Identifier: Apache-2.0 OR MIT

use landlock::Errno;
use landlockconfig::{Config, ConfigFormat};
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

fn parse_file<F>(config_fd: RawFd, flags: u32, parser: F) -> Result<*mut Config, Errno>
where
    F: FnOnce(File) -> Result<Config, Error>,
{
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    let fd = unsafe { BorrowedFd::borrow_raw(config_fd) };
    // Checks if it is a valid file descriptor.
    let file = File::from(fd.try_clone_to_owned()?);
    Ok(Box::into_raw(Box::new(parser(file)?)))
}

// TODO: Pass a set of buffers for warnings and errors.

// TODO: Return NULL if the ruleset is not supported.

// TODO: Add a flag to accept unknown JSON entries (e.g. for OCI specification).

/// Parses a JSON configuration file
///
/// # Parameters
///
/// * `config_fd`: A file descriptor referring to a JSON configuration file.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json_file(config_fd: RawFd, flags: u32) -> *mut Config {
    parse_file(config_fd, flags, |file| {
        Config::parse_json(file).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Parses a TOML configuration file
///
/// # Parameters
///
/// * `config_fd`: A file descriptor referring to a TOML configuration file.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml_file(config_fd: RawFd, flags: u32) -> *mut Config {
    parse_file(config_fd, flags, |mut file| {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut file, &mut buffer)?;
        Config::parse_toml(&buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

fn parse_buffer<F>(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
    parser: F,
) -> Result<*mut Config, Errno>
where
    F: FnOnce(&[u8]) -> Result<Config, Error>,
{
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    if buffer_ptr.is_null() {
        return Err(Errno::new(libc::EFAULT));
    }

    let buffer = if buffer_size == 0 {
        // Treat 0-sized buffer as null-terminated string.
        let c_str = unsafe { std::ffi::CStr::from_ptr(buffer_ptr as *const i8) };
        c_str.to_bytes()
    } else {
        unsafe { std::slice::from_raw_parts(buffer_ptr, buffer_size) }
    };

    let config = parser(buffer).map_err(Errno::from)?;
    Ok(Box::into_raw(Box::new(config)))
}

/// Parses a JSON configuration from a memory buffer
///
/// # Parameters
///
/// * `buffer_ptr`: Pointer to the buffer containing JSON data.
/// * `buffer_size`: Size of the buffer in bytes, or 0 if `buffer_ptr` is null-terminated.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json_buffer(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
) -> *mut Config {
    parse_buffer(buffer_ptr, buffer_size, flags, |buffer| {
        Config::parse_json(std::io::Cursor::new(buffer))
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Parses a TOML configuration from a memory buffer
///
/// # Parameters
///
/// * `buffer_ptr`: Pointer to the buffer containing TOML data.
/// * `buffer_size`: Size of the buffer in bytes, or 0 if `buffer_ptr` is null-terminated.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml_buffer(
    buffer_ptr: *const u8,
    buffer_size: usize,
    flags: u32,
) -> *mut Config {
    parse_buffer(buffer_ptr, buffer_size, flags, |buffer| {
        let data =
            std::str::from_utf8(buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Config::parse_toml(data).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

fn parse_directory(
    dir_path: *const c_char,
    flags: u32,
    format: ConfigFormat,
) -> Result<*mut Config, Errno> {
    if flags != 0 {
        return Err(Errno::new(libc::EINVAL));
    }

    if dir_path.is_null() {
        return Err(Errno::new(libc::EFAULT));
    }

    let path = unsafe { CStr::from_ptr(dir_path) }.to_str()?;
    let config =
        Config::parse_directory(path, format).map_err(|e| io_error_to_errno(Error::from(e)))?;
    Ok(Box::into_raw(Box::new(config)))
}

/// Parses all JSON configuration files in a directory
///
/// # Parameters
///
/// * `dir_path`: A pointer to a null-terminated string containing the directory path.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json_directory(
    dir_path: *const c_char,
    flags: u32,
) -> *mut Config {
    parse_directory(dir_path, flags, ConfigFormat::Json)
        .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Parses all TOML configuration files in a directory
///
/// # Parameters
///
/// * `dir_path`: A pointer to a null-terminated string containing the directory path.
/// * `flags`: Must be 0.
///
/// # Return values
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml_directory(
    dir_path: *const c_char,
    flags: u32,
) -> *mut Config {
    parse_directory(dir_path, flags, ConfigFormat::Toml)
        .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Frees a landlockconfig object
///
/// # Safety
///
/// The pointer must have been returned by landlockconfig_parse_*().
#[no_mangle]
pub unsafe extern "C" fn landlockconfig_free(config: *mut Config) {
    if !config.is_null() {
        drop(Box::from_raw(config));
    }
}

// TODO: Also return RestrictionStatus

/// Creates a ruleset from a landlockconfig object
///
/// # Parameters
///
/// * `config`: A pointer to a landlockconfig object.
/// * `flags`: Must be 0.
///
/// # Safety
///
/// `config` must have been returned by landlockconfig_parse_json() or
/// landlockconfig_parse_toml().
///
/// # Returns
///
/// * The ruleset file descriptor on success.
/// * -errno on error.
#[no_mangle]
pub unsafe extern "C" fn landlockconfig_build_ruleset(config: *const Config, flags: u32) -> RawFd {
    if flags != 0 {
        return unwrap_errno(Errno::new(libc::EINVAL));
    }

    if config.is_null() {
        return unwrap_errno(Errno::new(libc::EFAULT));
    }

    // TODO: Avoid cloning the config.
    let resolved = match unsafe { &*config }.clone().resolve() {
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
        let result = parse_directory(file_path.as_ptr(), 0, ConfigFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::ENOTDIR);
    }

    #[test]
    fn test_parse_directory_null_path() {
        let result = parse_directory(std::ptr::null(), 0, ConfigFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::EFAULT);
    }

    #[test]
    fn test_parse_directory_invalid_flags() {
        let file_path =
            CString::new(std::env::current_exe().unwrap().as_path().to_str().unwrap()).unwrap();
        let result = parse_directory(file_path.as_ptr(), 1, ConfigFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::EINVAL);
    }

    #[test]
    fn test_parse_directory_nonexistent() {
        let nonexistent_path = CString::new("/nonexistent/directory/").unwrap();

        let result = parse_directory(nonexistent_path.as_ptr(), 0, ConfigFormat::Json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(*err, libc::ENOENT);
    }
}
