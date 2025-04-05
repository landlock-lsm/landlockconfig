// SPDX-License-Identifier: Apache-2.0 OR MIT

use landlock::Errno;
use landlockconfig::Config;
use std::ffi::c_int;
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
    unsafe {
        *libc::__errno_location() = errno;
    }
    -1
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
    let config = parser(file).map_err(Errno::from)?;
    Ok(Box::into_raw(Box::new(config)))
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
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json_file(config_fd: RawFd, flags: u32) -> *mut Config {
    parse_file(config_fd, flags, |file| {
        Config::parse_json(file).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

// TODO: Add landlockconfig_parse_json_buffer()

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
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml_file(config_fd: RawFd, flags: u32) -> *mut Config {
    parse_file(config_fd, flags, |mut file| {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut file, &mut buffer)?;
        Config::parse_toml(&buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Frees a landlockconfig object
///
/// # Safety
///
/// The pointer must have been returned by landlockconfig_parse_json() or
/// landlockconfig_parse_toml().
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
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub unsafe extern "C" fn landlockconfig_build_ruleset(config: *const Config, flags: u32) -> RawFd {
    if flags != 0 {
        return unwrap_errno(Errno::new(libc::EINVAL));
    }

    if config.is_null() {
        return unwrap_errno(Errno::new(libc::EFAULT));
    }

    unsafe { &*config }
        .build_ruleset()
        .map(|r| {
            let fd: Option<OwnedFd> = r.into();
            fd.map(|fd| fd.into_raw_fd()).unwrap_or(-1)
        })
        .unwrap_or_else(unwrap_errno)
}
