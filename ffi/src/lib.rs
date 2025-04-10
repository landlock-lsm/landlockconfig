// SPDX-License-Identifier: Apache-2.0 OR MIT

use landlock::Errno;
use landlockconfig::Config;
use std::ffi::c_int;
use std::fs::File;
use std::io::Error;
use std::os::unix::io::{BorrowedFd, IntoRawFd, RawFd};

fn unwrap_errno<T>(err: T) -> c_int
where
    T: Into<Errno>,
{
    let mut errno = *err.into().as_ref();
    // TODO: Filter all error codes to document them, see libseccomp's _rc_filter().
    if errno <= 0 {
        // This should never happen.
        eprintln!("Error: Invalid errno value: {errno}");
        errno = libc::EIO;
    }
    -errno
}

fn parse_config<F>(config_fd: RawFd, parser: F) -> Result<*mut Config, Errno>
where
    F: FnOnce(File) -> Result<Config, Error>,
{
    let fd = unsafe { BorrowedFd::borrow_raw(config_fd) };
    // Checks if it is a valid file descriptor.
    let file = File::from(fd.try_clone_to_owned()?);
    let config = parser(file).map_err(Errno::from)?;
    Ok(Box::into_raw(Box::new(config)))
}

// TODO: pass a set of buffers for warnings and errors

/// Parses a JSON configuration file
///
/// # Returns
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json(config_fd: RawFd) -> *mut Config {
    parse_config(config_fd, |file| {
        Config::parse_json(file).map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| unwrap_errno(e) as *mut Config)
}

/// Parses a TOML configuration file
///
/// # Returns
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -errno on error.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml(config_fd: RawFd) -> *mut Config {
    parse_config(config_fd, |mut file| {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut file, &mut buffer)?;
        Config::parse_toml(&buffer).map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))
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
/// # Safety
///
/// The pointer must have been returned by landlockconfig_parse_json() or
/// landlockconfig_parse_toml().
///
/// # Returns
///
/// * The ruleset file descriptor on success.
/// * -errno on error.
#[no_mangle]
pub unsafe extern "C" fn landlockconfig_build_ruleset(config: *const Config) -> RawFd {
    if config.is_null() {
        return unwrap_errno(Errno::new(libc::EFAULT));
    }

    unsafe { &*config }
        .build_ruleset()
        .map(|r| r.into_raw_fd())
        .unwrap_or_else(unwrap_errno)
}
