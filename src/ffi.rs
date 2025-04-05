// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{BuildRulesetError, Config};
use landlock::RulesetError;
use libc;
use std::ffi::c_int;
use std::fs::File;
use std::io::Error;
use std::os::unix::io::{BorrowedFd, IntoRawFd, RawFd};

struct Errno(c_int);

impl Errno {
    fn sync(mut self) -> c_int {
        if self.0 <= 0 {
            // This should never happen.
            eprintln!("Error: Invalid errno value: {}", self.0);
            self.0 = libc::EIO;
        }
        unsafe {
            *libc::__errno_location() = self.0;
        }
        -1
    }
}

impl From<Error> for Errno {
    fn from(err: Error) -> Self {
        Errno(err.raw_os_error().unwrap_or(libc::EIO))
    }
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
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_json(config_fd: RawFd) -> *mut Config {
    parse_config(config_fd, |file| {
        Config::try_from_json(file).map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| e.sync() as *mut Config)
}

/// Parses a TOML configuration file
///
/// # Returns
///
/// * Pointer to a landlockconfig object on success. This object must be freed
///   with landlockconfig_free().
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub extern "C" fn landlockconfig_parse_toml(config_fd: RawFd) -> *mut Config {
    parse_config(config_fd, |mut file| {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut file, &mut buffer)?;
        Config::try_from_toml(&buffer).map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))
    })
    .unwrap_or_else(|e| e.sync() as *mut Config)
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

impl From<RulesetError> for Errno {
    fn from(err: RulesetError) -> Self {
        match err {
            RulesetError::HandleAccesses(_) => Errno(libc::EINVAL),
            RulesetError::CreateRuleset(landlock::CreateRulesetError::CreateRulesetCall {
                source,
                ..
            }) => source.into(),
            RulesetError::AddRules(e) => match e {
                landlock::AddRulesError::Fs(landlock::AddRuleError::AddRuleCall {
                    source, ..
                }) => source.into(),
                landlock::AddRulesError::Net(landlock::AddRuleError::AddRuleCall {
                    source,
                    ..
                }) => source.into(),
                _ => Errno(libc::EIO),
            },
            RulesetError::RestrictSelf(e) => match e {
                landlock::RestrictSelfError::RestrictSelfCall { source, .. } => source.into(),
                landlock::RestrictSelfError::SetNoNewPrivsCall { source, .. } => source.into(),
                _ => Errno(libc::EIO),
            },
            _ => Errno(libc::EIO),
        }
    }
}

impl From<BuildRulesetError> for Errno {
    fn from(err: BuildRulesetError) -> Self {
        match err {
            BuildRulesetError::Ruleset(e) => e.into(),
            _ => Errno(libc::EIO),
        }
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
/// * -1 on error, and errno set to the error code.
#[no_mangle]
pub unsafe extern "C" fn landlockconfig_build_ruleset(config: *const Config) -> RawFd {
    if config.is_null() {
        return Errno(libc::EFAULT).sync();
    }

    unsafe { &*config }
        .build_ruleset()
        .map(|r| r.into_raw_fd())
        .unwrap_or_else(|e| {
            let errno: Errno = e.into();
            errno.sync()
        })
}
