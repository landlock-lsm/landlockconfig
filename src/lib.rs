// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use config::{BuildRulesetError, Config, RuleError};

mod config;
mod nonempty;
mod parser;

#[cfg(test)]
mod tests_helpers;

#[cfg(test)]
mod tests_parser;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
