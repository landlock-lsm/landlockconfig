// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use config::{BuildRulesetError, Config, ConfigFormat, OptionalConfig, RuleError};

mod config;
mod nonempty;
mod parser;
mod variable;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests_helpers;

#[cfg(test)]
mod tests_parser;

#[cfg(test)]
mod tests_variable;

#[cfg(test)]
mod tests_compose;

#[cfg(test)]
mod tests_abi;
