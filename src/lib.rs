// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use config::{BuildRulesetError, Config};

mod config;
mod parser;

#[cfg(test)]
mod tests_parser;
