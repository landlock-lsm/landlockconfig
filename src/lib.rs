// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use policy::{
    BuildRulesetError, OptionalPolicy, ParseDirectoryError, Policy, PolicyFormat, ResolvedPolicy,
    RuleError,
};
pub use variable::ResolveError;

mod nonempty;
mod parser;
mod policy;
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
