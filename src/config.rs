// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::nonempty::NonEmptyStruct;
use crate::parser::{JsonConfig, TomlConfig};
use landlock::{
    AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope,
};
use std::collections::{BTreeMap, BTreeSet};
use std::num::TryFromIntError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildRulesetError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
    #[error(transparent)]
    Integer(#[from] TryFromIntError),
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
}

// TODO: Remove the Default implementation to avoid inconsistent configurations wrt. From<NonEmptySet<JsonConfig>>.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub(crate) variables: BTreeMap<String, BTreeSet<String>>,
    pub(crate) handled_fs: BitFlags<AccessFs>,
    pub(crate) handled_net: BitFlags<AccessNet>,
    pub(crate) scoped: BitFlags<Scope>,
    // Thanks to the BTreeMap:
    // * the paths are unique, which guarantee that allowed access are only set once for each path;
    // * the paths are sorted (the longest path is the last one), which makes configurations deterministic and idempotent.
    // Thanks to PathBuf, paths are normalized.
    pub(crate) rules_path_beneath: BTreeMap<PathBuf, BitFlags<AccessFs>>,
    pub(crate) rules_net_port: BTreeMap<u64, BitFlags<AccessNet>>,
}

impl From<NonEmptyStruct<JsonConfig>> for Config {
    fn from(json: NonEmptyStruct<JsonConfig>) -> Self {
        let mut config = Self::default();
        let json = json.into_inner();

        for variable in json.variable.unwrap_or_default() {
            let literal = variable.literal.unwrap_or_default();
            config
                .variables
                .insert(variable.name, literal.into_iter().collect());
        }

        for ruleset in json.ruleset.unwrap_or_default() {
            let ruleset = ruleset.into_inner();
            config.handled_fs |= ruleset
                .handledAccessFs
                .as_ref()
                .map(BitFlags::<AccessFs>::from)
                .unwrap_or_default();
            config.handled_net |= ruleset
                .handledAccessNet
                .as_ref()
                .map(BitFlags::<AccessNet>::from)
                .unwrap_or_default();
            config.scoped |= ruleset
                .scoped
                .as_ref()
                .map(BitFlags::<Scope>::from)
                .unwrap_or_default();
        }

        for path_beneath in json.pathBeneath.unwrap_or_default() {
            let access: BitFlags<AccessFs> = (&path_beneath.allowedAccess).into();

            /* Automatically augment and keep the ruleset consistent. */
            config.handled_fs |= access;

            for parent in path_beneath.parent {
                config
                    .rules_path_beneath
                    .entry(PathBuf::from(parent))
                    .and_modify(|a| *a |= access)
                    .or_insert(access);
            }
        }

        for net_port in json.netPort.unwrap_or_default() {
            let access: BitFlags<AccessNet> = (&net_port.allowedAccess).into();

            /* Automatically augment and keep the ruleset consistent. */
            config.handled_net |= access;

            for port in net_port.port {
                config
                    .rules_net_port
                    .entry(port)
                    .and_modify(|a| *a |= access)
                    .or_insert(access);
            }
        }

        config
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
}

// TODO: Add a merge method to compose with another Config.
impl Config {
    pub fn build_ruleset(&self) -> Result<(RulesetCreated, Vec<RuleError>), BuildRulesetError> {
        let mut ruleset = Ruleset::default();
        let ruleset_ref = &mut ruleset;
        if !self.handled_fs.is_empty() {
            ruleset_ref.handle_access(self.handled_fs)?;
        }
        if !self.handled_net.is_empty() {
            ruleset_ref.handle_access(self.handled_net)?;
        }
        if !self.scoped.is_empty() {
            ruleset_ref.scope(self.scoped)?;
        }
        let mut ruleset_created = ruleset.create()?;
        let ruleset_created_ref = &mut ruleset_created;
        let mut rule_errors = Vec::new();

        for (parent, allowed_access) in &self.rules_path_beneath {
            // TODO: Walk through all path and only open them once, including their
            // common parent directory to get a consistent hierarchy.
            let fd = match PathFd::new(parent) {
                Ok(fd) => fd,
                Err(e) => {
                    rule_errors.push(RuleError::PathFd(e));
                    continue;
                }
            };
            ruleset_created_ref.add_rule(PathBeneath::new(fd, *allowed_access))?;
        }

        for (port, allowed_access) in &self.rules_net_port {
            ruleset_created_ref.add_rule(
                // TODO: Check integer conversion in parse_json(), which would require changing the type of config and specifying where the error is.
                NetPort::new((*port).try_into()?, *allowed_access),
            )?;
        }

        Ok((ruleset_created, rule_errors))
    }

    pub fn parse_json<R>(reader: R) -> Result<Self, serde_json::Error>
    where
        R: std::io::Read,
    {
        let json = serde_json::from_reader::<_, NonEmptyStruct<JsonConfig>>(reader)?;
        Ok(json.into())
    }

    #[cfg(feature = "toml")]
    pub fn parse_toml(data: &str) -> Result<Self, toml::de::Error> {
        // The TOML parser does not handle Read implementations,
        // see https://github.com/toml-rs/toml/issues/326
        let json: NonEmptyStruct<JsonConfig> =
            toml::from_str::<NonEmptyStruct<TomlConfig>>(data)?.convert();
        Ok(json.into())
    }
}
