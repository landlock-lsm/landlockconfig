// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::parser::{JsonConfig, JsonRuleset, TomlConfig};
use landlock::{
    AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError,
};
use std::collections::BTreeMap;
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub(crate) handled_fs: BitFlags<AccessFs>,
    pub(crate) handled_net: BitFlags<AccessNet>,
    // Thanks to the BTreeMap:
    // * the paths are unique, which guarantee that allowed access are only set once for each path;
    // * the paths are sorted (the longest path is the last one), which makes configurations deterministic and idempotent.
    // Thanks to PathBuf, paths are normalized.
    pub(crate) rules_path_beneath: BTreeMap<PathBuf, BitFlags<AccessFs>>,
    pub(crate) rules_net_port: BTreeMap<u64, BitFlags<AccessNet>>,
}

impl From<JsonConfig> for Config {
    fn from(json: JsonConfig) -> Self {
        let mut config = Self::default();

        for ruleset in json.ruleset {
            match ruleset {
                JsonRuleset::Fs(fs) => {
                    let access: BitFlags<AccessFs> = (&fs.handledAccessFs).into();
                    config.handled_fs |= access;
                }
                JsonRuleset::Net(net) => {
                    let access: BitFlags<AccessNet> = (&net.handledAccessNet).into();
                    config.handled_net |= access;
                }
            }
        }

        if let Some(path_beneaths) = json.pathBeneath {
            for path_beneath in path_beneaths {
                let access: BitFlags<AccessFs> = (&path_beneath.allowedAccess).into();
                for parent in path_beneath.parent {
                    config
                        .rules_path_beneath
                        .entry(PathBuf::from(parent))
                        .and_modify(|a| *a |= access)
                        .or_insert(access);
                }
            }
        }

        if let Some(net_ports) = json.netPort {
            for net_port in net_ports {
                let access: BitFlags<AccessNet> = (&net_port.allowedAccess).into();
                for port in net_port.port {
                    config
                        .rules_net_port
                        .entry(port)
                        .and_modify(|a| *a |= access)
                        .or_insert(access);
                }
            }
        }

        config
    }
}

// TODO: Add a merge method to compose with another Config.
impl Config {
    pub fn build_ruleset(&self) -> Result<RulesetCreated, BuildRulesetError> {
        let mut ruleset = Ruleset::default();
        let ruleset_ref = &mut ruleset;
        if !self.handled_fs.is_empty() {
            ruleset_ref.handle_access(self.handled_fs)?;
        }
        if !self.handled_net.is_empty() {
            ruleset_ref.handle_access(self.handled_net)?;
        }
        let mut ruleset_created = ruleset.create()?;
        let ruleset_created_ref = &mut ruleset_created;

        for (parent, allowed_access) in &self.rules_path_beneath {
            // TODO: Walk through all path and only open them once, including their
            // common parent directory to get a consistent hierarchy.
            // TODO: Ignore failure to open path, but record a warning instead.
            let fd = PathFd::new(parent)?;
            ruleset_created_ref.add_rule(PathBeneath::new(fd, *allowed_access))?;
        }

        for (port, allowed_access) in &self.rules_net_port {
            ruleset_created_ref.add_rule(
                // TODO: Check integer conversion in parse_json(), which would require changing the type of config and specifying where the error is.
                NetPort::new((*port).try_into()?, *allowed_access),
            )?;
        }

        Ok(ruleset_created)
    }

    pub fn parse_json<R>(reader: R) -> Result<Self, serde_json::Error>
    where
        R: std::io::Read,
    {
        let json = serde_json::from_reader::<_, JsonConfig>(reader)?;
        Ok(json.into())
    }

    #[cfg(feature = "toml")]
    pub fn parse_toml(data: &str) -> Result<Self, toml::de::Error> {
        // The TOML parser does not handle Read implementations,
        // see https://github.com/toml-rs/toml/issues/326
        let json: JsonConfig = toml::from_str::<TomlConfig>(data)?.into();
        Ok(json.into())
    }
}
