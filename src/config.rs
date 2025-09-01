// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::nonempty::NonEmptyStruct;
use crate::parser::{JsonConfig, TemplateString, TomlConfig};
use crate::variable::{NameError, ResolveError, Variables, VecStringIterator};
use landlock::{
    AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope,
};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::num::TryFromIntError;
use std::path::{Path, PathBuf};
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

#[cfg_attr(test, derive(Default))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub(crate) variables: Variables,
    pub(crate) handled_fs: BitFlags<AccessFs>,
    pub(crate) handled_net: BitFlags<AccessNet>,
    pub(crate) scoped: BitFlags<Scope>,
    pub(crate) rules_path_beneath: BTreeMap<TemplateString, BitFlags<AccessFs>>,
    pub(crate) rules_net_port: BTreeMap<u64, BitFlags<AccessNet>>,
}

#[cfg_attr(test, derive(Default))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
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

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Name(#[from] NameError),
}

impl TryFrom<NonEmptyStruct<JsonConfig>> for Config {
    type Error = ConfigError;

    fn try_from(json: NonEmptyStruct<JsonConfig>) -> Result<Self, Self::Error> {
        let mut config = Self::empty();
        let json = json.into_inner();

        for variable in json.variable.unwrap_or_default() {
            let name = variable.name.parse()?;
            let literal = variable.literal.unwrap_or_default();
            // TODO: Check and warn if users tried to use variable in literal strings?
            config.variables.extend(name, literal.into_iter().collect());
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
                    .entry(parent)
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

        Ok(config)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
}

#[derive(Debug, Error)]
pub enum ParseJsonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

#[cfg(feature = "toml")]
#[derive(Debug, Error)]
pub enum ParseTomlError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    SerdeToml(#[from] toml::de::Error),
}

#[derive(Debug, Error)]
pub enum ParseFileError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseJson(#[from] ParseJsonError),
    #[cfg(feature = "toml")]
    #[error(transparent)]
    ParseToml(#[from] ParseTomlError),
}

fn format_parse_files_error(errors: &BTreeMap<PathBuf, ParseFileError>) -> String {
    errors
        .iter()
        .map(|(path, error)| format!("{}: {}", path.display(), error))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Error)]
pub enum ParseDirectoryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    // Use BTreeMap for deterministic errors.
    #[error("failed to parse configuration file(s):\n\n{}", format_parse_files_error(.0))]
    ParseFiles(BTreeMap<PathBuf, ParseFileError>),
    #[error("no configuration file found")]
    NoConfigFile,
}

pub enum ConfigFormat {
    Json,
    #[cfg(feature = "toml")]
    Toml,
}

impl ConfigFormat {
    fn extension(&self) -> &'static str {
        match self {
            ConfigFormat::Json => "json",
            #[cfg(feature = "toml")]
            ConfigFormat::Toml => "toml",
        }
    }
}

impl Config {
    // Do not implement Default for Config because it would not be useful but
    // misleading.  Indeed, the default configuration would allow everything and
    // could not be updated with public methods (e.g. compose).
    fn empty() -> Self {
        Self {
            variables: Default::default(),
            handled_fs: Default::default(),
            handled_net: Default::default(),
            scoped: Default::default(),
            rules_path_beneath: Default::default(),
            rules_net_port: Default::default(),
        }
    }

    /// Composes two configurations by merging `other` with `self` in a safe
    /// best-effort way, which means the common handled access rights with all
    /// rules.
    ///
    /// When composing configurations with different ABI versions (e.g., one
    /// against ABI::V1 and another against ABI::V2), the composition will
    /// downgrade to the intersection of handled access rights, ensuring the
    /// resulting configuration remains functional across both contexts.
    ///
    /// # Behavior
    ///
    /// - Handled access rights are combined using bitwise AND (intersection).
    /// - Rules are merged with access rights limited to commonly handled ones.
    /// - Paths with empty access rights after intersection are removed.
    /// - Variables from both configurations are merged.
    ///
    /// # Commutativity
    ///
    /// This operation is commutative: `a.compose(&b)` produces the same result
    /// as `b.compose(&a)`. The order of composition does not affect the final
    /// configuration, ensuring predictable behavior regardless of the sequence
    /// in which configurations are combined.
    pub fn compose(&mut self, other: &Self) {
        let common_handled_fs = self.handled_fs & other.handled_fs;
        let common_handled_net = self.handled_net & other.handled_net;

        // First step: downgrade the current access rights according to other's
        // handled access rights, and remove entries with empty accesses.
        self.rules_path_beneath.retain(|_, access| {
            *access &= common_handled_fs;
            !access.is_empty()
        });
        self.rules_net_port.retain(|_, access| {
            *access &= common_handled_net;
            !access.is_empty()
        });

        // Second step: add the new rules from other, downgrade according to
        // common handled access rights, if they are not empty.
        for (path, access) in &other.rules_path_beneath {
            let downgraded_access = *access & common_handled_fs;
            if !downgraded_access.is_empty() {
                self.rules_path_beneath
                    .entry(path.clone())
                    .and_modify(|a| *a |= downgraded_access)
                    .or_insert(downgraded_access);
            }
        }
        for (port, access) in &other.rules_net_port {
            let downgraded_access = *access & common_handled_net;
            if !downgraded_access.is_empty() {
                self.rules_net_port
                    .entry(*port)
                    .and_modify(|a| *a |= downgraded_access)
                    .or_insert(downgraded_access);
            }
        }

        // Third step: merge variables.
        for (name, value) in other.variables.iter() {
            self.variables.extend(name.clone(), value.clone());
        }

        // Fourth step: downgrade the handled access rights.
        self.handled_fs &= other.handled_fs;
        self.handled_net &= other.handled_net;
        self.scoped &= other.scoped;
    }

    pub fn parse_json<R>(reader: R) -> Result<Self, ParseJsonError>
    where
        R: std::io::Read,
    {
        let json = serde_json::from_reader::<_, NonEmptyStruct<JsonConfig>>(reader)?;
        Ok(json.try_into()?)
    }

    #[cfg(feature = "toml")]
    pub fn parse_toml(data: &str) -> Result<Self, ParseTomlError> {
        // The TOML parser does not handle Read implementations,
        // see https://github.com/toml-rs/toml/issues/326
        let json: NonEmptyStruct<JsonConfig> =
            toml::from_str::<NonEmptyStruct<TomlConfig>>(data)?.convert();
        Ok(json.try_into()?)
    }

    /// Parse all configuration files in a directory with the specified format.
    ///
    /// This method reads all files in the given directory that match the specified
    /// format's file extension and are regular files (not directories or hidden files
    /// starting with '.'). Each valid configuration file is parsed and composed into
    /// a single configuration using the [`compose`](Config::compose) method.
    ///
    /// # Returns
    ///
    /// Returns a composed `Config` from all valid configuration files found in the
    /// directory, or ParseDirectoryError otherwise.
    pub fn parse_directory<T>(path: T, format: ConfigFormat) -> Result<Self, ParseDirectoryError>
    where
        T: AsRef<Path>,
    {
        let mut full_config = None;
        let mut errors = BTreeMap::new();

        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.extension() != Some(format.extension().as_ref()) {
                continue;
            }

            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }

            if !path.is_file() {
                continue;
            }

            match format {
                ConfigFormat::Json => match File::open(&path) {
                    Ok(file) => match Self::parse_json(file) {
                        Ok(config) => full_config.compose(&config),
                        Err(e) => {
                            // Duplicated file names should be very rare when
                            // listing the content of a directory, and ignoring
                            // errors for now-removed files is OK.
                            errors.insert(path.clone(), e.into());
                        }
                    },
                    Err(e) => {
                        // Ignore race conditions when files are removed.
                        if e.kind() != std::io::ErrorKind::NotFound {
                            errors.insert(path.clone(), e.into());
                        }
                    }
                },
                #[cfg(feature = "toml")]
                ConfigFormat::Toml => match std::fs::read_to_string(&path) {
                    Ok(data) => match Self::parse_toml(data.as_str()) {
                        Ok(config) => full_config.compose(&config),
                        Err(e) => {
                            errors.insert(path.clone(), e.into());
                        }
                    },
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            errors.insert(path.clone(), e.into());
                        }
                    }
                },
            }
        }

        if !errors.is_empty() {
            return Err(ParseDirectoryError::ParseFiles(errors));
        }
        full_config.ok_or(ParseDirectoryError::NoConfigFile)
    }

    pub fn resolve(self) -> Result<ResolvedConfig, ResolveError> {
        self.try_into()
    }
}

#[test]
fn test_config_default_empty() {
    let config = Config::default();
    assert_eq!(config.handled_fs, BitFlags::EMPTY);
    assert_eq!(config.handled_net, BitFlags::EMPTY);
    assert_eq!(config.scoped, BitFlags::EMPTY);

    assert_eq!(config, Config::empty());
}

pub trait OptionalConfig {
    fn compose(&mut self, other: &Config);
}

impl OptionalConfig for Option<Config> {
    fn compose(&mut self, other: &Config) {
        match self {
            Some(config) => config.compose(other),
            None => *self = Some(other.clone()),
        }
    }
}

impl ResolvedConfig {
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
}

impl TryFrom<Config> for ResolvedConfig {
    type Error = ResolveError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        let mut rules_path_beneath: BTreeMap<PathBuf, BitFlags<AccessFs>> = Default::default();
        for (path_beneath, access) in config.rules_path_beneath {
            let set = config.variables.resolve(&path_beneath)?;
            for path in VecStringIterator::new(&set) {
                rules_path_beneath
                    .entry(PathBuf::from(path))
                    .and_modify(|a| *a |= access)
                    .or_insert(access);
            }
        }

        Ok(Self {
            handled_fs: config.handled_fs,
            handled_net: config.handled_net,
            scoped: config.scoped,
            rules_path_beneath,
            rules_net_port: config.rules_net_port,
        })
    }
}

#[cfg(test)]
mod tests_compose {
    use super::*;
    use landlock::{Access, ABI};

    #[test]
    fn test_empty_ruleset() {
        let mut c1 = Config {
            handled_fs: AccessFs::Execute.into(),
            ..Default::default()
        };
        let c2 = c1.clone();
        c1.compose(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_ruleset() {
        let mut c1 = Config {
            handled_fs: AccessFs::Execute.into(),
            ..Default::default()
        };
        let c2 = Config {
            handled_net: AccessNet::BindTcp.into(),
            ..Default::default()
        };
        let expect = Config {
            ..Default::default()
        };
        c1.compose(&c2);
        assert_eq!(c1, expect);
    }

    #[test]
    fn test_compose_v1_v2_without_one_right() {
        let c1_access = AccessFs::from_all(ABI::V1);
        let mut c1 = Config {
            handled_fs: c1_access,
            rules_path_beneath: [
                (TemplateString::from_text("/common"), c1_access),
                (TemplateString::from_text("/c1"), c1_access),
            ]
            .into(),
            ..Default::default()
        };

        assert!(c1_access.contains(AccessFs::WriteFile));
        let c2_access = AccessFs::from_all(ABI::V2) & !AccessFs::WriteFile;
        let c2 = Config {
            handled_fs: c2_access,
            rules_path_beneath: [
                (TemplateString::from_text("/common"), c2_access),
                (TemplateString::from_text("/c2"), c2_access),
            ]
            .into(),
            ..Default::default()
        };

        c1.compose(&c2);
        assert_eq!(
            c1,
            Config {
                handled_fs: c1_access & c2_access,
                rules_path_beneath: [
                    (TemplateString::from_text("/common"), c1_access & c2_access),
                    (TemplateString::from_text("/c1"), c1_access & c2_access),
                    (TemplateString::from_text("/c2"), c1_access & c2_access),
                ]
                .into(),
                ..Default::default()
            }
        );
    }
}
