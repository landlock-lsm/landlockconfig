use landlock::{
    Access, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, ABI,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::num::TryFromIntError;
use thiserror::Error;

pub use landlock::{RestrictionStatus, RulesetStatus};

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsonFsAccessItem {
    Execute,
    WriteFile,
    ReadFile,
    ReadDir,
    RemoveDir,
    RemoveFile,
    MakeChar,
    MakeDir,
    MakeReg,
    MakeSock,
    MakeFifo,
    MakeBlock,
    MakeSym,
    #[serde(rename = "v1.all")]
    V1All,
    #[serde(rename = "v1.read_execute")]
    V1ReadExecute,
    #[serde(rename = "v1.read_write")]
    V1ReadWrite,
    Refer,
    #[serde(rename = "v2.all")]
    V2All,
    #[serde(rename = "v2.read_execute")]
    V2ReadExecute,
    #[serde(rename = "v2.read_write")]
    V2ReadWrite,
    Truncate,
    #[serde(rename = "v3.all")]
    V3All,
    #[serde(rename = "v3.read_execute")]
    V3ReadExecute,
    #[serde(rename = "v3.read_write")]
    V3ReadWrite,
    #[serde(rename = "v4.all")]
    V4All,
    #[serde(rename = "v4.read_execute")]
    V4ReadExecute,
    #[serde(rename = "v4.read_write")]
    V4ReadWrite,
    IoctlDev,
    #[serde(rename = "v5.all")]
    V5All,
    #[serde(rename = "v5.read_execute")]
    V5ReadExecute,
    #[serde(rename = "v5.read_write")]
    V5ReadWrite,
}

fn get_fs_read_execute(abi: ABI) -> BitFlags<AccessFs> {
    AccessFs::from_read(abi) | (AccessFs::from_all(abi) & AccessFs::Refer)
}

fn get_fs_read_write(abi: ABI) -> BitFlags<AccessFs> {
    // from_all() == from_read() | from_write()
    AccessFs::from_all(abi) & !AccessFs::Execute
}

impl From<&JsonFsAccessItem> for BitFlags<AccessFs> {
    fn from(js: &JsonFsAccessItem) -> Self {
        match js {
            JsonFsAccessItem::Execute => AccessFs::Execute.into(),
            JsonFsAccessItem::WriteFile => AccessFs::WriteFile.into(),
            JsonFsAccessItem::ReadFile => AccessFs::ReadFile.into(),
            JsonFsAccessItem::ReadDir => AccessFs::ReadDir.into(),
            JsonFsAccessItem::RemoveDir => AccessFs::RemoveDir.into(),
            JsonFsAccessItem::RemoveFile => AccessFs::RemoveFile.into(),
            JsonFsAccessItem::MakeChar => AccessFs::MakeChar.into(),
            JsonFsAccessItem::MakeDir => AccessFs::MakeDir.into(),
            JsonFsAccessItem::MakeReg => AccessFs::MakeReg.into(),
            JsonFsAccessItem::MakeSock => AccessFs::MakeSock.into(),
            JsonFsAccessItem::MakeFifo => AccessFs::MakeFifo.into(),
            JsonFsAccessItem::MakeBlock => AccessFs::MakeBlock.into(),
            JsonFsAccessItem::MakeSym => AccessFs::MakeSym.into(),
            JsonFsAccessItem::V1All => AccessFs::from_all(ABI::V1),
            JsonFsAccessItem::V1ReadExecute => get_fs_read_execute(ABI::V1),
            JsonFsAccessItem::V1ReadWrite => get_fs_read_write(ABI::V1),
            JsonFsAccessItem::Refer => AccessFs::Refer.into(),
            JsonFsAccessItem::V2All => AccessFs::from_all(ABI::V2),
            JsonFsAccessItem::V2ReadExecute => get_fs_read_execute(ABI::V2),
            JsonFsAccessItem::V2ReadWrite => get_fs_read_write(ABI::V2),
            JsonFsAccessItem::Truncate => AccessFs::Truncate.into(),
            JsonFsAccessItem::V3All => AccessFs::from_all(ABI::V3),
            JsonFsAccessItem::V3ReadExecute => get_fs_read_execute(ABI::V3),
            JsonFsAccessItem::V3ReadWrite => get_fs_read_write(ABI::V3),
            JsonFsAccessItem::V4All => AccessFs::from_all(ABI::V4),
            JsonFsAccessItem::V4ReadExecute => get_fs_read_execute(ABI::V4),
            JsonFsAccessItem::V4ReadWrite => get_fs_read_write(ABI::V4),
            JsonFsAccessItem::IoctlDev => AccessFs::IoctlDev.into(),
            JsonFsAccessItem::V5All => AccessFs::from_all(ABI::V5),
            JsonFsAccessItem::V5ReadExecute => get_fs_read_execute(ABI::V5),
            JsonFsAccessItem::V5ReadWrite => get_fs_read_write(ABI::V5),
        }
    }
}

#[test]
fn test_v1_read_execute() {
    let rx: BitFlags<AccessFs> = (&JsonFsAccessItem::V1ReadExecute).into();
    assert_eq!(
        rx,
        AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir
    );

    assert!(rx.contains(AccessFs::Execute));

    // Refer is only available since v2.
    assert!(!rx.contains(AccessFs::Refer));
}

#[test]
fn test_v2_read_execute() {
    let rx: BitFlags<AccessFs> = (&JsonFsAccessItem::V2ReadExecute).into();
    assert!(rx.contains(AccessFs::Execute));
    assert!(rx.contains(AccessFs::Refer));
}

#[test]
fn test_v1_read_write() {
    let rw: BitFlags<AccessFs> = (&JsonFsAccessItem::V1ReadWrite).into();
    assert_eq!(
        rw,
        AccessFs::WriteFile
            | AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym
    );

    assert!(!rw.contains(AccessFs::Execute));

    // Refer is only available since v2.
    assert!(!rw.contains(AccessFs::Refer));
}

#[test]
fn test_v2_read_write() {
    let rw: BitFlags<AccessFs> = (&JsonFsAccessItem::V2ReadWrite).into();
    assert!(!rw.contains(AccessFs::Execute));
    assert!(rw.contains(AccessFs::Refer));
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsonFsAccessSet(BTreeSet<JsonFsAccessItem>);

impl From<&JsonFsAccessSet> for BitFlags<AccessFs> {
    fn from(set: &JsonFsAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: BitFlags<AccessFs> = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsonNetAccessItem {
    BindTcp,
    ConnectTcp,
    #[serde(rename = "v4.all")]
    V4All,
    #[serde(rename = "v5.all")]
    V5All,
}

impl From<&JsonNetAccessItem> for BitFlags<AccessNet> {
    fn from(js: &JsonNetAccessItem) -> Self {
        match js {
            JsonNetAccessItem::BindTcp => AccessNet::BindTcp.into(),
            JsonNetAccessItem::ConnectTcp => AccessNet::ConnectTcp.into(),
            JsonNetAccessItem::V4All => AccessNet::from_all(ABI::V4),
            JsonNetAccessItem::V5All => AccessNet::from_all(ABI::V5),
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsonNetAccessSet(BTreeSet<JsonNetAccessItem>);

impl From<&JsonNetAccessSet> for BitFlags<AccessNet> {
    fn from(set: &JsonNetAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: BitFlags<AccessNet> = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsonRulesetAccessFs {
    handledAccessFs: JsonFsAccessSet,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct TomlRulesetAccessFs {
    handled_access_fs: JsonFsAccessSet,
}

impl From<TomlRulesetAccessFs> for JsonRulesetAccessFs {
    fn from(toml: TomlRulesetAccessFs) -> Self {
        Self {
            handledAccessFs: toml.handled_access_fs,
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsonRulesetAccessNet {
    handledAccessNet: JsonNetAccessSet,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct TomlRulesetAccessNet {
    handled_access_net: JsonNetAccessSet,
}

impl From<TomlRulesetAccessNet> for JsonRulesetAccessNet {
    fn from(toml: TomlRulesetAccessNet) -> Self {
        Self {
            handledAccessNet: toml.handled_access_net,
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, untagged)]
enum JsonRuleset {
    Fs(JsonRulesetAccessFs),
    Net(JsonRulesetAccessNet),
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, untagged)]
enum TomlRuleset {
    Fs(TomlRulesetAccessFs),
    Net(TomlRulesetAccessNet),
}

impl From<TomlRuleset> for JsonRuleset {
    fn from(toml: TomlRuleset) -> Self {
        match toml {
            TomlRuleset::Fs(fs) => JsonRuleset::Fs(fs.into()),
            TomlRuleset::Net(net) => JsonRuleset::Net(net.into()),
        }
    }
}

// TODO: Make paths canonical (e.g. remove extra slashes and dots) and only open the same paths
// once.
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsonPathBeneath {
    allowedAccess: JsonFsAccessSet,
    parent: BTreeSet<String>,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlPathBeneath {
    allowed_access: JsonFsAccessSet,
    parent: BTreeSet<String>,
}

impl From<TomlPathBeneath> for JsonPathBeneath {
    fn from(toml: TomlPathBeneath) -> Self {
        Self {
            allowedAccess: toml.allowed_access,
            parent: toml.parent,
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsonNetPort {
    allowedAccess: JsonNetAccessSet,
    port: BTreeSet<u64>,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlNetPort {
    allowed_access: JsonNetAccessSet,
    port: BTreeSet<u64>,
}

impl From<TomlNetPort> for JsonNetPort {
    fn from(toml: TomlNetPort) -> Self {
        Self {
            allowedAccess: toml.allowed_access,
            port: toml.port,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsonConfig {
    ruleset: BTreeSet<JsonRuleset>,
    pathBeneath: Option<BTreeSet<JsonPathBeneath>>,
    netPort: Option<BTreeSet<JsonNetPort>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    ruleset: BTreeSet<TomlRuleset>,
    path_beneath: Option<BTreeSet<TomlPathBeneath>>,
    net_port: Option<BTreeSet<TomlNetPort>>,
}

impl From<TomlConfig> for JsonConfig {
    fn from(toml: TomlConfig) -> Self {
        Self {
            ruleset: toml.ruleset.into_iter().map(Into::into).collect(),
            pathBeneath: toml
                .path_beneath
                .map(|set| set.into_iter().map(Into::into).collect()),
            netPort: toml
                .net_port
                .map(|set| set.into_iter().map(Into::into).collect()),
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CreateRulesetError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
    #[error(transparent)]
    Integer(#[from] TryFromIntError),
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
}

impl JsonConfig {
    fn create_ruleset(
        &self, // TODO: Handle Vec<Config> and automatically merge them.
    ) -> Result<RulesetCreated, CreateRulesetError> {
        let mut ruleset = Ruleset::default();
        let ruleset_ref = &mut ruleset;
        for a in &self.ruleset {
            match a {
                JsonRuleset::Fs(r) => {
                    let access_ref = &r.handledAccessFs;
                    let access_fs: BitFlags<AccessFs> = access_ref.into();
                    ruleset_ref.handle_access(access_fs)?;
                }
                JsonRuleset::Net(r) => {
                    let access_ref = &r.handledAccessNet;
                    let access_net: BitFlags<AccessNet> = access_ref.into();
                    ruleset_ref.handle_access(access_net)?;
                }
            }
        }

        let mut ruleset_created = ruleset.create()?;
        let ruleset_created_ref = &mut ruleset_created;

        for rule in self.pathBeneath.iter().flatten() {
            let access_ref = &rule.allowedAccess;
            let access_fs: BitFlags<AccessFs> = access_ref.into();

            // TODO: Walk through all path and only open them once, including their
            // common parent directory to get a consistent hierarchy.
            for path in &rule.parent {
                let parent = PathFd::new(path)?;
                ruleset_created_ref.add_rule(PathBeneath::new(parent, access_fs))?;
            }
        }

        for rule in self.netPort.iter().flatten() {
            let access_ref = &rule.allowedAccess;
            let access_net: BitFlags<AccessNet> = access_ref.into();

            // Find in FDs the referenced name
            // WARNING: Will close the related FD (e.g. stdout)
            for port in &rule.port {
                ruleset_created_ref.add_rule(
                    // TODO: Check integer conversion in parse_json(), which would require changing the type of config and specifying where the error is.
                    NetPort::new((*port).try_into()?, access_net),
                )?;
            }
        }

        Ok(ruleset_created)
    }
}

pub struct Config(JsonConfig);

// TODO: Add a merge method to compose with another Config.
impl Config {
    pub fn try_from_json<R>(reader: R) -> Result<Self, serde_json::Error>
    where
        R: std::io::Read,
    {
        Ok(Self(serde_json::from_reader::<_, JsonConfig>(reader)?))
    }

    #[cfg(feature = "toml")]
    pub fn try_from_toml(data: &str) -> Result<Self, toml::de::Error> {
        // The TOML parser does not handle Read implementations,
        // see https://github.com/toml-rs/toml/issues/326
        Ok(Self(toml::from_str::<TomlConfig>(data)?.into()))
    }

    pub fn create_ruleset(&self) -> Result<RulesetCreated, CreateRulesetError> {
        self.0.create_ruleset()
    }
}
