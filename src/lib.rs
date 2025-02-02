use landlock::{
    AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::num::TryFromIntError;
use std::os::fd::{FromRawFd, OwnedFd};
use thiserror::Error;

pub use landlock::RulesetStatus;

#[derive(Debug, Default, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsCompatLevel {
    #[default]
    BestEffort,
    SoftRequirement,
    HardRequirement,
}

impl From<&JsCompatLevel> for CompatLevel {
    fn from(js: &JsCompatLevel) -> Self {
        match js {
            JsCompatLevel::BestEffort => CompatLevel::BestEffort,
            JsCompatLevel::SoftRequirement => CompatLevel::SoftRequirement,
            JsCompatLevel::HardRequirement => CompatLevel::HardRequirement,
        }
    }
}

// https://serde.rs/enum-representations.html
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, untagged)]
enum JsFileDescriptorItem {
    Path(String),
    Fd(i32),
}

// TODO: Walk through all path and only open them once, including their common parent directory to
// get a consistent hierarchy.
//
// TODO: Use and extend PathFd instead of File.
impl TryFrom<&JsFileDescriptorItem> for File {
    type Error = std::io::Error;

    fn try_from(item: &JsFileDescriptorItem) -> Result<Self, Self::Error> {
        match item {
            JsFileDescriptorItem::Path(p) => Ok(File::open(p)?),
            JsFileDescriptorItem::Fd(fd) => {
                let f = unsafe { File::from_raw_fd(*fd) };
                // FIXME: Use fcntl(fd, F_GETFD) to check FD instead of panicking.
                let _ = f.metadata()?;
                Ok(f)
            }
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsFsAccessItem {
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
    Refer,
    Truncate,
    IoctlDev,
}

impl From<&JsFsAccessItem> for AccessFs {
    fn from(js: &JsFsAccessItem) -> Self {
        match js {
            JsFsAccessItem::Execute => AccessFs::Execute,
            JsFsAccessItem::WriteFile => AccessFs::WriteFile,
            JsFsAccessItem::ReadFile => AccessFs::ReadFile,
            JsFsAccessItem::ReadDir => AccessFs::ReadDir,
            JsFsAccessItem::RemoveDir => AccessFs::RemoveDir,
            JsFsAccessItem::RemoveFile => AccessFs::RemoveFile,
            JsFsAccessItem::MakeChar => AccessFs::MakeChar,
            JsFsAccessItem::MakeDir => AccessFs::MakeDir,
            JsFsAccessItem::MakeReg => AccessFs::MakeReg,
            JsFsAccessItem::MakeSock => AccessFs::MakeSock,
            JsFsAccessItem::MakeFifo => AccessFs::MakeFifo,
            JsFsAccessItem::MakeBlock => AccessFs::MakeBlock,
            JsFsAccessItem::MakeSym => AccessFs::MakeSym,
            JsFsAccessItem::Refer => AccessFs::Refer,
            JsFsAccessItem::Truncate => AccessFs::Truncate,
            JsFsAccessItem::IoctlDev => AccessFs::IoctlDev,
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsFsAccessSet(BTreeSet<JsFsAccessItem>);

impl From<&JsFsAccessSet> for BitFlags<AccessFs> {
    fn from(set: &JsFsAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: AccessFs = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsNetAccessItem {
    BindTcp,
    ConnectTcp,
}

impl From<&JsNetAccessItem> for AccessNet {
    fn from(js: &JsNetAccessItem) -> Self {
        match js {
            JsNetAccessItem::BindTcp => AccessNet::BindTcp,
            JsNetAccessItem::ConnectTcp => AccessNet::ConnectTcp,
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsNetAccessSet(BTreeSet<JsNetAccessItem>);

impl From<&JsNetAccessSet> for BitFlags<AccessNet> {
    fn from(set: &JsNetAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: AccessNet = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsRulesetAccessFs {
    handledAccessFs: JsFsAccessSet,
    #[serde(default)]
    compatibility: JsCompatLevel,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsRulesetAccessNet {
    handledAccessNet: JsNetAccessSet,
    #[serde(default)]
    compatibility: JsCompatLevel,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, untagged)]
enum JsRuleset {
    Fs(JsRulesetAccessFs),
    Net(JsRulesetAccessNet),
}

// TODO: Make paths canonical (e.g. remove extra slashes and dots) and only open the same paths
// once.
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsPathBeneath {
    allowedAccess: JsFsAccessSet,
    parentFd: BTreeSet<JsFileDescriptorItem>,
    #[serde(default)]
    compatibility: JsCompatLevel,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct JsNetPort {
    allowedAccess: JsNetAccessSet,
    port: BTreeSet<u64>,
    #[serde(default)]
    compatibility: JsCompatLevel,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct Config {
    ruleset: BTreeSet<JsRuleset>,
    pathBeneath: Option<BTreeSet<JsPathBeneath>>,
    netPort: Option<BTreeSet<JsNetPort>>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildRulesetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Integer(#[from] TryFromIntError),
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
}

// Logging denials should be configurable by users but also overridable by the caller.
// Enforcement should only be configured by the caller (e.g. after execve).
//
// TODO: take a Config as optional input to compose configuration snippets.
pub fn parse_config<R>(reader: R) -> Result<Config, serde_json::Error>
where
    R: std::io::Read,
{
    let json = serde_json::from_reader::<R, Config>(reader)?;
    Ok(json)
}

pub fn build_ruleset(
    // TODO: Handle Vec<Config> and automatically merge them.
    config: &Config,
    _file_descriptors: Option<BTreeSet<OwnedFd>>,
) -> Result<RulesetCreated, BuildRulesetError> {
    let mut ruleset = Ruleset::default();
    let ruleset_ref = &mut ruleset;
    for a in &config.ruleset {
        match a {
            JsRuleset::Fs(r) => {
                let access_ref = &r.handledAccessFs;
                let access_fs: BitFlags<AccessFs> = access_ref.into();
                ruleset_ref.set_compatibility((&r.compatibility).into());
                ruleset_ref.handle_access(access_fs)?;
            }
            JsRuleset::Net(r) => {
                let access_ref = &r.handledAccessNet;
                let access_net: BitFlags<AccessNet> = access_ref.into();
                ruleset_ref.set_compatibility((&r.compatibility).into());
                ruleset_ref.handle_access(access_net)?;
            }
        }
    }

    ruleset_ref.set_compatibility(CompatLevel::default());
    let mut ruleset_created = ruleset.create()?;
    let ruleset_created_ref = &mut ruleset_created;

    for rule in config.pathBeneath.iter().flatten() {
        let access_ref = &rule.allowedAccess;
        let access_fs: BitFlags<AccessFs> = access_ref.into();

        // Find in FDs the referenced name
        // WARNING: Will close the related FD (e.g. stdout)
        for fd in &rule.parentFd {
            // TODO: Handle rule.compatibility for fd.
            let parent_fd: File = fd.try_into()?;
            ruleset_created_ref.add_rule(
                PathBeneath::new(parent_fd, access_fs)
                    .set_compatibility((&rule.compatibility).into()),
            )?;
        }
    }

    for rule in config.netPort.iter().flatten() {
        let access_ref = &rule.allowedAccess;
        let access_net: BitFlags<AccessNet> = access_ref.into();

        // Find in FDs the referenced name
        // WARNING: Will close the related FD (e.g. stdout)
        for port in &rule.port {
            ruleset_created_ref.add_rule(
                // TODO: Check integer conversion in parse_config(), which would require changing the type of config and specifying where the error is.
                NetPort::new((*port).try_into()?, access_net)
                    .set_compatibility((&rule.compatibility).into()),
            )?;
        }
    }

    Ok(ruleset_created)
}

pub fn restrict_self(
    ruleset_created: RulesetCreated,
    _config: Option<&Config>,
) -> Result<RestrictionStatus, RulesetError> {
    // With future Landlock features, specified in config, we should be able to change the behavior of restrict_self(): e.g. log flags, context of restriction...
    ruleset_created.restrict_self()
}
