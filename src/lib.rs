use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, ABI,
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

impl From<&JsFsAccessItem> for BitFlags<AccessFs> {
    fn from(js: &JsFsAccessItem) -> Self {
        match js {
            JsFsAccessItem::Execute => AccessFs::Execute.into(),
            JsFsAccessItem::WriteFile => AccessFs::WriteFile.into(),
            JsFsAccessItem::ReadFile => AccessFs::ReadFile.into(),
            JsFsAccessItem::ReadDir => AccessFs::ReadDir.into(),
            JsFsAccessItem::RemoveDir => AccessFs::RemoveDir.into(),
            JsFsAccessItem::RemoveFile => AccessFs::RemoveFile.into(),
            JsFsAccessItem::MakeChar => AccessFs::MakeChar.into(),
            JsFsAccessItem::MakeDir => AccessFs::MakeDir.into(),
            JsFsAccessItem::MakeReg => AccessFs::MakeReg.into(),
            JsFsAccessItem::MakeSock => AccessFs::MakeSock.into(),
            JsFsAccessItem::MakeFifo => AccessFs::MakeFifo.into(),
            JsFsAccessItem::MakeBlock => AccessFs::MakeBlock.into(),
            JsFsAccessItem::MakeSym => AccessFs::MakeSym.into(),
            JsFsAccessItem::V1All => AccessFs::from_all(ABI::V1),
            JsFsAccessItem::V1ReadExecute => get_fs_read_execute(ABI::V1),
            JsFsAccessItem::V1ReadWrite => get_fs_read_write(ABI::V1),
            JsFsAccessItem::Refer => AccessFs::Refer.into(),
            JsFsAccessItem::V2All => AccessFs::from_all(ABI::V2),
            JsFsAccessItem::V2ReadExecute => get_fs_read_execute(ABI::V2),
            JsFsAccessItem::V2ReadWrite => get_fs_read_write(ABI::V2),
            JsFsAccessItem::Truncate => AccessFs::Truncate.into(),
            JsFsAccessItem::V3All => AccessFs::from_all(ABI::V3),
            JsFsAccessItem::V3ReadExecute => get_fs_read_execute(ABI::V3),
            JsFsAccessItem::V3ReadWrite => get_fs_read_write(ABI::V3),
            JsFsAccessItem::V4All => AccessFs::from_all(ABI::V4),
            JsFsAccessItem::V4ReadExecute => get_fs_read_execute(ABI::V4),
            JsFsAccessItem::V4ReadWrite => get_fs_read_write(ABI::V4),
            JsFsAccessItem::IoctlDev => AccessFs::IoctlDev.into(),
            JsFsAccessItem::V5All => AccessFs::from_all(ABI::V5),
            JsFsAccessItem::V5ReadExecute => get_fs_read_execute(ABI::V5),
            JsFsAccessItem::V5ReadWrite => get_fs_read_write(ABI::V5),
        }
    }
}

#[test]
fn test_v1_read_execute() {
    let rx: BitFlags<AccessFs> = (&JsFsAccessItem::V1ReadExecute).into();
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
    let rx: BitFlags<AccessFs> = (&JsFsAccessItem::V2ReadExecute).into();
    assert!(rx.contains(AccessFs::Execute));
    assert!(rx.contains(AccessFs::Refer));
}

#[test]
fn test_v1_read_write() {
    let rw: BitFlags<AccessFs> = (&JsFsAccessItem::V1ReadWrite).into();
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
    let rw: BitFlags<AccessFs> = (&JsFsAccessItem::V2ReadWrite).into();
    assert!(!rw.contains(AccessFs::Execute));
    assert!(rw.contains(AccessFs::Refer));
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsFsAccessSet(BTreeSet<JsFsAccessItem>);

impl From<&JsFsAccessSet> for BitFlags<AccessFs> {
    fn from(set: &JsFsAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: BitFlags<AccessFs> = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsNetAccessItem {
    BindTcp,
    ConnectTcp,
    #[serde(rename = "v4.all")]
    V4All,
    #[serde(rename = "v5.all")]
    V5All,
}

impl From<&JsNetAccessItem> for BitFlags<AccessNet> {
    fn from(js: &JsNetAccessItem) -> Self {
        match js {
            JsNetAccessItem::BindTcp => AccessNet::BindTcp.into(),
            JsNetAccessItem::ConnectTcp => AccessNet::ConnectTcp.into(),
            JsNetAccessItem::V4All => AccessNet::from_all(ABI::V4),
            JsNetAccessItem::V5All => AccessNet::from_all(ABI::V5),
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsNetAccessSet(BTreeSet<JsNetAccessItem>);

impl From<&JsNetAccessSet> for BitFlags<AccessNet> {
    fn from(set: &JsNetAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: BitFlags<AccessNet> = item.into();
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
