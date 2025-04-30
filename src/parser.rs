// SPDX-License-Identifier: Apache-2.0 OR MIT

use landlock::{Access, AccessFs, AccessNet, BitFlags, Scope, ABI};
use serde::Deserialize;
use std::collections::BTreeSet;

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
    #[serde(rename = "v6.all")]
    V6All,
    #[serde(rename = "v6.read_execute")]
    V6ReadExecute,
    #[serde(rename = "v6.read_write")]
    V6ReadWrite,
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
            JsonFsAccessItem::V6All => AccessFs::from_all(ABI::V6),
            JsonFsAccessItem::V6ReadExecute => get_fs_read_execute(ABI::V6),
            JsonFsAccessItem::V6ReadWrite => get_fs_read_write(ABI::V6),
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
pub(crate) struct JsonFsAccessSet(BTreeSet<JsonFsAccessItem>);

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
    #[serde(rename = "v6.all")]
    V6All,
}

impl From<&JsonNetAccessItem> for BitFlags<AccessNet> {
    fn from(js: &JsonNetAccessItem) -> Self {
        match js {
            JsonNetAccessItem::BindTcp => AccessNet::BindTcp.into(),
            JsonNetAccessItem::ConnectTcp => AccessNet::ConnectTcp.into(),
            JsonNetAccessItem::V4All => AccessNet::from_all(ABI::V4),
            JsonNetAccessItem::V5All => AccessNet::from_all(ABI::V5),
            JsonNetAccessItem::V6All => AccessNet::from_all(ABI::V6),
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonNetAccessSet(BTreeSet<JsonNetAccessItem>);

impl From<&JsonNetAccessSet> for BitFlags<AccessNet> {
    fn from(set: &JsonNetAccessSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let access: BitFlags<AccessNet> = item.into();
            flags | access
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum JsonScopeItem {
    AbstractUnixSocket,
    Signal,
    #[serde(rename = "v6.all")]
    V6All,
}

impl From<&JsonScopeItem> for BitFlags<Scope> {
    fn from(js: &JsonScopeItem) -> Self {
        match js {
            JsonScopeItem::AbstractUnixSocket => Scope::AbstractUnixSocket.into(),
            JsonScopeItem::Signal => Scope::Signal.into(),
            JsonScopeItem::V6All => Scope::from_all(ABI::V6),
        }
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonScopeSet(BTreeSet<JsonScopeItem>);

impl From<&JsonScopeSet> for BitFlags<Scope> {
    fn from(set: &JsonScopeSet) -> Self {
        set.0.iter().fold(BitFlags::EMPTY, |flags, item| {
            let scope: BitFlags<Scope> = item.into();
            flags | scope
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub(crate) struct JsonRuleset {
    pub(crate) handledAccessFs: Option<JsonFsAccessSet>,
    pub(crate) handledAccessNet: Option<JsonNetAccessSet>,
    pub(crate) scoped: Option<JsonScopeSet>,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlRuleset {
    handled_access_fs: Option<JsonFsAccessSet>,
    handled_access_net: Option<JsonNetAccessSet>,
    scoped: Option<JsonScopeSet>,
}

impl From<TomlRuleset> for JsonRuleset {
    fn from(toml: TomlRuleset) -> Self {
        Self {
            handledAccessFs: toml.handled_access_fs,
            handledAccessNet: toml.handled_access_net,
            scoped: toml.scoped,
        }
    }
}

// TODO: Make paths canonical (e.g. remove extra slashes and dots) and only open the same paths
// once.
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub(crate) struct JsonPathBeneath {
    pub(crate) allowedAccess: JsonFsAccessSet,
    pub(crate) parent: BTreeSet<String>,
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
pub(crate) struct JsonNetPort {
    pub allowedAccess: JsonNetAccessSet,
    pub port: BTreeSet<u64>,
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
pub(crate) struct JsonConfig {
    pub(crate) ruleset: BTreeSet<JsonRuleset>,
    pub(crate) pathBeneath: Option<BTreeSet<JsonPathBeneath>>,
    pub(crate) netPort: Option<BTreeSet<JsonNetPort>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlConfig {
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
