// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    nonempty::{NonEmptySet, NonEmptyStruct, NonEmptyStructInner},
    variable::{Name, ResolveError},
};
use landlock::{Access, AccessFs, AccessNet, BitFlags, Scope, ABI};
use serde::de::{Unexpected, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TemplateToken {
    Text(String),
    Var(Name),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateString(pub Vec<TemplateToken>);

impl TemplateString {
    #[cfg(test)]
    pub(crate) fn from_text<T>(text: T) -> Self
    where
        T: Into<String>,
    {
        Self(vec![TemplateToken::Text(text.into())])
    }
}

impl std::fmt::Display for TemplateString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for token in &self.0 {
            match token {
                TemplateToken::Text(text) => f.write_str(text)?,
                TemplateToken::Var(var) => write!(f, "${{{}}}", var)?,
            }
        }
        Ok(())
    }
}

impl Serialize for TemplateString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, PartialEq)]
enum TemplateState {
    Text(usize),
    FirstDollar(usize),
    Variable(usize),
}

struct TemplateStringVisitor;

impl<'de> de::Visitor<'de> for TemplateStringVisitor {
    type Value = TemplateString;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string with optional variable references like ${var}")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut tokens = Vec::new();
        let mut state = TemplateState::Text(0);

        let push_text = |tokens: &mut Vec<TemplateToken>, new_text: &str| {
            if !new_text.is_empty() {
                if let Some(TemplateToken::Text(ref mut text)) = tokens.last_mut() {
                    text.push_str(new_text);
                } else {
                    tokens.push(TemplateToken::Text(new_text.to_string()));
                }
            }
        };

        for (i, c) in value.char_indices() {
            state = match state {
                TemplateState::Text(text_start) => match c {
                    '$' => TemplateState::FirstDollar(text_start),
                    _ => TemplateState::Text(text_start),
                },
                TemplateState::FirstDollar(text_start) => match c {
                    '$' => {
                        // Get text up to the second dollar sign
                        push_text(&mut tokens, &value[text_start..i]);
                        TemplateState::Text(i + 1)
                    }
                    '{' => {
                        // Get text up to the beginning of the variable
                        push_text(&mut tokens, &value[text_start..i - 1]);
                        TemplateState::Variable(i + 1)
                    }
                    _ => {
                        // Just a regular dollar followed by something else
                        TemplateState::Text(text_start)
                    }
                },
                TemplateState::Variable(name_start) => match c {
                    '}' => {
                        // Get the variable name
                        let name = Name::from_str(&value[name_start..i]).map_err(|e| {
                            E::custom(format!(
                                "invalid variable name at position {}: {}",
                                name_start - 2,
                                e
                            ))
                        })?;
                        tokens.push(TemplateToken::Var(name));
                        TemplateState::Text(i + 1)
                    }
                    _ => TemplateState::Variable(name_start),
                },
            };
        }

        match state {
            TemplateState::Text(text_start) | TemplateState::FirstDollar(text_start) => {
                // Get text up to the second dollar sign
                push_text(&mut tokens, &value[text_start..]);
            }
            TemplateState::Variable(name_start) => {
                return Err(E::custom(format!(
                    "unclosed variable reference starting at position {}",
                    name_start - 2
                )));
            }
        }

        Ok(TemplateString(tokens))
    }
}

#[cfg(test)]
mod tests_template_string {
    use super::*;
    use serde::de::{Error, Visitor};

    #[derive(Debug, PartialEq)]
    struct TestError(String);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    impl Error for TestError {
        fn custom<T: std::fmt::Display>(msg: T) -> Self {
            TestError(msg.to_string())
        }
    }

    #[test]
    fn test_visit_str_plain_text() {
        assert_eq!(
            TemplateStringVisitor.visit_str::<TestError>("bar").unwrap(),
            TemplateString(vec![TemplateToken::Text("bar".to_string())])
        );
    }

    #[test]
    fn test_visit_str_empty_string() {
        assert_eq!(
            TemplateStringVisitor.visit_str::<TestError>("").unwrap(),
            TemplateString(vec![])
        );
    }

    #[test]
    fn test_visit_str_single_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("${foo}")
                .unwrap(),
            TemplateString(vec![TemplateToken::Var(Name::from_str("foo").unwrap())])
        );
    }

    #[test]
    fn test_visit_str_text_and_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("${foo} bar")
                .unwrap(),
            TemplateString(vec![
                TemplateToken::Var(Name::from_str("foo").unwrap()),
                TemplateToken::Text(" bar".to_string()),
            ])
        );
    }

    #[test]
    fn test_visit_str_multiple_variables() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("${foo} bar ${baz}")
                .unwrap(),
            TemplateString(vec![
                TemplateToken::Var(Name::from_str("foo").unwrap()),
                TemplateToken::Text(" bar ".to_string()),
                TemplateToken::Var(Name::from_str("baz").unwrap())
            ])
        );
    }

    #[test]
    fn test_visit_str_escaped_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("$${escaped}")
                .unwrap(),
            TemplateString(vec![TemplateToken::Text("${escaped}".to_string())])
        );
    }

    #[test]
    fn test_visit_str_escaped_non_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("$$foo")
                .unwrap(),
            TemplateString(vec![TemplateToken::Text("$foo".to_string())])
        );
    }

    #[test]
    fn test_visit_str_escaped_variable_with_text() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("foo $${escaped} baz")
                .unwrap(),
            TemplateString(vec![TemplateToken::Text("foo ${escaped} baz".to_string())])
        );
    }

    #[test]
    fn test_visit_str_unclosed_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("${unclosed")
                .unwrap_err()
                .0,
            "unclosed variable reference starting at position 0"
        );
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>(" ${unclosed")
                .unwrap_err()
                .0,
            "unclosed variable reference starting at position 1"
        );
    }

    #[test]
    fn test_visit_str_invalid_variable_first_char() {
        assert_eq!(TemplateStringVisitor
            .visit_str::<TestError>(" ${0}")
            .unwrap_err()
            .0,
            "invalid variable name at position 1: invalid first character in name (must be ASCII alphabetic): 0");
    }

    #[test]
    fn test_visit_str_invalid_variable_name() {
        assert_eq!(TemplateStringVisitor
            .visit_str::<TestError>("${invalid-name}")
            .unwrap_err()
            .0,
            "invalid variable name at position 0: invalid character(s) in name (must be ASCII alphanumeric or '_'): invalid-name");
    }

    #[test]
    fn test_visit_str_empty_variable() {
        assert_eq!(
            TemplateStringVisitor
                .visit_str::<TestError>("  ${}")
                .unwrap_err()
                .0,
            "invalid variable name at position 2: name cannot be empty"
        );
    }
}

impl<'de> Deserialize<'de> for TemplateString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(TemplateStringVisitor)
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum JsonFsAccessItem {
    #[serde(rename = "abi.all")]
    AbiAll,
    #[serde(rename = "abi.read_execute")]
    AbiReadExecute,
    #[serde(rename = "abi.read_write")]
    AbiReadWrite,
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

trait AbiGroup<A>
where
    A: Access,
{
    fn resolve_bitflags(&self, abi: ABI) -> BitFlags<A>;
}

enum AbiGroupFs {
    All,
    ReadExecute,
    ReadWrite,
}

impl AbiGroup<AccessFs> for AbiGroupFs {
    fn resolve_bitflags(&self, abi: ABI) -> BitFlags<AccessFs> {
        match self {
            Self::All => AccessFs::from_all(abi),
            Self::ReadExecute => {
                AccessFs::from_read(abi) | (AccessFs::from_all(abi) & AccessFs::Refer)
            }
            // from_all() == from_read() | from_write()
            Self::ReadWrite => AccessFs::from_all(abi) & !AccessFs::Execute,
        }
    }
}

type ValueAccessFs = ValueAccess<AccessFs, AbiGroupFs>;

enum ValueAccess<A, G>
where
    A: Access,
    G: AbiGroup<A>,
{
    // TODO: Replace with Value(A) when removing old vN groups.
    Value(BitFlags<A>),
    Group(G),
}

impl<A, G> ValueAccess<A, G>
where
    A: Access,
    G: AbiGroup<A>,
{
    fn resolve_bitflags<V>(access: V, abi: Option<ABI>) -> Result<BitFlags<A>, ResolveError>
    where
        V: Into<Self>,
    {
        match access.into() {
            Self::Value(a) => Ok(a),
            Self::Group(g) => {
                // Simulate a missing variable
                Ok(g.resolve_bitflags(
                    abi.ok_or(ResolveError::VariableNotFound(Name::from_str("abi")?))?,
                ))
            }
        }
    }
}

impl<A, G> From<A> for ValueAccess<A, G>
where
    A: Access,
    G: AbiGroup<A>,
{
    fn from(access: A) -> Self {
        Self::Value(access.into())
    }
}

impl<A, G> From<BitFlags<A>> for ValueAccess<A, G>
where
    A: Access,
    G: AbiGroup<A>,
{
    fn from(a: BitFlags<A>) -> Self {
        Self::Value(a)
    }
}

impl From<&JsonFsAccessItem> for ValueAccessFs {
    fn from(js: &JsonFsAccessItem) -> Self {
        match js {
            JsonFsAccessItem::AbiAll => Self::Group(AbiGroupFs::All),
            JsonFsAccessItem::AbiReadExecute => Self::Group(AbiGroupFs::ReadExecute),
            JsonFsAccessItem::AbiReadWrite => Self::Group(AbiGroupFs::ReadWrite),
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
            JsonFsAccessItem::V1All => AbiGroupFs::All.resolve_bitflags(ABI::V1).into(),
            JsonFsAccessItem::V1ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V1).into()
            }
            JsonFsAccessItem::V1ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V1).into(),
            JsonFsAccessItem::Refer => AccessFs::Refer.into(),
            JsonFsAccessItem::V2All => AbiGroupFs::All.resolve_bitflags(ABI::V2).into(),
            JsonFsAccessItem::V2ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V2).into()
            }
            JsonFsAccessItem::V2ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V2).into(),
            JsonFsAccessItem::Truncate => AccessFs::Truncate.into(),
            JsonFsAccessItem::V3All => AbiGroupFs::All.resolve_bitflags(ABI::V3).into(),
            JsonFsAccessItem::V3ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V3).into()
            }
            JsonFsAccessItem::V3ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V3).into(),
            JsonFsAccessItem::V4All => AbiGroupFs::All.resolve_bitflags(ABI::V4).into(),
            JsonFsAccessItem::V4ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V4).into()
            }
            JsonFsAccessItem::V4ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V4).into(),
            JsonFsAccessItem::IoctlDev => AccessFs::IoctlDev.into(),
            JsonFsAccessItem::V5All => AbiGroupFs::All.resolve_bitflags(ABI::V5).into(),
            JsonFsAccessItem::V5ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V5).into()
            }
            JsonFsAccessItem::V5ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V5).into(),
            JsonFsAccessItem::V6All => AbiGroupFs::All.resolve_bitflags(ABI::V6).into(),
            JsonFsAccessItem::V6ReadExecute => {
                AbiGroupFs::ReadExecute.resolve_bitflags(ABI::V6).into()
            }
            JsonFsAccessItem::V6ReadWrite => AbiGroupFs::ReadWrite.resolve_bitflags(ABI::V6).into(),
        }
    }
}

#[test]
fn test_v1_read_execute() {
    let rx = ValueAccessFs::resolve_bitflags(&JsonFsAccessItem::V1ReadExecute, None).unwrap();
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
    let rx = ValueAccessFs::resolve_bitflags(&JsonFsAccessItem::V2ReadExecute, None).unwrap();
    assert!(rx.contains(AccessFs::Execute));
    assert!(rx.contains(AccessFs::Refer));
}

#[test]
fn test_v1_read_write() {
    let rw = ValueAccessFs::resolve_bitflags(&JsonFsAccessItem::V1ReadWrite, None).unwrap();
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
    let rw = ValueAccessFs::resolve_bitflags(&JsonFsAccessItem::V2ReadWrite, None).unwrap();
    assert!(!rw.contains(AccessFs::Execute));
    assert!(rw.contains(AccessFs::Refer));
}

impl NonEmptySet<JsonFsAccessItem> {
    pub fn resolve_bitflags(&self, abi: Option<ABI>) -> Result<BitFlags<AccessFs>, ResolveError> {
        self.iter().try_fold(BitFlags::EMPTY, |flags, item| {
            let access = ValueAccessFs::resolve_bitflags(item, abi)?;
            Ok(flags | access)
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum JsonNetAccessItem {
    #[serde(rename = "abi.all")]
    AbiAll,
    BindTcp,
    ConnectTcp,
    #[serde(rename = "v4.all")]
    V4All,
    #[serde(rename = "v5.all")]
    V5All,
    #[serde(rename = "v6.all")]
    V6All,
}

enum AbiGroupNet {
    All,
}

impl AbiGroup<AccessNet> for AbiGroupNet {
    fn resolve_bitflags(&self, abi: ABI) -> BitFlags<AccessNet> {
        match self {
            Self::All => AccessNet::from_all(abi),
        }
    }
}

type ValueAccessNet = ValueAccess<AccessNet, AbiGroupNet>;

impl From<&JsonNetAccessItem> for ValueAccessNet {
    fn from(js: &JsonNetAccessItem) -> Self {
        match js {
            JsonNetAccessItem::AbiAll => Self::Group(AbiGroupNet::All),
            JsonNetAccessItem::BindTcp => AccessNet::BindTcp.into(),
            JsonNetAccessItem::ConnectTcp => AccessNet::ConnectTcp.into(),
            JsonNetAccessItem::V4All => AbiGroupNet::All.resolve_bitflags(ABI::V4).into(),
            JsonNetAccessItem::V5All => AbiGroupNet::All.resolve_bitflags(ABI::V5).into(),
            JsonNetAccessItem::V6All => AbiGroupNet::All.resolve_bitflags(ABI::V6).into(),
        }
    }
}

impl NonEmptySet<JsonNetAccessItem> {
    pub fn resolve_bitflags(&self, abi: Option<ABI>) -> Result<BitFlags<AccessNet>, ResolveError> {
        self.iter().try_fold(BitFlags::EMPTY, |flags, item| {
            let access = ValueAccessNet::resolve_bitflags(item, abi)?;
            Ok(flags | access)
        })
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum JsonScopeItem {
    #[serde(rename = "abi.all")]
    AbiAll,
    AbstractUnixSocket,
    Signal,
    #[serde(rename = "v6.all")]
    V6All,
}

enum AbiGroupScope {
    All,
}

impl AbiGroup<Scope> for AbiGroupScope {
    fn resolve_bitflags(&self, abi: ABI) -> BitFlags<Scope> {
        match self {
            Self::All => Scope::from_all(abi),
        }
    }
}

type ValueScope = ValueAccess<Scope, AbiGroupScope>;

impl From<&JsonScopeItem> for ValueScope {
    fn from(js: &JsonScopeItem) -> Self {
        match js {
            JsonScopeItem::AbiAll => Self::Group(AbiGroupScope::All),
            JsonScopeItem::AbstractUnixSocket => Scope::AbstractUnixSocket.into(),
            JsonScopeItem::Signal => Scope::Signal.into(),
            JsonScopeItem::V6All => AbiGroupScope::All.resolve_bitflags(ABI::V6).into(),
        }
    }
}

impl NonEmptySet<JsonScopeItem> {
    pub fn resolve_bitflags(&self, abi: Option<ABI>) -> Result<BitFlags<Scope>, ResolveError> {
        self.iter().try_fold(BitFlags::EMPTY, |flags, item| {
            let access = ValueScope::resolve_bitflags(item, abi)?;
            Ok(flags | access)
        })
    }
}

// At least one of the fields must be set, which is guaranteed when wrapped with NonEmptyStruct.
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub(crate) struct JsonRuleset {
    pub(crate) handledAccessFs: Option<NonEmptySet<JsonFsAccessItem>>,
    pub(crate) handledAccessNet: Option<NonEmptySet<JsonNetAccessItem>>,
    pub(crate) scoped: Option<NonEmptySet<JsonScopeItem>>,
}

impl NonEmptyStructInner for JsonRuleset {
    const ERROR_MESSAGE: &'static str = "empty ruleset";

    fn is_empty(&self) -> bool {
        self.handledAccessFs
            .as_ref()
            .is_none_or(|set| set.is_empty())
            && self
                .handledAccessNet
                .as_ref()
                .is_none_or(|set| set.is_empty())
            && self.scoped.as_ref().is_none_or(|set| set.is_empty())
    }
}

// At least one of the fields must be set, which is guaranteed when wrapped with NonEmptyStruct.
#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlRuleset {
    handled_access_fs: Option<NonEmptySet<JsonFsAccessItem>>,
    handled_access_net: Option<NonEmptySet<JsonNetAccessItem>>,
    scoped: Option<NonEmptySet<JsonScopeItem>>,
}

impl NonEmptyStructInner for TomlRuleset {
    const ERROR_MESSAGE: &'static str = "empty ruleset";

    fn is_empty(&self) -> bool {
        self.handled_access_fs
            .as_ref()
            .is_none_or(|set| set.is_empty())
            && self
                .handled_access_net
                .as_ref()
                .is_none_or(|set| set.is_empty())
            && self.scoped.as_ref().is_none_or(|set| set.is_empty())
    }
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
    pub(crate) allowedAccess: NonEmptySet<JsonFsAccessItem>,
    pub(crate) parent: NonEmptySet<TemplateString>,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlPathBeneath {
    allowed_access: NonEmptySet<JsonFsAccessItem>,
    parent: NonEmptySet<TemplateString>,
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
    pub(crate) allowedAccess: NonEmptySet<JsonNetAccessItem>,
    pub(crate) port: NonEmptySet<u64>,
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
struct TomlNetPort {
    allowed_access: NonEmptySet<JsonNetAccessItem>,
    port: NonEmptySet<u64>,
}

impl From<TomlNetPort> for JsonNetPort {
    fn from(toml: TomlNetPort) -> Self {
        Self {
            allowedAccess: toml.allowed_access,
            port: toml.port,
        }
    }
}

struct JsonAbiVisitor;

impl JsonAbiVisitor {
    fn visit_integer<E, I>(value: I, unexpected: Unexpected) -> Result<JsonAbi, E>
    where
        E: de::Error,
        I: TryInto<i32>,
    {
        match value.try_into() {
            Ok(abi) if abi > 0 => Ok(JsonAbi(abi)),
            _ => Err(E::invalid_value(
                unexpected,
                &"ABI version must be between 1 and 2^31 - 1 (inclusive)",
            )),
        }
    }
}

impl<'de> Visitor<'de> for JsonAbiVisitor {
    type Value = JsonAbi;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Landlock ABI version")
    }

    // u64 deserialization is needed for JSON.
    fn visit_u64<E>(self, value: u64) -> Result<JsonAbi, E>
    where
        E: de::Error,
    {
        Self::visit_integer(value, Unexpected::Unsigned(value))
    }

    // i64 deserialization is needed for TOML.
    fn visit_i64<E>(self, value: i64) -> Result<JsonAbi, E>
    where
        E: de::Error,
    {
        Self::visit_integer(value, Unexpected::Signed(value))
    }
}

#[derive(Debug)]
pub(crate) struct JsonAbi(i32);

impl From<JsonAbi> for ABI {
    fn from(abi: JsonAbi) -> Self {
        abi.0.into()
    }
}

impl<'de> serde::Deserialize<'de> for JsonAbi {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_u64(JsonAbiVisitor)
    }
}

#[derive(Debug, Deserialize, Ord, Eq, PartialOrd, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub(crate) struct JsonVariable {
    pub(crate) name: String,
    pub(crate) literal: Option<NonEmptySet<String>>,
}

type TomlVariable = JsonVariable;

// At least one of the fields must be set, which is guaranteed when wrapped with NonEmptyStruct.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub(crate) struct JsonConfig {
    pub(crate) abi: Option<JsonAbi>,
    pub(crate) variable: Option<NonEmptySet<JsonVariable>>,
    pub(crate) ruleset: Option<NonEmptySet<NonEmptyStruct<JsonRuleset>>>,
    pub(crate) pathBeneath: Option<NonEmptySet<JsonPathBeneath>>,
    pub(crate) netPort: Option<NonEmptySet<JsonNetPort>>,
}

impl NonEmptyStructInner for JsonConfig {
    const ERROR_MESSAGE: &'static str = "empty configuration";

    fn is_empty(&self) -> bool {
        self.variable.as_ref().is_none_or(|set| set.is_empty())
            && self.ruleset.as_ref().is_none_or(|set| set.is_empty())
            && self.pathBeneath.as_ref().is_none_or(|set| set.is_empty())
            && self.netPort.as_ref().is_none_or(|set| set.is_empty())
    }
}

// At least one of the fields must be set, which is guaranteed when wrapped with NonEmptyStruct.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlConfig {
    abi: Option<JsonAbi>,
    variable: Option<NonEmptySet<TomlVariable>>,
    ruleset: Option<NonEmptySet<NonEmptyStruct<TomlRuleset>>>,
    path_beneath: Option<NonEmptySet<TomlPathBeneath>>,
    net_port: Option<NonEmptySet<TomlNetPort>>,
}

impl NonEmptyStructInner for TomlConfig {
    const ERROR_MESSAGE: &'static str = "empty configuration";

    fn is_empty(&self) -> bool {
        self.variable.as_ref().is_none_or(|set| set.is_empty())
            && self.ruleset.as_ref().is_none_or(|set| set.is_empty())
            && self.path_beneath.as_ref().is_none_or(|set| set.is_empty())
            && self.net_port.as_ref().is_none_or(|set| set.is_empty())
    }
}

impl From<TomlConfig> for JsonConfig {
    fn from(toml: TomlConfig) -> Self {
        Self {
            abi: toml.abi,
            variable: toml.variable,
            ruleset: toml
                .ruleset
                .map(|set| set.into_iter().map(|r| r.convert()).collect()),
            pathBeneath: toml
                .path_beneath
                .map(|set| set.into_iter().map(Into::into).collect()),
            netPort: toml
                .net_port
                .map(|set| set.into_iter().map(Into::into).collect()),
        }
    }
}
