// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{config::ResolvedConfig, tests_helpers::parse_json, Config};
use landlock::{Access, AccessFs, AccessNet, Scope, ABI};
use std::path::PathBuf;

fn test_idempotence(config: &Config) {
    let mut bkp = config.clone();
    bkp.compose(config);
    assert_eq!(bkp, *config);
}

fn get_composition(json1: &str, json2: &str) -> ResolvedConfig {
    let j1 = parse_json(json1).unwrap();
    test_idempotence(&j1);

    let j2 = parse_json(json2).unwrap();
    test_idempotence(&j2);

    let mut c1 = j1.clone();
    c1.compose(&j2);
    test_idempotence(&c1);

    let mut c2 = j2.clone();
    c2.compose(&j1);
    test_idempotence(&c2);

    // Test commutativity
    assert_eq!(c1, c2);

    c1.resolve().unwrap()
}

#[test]
fn test_compose_most_fs_net() {
    let json1 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "v4.all" ],
                "handledAccessNet": [ "v4.all" ],
                "scoped": [ "v6.all" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "v6.all" ],
                "parent": [ "a" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "v6.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::from_all(ABI::V4),
            handled_net: AccessNet::from_all(ABI::V4),
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::from_all(ABI::V4))].into(),
            rules_net_port: [(1, AccessNet::from_all(ABI::V4))].into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_scope() {
    let json1 = r#"{
        "ruleset": [
            {
                "scoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "ruleset": [
            {
                "scoped": [ "v6.all" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            scoped: Scope::AbstractUnixSocket.into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_exclusive() {
    let json1 = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "a" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        // No remaining access rights.
        ResolvedConfig {
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_complement1() {
    let json1 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "read_file" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "a" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::ReadFile.into(),
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::ReadFile.into()),
                (PathBuf::from("b"), AccessFs::ReadFile.into()),
            ]
            .into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_complement2() {
    let json1 = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "a" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::Execute.into()),].into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_standalone_variable() {
    let json1 = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute.into()),
                (PathBuf::from("b"), AccessFs::Execute.into()),
            ]
            .into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_shared_variable() {
    let json1 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "read_file" ]
            }
        ],
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "variable": [
            {
                "name": "foo"
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "${foo}" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "x/${foo}" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("x/a"), AccessFs::ReadFile.into()),
                (PathBuf::from("x/b"), AccessFs::ReadFile.into()),
            ]
            .into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_same_resolved_path() {
    let json1 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "read_file" ]
            }
        ],
        "variable": [
            {
                "name": "foo",
                "literal": [ "a" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "variable": [
            {
                "name": "bar",
                "literal": [ "a" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "${bar}" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile)]
                .into(),
            ..Default::default()
        }
    );
}
