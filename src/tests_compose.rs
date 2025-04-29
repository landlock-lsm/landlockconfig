// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{config::ResolvedConfig, tests_helpers::parse_json, Config};
use landlock::AccessFs;
use std::path::PathBuf;

fn get_compositions(json1: &str, json2: &str) -> (Config, Config) {
    let mut c1 = parse_json(json1).unwrap();
    c1.compose(&parse_json(json2).unwrap());

    let mut c2 = parse_json(json2).unwrap();
    c2.compose(&parse_json(json1).unwrap());

    (c1, c2)
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

    let (c1, c2) = get_compositions(json1, json2);
    // Test commutativity
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
            ]
            .into(),
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

    let (c1, c2) = get_compositions(json1, json2);
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
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

    let (c1, c2) = get_compositions(json1, json2);
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::ReadFile.into()),
            ]
            .into(),
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

    let (c1, c2) = get_compositions(json1, json2);
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
            ]
            .into(),
            ..Default::default()
        }
    );
}

#[test]
fn test_compose_shared_variable() {
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

    let (c1, c2) = get_compositions(json1, json2);
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
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

    let (c1, c2) = get_compositions(json1, json2);
    assert_eq!(c1, c2);
    assert_eq!(
        c1.resolve().unwrap(),
        ResolvedConfig {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile)]
                .into(),
            ..Default::default()
        }
    );
}
