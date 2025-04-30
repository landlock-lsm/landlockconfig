// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::Config;
use landlock::{Access, AccessFs, AccessNet, Scope, ABI};
use serde_json::error::Category;
use serde_json::Value;
use std::path::PathBuf;
use std::{env, fs};

const LATEST_ABI: ABI = ABI::V6;

lazy_static! {
    static ref JSON_VALIDATOR: jsonschema::Validator = {
        let crate_dir = PathBuf::from(
            env::var("CARGO_MANIFEST_DIR")
                .expect("The environment variable CARGO_MANIFEST_DIR is not set"),
        );
        let schema_path = crate_dir.join("schema/landlockconfig.json");
        let schema_str =
            fs::read_to_string(schema_path).expect("Failed to read the JSON schema file");
        let schema: Value = serde_json::from_str(&schema_str).expect("Invalid JSON");
        jsonschema::validator_for(&schema).expect("Invalid JSON schema")
    };
}

fn validate_json(json: &str) -> Result<(), ()> {
    let json = serde_json::from_str::<Value>(json).expect("Invalid JSON");
    JSON_VALIDATOR.validate(&json).map(|_| ()).map_err(|e| {
        eprintln!("JSON schema validation error: {e}");
    })
}

#[test]
fn test_json_schema() {
    let test_json = r#"{
        "ruleset": 0
    }"#;

    validate_json(test_json).expect_err("JSON schema validator should return a type error")
}

fn assert_json(data: &str, ret: Result<(), Category>) {
    assert_eq!(parse_json(data).map(|_| ()), ret);
}

fn parse_json(json: &str) -> Result<Config, Category> {
    let cursor = std::io::Cursor::new(json);
    let parsing = Config::parse_json(cursor).map_err(|e| {
        eprintln!("JSON parsing error: {e}");
        e.classify()
    });

    // Ensures the JSON schema is consistent and stays up-to-date with the crate.
    let valid = validate_json(json);
    if parsing.is_ok() != valid.is_ok() {
        panic!("Inconsistent validation: parser and schema validator disagree");
    }
    parsing
}

fn parse_toml(toml: &str) -> Result<Config, toml::de::Error> {
    Config::parse_toml(toml).map_err(|e| {
        eprintln!("TOML parsing error: {e}");
        e
    })
}

fn assert_versions<F>(first_known_version: ABI, ruleset_property: F)
where
    F: Fn(u32) -> Vec<String>,
{
    let latest_version = LATEST_ABI as u32;
    let known_versions = (first_known_version as u32)..=latest_version;
    let next_version = latest_version + 1;
    for version in 0..=next_version {
        let expected = if known_versions.contains(&version) {
            Ok(())
        } else {
            Err(Category::Data)
        };
        println!("Testing version {version} and expecting {:?}", expected);
        for property in ruleset_property(version) {
            println!("  Testing property {property:?}");
            assert_json(
                format!(
                    r#"{{
                        "ruleset": [
                            {{
                                {property}
                            }}
                        ]
                    }}"#
                )
                .as_ref(),
                expected,
            );
        }
    }
}

// FIXME: Such an empty ruleset doesn't make sense and should not be allowed.
#[test]
fn test_empty_ruleset() {
    let json = r#"{
        "ruleset": []
    }"#;
    assert_eq!(parse_json(json), Ok(Default::default()),);
}

#[test]
fn test_one_handled_access_fs() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_handled_access_fs_json() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [
                    "execute",
                    "write_file",
                    "read_file",
                    "read_dir",
                    "remove_dir",
                    "remove_file",
                    "make_char",
                    "make_dir",
                    "make_reg",
                    "make_sock",
                    "make_fifo",
                    "make_block",
                    "make_sym",
                    "v1.all",
                    "v1.read_execute",
                    "v1.read_write",
                    "refer",
                    "v2.all",
                    "v2.read_execute",
                    "v2.read_write",
                    "truncate",
                    "v3.all",
                    "v3.read_execute",
                    "v3.read_write",
                    "v4.all",
                    "v4.read_execute",
                    "v4.read_write",
                    "ioctl_dev",
                    "v5.all",
                    "v5.read_execute",
                    "v5.read_write",
                    "v6.all",
                    "v6.read_execute",
                    "v6.read_write"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        })
    );
}

#[test]
fn test_all_handled_access_fs_toml() {
    let toml = r#"
        [[ruleset]]
        handled_access_fs = [
            "execute",
            "write_file",
            "read_file",
            "read_dir",
            "remove_dir",
            "remove_file",
            "make_char",
            "make_dir",
            "make_reg",
            "make_sock",
            "make_fifo",
            "make_block",
            "make_sym",
            "v1.all",
            "v1.read_execute",
            "v1.read_write",
            "refer",
            "v2.all",
            "v2.read_execute",
            "v2.read_write",
            "truncate",
            "v3.all",
            "v3.read_execute",
            "v3.read_write",
            "v4.all",
            "v4.read_execute",
            "v4.read_write",
            "ioctl_dev",
            "v5.all",
            "v5.read_execute",
            "v5.read_write",
            "v6.all",
            "v6.read_execute",
            "v6.read_write",
        ]
    "#;
    assert_eq!(
        parse_toml(toml),
        Ok(Config {
            handled_fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        })
    );
}

#[test]
fn test_versions_access_fs() {
    assert_versions(ABI::V1, |version| {
        vec![
            format!(r#""handledAccessFs": [ "v{version}.all" ]"#),
            format!(r#""handledAccessFs": [ "v{version}.read_write" ]"#),
            format!(r#""handledAccessFs": [ "v{version}.read_execute" ]"#),
        ]
    });
}

#[test]
fn test_unknown_ruleset_field() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "foo": []
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data),);
}

#[test]
fn test_dup_handled_access_fs_1() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute", "write_file", "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute | AccessFs::WriteFile,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_handled_access_fs_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "write_file" ]
            },
            {
                "handledAccessFs": [ "execute" ]
            },
            {
                "handledAccessFs": [ "write_file" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute | AccessFs::WriteFile,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_handled_access_fs_1() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_handled_access_fs_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_one_path_beneath_str() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_one_path_beneath_int() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ 2 ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_dup_path_beneath_1() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".", "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_path_beneath_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_overlap_path_beneath() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            },
            {
                "handledAccessFs": [ "read_file", "write_file" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "write_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute", "read_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile,
            rules_path_beneath: [(
                PathBuf::from("."),
                AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile
            )]
            .into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_normalization_path_beneath() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".", "./", ".", "a/./b" ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".//", "a/////b", "c/../c" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [
                (PathBuf::from("."), AccessFs::Execute.into()),
                (PathBuf::from("a/b"), AccessFs::Execute.into()),
                (PathBuf::from("c/../c"), AccessFs::Execute.into()),
            ]
            .into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_one_handled_access_net() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_handled_access_net() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [
                    "bind_tcp",
                    "connect_tcp",
                    "v4.all",
                    "v5.all",
                    "v6.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::from_all(LATEST_ABI),
            ..Default::default()
        }),
    );
}

#[test]
fn test_versions_access_net() {
    assert_versions(ABI::V4, |version| {
        vec![format!(r#""handledAccessNet": [ "v{version}.all" ]"#)]
    });
}

#[test]
fn test_dup_handled_access_net_1() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp", "connect_tcp", "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_handled_access_net_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "connect_tcp" ]
            },
            {
                "handledAccessNet": [ "bind_tcp" ]
            },
            {
                "handledAccessNet": [ "connect_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_handled_access_net_1() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_handled_access_net_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_one_net_port() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp.into(),
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_overlap_net_port() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp", "connect_tcp" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            },
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            },
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            rules_net_port: [(443, AccessNet::BindTcp | AccessNet::ConnectTcp)].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_inconsistent_handled_access() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ],
                "handledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_one_scoped() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            scoped: Scope::AbstractUnixSocket.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_scoped() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [
                    "abstract_unix_socket",
                    "signal",
                    "v6.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            scoped: Scope::from_all(LATEST_ABI),
            ..Default::default()
        }),
    );
}

#[test]
fn test_versions_scope() {
    assert_versions(ABI::V6, |version| {
        vec![format!(r#""scoped": [ "v{version}.all" ]"#)]
    });
}

#[test]
fn test_dup_scoped_1() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [ "abstract_unix_socket", "signal", "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            scoped: Scope::Signal | Scope::AbstractUnixSocket,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_scoped_2() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [ "signal" ]
            },
            {
                "scoped": [ "abstract_unix_socket" ]
            },
            {
                "scoped": [ "signal" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            scoped: Scope::Signal | Scope::AbstractUnixSocket,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_scoped_1() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_scoped_2() {
    let json = r#"{
        "ruleset": [
            {
                "scoped": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

/* Test inference. */

#[test]
fn test_infer_mixed_handled_and_rule() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute.into(),
            handled_net: AccessNet::BindTcp.into(),
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_infer_handled_access_fs() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "write_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute | AccessFs::WriteFile | AccessFs::ReadFile,
            rules_path_beneath: [(PathBuf::from("."), AccessFs::WriteFile | AccessFs::ReadFile)]
                .into(),
            ..Default::default()
        })
    );
}

#[test]
fn test_infer_handled_access_net() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            rules_net_port: [(443, AccessNet::ConnectTcp.into())].into(),
            ..Default::default()
        })
    );
}
