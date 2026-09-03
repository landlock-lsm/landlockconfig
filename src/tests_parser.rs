// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::parser::LATEST_ABI;
use crate::policy::ResolvedPolicy;
use crate::tests_helpers::{parse_json, parse_toml, validate_json};
use crate::Policy;
use landlock::{Access, AccessFs, AccessNet, Scope, ABI};
use serde_json::error::Category;
use std::path::PathBuf;

#[test]
fn test_json_schema() {
    let test_json = r#"{
        "abi": 6,
        "ruleset": 0
    }"#;

    validate_json(test_json).expect_err("JSON schema validator should return a type error")
}

#[test]
fn test_embedded_json_schema() {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schema/landlock-policy.json");
    assert_eq!(
        crate::JSON_SCHEMA,
        std::fs::read_to_string(schema_path).unwrap()
    );
}

/* Test "empty policy" error. */

#[test]
fn test_empty_policy_json_1() {
    let json = r#"{
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_policy_json_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": null
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_policy_toml() {
    let toml = "";
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_null_fields_json() {
    let fields = [
        (
            "abi",
            r#"{
                "abi": null,
                "ruleset": [{ "handledAccessFs": ["execute"] }]
            }"#,
        ),
        (
            "variable",
            r#"{
                "abi": 6,
                "variable": null,
                "ruleset": [{ "handledAccessFs": ["execute"] }]
            }"#,
        ),
        (
            "ruleset",
            r#"{
                "abi": 6,
                "ruleset": null,
                "variable": [{ "name": "foo" }]
            }"#,
        ),
        (
            "pathBeneath",
            r#"{
                "abi": 6,
                "pathBeneath": null,
                "ruleset": [{ "handledAccessFs": ["execute"] }]
            }"#,
        ),
        (
            "netPort",
            r#"{
                "abi": 6,
                "netPort": null,
                "ruleset": [{ "handledAccessFs": ["execute"] }]
            }"#,
        ),
        (
            "handledAccessFs",
            r#"{
                "abi": 6,
                "ruleset": [{
                    "handledAccessFs": null,
                    "handledAccessNet": ["bind_tcp"]
                }]
            }"#,
        ),
        (
            "handledAccessNet",
            r#"{
                "abi": 6,
                "ruleset": [{
                    "handledAccessFs": ["execute"],
                    "handledAccessNet": null
                }]
            }"#,
        ),
        (
            "scoped",
            r#"{
                "abi": 6,
                "ruleset": [{
                    "handledAccessFs": ["execute"],
                    "scoped": null
                }]
            }"#,
        ),
        (
            "literal",
            r#"{
                "abi": 6,
                "variable": [{ "name": "foo", "literal": null }]
            }"#,
        ),
    ];

    for (field, json) in fields {
        println!("Testing null {field}");
        assert_eq!(parse_json(json), Err(Category::Data));
    }
}

/* Test "invalid length 0, expected at least one element" error. */

#[test]
fn test_empty_ruleset_array_json() {
    let json = r#"{
        "abi": 6,
        "ruleset": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_handled_access_fs_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_handled_access_fs_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ ]
            },
            {
                "handledAccessFs": [ "execute" ]
            },
            {
                "handledAccessFs": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data),);
}

#[test]
fn test_empty_handled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessNet": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_scoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "scoped": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_path_beneath() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_path_beneath_access() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_path_beneath_parent() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port() {
    let json = r#"{
        "abi": 6,
        "netPort": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port_access() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port_number() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

/* Test "empty ruleset" error. */

#[test]
fn test_empty_ruleset_json() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {}
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_ruleset_toml() {
    let toml = r#"
        abi = 6
        [[ruleset]]
    "#;
    assert!(parse_toml(toml).is_err());
}

/* Test full ruleset. */

#[test]
fn test_full_ruleset_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ],
                "handledAccessNet": [ "bind_tcp" ],
                "scoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute.into(),
            handled_net: AccessNet::BindTcp.into(),
            scoped: Scope::AbstractUnixSocket.into(),
            ..Default::default()
        })
    );
}

#[test]
fn test_full_ruleset_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp" ],
                "scoped": [ "abstract_unix_socket" ],
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute.into(),
            handled_net: AccessNet::BindTcp.into(),
            scoped: Scope::AbstractUnixSocket.into(),
            ..Default::default()
        })
    );
}

/* Test ruleset's handledAccessFs. */

#[test]
fn test_one_handled_access_fs() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_handled_access_fs_json() {
    let json = format!(
        r#"{{
            "abi": {},
            "ruleset": [
                {{
                    "handledAccessFs": [
                        "abi.all",
                        "abi.read_execute",
                        "abi.read_write",
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
                        "refer",
                        "truncate",
                        "ioctl_dev"
                        ]
                }}
            ]
        }}"#,
        LATEST_ABI as u32
    );
    assert_eq!(
        parse_json(&json),
        Ok(Policy {
            abi: Some(LATEST_ABI),
            handled_fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        })
    );
}

#[test]
fn test_all_handled_access_fs_toml() {
    let toml = format!(
        r#"
        abi = {}
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
            "abi.read_execute",
            "abi.read_write",
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
            "refer",
            "truncate",
            "ioctl_dev",
        ]
        "#,
        LATEST_ABI as u32
    );
    assert_eq!(
        parse_toml(&toml).unwrap(),
        Policy {
            abi: Some(LATEST_ABI),
            handled_fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        }
    );
}

#[test]
fn test_unknown_ruleset_field() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ],
        "foo": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data),);
}

#[test]
fn test_dup_handled_access_fs_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute", "write_file", "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute | AccessFs::WriteFile,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_handled_access_fs_2() {
    let json = r#"{
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute | AccessFs::WriteFile,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_handled_access_fs_1() {
    let json = r#"{
        "abi": 6,
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
        "abi": 6,
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
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_one_path_beneath_int() {
    let json = r#"{
        "abi": 6,
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
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_path_beneath_2() {
    let json = r#"{
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_overlap_path_beneath() {
    let json = r#"{
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
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
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
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

/* Test ruleset's handledAccessNet. */

#[test]
fn test_one_handled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_handled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessNet": [
                    "bind_tcp",
                    "connect_tcp",
                    "abi.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::from_all(ABI::V6),
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_handled_access_net_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessNet": [ "bind_tcp", "connect_tcp", "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_handled_access_net_2() {
    let json = r#"{
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_handled_access_net_1() {
    let json = r#"{
        "abi": 6,
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
        "abi": 6,
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
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp.into(),
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_overlap_net_port() {
    let json = r#"{
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            rules_net_port: [(443, AccessNet::BindTcp | AccessNet::ConnectTcp)].into(),
            ..Default::default()
        }),
    );
}

/* Test ruleset's properties. */

#[test]
fn test_mix_handled_access_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ],
                "handledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute.into(),
            handled_net: AccessNet::BindTcp.into(),
            ..Default::default()
        })
    );
}

#[test]
fn test_mix_handled_access_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ],
                "handledAccessNet": [ "bind_tcp" ]
            },
            {
                "handledAccessNet": [ "connect_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_fs: AccessFs::Execute.into(),
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            ..Default::default()
        })
    );
}

/* Test ruleset's scoped. */

#[test]
fn test_one_scoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "scoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            scoped: Scope::AbstractUnixSocket.into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_all_scoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "scoped": [
                    "abstract_unix_socket",
                    "signal",
                    "abi.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            scoped: Scope::from_all(ABI::V6),
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_scoped_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "scoped": [ "abstract_unix_socket", "signal", "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            scoped: Scope::Signal | Scope::AbstractUnixSocket,
            ..Default::default()
        }),
    );
}

#[test]
fn test_dup_scoped_2() {
    let json = r#"{
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            scoped: Scope::Signal | Scope::AbstractUnixSocket,
            ..Default::default()
        }),
    );
}

#[test]
fn test_unknown_scoped_1() {
    let json = r#"{
        "abi": 6,
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
        "abi": 6,
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
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
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
        "abi": 6,
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
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
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
        "abi": 6,
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
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp | AccessNet::ConnectTcp,
            rules_net_port: [(443, AccessNet::ConnectTcp.into())].into(),
            ..Default::default()
        })
    );
}

#[test]
fn test_path_beneath_alone() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..Default::default()
        })
    );
}

#[test]
fn test_net_port_alone() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            abi: Some(ABI::V6),
            handled_net: AccessNet::BindTcp.into(),
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Default::default()
        })
    );
}
