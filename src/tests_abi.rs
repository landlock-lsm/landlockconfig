// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    parser::TemplateString,
    tests_helpers::{parse_json, parse_json_schema, parse_toml, LATEST_ABI},
    Config,
};
use landlock::{Access, AccessFs, AccessNet, Scope, ABI};
use serde_json::error::Category;

#[test]
fn test_access_fs_with_value() {
    let json = r#"{
        "abi": 2,
        "ruleset": [
            {
                "handledAccessFs": [
                    "abi.all"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    let config = Config {
        abi: Some(ABI::V2),
        handled_fs: AccessFs::from_all(ABI::V2),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), config);
    assert_eq!(parse_toml(toml).unwrap(), config);
}

#[test]
fn test_access_fs_without_value() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [
                    "abi.all"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_format_error() {
    let json = r#"{
        "abi": 1
    }"#;
    let toml = r#"
        abi = 1
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_format_ok() {
    let json = r#"{
        "abi": 1,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    let config = Config {
        abi: Some(ABI::V1),
        handled_fs: AccessFs::Execute.into(),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), config);
    assert_eq!(parse_toml(toml).unwrap(), config);
}

#[test]
fn test_dup_abi() {
    let json = r#"{
        "abi": 1,
        "abi": 1,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        abi = 1
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    // Test that duplicate 'abi' fields are rejected by the parser.  Uses
    // parse_json_schema(json, false) because duplicate field rejection is a
    // parser-level concern, not schema-level (JSON schema assumes valid JSON).
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_all_versions_abi_all() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "handledAccessFs": [ "abi.all" ],
                        "handledAccessNet": [ "abi.all" ],
                        "scoped": [ "abi.all" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.all" ],
                        "parent": [ "." ]
                    }}
                ],
                "netPort": [
                    {{
                        "allowedAccess": [ "abi.all" ],
                        "port": [ 1 ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            handled_access_fs = [ "abi.all" ]
            handled_access_net = [ "abi.all" ]
            scoped = [ "abi.all" ]
            [[path_beneath]]
            allowed_access = [ "abi.all" ]
            parent = [ "." ]
            [[net_port]]
            allowed_access = [ "abi.all" ]
            port = [ 1 ]
            "#,
            version
        );

        let abi = version.into();
        let mut config = Config {
            abi: Some(abi),
            handled_fs: AccessFs::from_all(abi),
            handled_net: AccessNet::from_all(abi),
            scoped: Scope::from_all(abi),
            rules_path_beneath: [(TemplateString::from_text("."), AccessFs::from_all(abi))].into(),
            ..Default::default()
        };
        if abi >= ABI::V4 {
            // Do not add rules with empty access right.
            config.rules_net_port = [(1, AccessNet::from_all(abi))].into();
        }
        println!("Testing ABI {version} and expecting {config:?}");
        assert_eq!(parse_json(&json).unwrap(), config);
        assert_eq!(parse_toml(&toml).unwrap(), config);
    }
}

#[test]
fn test_all_versions_abi_read_execute() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "handledAccessFs": [ "abi.read_execute" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.read_execute" ],
                        "parent": [ "." ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            handled_access_fs = [ "abi.read_execute" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_execute" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let expected_access =
            AccessFs::from_read(abi) | (AccessFs::from_all(abi) & AccessFs::Refer);

        let config = Config {
            abi: Some(abi),
            handled_fs: expected_access,
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Default::default()
        };
        println!("Testing ABI {version} read_execute and expecting {config:?}");
        assert_eq!(parse_json(&json).unwrap(), config);
        assert_eq!(parse_toml(&toml).unwrap(), config);
    }
}

#[test]
fn test_all_versions_abi_read_write() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "handledAccessFs": [ "abi.read_write" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.read_write" ],
                        "parent": [ "." ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            handled_access_fs = [ "abi.read_write" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_write" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let expected_access = AccessFs::from_all(abi) & !AccessFs::Execute;

        let config = Config {
            abi: Some(abi),
            handled_fs: expected_access,
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Default::default()
        };
        println!("Testing ABI {version} read_write and expecting {config:?}");
        assert_eq!(parse_json(&json).unwrap(), config);
        assert_eq!(parse_toml(&toml).unwrap(), config);
    }
}

#[test]
fn test_zero() {
    let json = r#"{
        "abi": 0,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 0
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_negative() {
    let json = r#"{
        "abi": -1,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = -1
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_i32() {
    // 2^31 - 1
    let json = r#"{
        "abi": 2147483647,
        "ruleset": [
            {
                "handledAccessFs": [ "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2147483647
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    let abi = ABI::from(2147483647);
    // To not require perfect syncing between this crate and the Landlock crate,
    // only check that the returned ABI is greater than or equal to the
    // currently greatest ABI.
    assert!(abi >= LATEST_ABI);
    let config = Config {
        abi: Some(abi),
        handled_fs: AccessFs::from_all(abi),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), config);
    assert_eq!(parse_toml(toml).unwrap(), config);
}

#[test]
fn test_p31() {
    // 2^31
    let json = r#"{
        "abi": 2147483648,
        "ruleset": [
            {
                "handledAccessFs": [ "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2147483648
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p32() {
    // 2^32
    let json = r#"{
        "abi": 4294967295,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 4294967295
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p64() {
    // 2^64
    let json = r#"{
        "abi": 18446744073709551616,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 18446744073709551616
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p128() {
    // 2^128
    let json = r#"{
        "abi": 340282366920938463463374607431768211456,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 340282366920938463463374607431768211456
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}
