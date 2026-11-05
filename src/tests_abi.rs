// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    parser::{TemplateString, LATEST_ABI},
    policy::{ParseJsonError, ParseTomlError, PolicyError},
    tests_helpers::{parse_json, parse_json_schema, parse_toml},
    Policy,
};
use landlock::{Access, AccessFs, AccessNet, LandlockStatus, RulesetStatus, Scope, ABI};
use serde_json::error::Category;

fn assert_access_abi_error(
    json: &str,
    toml: &str,
    category: &'static str,
    name: &'static str,
    policy_abi: ABI,
    required_abi: ABI,
) {
    let json_error = Policy::parse_json(std::io::Cursor::new(json)).unwrap_err();
    assert!(matches!(
        &json_error,
        ParseJsonError::Policy(PolicyError::AccessRightAbi {
            category: actual_category,
            name: actual_name,
            policy_abi: actual_policy_abi,
            required_abi: actual_required_abi,
        }) if *actual_category == category
            && *actual_name == name
            && *actual_policy_abi == policy_abi
            && *actual_required_abi == required_abi
    ));
    assert_eq!(
        json_error.to_string(),
        format!(
            "{category} '{name}' requires ABI {required_abi}, but the policy uses ABI {policy_abi}"
        )
    );
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));

    let toml_error = Policy::parse_toml(toml).unwrap_err();
    assert!(matches!(
        &toml_error,
        ParseTomlError::Policy(PolicyError::AccessRightAbi {
            category: actual_category,
            name: actual_name,
            policy_abi: actual_policy_abi,
            required_abi: actual_required_abi,
        }) if *actual_category == category
            && *actual_name == name
            && *actual_policy_abi == policy_abi
            && *actual_required_abi == required_abi
    ));
    assert_eq!(
        toml_error.to_string(),
        format!(
            "{category} '{name}' requires ABI {required_abi}, but the policy uses ABI {policy_abi}"
        )
    );
}

fn assert_uncovered_exception(
    json: &str,
    toml: &str,
    category: &'static str,
    name: &'static str,
    policy_abi: ABI,
) {
    let json_error = Policy::parse_json(std::io::Cursor::new(json)).unwrap_err();
    assert!(matches!(
        &json_error,
        ParseJsonError::Policy(PolicyError::AccessExceptionUncovered {
            category: actual_category,
            name: actual_name,
            policy_abi: actual_policy_abi,
        }) if *actual_category == category
            && *actual_name == name
            && *actual_policy_abi == policy_abi
    ));
    assert!(json_error
        .to_string()
        .contains("requires an explicit positive ABI group"));
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));

    let toml_error = Policy::parse_toml(toml).unwrap_err();
    assert!(matches!(
        &toml_error,
        ParseTomlError::Policy(PolicyError::AccessExceptionUncovered {
            category: actual_category,
            name: actual_name,
            policy_abi: actual_policy_abi,
        }) if *actual_category == category
            && *actual_name == name
            && *actual_policy_abi == policy_abi
    ));
    assert!(toml_error
        .to_string()
        .contains("requires an explicit positive ABI group"));
}

fn assert_access_contradiction(json: &str, toml: &str, category: &'static str, name: &'static str) {
    let json_error = Policy::parse_json(std::io::Cursor::new(json)).unwrap_err();
    assert!(matches!(
        &json_error,
        ParseJsonError::Policy(PolicyError::AccessContradiction {
            category: actual_category,
            name: actual_name,
        }) if *actual_category == category && *actual_name == name
    ));
    assert!(json_error
        .to_string()
        .contains("both included and excluded"));
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));

    let toml_error = Policy::parse_toml(toml).unwrap_err();
    assert!(matches!(
        &toml_error,
        ParseTomlError::Policy(PolicyError::AccessContradiction {
            category: actual_category,
            name: actual_name,
        }) if *actual_category == category && *actual_name == name
    ));
    assert!(toml_error
        .to_string()
        .contains("both included and excluded"));
}

fn assert_rule_access_conflict(json: &str, toml: &str, category: &'static str, name: &'static str) {
    let json_error = Policy::parse_json(std::io::Cursor::new(json)).unwrap_err();
    assert!(matches!(
        &json_error,
        ParseJsonError::Policy(PolicyError::RuleAccessConflict {
            category: actual_category,
            name: actual_name,
        }) if *actual_category == category && *actual_name == name
    ));
    assert!(json_error.to_string().contains("use an ABI group"));
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));

    let toml_error = Policy::parse_toml(toml).unwrap_err();
    assert!(matches!(
        &toml_error,
        ParseTomlError::Policy(PolicyError::RuleAccessConflict {
            category: actual_category,
            name: actual_name,
        }) if *actual_category == category && *actual_name == name
    ));
}

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

    let policy = Policy {
        abi: Some(ABI::V2),
        handled_fs: AccessFs::from_all(ABI::V2),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_filesystem_access_abi_boundaries() {
    for (policy_abi, required_abi, name, access) in [
        (ABI::V1, ABI::V2, "refer", AccessFs::Refer),
        (ABI::V2, ABI::V3, "truncate", AccessFs::Truncate),
        (ABI::V4, ABI::V5, "ioctl_dev", AccessFs::IoctlDev),
    ] {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [{{ "handledAccessFs": ["{name}"] }}]
            }}"#,
            policy_abi as u32
        );
        let toml = format!(
            r#"
                abi = {}
                [[ruleset]]
                handled_access_fs = ["{name}"]
            "#,
            policy_abi as u32
        );
        assert_access_abi_error(
            &json,
            &toml,
            "filesystem access right",
            name,
            policy_abi,
            required_abi,
        );

        let json = json.replace(
            &format!("\"abi\": {}", policy_abi as u32),
            &format!("\"abi\": {}", required_abi as u32),
        );
        let toml = toml.replace(
            &format!("abi = {}", policy_abi as u32),
            &format!("abi = {}", required_abi as u32),
        );
        assert!(parse_json(&json).unwrap().handled_fs.contains(access));
        assert!(parse_toml(&toml).unwrap().handled_fs.contains(access));
    }
}

#[test]
fn test_network_access_abi_boundaries() {
    for (name, access) in [
        ("bind_tcp", AccessNet::BindTcp),
        ("connect_tcp", AccessNet::ConnectTcp),
    ] {
        let json = format!(
            r#"{{
                "abi": 3,
                "ruleset": [{{ "handledAccessNet": ["{name}"] }}]
            }}"#
        );
        let toml = format!(
            r#"
                abi = 3
                [[ruleset]]
                handled_access_net = ["{name}"]
            "#
        );
        assert_access_abi_error(&json, &toml, "network access right", name, ABI::V3, ABI::V4);

        let json = json.replace("\"abi\": 3", "\"abi\": 4");
        let toml = toml.replace("abi = 3", "abi = 4");
        assert!(parse_json(&json).unwrap().handled_net.contains(access));
        assert!(parse_toml(&toml).unwrap().handled_net.contains(access));
    }
}

#[test]
fn test_scope_abi_boundaries() {
    for (name, scope) in [
        ("abstract_unix_socket", Scope::AbstractUnixSocket),
        ("signal", Scope::Signal),
    ] {
        let json = format!(
            r#"{{
                "abi": 5,
                "ruleset": [{{ "scoped": ["{name}"] }}]
            }}"#
        );
        let toml = format!(
            r#"
                abi = 5
                [[ruleset]]
                scoped = ["{name}"]
            "#
        );
        assert_access_abi_error(&json, &toml, "scope", name, ABI::V5, ABI::V6);

        let json = json.replace("\"abi\": 5", "\"abi\": 6");
        let toml = toml.replace("abi = 5", "abi = 6");
        assert!(parse_json(&json).unwrap().scoped.contains(scope));
        assert!(parse_toml(&toml).unwrap().scoped.contains(scope));
    }
}

#[test]
fn test_future_abi_concrete_access() {
    let json = format!(
        r#"{{
            "abi": {},
            "ruleset": [{{
                "handledAccessFs": ["execute"],
                "handledAccessNet": ["bind_tcp"],
                "scoped": ["signal"]
            }}]
        }}"#,
        i32::MAX
    );
    let toml = format!(
        r#"
            abi = {}
            [[ruleset]]
            handled_access_fs = ["execute"]
            handled_access_net = ["bind_tcp"]
            scoped = ["signal"]
        "#,
        i32::MAX
    );
    let policy = Policy {
        abi: Some(LATEST_ABI),
        handled_fs: AccessFs::Execute.into(),
        handled_net: AccessNet::BindTcp.into(),
        scoped: Scope::Signal.into(),
        ..Default::default()
    };
    assert_eq!(parse_json(&json).unwrap(), policy);
    assert_eq!(parse_toml(&toml).unwrap(), policy);
}

#[test]
fn test_group_only_no_op() {
    let json = r#"{
        "abi": 3,
        "ruleset": [{
            "handledAccessFs": ["execute"],
            "handledAccessNet": ["abi.all"],
            "scoped": ["abi.all"]
        }],
        "netPort": [{
            "allowedAccess": ["abi.all"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 3
        [[ruleset]]
        handled_access_fs = ["execute"]
        handled_access_net = ["abi.all"]
        scoped = ["abi.all"]
        [[net_port]]
        allowed_access = ["abi.all"]
        port = [80]
    "#;
    let policy = Policy {
        abi: Some(ABI::V3),
        handled_fs: AccessFs::Execute.into(),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_scope_default_boundary() {
    let json = r#"{
        "abi": 5,
        "ruleset": [{
            "handledAccessFs": [],
            "handledAccessNet": []
        }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = []
        handled_access_net = []
    "#;

    assert!(matches!(
        Policy::parse_json(std::io::Cursor::new(json)),
        Err(ParseJsonError::Policy(PolicyError::EmptyRuleset))
    ));
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(matches!(
        Policy::parse_toml(toml),
        Err(ParseTomlError::Policy(PolicyError::EmptyRuleset))
    ));

    let json = json.replace("\"abi\": 5", "\"abi\": 6");
    let toml = toml.replace("abi = 5", "abi = 6");
    let policy = Policy {
        abi: Some(ABI::V6),
        scoped: Scope::from_all(ABI::V6),
        ..Default::default()
    };
    assert_eq!(parse_json(&json).unwrap(), policy);
    assert_eq!(parse_toml(&toml).unwrap(), policy);
}

#[test]
fn test_path_allowance_abi_boundary() {
    let json = r#"{
        "abi": 1,
        "pathBeneath": [{
            "allowedAccess": ["refer"],
            "parent": ["."]
        }]
    }"#;
    let toml = r#"
        abi = 1
        [[path_beneath]]
        allowed_access = ["refer"]
        parent = ["."]
    "#;
    assert_access_abi_error(
        json,
        toml,
        "filesystem access right",
        "refer",
        ABI::V1,
        ABI::V2,
    );

    let json = json.replace("\"abi\": 1", "\"abi\": 2");
    let toml = toml.replace("abi = 1", "abi = 2");
    assert_eq!(
        parse_json(&json)
            .unwrap()
            .rules_path_beneath
            .get(&TemplateString::from_text(".")),
        Some(&AccessFs::Refer.into())
    );
    assert_eq!(
        parse_toml(&toml)
            .unwrap()
            .rules_path_beneath
            .get(&TemplateString::from_text(".")),
        Some(&AccessFs::Refer.into())
    );
}

#[test]
fn test_port_allowance_abi_boundary() {
    let json = r#"{
        "abi": 3,
        "netPort": [{
            "allowedAccess": ["connect_tcp"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 3
        [[net_port]]
        allowed_access = ["connect_tcp"]
        port = [80]
    "#;
    assert_access_abi_error(
        json,
        toml,
        "network access right",
        "connect_tcp",
        ABI::V3,
        ABI::V4,
    );

    let json = json.replace("\"abi\": 3", "\"abi\": 4");
    let toml = toml.replace("abi = 3", "abi = 4");
    assert_eq!(
        parse_json(&json).unwrap().rules_net_port.get(&80),
        Some(&AccessNet::ConnectTcp.into())
    );
    assert_eq!(
        parse_toml(&toml).unwrap().rules_net_port.get(&80),
        Some(&AccessNet::ConnectTcp.into())
    );
}

#[test]
fn test_exception_abi_boundary() {
    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessFs": ["abi.all", "-ioctl_dev"],
            "handledAccessNet": [],
            "scoped": []
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_fs = ["abi.all", "-ioctl_dev"]
        handled_access_net = []
        scoped = []
    "#;
    assert_access_abi_error(
        json,
        toml,
        "filesystem access right",
        "ioctl_dev",
        ABI::V4,
        ABI::V5,
    );

    let json = json.replace("\"abi\": 4", "\"abi\": 5");
    let toml = toml.replace("abi = 4", "abi = 5");
    let policy = Policy {
        abi: Some(ABI::V5),
        handled_fs: AccessFs::from_all(ABI::V5) & !AccessFs::IoctlDev,
        ..Default::default()
    };
    assert_eq!(parse_json(&json).unwrap(), policy);
    assert_eq!(parse_toml(&toml).unwrap(), policy);
}

#[test]
fn test_exception_coverage() {
    let json = r#"{
        "abi": 5,
        "ruleset": [{ "handledAccessFs": ["-ioctl_dev"] }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["-ioctl_dev"]
    "#;
    assert_uncovered_exception(json, toml, "filesystem access right", "ioctl_dev", ABI::V5);

    let json = r#"{
        "abi": 5,
        "ruleset": [{
            "handledAccessFs": ["abi.read_execute", "-ioctl_dev"]
        }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["abi.read_execute", "-ioctl_dev"]
    "#;
    assert_uncovered_exception(json, toml, "filesystem access right", "ioctl_dev", ABI::V5);
}

#[test]
fn test_exception_contradiction() {
    let json = r#"{
        "abi": 5,
        "ruleset": [{
            "handledAccessFs": ["abi.all", "ioctl_dev", "-ioctl_dev"]
        }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["abi.all", "ioctl_dev", "-ioctl_dev"]
    "#;
    assert_access_contradiction(json, toml, "filesystem access right", "ioctl_dev");

    let json = r#"{
        "abi": 5,
        "ruleset": [
            { "handledAccessFs": ["abi.all"] },
            { "handledAccessFs": ["ioctl_dev"] },
            { "handledAccessFs": ["-ioctl_dev"] }
        ]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["abi.all"]
        [[ruleset]]
        handled_access_fs = ["ioctl_dev"]
        [[ruleset]]
        handled_access_fs = ["-ioctl_dev"]
    "#;
    assert_access_contradiction(json, toml, "filesystem access right", "ioctl_dev");

    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessNet": ["abi.all", "bind_tcp", "-bind_tcp"]
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_net = ["abi.all", "bind_tcp", "-bind_tcp"]
    "#;
    assert_access_contradiction(json, toml, "network access right", "bind_tcp");

    let json = r#"{
        "abi": 6,
        "ruleset": [{
            "scoped": ["abi.all", "signal", "-signal"]
        }]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        scoped = ["abi.all", "signal", "-signal"]
    "#;
    assert_access_contradiction(json, toml, "scope", "signal");
}

#[test]
fn test_repeated_exception_coverage() {
    let json = r#"{
        "abi": 5,
        "ruleset": [
            { "handledAccessFs": ["-ioctl_dev"] },
            { "handledAccessFs": ["abi.all"] },
            { "handledAccessNet": [], "scoped": [] }
        ]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["-ioctl_dev"]
        [[ruleset]]
        handled_access_fs = ["abi.all"]
        [[ruleset]]
        handled_access_net = []
        scoped = []
    "#;
    let expected = AccessFs::from_all(ABI::V5) & !AccessFs::IoctlDev;
    assert_eq!(parse_json(json).unwrap().handled_fs, expected);
    assert_eq!(parse_toml(toml).unwrap().handled_fs, expected);

    let reversed = json.replace(
        r#"{ "handledAccessFs": ["-ioctl_dev"] },
            { "handledAccessFs": ["abi.all"] }"#,
        r#"{ "handledAccessFs": ["abi.all"] },
            { "handledAccessFs": ["-ioctl_dev"] }"#,
    );
    assert_ne!(reversed, json);
    assert_eq!(parse_json(&reversed).unwrap().handled_fs, expected);
}

#[test]
fn test_rule_group_masking() {
    let json = r#"{
        "abi": 5,
        "ruleset": [{
            "handledAccessFs": ["abi.all", "-ioctl_dev"],
            "handledAccessNet": [],
            "scoped": []
        }],
        "pathBeneath": [{
            "allowedAccess": ["abi.all"],
            "parent": ["."]
        }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        handled_access_fs = ["abi.all", "-ioctl_dev"]
        handled_access_net = []
        scoped = []
        [[path_beneath]]
        allowed_access = ["abi.all"]
        parent = ["."]
    "#;
    let expected = AccessFs::from_all(ABI::V5) & !AccessFs::IoctlDev;
    let json_policy = parse_json(json).unwrap();
    assert_eq!(json_policy.handled_fs, expected);
    assert_eq!(
        json_policy
            .rules_path_beneath
            .get(&TemplateString::from_text(".")),
        Some(&expected)
    );
    let toml_policy = parse_toml(toml).unwrap();
    assert_eq!(toml_policy.handled_fs, expected);
    assert_eq!(
        toml_policy
            .rules_path_beneath
            .get(&TemplateString::from_text(".")),
        Some(&expected)
    );

    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessFs": [],
            "handledAccessNet": ["abi.all", "-bind_tcp"],
            "scoped": []
        }],
        "netPort": [{
            "allowedAccess": ["abi.all"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_fs = []
        handled_access_net = ["abi.all", "-bind_tcp"]
        scoped = []
        [[net_port]]
        allowed_access = ["abi.all"]
        port = [80]
    "#;
    let policy = Policy {
        abi: Some(ABI::V4),
        handled_net: AccessNet::ConnectTcp.into(),
        rules_net_port: [(80, AccessNet::ConnectTcp.into())].into(),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_explicit_rule_conflict() {
    for allowed_access in [r#"["ioctl_dev"]"#, r#"["abi.all", "ioctl_dev"]"#] {
        let json = format!(
            r#"{{
                "abi": 5,
                "ruleset": [{{
                    "handledAccessFs": ["abi.all", "-ioctl_dev"]
                }}],
                "pathBeneath": [{{
                    "allowedAccess": {allowed_access},
                    "parent": ["."]
                }}]
            }}"#
        );
        let toml = format!(
            r#"
                abi = 5
                [[ruleset]]
                handled_access_fs = ["abi.all", "-ioctl_dev"]
                [[path_beneath]]
                allowed_access = {allowed_access}
                parent = ["."]
            "#
        );
        assert_rule_access_conflict(&json, &toml, "filesystem access right", "ioctl_dev");
    }

    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessFs": [],
            "handledAccessNet": ["abi.all", "-bind_tcp"],
            "scoped": []
        }],
        "netPort": [{
            "allowedAccess": ["bind_tcp"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_fs = []
        handled_access_net = ["abi.all", "-bind_tcp"]
        scoped = []
        [[net_port]]
        allowed_access = ["bind_tcp"]
        port = [80]
    "#;
    assert_rule_access_conflict(json, toml, "network access right", "bind_tcp");
}

#[test]
fn test_fully_masked_group_rule() {
    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessFs": ["execute"],
            "handledAccessNet": ["abi.all", "-bind_tcp", "-connect_tcp"],
            "scoped": []
        }],
        "netPort": [{
            "allowedAccess": ["abi.all"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_fs = ["execute"]
        handled_access_net = ["abi.all", "-bind_tcp", "-connect_tcp"]
        scoped = []
        [[net_port]]
        allowed_access = ["abi.all"]
        port = [80]
    "#;
    let policy = Policy {
        abi: Some(ABI::V4),
        handled_fs: AccessFs::Execute.into(),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_exceptions_empty_all_categories() {
    let json = r#"{
        "abi": 4,
        "ruleset": [{
            "handledAccessFs": [],
            "handledAccessNet": ["abi.all", "-bind_tcp", "-connect_tcp"],
            "scoped": []
        }]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        handled_access_fs = []
        handled_access_net = ["abi.all", "-bind_tcp", "-connect_tcp"]
        scoped = []
    "#;
    assert!(matches!(
        Policy::parse_json(std::io::Cursor::new(json)),
        Err(ParseJsonError::Policy(PolicyError::EmptyRuleset))
    ));
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(matches!(
        Policy::parse_toml(toml),
        Err(ParseTomlError::Policy(PolicyError::EmptyRuleset))
    ));
}

#[test]
fn test_scope_exception_coverage() {
    let json = r#"{
        "abi": 5,
        "ruleset": [{ "scoped": ["abi.all", "-signal"] }]
    }"#;
    let toml = r#"
        abi = 5
        [[ruleset]]
        scoped = ["abi.all", "-signal"]
    "#;
    assert_access_abi_error(json, toml, "scope", "signal", ABI::V5, ABI::V6);

    let json = r#"{
        "abi": 6,
        "ruleset": [{
            "scoped": ["abstract_unix_socket", "-signal"]
        }]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        scoped = ["abstract_unix_socket", "-signal"]
    "#;
    assert_uncovered_exception(json, toml, "scope", "signal", ABI::V6);

    let json = r#"{
        "abi": 6,
        "ruleset": [{ "scoped": ["abi.all", "-signal"] }]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        scoped = ["abi.all", "-signal"]
    "#;
    assert_eq!(
        parse_json(json).unwrap().scoped,
        Scope::from_all(ABI::V6) & !Scope::Signal
    );
    assert_eq!(
        parse_toml(toml).unwrap().scoped,
        Scope::from_all(ABI::V6) & !Scope::Signal
    );
}

#[test]
fn test_missing() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": ["execute"]
            }
        ]
    }"#;
    let toml = r#"
        [[ruleset]]
        handled_access_fs = ["execute"]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_abi_only() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(r#"{{ "abi": {version} }}"#);
        let toml = format!("abi = {version}");
        let abi = ABI::from(version);
        let config = Policy {
            abi: Some(abi),
            handled_fs: AccessFs::from_all(abi),
            handled_net: AccessNet::from_all(abi),
            scoped: Scope::from_all(abi),
            ..Default::default()
        };

        assert_eq!(parse_json(&json).unwrap(), config);
        assert_eq!(parse_toml(&toml).unwrap(), config);
    }
}

#[test]
fn test_non_integer() {
    let json = r#"{
        "abi": "6",
        "ruleset": [
            {
                "handledAccessFs": ["execute"]
            }
        ]
    }"#;
    let toml = r#"
        abi = "6"
        [[ruleset]]
        handled_access_fs = ["execute"]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_fractional() {
    let json = r#"{ "abi": 6.5 }"#;
    let toml = "abi = 6.5";

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

    let policy = Policy {
        abi: Some(ABI::V1),
        handled_fs: AccessFs::Execute.into(),
        ..Default::default()
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
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
        let mut policy = Policy {
            abi: Some(abi),
            handled_fs: AccessFs::from_all(abi),
            handled_net: AccessNet::from_all(abi),
            scoped: Scope::from_all(abi),
            rules_path_beneath: [(TemplateString::from_text("."), AccessFs::from_all(abi))].into(),
            ..Default::default()
        };
        if abi >= ABI::V4 {
            // Do not add rules with empty access right.
            policy.rules_net_port = [(1, AccessNet::from_all(abi))].into();
        }
        println!("Testing ABI {version} and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
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

        let policy = Policy {
            abi: Some(abi),
            handled_fs: expected_access,
            handled_net: AccessNet::from_all(abi),
            scoped: Scope::from_all(abi),
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Default::default()
        };
        println!("Testing ABI {version} read_execute and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
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

        let policy = Policy {
            abi: Some(abi),
            handled_fs: expected_access,
            handled_net: AccessNet::from_all(abi),
            scoped: Scope::from_all(abi),
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Default::default()
        };
        println!("Testing ABI {version} read_write and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
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
fn test_kernel_abi_downgrade() {
    let Ok(kernel_abi) = std::env::var("LANDLOCK_CRATE_TEST_ABI") else {
        eprintln!("Skipping test_kernel_abi_downgrade: LANDLOCK_CRATE_TEST_ABI is not set");
        return;
    };
    let kernel_abi = kernel_abi.parse::<i32>().unwrap();
    let latest = LATEST_ABI as i32;

    for requested_abi in (1..=latest).chain([latest + 1, i32::MAX]) {
        let status = std::thread::spawn(move || {
            let json = format!(r#"{{ "abi": {requested_abi} }}"#);
            let config = Policy::parse_json(json.as_bytes()).unwrap();
            let resolved = config.resolve().unwrap();
            let (ruleset, rule_errors) = resolved.build_ruleset().unwrap();
            assert!(rule_errors.is_empty());
            ruleset.restrict_self().unwrap()
        })
        .join()
        .unwrap();

        let policy_abi = requested_abi.min(latest);
        let expected_ruleset = if kernel_abi == 0 {
            RulesetStatus::NotEnforced
        } else if kernel_abi >= policy_abi {
            RulesetStatus::FullyEnforced
        } else {
            RulesetStatus::PartiallyEnforced
        };
        assert_eq!(status.ruleset, expected_ruleset);
        assert!(status.no_new_privs);

        match status.landlock {
            LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
                assert_eq!(kernel_abi, 0);
            }
            LandlockStatus::Available {
                effective_abi: kernel_effective_abi,
                kernel_abi: reported_kernel_abi,
            } => {
                assert!(kernel_abi > 0);
                assert_eq!(kernel_effective_abi, ABI::from(kernel_abi));
                assert_eq!(
                    reported_kernel_abi,
                    (kernel_abi != kernel_effective_abi as i32).then_some(kernel_abi)
                );
            }
        }
    }
}

#[test]
fn test_exception_kernel_abi_downgrade() {
    let Ok(kernel_abi) = std::env::var("LANDLOCK_CRATE_TEST_ABI") else {
        eprintln!(
            "Skipping test_exception_kernel_abi_downgrade: LANDLOCK_CRATE_TEST_ABI is not set"
        );
        return;
    };
    let kernel_abi = kernel_abi.parse::<i32>().unwrap();

    let status = std::thread::spawn(|| {
        let json = r#"{
            "abi": 5,
            "ruleset": [{
                "handledAccessFs": ["abi.all", "-ioctl_dev"],
                "handledAccessNet": [],
                "scoped": []
            }]
        }"#;
        let policy = Policy::parse_json(json.as_bytes()).unwrap();
        assert_eq!(
            policy.handled_fs,
            AccessFs::from_all(ABI::V5) & !AccessFs::IoctlDev
        );
        let resolved = policy.resolve().unwrap();
        let (ruleset, rule_errors) = resolved.build_ruleset().unwrap();
        assert!(rule_errors.is_empty());
        ruleset.restrict_self().unwrap()
    })
    .join()
    .unwrap();

    let expected = match kernel_abi {
        0 => RulesetStatus::NotEnforced,
        1 | 2 => RulesetStatus::PartiallyEnforced,
        _ => RulesetStatus::FullyEnforced,
    };
    assert_eq!(status.ruleset, expected);
    assert!(status.no_new_privs);
}

#[test]
fn test_latest_supported() {
    assert_eq!(LATEST_ABI, ABI::V6);
}

#[test]
fn test_latest_plus_one() {
    let requested = LATEST_ABI as i32 + 1;
    let json = format!(r#"{{ "abi": {requested} }}"#);
    let toml = format!("abi = {requested}");
    let config = Policy {
        abi: Some(LATEST_ABI),
        handled_fs: AccessFs::from_all(LATEST_ABI),
        handled_net: AccessNet::from_all(LATEST_ABI),
        scoped: Scope::from_all(LATEST_ABI),
        ..Default::default()
    };

    assert_eq!(parse_json(&json).unwrap(), config);
    assert_eq!(parse_toml(&toml).unwrap(), config);
}

#[test]
fn test_i32_max() {
    // 2^31 - 1
    let json = r#"{ "abi": 2147483647 }"#;
    let toml = "abi = 2147483647";
    let config = Policy {
        abi: Some(LATEST_ABI),
        handled_fs: AccessFs::from_all(LATEST_ABI),
        handled_net: AccessNet::from_all(LATEST_ABI),
        scoped: Scope::from_all(LATEST_ABI),
        ..Default::default()
    };

    assert_eq!(parse_json(json).unwrap(), config);
    assert_eq!(parse_toml(toml).unwrap(), config);
}

#[test]
fn test_future_abi_unknown_syntax() {
    let json = [
        r#"{
            "abi": 2147483647,
            "ruleset": [
                {
                    "handledAccessFs": ["future_right"]
                }
            ]
        }"#,
        r#"{
            "abi": 2147483647,
            "ruleset": [
                {
                    "futureAccess": ["execute"]
                }
            ]
        }"#,
        r#"{
            "abi": 2147483647,
            "futureRule": []
        }"#,
    ];
    let toml = [
        r#"
            abi = 2147483647
            [[ruleset]]
            handled_access_fs = ["future_right"]
        "#,
        r#"
            abi = 2147483647
            [[ruleset]]
            future_access = ["execute"]
        "#,
        r#"
            abi = 2147483647
            [[future_rule]]
        "#,
    ];

    for json in json {
        assert_eq!(parse_json(json), Err(Category::Data));
    }
    for toml in toml {
        assert!(parse_toml(toml).is_err());
    }
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
