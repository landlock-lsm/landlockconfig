use crate::*;
use serde_json::error::Category;

fn assert_json(data: &str, ret: Result<(), Category>) {
    let cursor = std::io::Cursor::new(data);
    let parsing_ret = Config::parse_json(cursor)
        .map(|_| ())
        .map_err(|e| e.classify());
    assert_eq!(parsing_ret, ret);
}

fn parse_json(json: &str) -> Result<Config, Category> {
    let cursor = std::io::Cursor::new(json);
    Config::parse_json(cursor).map_err(|e| e.classify())
}

fn parse_toml(toml: &str) -> Result<Config, toml::de::Error> {
    Config::parse_toml(toml)
}

const LATEST_VERSION: u32 = 5;

fn assert_versions(name: &str, first_known_version: u32) {
    let known_versions = first_known_version..=LATEST_VERSION;
    let next_version = LATEST_VERSION + 1;
    for version in 0..=next_version {
        let expected = if known_versions.contains(&version) {
            Ok(())
        } else {
            Err(Category::Data)
        };
        println!("Testing version {version} and expecting {:?}", expected);
        assert_json(
            format!(
                r#"{{
                    "ruleset": [
                        {{
                            "{name}": [ "v{version}.all" ]
                        }}
                    ]
                }}"#
            )
            .as_ref(),
            expected,
        );
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
                    "v5.read_write"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::from_all(ABI::V5),
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
        ]
    "#;
    assert_eq!(
        parse_toml(toml),
        Ok(Config {
            handled_fs: AccessFs::from_all(ABI::V5),
            ..Default::default()
        })
    );
}

#[test]
fn test_versions_access_fs() {
    assert_versions("handledAccessFs", 1);
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
                "handledAccessFs": [ "execute", "execute" ]
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
fn test_dup_handled_access_fs_2() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            },
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
                "handledAccessFs": [ "read_file" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute", "read_file" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_fs: AccessFs::Execute | AccessFs::ReadFile,
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute | AccessFs::ReadFile)]
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
                    "v5.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            handled_net: AccessNet::from_all(ABI::V5),
            ..Default::default()
        }),
    );
}

#[test]
fn test_versions_access_net() {
    assert_versions("handledAccessNet", 4);
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

// FIXME: This should be forbidden at the parser level.
#[test]
fn test_inconsistent_access_net() {
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
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Default::default()
        }),
    );
}
