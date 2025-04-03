use landlockconfig::*;
use serde_json::error::Category;

fn assert_json(data: &str, ret: Result<(), Category>) {
    let cursor = std::io::Cursor::new(data);
    let parsing_ret = parse_json(cursor).map(|_| ()).map_err(|e| e.classify());
    assert_eq!(parsing_ret, ret);
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
    assert_json(
        r#"{
            "ruleset": []
        }"#,
        Ok(()),
    );
}

#[test]
fn test_one_handled_access_fs() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_all_handled_access_fs_json() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_all_handled_access_fs_toml() {
    let data = r#"
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
    assert_eq!(parse_toml(data).map(|_| ()), Ok(()));
}

#[test]
fn test_versions_access_fs() {
    assert_versions("handledAccessFs", 1);
}

#[test]
fn test_unknown_ruleset_field() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                }
            ],
            "foo": []
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_dup_handled_access_fs_1() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute", "execute" ]
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_dup_handled_access_fs_2() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                },
                {
                    "handledAccessFs": [ "execute" ]
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_unknown_handled_access_fs_1() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "foo" ]
                }
            ]
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_unknown_handled_access_fs_2() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "bind_tcp" ]
                }
            ]
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_one_path_beneath_str() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_one_path_beneath_int() {
    assert_json(
        r#"{
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
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_dup_path_beneath_1() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_dup_path_beneath_2() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_overlap_path_beneath() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_one_handled_access_net() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessNet": [ "bind_tcp" ]
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_all_handled_access_net() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_versions_access_net() {
    assert_versions("handledAccessNet", 4);
}

#[test]
fn test_unknown_handled_access_net_1() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessNet": [ "foo" ]
                }
            ]
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_unknown_handled_access_net_2() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessNet": [ "execute" ]
                }
            ]
        }"#,
        Err(Category::Data),
    );
}

#[test]
fn test_one_net_port() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}

#[test]
fn test_inconsistent_handled_access() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "handledAccessNet": [ "bind_tcp" ]
                }
            ]
        }"#,
        Err(Category::Data),
    );
}

// FIXME: This should be forbidden at the parser level.
#[test]
fn test_inconsistent_access_net() {
    assert_json(
        r#"{
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
        }"#,
        Ok(()),
    );
}
