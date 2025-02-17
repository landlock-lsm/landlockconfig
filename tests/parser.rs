use landlockconfig::*;
use serde_json::error::Category;

fn assert_json(data: &str, ret: Result<(), Category>) {
    let cursor = std::io::Cursor::new(data);
    let parsing_ret = parse_config(cursor).map(|_| ()).map_err(|e| e.classify());
    assert_eq!(parsing_ret, ret);
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
fn test_compat_handled_fs_1() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "best_effort"
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_compat_handled_fs_2() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "soft_requirement"
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_compat_handled_fs_3() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "hard_requirement"
                }
            ]
        }"#,
        Ok(()),
    );
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
                    "parentFd": [ "." ]
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
                    "parentFd": [ 2 ]
                }
            ]
        }"#,
        Ok(()),
    );
}

#[test]
fn test_compat_path_beneath() {
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
                    "parentFd": [ "." ],
                    "compatibility": "best_effort"
                }
            ]
        }"#,
        Ok(()),
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
                    "parentFd": [ ".", "." ]
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
                    "parentFd": [ "." ]
                },
                {
                    "allowedAccess": [ "execute" ],
                    "parentFd": [ "." ]
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
                    "parentFd": [ "." ]
                },
                {
                    "allowedAccess": [ "execute", "read_file" ],
                    "parentFd": [ "." ]
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
fn test_compat_handled_access_net() {
    assert_json(
        r#"{
            "ruleset": [
                {
                    "handledAccessNet": [ "bind_tcp" ],
                    "compatibility": "best_effort"
                }
            ]
        }"#,
        Ok(()),
    );
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
fn test_compat_net_port() {
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
                    "port": [ 443 ],
                    "compatibility": "best_effort"
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
