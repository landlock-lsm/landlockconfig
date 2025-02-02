use landlockconfig::*;
use std::io::Cursor;

// FIXME: Such an empty ruleset doesn't make sense and should not be allowed.
#[test]
fn test_empty_ruleset() {
    let json = r#"
        {
            "ruleset": []
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_one_handled_access_fs() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_handled_fs_1() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "best_effort"
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_handled_fs_2() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "soft_requirement"
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_handled_fs_3() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "compatibility": "hard_requirement"
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_unknown_ruleset_field() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                }
            ],
            "foo": []
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

#[test]
fn test_dup_handled_access_fs_1() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute", "execute" ]
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_dup_handled_access_fs_2() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                },
                {
                    "handledAccessFs": [ "execute" ]
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_unknown_handled_access_fs_1() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "foo" ]
                }
            ]
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

#[test]
fn test_unknown_handled_access_fs_2() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "bind_tcp" ]
                }
            ]
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

#[test]
fn test_one_path_beneath_str() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_one_path_beneath_int() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_path_beneath() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_dup_path_beneath_1() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_dup_path_beneath_2() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_overlap_path_beneath() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_one_handled_access_net() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessNet": [ "bind_tcp" ]
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_handled_access_net() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessNet": [ "bind_tcp" ],
                    "compatibility": "best_effort"
                }
            ]
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_unknown_handled_access_net_1() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessNet": [ "foo" ]
                }
            ]
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

#[test]
fn test_unknown_handled_access_net_2() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessNet": [ "execute" ]
                }
            ]
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

#[test]
fn test_one_net_port() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_compat_net_port() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}

#[test]
fn test_inconsistent_handled_access() {
    let json = r#"
        {
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ],
                    "handledAccessNet": [ "bind_tcp" ]
                }
            ]
        }
        "#;

    assert!(parse_config(Cursor::new(json)).is_err());
}

// FIXME: This should be forbidden at the parser level.
#[test]
fn test_inconsistent_access_net() {
    let json = r#"
        {
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
        }
        "#;

    parse_config(Cursor::new(json)).unwrap();
}
