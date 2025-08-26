// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    config::ResolvedConfig,
    parser::{TemplateString, TemplateToken},
    tests_helpers::{parse_json, parse_json_schema, parse_toml},
    variable::{Name, ResolveError, Variables},
    Config,
};
use landlock::AccessFs;
use serde_json::error::Category;
use std::{path::PathBuf, str::FromStr};

#[test]
fn test_empty_variable() {
    let json = r#"{
        "variable": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_variable_item() {
    let json = r#"{
        "variable": [
            {}
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_variable_name() {
    let json = r#"{
        "variable": [
            {
                "literal": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_without_value() {
    let json = r#"{
        "variable": [
            {
                "name": "bar"
            }
        ]
    }"#;
    let empty: &[&str] = &[];
    assert_eq!(
        parse_json(json),
        Ok(Config {
            variables: Variables::try_from([("bar", empty)]).unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn test_one_variable_json() {
    let json = r#"{
        "variable": [
            {
                "name": "bar",
                "literal": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            variables: Variables::try_from([("bar", ["foo"])]).unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn test_one_variable_toml() {
    let toml = r#"
        [[variable]]
        name = "bar"
        literal = [
            "foo",
        ]
    "#;
    assert_eq!(
        parse_toml(toml).unwrap(),
        Config {
            variables: Variables::try_from([("bar", ["foo"])]).unwrap(),
            ..Default::default()
        }
    );
}

#[test]
fn test_one_variable_simple_1() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Config {
            variables: Variables::try_from([("foo", vec!["a", "b"])]).unwrap(),
            ..Default::default()
        })
    );
}

fn json_var_declaration(name: &str) -> String {
    format!(
        r#"{{
            "variable": [
                {{
                    "name": "{}",
                    "literal": [ "value" ]
                }}
            ]
        }}"#,
        name
    )
}

fn json_var_use(name: &str) -> String {
    format!(
        r#"{{
            "pathBeneath": [
                {{
                    "allowedAccess": [ "execute" ],
                    "parent": [ "${{{}}}" ]
            }}
            ]
        }}"#,
        name
    )
}

fn assert_invalid_var_name(name: &str) {
    assert_eq!(
        parse_json_schema(&json_var_declaration(name), false),
        Err(Category::Data)
    );

    // Fails because the variable is not defined, but also because the name is
    // invalid.
    assert_eq!(
        parse_json_schema(&json_var_use(name), false),
        Err(Category::Data)
    );
}

#[test]
fn test_variable_name_invalid() {
    // Start with digit
    assert_invalid_var_name("1foo");

    // Start with underscore
    assert_invalid_var_name("_foo");

    // Single non-ascii alphabetic character
    assert_invalid_var_name("À");

    // Contain non-letter character
    assert_invalid_var_name("e€");

    // Leading space
    assert_invalid_var_name(" foo");

    // Space in middle
    assert_invalid_var_name("foo bar");

    // Trailing space
    assert_invalid_var_name("foo ");

    // Contain hyphen
    assert_invalid_var_name("foo-bar");

    // Contain non-ASCII characters
    assert_invalid_var_name("foo_çë");
}

fn assert_valid_var_name(name: &str) {
    assert_eq!(
        parse_json(&json_var_declaration(name)),
        Ok(Config {
            variables: Variables::try_from([(name, ["value"])]).unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn test_variable_name_valid() {
    // Single uppercase letter
    assert_valid_var_name("F");

    // All uppercase
    assert_valid_var_name("FOO");

    // Capitalized first letter
    assert_valid_var_name("Foo");

    // Single lowercase letter
    assert_valid_var_name("f");

    // Mixed case
    assert_valid_var_name("fOo");

    // Standard lowercase identifier
    assert_valid_var_name("foo");

    // Trailing underscore
    assert_valid_var_name("foo_");

    // Multiple consecutive underscores
    assert_valid_var_name("foo__bar");

    // Middle underscore
    assert_valid_var_name("foo_bar");
}

#[test]
fn test_variable_name_valid_single_letter() {
    assert_eq!(
        parse_json(&json_var_declaration("a")),
        Ok(Config {
            variables: Variables::try_from([("a", ["value"])]).unwrap(),
            ..Default::default()
        })
    );
}

#[test]
fn test_one_variable_template_error_1() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${a" ]
            }
        ]
    }"#;
    assert_eq!(parse_json_schema(json, false), Err(Category::Data),);
}

#[test]
fn test_one_variable_template_missing() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}/${bar}" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Err(ResolveError::VariableNotFound(
            Name::from_str("bar").unwrap()
        )),
    );
}

#[test]
fn test_one_variable_json_toml_template() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [
                    "a",
                    "b"
                ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json_reverse = r#"{
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ],
        "variable": [
            {
                "name": "foo",
                "literal": [
                    "b",
                    "a"
                ]
            }
        ]
    }"#;

    let toml = r#"
        [[variable]]
        name = "foo"
        literal = [
            "a",
            "b",
        ]

        [[path_beneath]]
        allowed_access = [ "execute" ]
        parent = [ "${foo}" ]
    "#;
    let toml_reverse = r#"
        [[path_beneath]]
        allowed_access = [ "execute" ]
        parent = [ "${foo}" ]

        [[variable]]
        name = "foo"
        literal = [
            "b",
            "a",
        ]
    "#;

    let config = Config {
        variables: Variables::try_from([("foo", vec!["a", "b"])]).unwrap(),
        handled_fs: AccessFs::Execute.into(),
        rules_path_beneath: [(
            TemplateString(vec![TemplateToken::Var(Name::from_str("foo").unwrap())]),
            AccessFs::Execute.into(),
        )]
        .into(),
        ..Default::default()
    };
    let resolved = ResolvedConfig {
        handled_fs: AccessFs::Execute.into(),
        rules_path_beneath: [
            (PathBuf::from("a"), AccessFs::Execute.into()),
            (PathBuf::from("b"), AccessFs::Execute.into()),
        ]
        .into(),
        ..Default::default()
    };

    let out_json = parse_json(json).unwrap();
    assert_eq!(out_json, config);
    assert_eq!(out_json.resolve().unwrap(), resolved);

    let out_json_reverse = parse_json(json_reverse).unwrap();
    assert_eq!(out_json_reverse, config);
    assert_eq!(out_json_reverse.resolve().unwrap(), resolved);

    let out_toml = parse_toml(toml).unwrap();
    assert_eq!(out_toml, config);
    assert_eq!(out_toml.resolve().unwrap(), resolved);

    let out_toml_reverse = parse_toml(toml_reverse).unwrap();
    assert_eq!(out_toml_reverse, config);
    assert_eq!(out_toml_reverse.resolve().unwrap(), resolved);
}

#[test]
fn test_two_variable_template() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            },
            {
                "name": "bar",
                "literal": [ "X", "Y", "Z" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "before/${foo}/${bar}/after" ]
            }
        ]
    }"#;
    let config = parse_json(json).unwrap();
    assert_eq!(
        config,
        Config {
            variables: Variables::try_from([("foo", vec!["a", "b"]), ("bar", vec!["X", "Y", "Z"])])
                .unwrap(),
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [(
                TemplateString(vec![
                    TemplateToken::Text("before/".into()),
                    TemplateToken::Var(Name::from_str("foo").unwrap()),
                    TemplateToken::Text("/".into()),
                    TemplateToken::Var(Name::from_str("bar").unwrap()),
                    TemplateToken::Text("/after".into())
                ]),
                AccessFs::Execute.into()
            )]
            .into(),
            ..Default::default()
        }
    );
    assert_eq!(
        config.resolve(),
        Ok(ResolvedConfig {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [
                (PathBuf::from("before/a/X/after"), AccessFs::Execute.into()),
                (PathBuf::from("before/a/Y/after"), AccessFs::Execute.into()),
                (PathBuf::from("before/a/Z/after"), AccessFs::Execute.into()),
                (PathBuf::from("before/b/X/after"), AccessFs::Execute.into()),
                (PathBuf::from("before/b/Y/after"), AccessFs::Execute.into()),
                (PathBuf::from("before/b/Z/after"), AccessFs::Execute.into()),
            ]
            .into(),
            ..Default::default()
        }),
    );
}

#[test]
fn test_special_characters() {
    let json = r#"{
        "variable": [
            {
                "name": "foo",
                "literal": [ "bar" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [
                    "$$",
                    "$${foo}",
                    "$${${foo}",
                    "{${foo}"
                ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedConfig {
            handled_fs: AccessFs::Execute.into(),
            rules_path_beneath: [
                (PathBuf::from("$"), AccessFs::Execute.into()),
                (PathBuf::from("${foo}"), AccessFs::Execute.into()),
                (PathBuf::from("${bar"), AccessFs::Execute.into()),
                (PathBuf::from("{bar"), AccessFs::Execute.into()),
            ]
            .into(),
            ..Default::default()
        })
    );
}
