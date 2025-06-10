// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    tests_helpers::{parse_json, parse_toml},
    Config,
};
use serde_json::error::Category;

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
    assert_eq!(
        parse_json(json),
        Ok(Config {
            variables: [("bar".to_string(), [].into())].into(),
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
            variables: [("bar".to_string(), ["foo".to_string()].into())].into(),
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
            variables: [("bar".to_string(), ["foo".to_string()].into())].into(),
            ..Default::default()
        }
    );
}
