// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::policy::{ParseJsonError, ParseTomlError};
use crate::Policy;
use landlock::ABI;
use serde_json::error::Category;
use serde_json::Value;

pub(crate) const LATEST_ABI: ABI = ABI::V6;

lazy_static! {
    static ref JSON_VALIDATOR: jsonschema::Validator = {
        let schema: Value = serde_json::from_str(crate::JSON_SCHEMA).expect("Invalid JSON");
        jsonschema::validator_for(&schema).expect("Invalid JSON schema")
    };
}

pub(crate) fn validate_json(json: &str) -> Result<(), ()> {
    let json = serde_json::from_str::<Value>(json).expect("Invalid JSON");
    JSON_VALIDATOR.validate(&json).map(|_| ()).map_err(|e| {
        eprintln!("JSON schema validation error: {e}");
    })
}

// TODO: Return ParseJsonError
pub(crate) fn parse_json_schema(json: &str, with_schema: bool) -> Result<Policy, Category> {
    let cursor = std::io::Cursor::new(json);
    let parsing = Policy::parse_json(cursor).map_err(|e| {
        eprintln!("JSON parsing error: {e}");
        match e {
            ParseJsonError::SerdeJson(e) => e.classify(),
            _ => Category::Data,
        }
    });

    // Ensures the JSON schema is consistent and stays up-to-date with the crate.
    let valid = validate_json(json);
    if with_schema {
        if parsing.is_ok() != valid.is_ok() {
            panic!("Inconsistent validation: parser and schema validator disagree");
        }
    } else if parsing.is_ok() == valid.is_ok() {
        panic!("Consistent validation: parser and schema validator agree");
    }
    parsing
}

pub(crate) fn parse_json(json: &str) -> Result<Policy, Category> {
    parse_json_schema(json, true)
}

pub(crate) fn parse_toml(toml: &str) -> Result<Policy, ParseTomlError> {
    Policy::parse_toml(toml).map_err(|e| {
        eprintln!("TOML parsing error: {e}");
        e
    })
}
