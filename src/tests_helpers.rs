// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::policy::{ParseJsonError, ParseTomlError};
use crate::Policy;
use serde_json::error::Category;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

lazy_static! {
    static ref JSON_VALIDATOR: jsonschema::Validator = {
        let schema: Value = serde_json::from_str(crate::JSON_SCHEMA).expect("Invalid JSON");
        jsonschema::validator_for(&schema).expect("Invalid JSON schema")
    };
}

// check-jsonschema is not available in every package build environment.
const CHECK_JSONSCHEMA_ENV: &str = "LANDLOCK_POLICY_TEST_JSON_SCHEMA";

fn format_process_output(output: &Output) -> String {
    let quote = |output: &[u8]| {
        String::from_utf8_lossy(output)
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        quote(&output.stdout),
        quote(&output.stderr)
    )
}

fn validate_json_external(json: &str, expected: bool) {
    match std::env::var(CHECK_JSONSCHEMA_ENV).as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => return,
        Ok("1") => {}
        _ => panic!("Invalid {CHECK_JSONSCHEMA_ENV} value; expected 0 or 1"),
    }

    let mut child = Command::new("check-jsonschema")
        .arg("--schemafile")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schema/landlock-policy.json"
        ))
        .args(["--force-filetype", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| {
            panic!(
                "Failed to run check-jsonschema: {error}. Install check-jsonschema to run \
                 the external JSON validation"
            )
        });

    let mut stdin = child.stdin.take().expect("Missing check-jsonschema stdin");
    let (output, write_result) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(json.as_bytes()));
        let output = child
            .wait_with_output()
            .expect("Failed to wait for check-jsonschema");
        let write_result = writer
            .join()
            .expect("Failed to join check-jsonschema writer");
        (output, write_result)
    });

    if let Err(error) = write_result {
        panic!(
            "Failed to write JSON to check-jsonschema: {error}\n{}",
            format_process_output(&output)
        );
    }

    let expected_status = if expected { 0 } else { 1 };
    if output.status.code() != Some(expected_status) || (!expected && !output.stderr.is_empty()) {
        panic!(
            "Unexpected check-jsonschema result for expected validity {expected}\n{}",
            format_process_output(&output)
        );
    }
}

pub(crate) fn validate_json(json: &str) -> Result<(), ()> {
    let value = serde_json::from_str::<Value>(json).expect("Invalid JSON");
    let validation = JSON_VALIDATOR.validate(&value).map(|_| ()).map_err(|e| {
        eprintln!("JSON schema validation error: {e}");
    });
    validate_json_external(json, validation.is_ok());
    validation
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
