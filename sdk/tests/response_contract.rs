//! Cross-repository conformance tests for the canonical plugin response contract.

use std::collections::BTreeSet;

use serde_json::Value;

const RESPONSE_SCHEMA: &str =
    include_str!("../../wit/contracts/kinetix.plugin.response.v1.schema.json");
const ALL_EVENTS: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/all-events.json");
const WARNING: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/warning.json");
const TERMINAL_ERROR: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/terminal-error.json");
const INVALID_VERSION: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/invalid-version.json");
const INVALID_MISSING_TEXT: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/invalid-missing-text.json");
const INVALID_ERROR_NOT_TERMINAL: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/invalid-error-not-terminal.json");

fn parse(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture must be valid JSON")
}

fn assert_v1_envelope(value: &Value) {
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("kinetix.plugin.response")
    );
    assert_eq!(
        value.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert!(value.get("events").and_then(Value::as_array).is_some());
}

#[test]
fn valid_host_golden_fixtures_are_plugin_v1_envelopes() {
    for raw in [ALL_EVENTS, WARNING, TERMINAL_ERROR] {
        assert_v1_envelope(&parse(raw));
    }
}

#[test]
fn shared_fixtures_cover_every_v1_event_type() {
    let mut event_types = BTreeSet::new();

    for raw in [ALL_EVENTS, WARNING, TERMINAL_ERROR] {
        let value = parse(raw);
        for event in value["events"].as_array().expect("events array") {
            event_types.insert(
                event["type"]
                    .as_str()
                    .expect("fixture event type")
                    .to_string(),
            );
        }
    }

    let expected = BTreeSet::from([
        "error".to_string(),
        "finish".to_string(),
        "start".to_string(),
        "text_delta".to_string(),
        "thinking_delta".to_string(),
        "tool_call_args_delta".to_string(),
        "tool_call_start".to_string(),
        "usage".to_string(),
        "warning".to_string(),
    ]);
    assert_eq!(event_types, expected);
}

#[test]
fn shared_invalid_fixtures_cover_contract_failures() {
    let invalid_version = parse(INVALID_VERSION);
    assert_ne!(
        invalid_version
            .get("schema_version")
            .and_then(Value::as_u64),
        Some(1)
    );

    let missing_text = parse(INVALID_MISSING_TEXT);
    assert!(
        missing_text["events"][0].get("text").is_none(),
        "invalid fixture must omit text"
    );

    let mixed_error = parse(INVALID_ERROR_NOT_TERMINAL);
    let events = mixed_error["events"].as_array().expect("events array");
    assert!(events.len() > 1);
    assert!(events.iter().any(|event| event["type"] == "error"));
}

#[test]
fn shared_schema_matches_rust_integer_boundaries() {
    let schema = parse(RESPONSE_SCHEMA);
    let event_schemas = schema
        .pointer("/$defs/event/oneOf")
        .and_then(Value::as_array)
        .expect("event schemas");

    let event_schema = |event_type: &str| {
        event_schemas
            .iter()
            .find(|event| {
                event
                    .pointer("/properties/type/const")
                    .and_then(Value::as_str)
                    == Some(event_type)
            })
            .expect("event schema")
    };

    let usage = event_schema("usage");
    for field in ["input", "output", "cached", "cache_write", "thinking"] {
        let pointer = format!("/properties/{field}/maximum");
        assert_eq!(
            usage.pointer(&pointer).and_then(Value::as_u64),
            Some(u64::MAX)
        );
    }

    let error = event_schema("error");
    assert_eq!(
        error
            .pointer("/properties/retry_after_secs/maximum")
            .and_then(Value::as_u64),
        Some(u64::MAX)
    );
}
