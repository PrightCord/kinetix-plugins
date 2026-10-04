//! Shared semantic conformance checks for Kinetix provider adapters.
//!
//! This crate is a dev-dependency only. Adapter crates provide a thin bridge
//! to their private implementation and a JSON profile declaring support per
//! upstream transport. The same Kinetix request/response fixtures then check
//! that supported semantics survive translation and unsupported semantics are
//! rejected explicitly.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

const REQUEST_TEXT: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/requests/text.json");
const REQUEST_IMAGE: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/image.json");
const REQUEST_REASONING: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/reasoning.json");
const REQUEST_TOOL_CALL: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/tool-call.json");
const REQUEST_PARALLEL_TOOLS: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/parallel-tools.json");
const REQUEST_TOOL_CONTINUATION: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/tool-result-continuation.json");
const REQUEST_TOOL_ERROR: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/tool-result-error.json");
const REQUEST_SCHEMA: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/structured-schema.json");
const REQUEST_SCHEMA_MAX_LENGTH: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/schema-max-length.json");
const REQUEST_MALFORMED_TOOL_ARGUMENTS: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/malformed-tool-arguments.json");
const REQUEST_MALFORMED_TOOL_HISTORY: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/malformed-tool-history.json");
const REQUEST_MIXED: &str =
    include_str!("../../wit/fixtures/plugin-request/v1/mixed-vision-tools-reasoning.json");
const RESPONSE_FIXTURES: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/responses.json");
const CANONICAL_RESPONSE_FIXTURE: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/parallel-tools-reasoning.json");

const REQUIRED_CAPABILITIES: &[&str] = &[
    "text_generation",
    "streaming",
    "non_streaming",
    "tool_calls",
    "parallel_tool_calls",
    "tool_result_continuation",
    "tool_result_errors",
    "image_input",
    "reasoning_controls",
    "reasoning_output",
    "structured_schemas",
    "schema_max_length",
    "stop_reasons",
    "usage_extraction",
    "error_classification",
    "client_cancellation",
];

/// Adapter entry points exercised by the reusable fixture suite.
pub trait Adapter {
    fn build_body(&self, request: &Value, provider: &Value, model: &Value)
        -> Result<Value, String>;

    fn parse_stream_chunk(&self, chunk: &Value) -> Result<Value, String>;
    fn parse_full_response(&self, response: &Value) -> Result<Value, String>;
    fn classify_error(&self, status: u16, body: &Value, headers: &Value) -> Result<Value, String>;
}

#[derive(Debug, Deserialize)]
struct Profile {
    schema_version: u32,
    adapter: String,
    transports: Vec<TransportProfile>,
}

#[derive(Debug, Deserialize)]
struct TransportProfile {
    format: String,
    model: Value,
    #[serde(default = "empty_object")]
    provider: Value,
    capabilities: BTreeMap<String, CapabilityStatus>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CapabilityStatus {
    Supported,
    Unsupported,
    NotApplicable,
}

fn empty_object() -> Value {
    json!({})
}

/// Run the complete shared fixture set against every declared transport.
pub fn check(adapter: &impl Adapter, profile_json: &str) -> Result<(), String> {
    let profile: Profile = serde_json::from_str(profile_json)
        .map_err(|error| format!("invalid adapter conformance profile: {error}"))?;
    if profile.schema_version != 1 {
        return Err(format!(
            "{} profile has unsupported schema_version {}",
            profile.adapter, profile.schema_version
        ));
    }
    if profile.adapter.trim().is_empty() || profile.transports.is_empty() {
        return Err("adapter profile requires a name and at least one transport".into());
    }

    let responses: Value = serde_json::from_str(RESPONSE_FIXTURES)
        .expect("shared adapter response fixtures must be valid JSON");
    let protocol_fixtures = responses
        .get("transports")
        .and_then(Value::as_object)
        .expect("response fixtures must contain transports");
    let canonical_response: Value = serde_json::from_str(CANONICAL_RESPONSE_FIXTURE)
        .expect("canonical plugin response fixture must be valid JSON");
    let canonical_events = canonical_response["events"]
        .as_array()
        .expect("canonical plugin response fixture must contain events");
    let mut formats = BTreeSet::new();

    for transport in &profile.transports {
        if !formats.insert(transport.format.as_str()) {
            return Err(format!(
                "{} declares transport '{}' more than once",
                profile.adapter, transport.format
            ));
        }
        validate_capabilities(&profile.adapter, transport)?;
        let context = format!("{} / {}", profile.adapter, transport.format);

        check_request_feature(
            adapter,
            &context,
            transport,
            "text_generation",
            REQUEST_TEXT,
            &["conformance text"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "image_input",
            REQUEST_IMAGE,
            &["QUJD"],
        )?;
        check_reasoning(adapter, &context, transport)?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "tool_calls",
            REQUEST_TOOL_CALL,
            &["read_file", "src/main.rs"],
        )?;
        check_tool_name_identity(adapter, &context, transport)?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "parallel_tool_calls",
            REQUEST_PARALLEL_TOOLS,
            &["get_weather", "read_file", "Paris", "src/main.rs"],
        )?;
        check_tool_result_continuation(adapter, &context, transport)?;
        check_tool_result_payloads(adapter, &context, transport)?;
        check_tool_result_errors(adapter, &context, transport)?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "structured_schemas",
            REQUEST_SCHEMA,
            &["query", "required", "Search files"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "schema_max_length",
            REQUEST_SCHEMA_MAX_LENGTH,
            &["maxLength", "32"],
        )?;
        check_malformed_tool_arguments(adapter, &context, transport)?;
        check_malformed_tool_history(adapter, &context, transport)?;
        check_mixed_request(adapter, &context, transport)?;

        let response_fixture = protocol_fixtures
            .get(&transport.format)
            .ok_or_else(|| format!("{context} has no shared response fixture"))?;
        check_expected_response_fixture(&context, response_fixture, canonical_events)?;
        check_response_feature(
            adapter,
            &context,
            transport,
            response_fixture,
            "streaming",
            true,
        )?;
        check_response_feature(
            adapter,
            &context,
            transport,
            response_fixture,
            "non_streaming",
            false,
        )?;
        if transport.capabilities["streaming"] == CapabilityStatus::Supported
            && transport.capabilities["non_streaming"] == CapabilityStatus::Supported
        {
            check_stream_full_equivalence(adapter, &context, response_fixture)?;
        }
        check_stop_reasons(adapter, &context, transport, response_fixture)?;
        check_provider_response_tolerance(adapter, &context, transport)?;
        check_error_classification(adapter, &context, transport)?;
    }

    Ok(())
}

fn validate_capabilities(adapter: &str, transport: &TransportProfile) -> Result<(), String> {
    let found: BTreeSet<_> = transport.capabilities.keys().map(String::as_str).collect();
    let required: BTreeSet<_> = REQUIRED_CAPABILITIES.iter().copied().collect();
    let missing: Vec<_> = required.difference(&found).copied().collect();
    let unknown: Vec<_> = found.difference(&required).copied().collect();
    if !missing.is_empty() || !unknown.is_empty() {
        return Err(format!(
            "{adapter} / {} capability declaration mismatch; missing: [{}], unknown: [{}]",
            transport.format,
            missing.join(", "),
            unknown.join(", ")
        ));
    }
    for dependent in [
        "parallel_tool_calls",
        "tool_result_continuation",
        "tool_result_errors",
    ] {
        if transport.capabilities[dependent] == CapabilityStatus::Supported
            && transport.capabilities["tool_calls"] != CapabilityStatus::Supported
        {
            return Err(format!(
                "{adapter} / {} declares {dependent} supported without tool_calls",
                transport.format
            ));
        }
    }
    if transport.capabilities["tool_result_errors"] == CapabilityStatus::Supported
        && transport.capabilities["tool_result_continuation"] != CapabilityStatus::Supported
    {
        return Err(format!(
            "{adapter} / {} declares tool_result_errors supported without tool_result_continuation",
            transport.format
        ));
    }
    if transport.capabilities["schema_max_length"] == CapabilityStatus::Supported
        && transport.capabilities["structured_schemas"] != CapabilityStatus::Supported
    {
        return Err(format!(
            "{adapter} / {} declares schema_max_length supported without structured_schemas",
            transport.format
        ));
    }
    if transport.capabilities["client_cancellation"] != CapabilityStatus::NotApplicable {
        return Err(format!(
            "{adapter} / {} must mark client_cancellation not_applicable; cancellation is outside the adapter test seam",
            transport.format
        ));
    }
    Ok(())
}

fn parse_fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("shared adapter request fixture must be valid JSON")
}

fn check_request_feature(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    capability: &str,
    fixture: &str,
    markers: &[&str],
) -> Result<(), String> {
    let request = parse_fixture(fixture);
    match transport.capabilities[capability] {
        CapabilityStatus::Supported => {
            let body = adapter
                .build_body(&request, &transport.provider, &transport.model)
                .map_err(|error| {
                    format!("{context} declares {capability} supported but rejected it: {error}")
                })?;
            let serialized = body.to_string();
            for marker in markers {
                if !serialized.contains(marker) {
                    return Err(format!(
                        "{context} silently lost {capability} marker '{marker}'"
                    ));
                }
            }
            if transport.format != "antigravity" {
                let identities: &[&str] = match capability {
                    "tool_calls" => &["call_read"],
                    "parallel_tool_calls" => &["call_weather", "call_read"],
                    "tool_result_continuation" => &["call_read"],
                    _ => &[],
                };
                for id in identities {
                    if !serialized.contains(id) {
                        return Err(format!(
                            "{context} silently lost {capability} identity '{id}'"
                        ));
                    }
                }
            }
            if capability == "reasoning_controls"
                && transport.format == "antigravity"
                && body.pointer("/request/generationConfig/thinkingConfig/thinkingLevel")
                    != Some(&json!("high"))
            {
                return Err(format!(
                    "{context} did not map high reasoning effort to Gemini thinkingLevel"
                ));
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            capability,
            adapter.build_body(&request, &transport.provider, &transport.model),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn check_reasoning(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    check_request_feature(
        adapter,
        context,
        transport,
        "reasoning_controls",
        REQUEST_REASONING,
        &["thinking", "high"],
    )
}

fn expect_unsupported<T>(
    context: &str,
    capability: &str,
    result: Result<T, String>,
) -> Result<(), String> {
    match result {
        Ok(_) => Err(format!(
            "{context} declares {capability} unsupported but accepted it"
        )),
        Err(error) => {
            let lower = error.to_ascii_lowercase();
            if lower.contains("unsupported") || lower.contains("not support") {
                Ok(())
            } else {
                Err(format!(
                    "{context} must explicitly reject unsupported {capability}; got: {error}"
                ))
            }
        }
    }
}

fn check_tool_name_identity(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    if transport.capabilities["tool_calls"] != CapabilityStatus::Supported {
        return Ok(());
    }

    let client_name = if transport.format == "antigravity" {
        "read file!"
    } else {
        "read_file"
    };
    let mut request = parse_fixture(REQUEST_TOOL_CALL);
    request["tools"][0]["name"] = json!(client_name);
    request["messages"][1]["parts"][0]["name"] = json!(client_name);
    request["messages"].as_array_mut().unwrap().push(json!({
        "role": "tool",
        "parts": [{
            "type": "tool_result",
            "tool_call_id": "call_read",
            "name": client_name,
            "content": "tool output",
            "is_error": false
        }]
    }));
    request["tool_choice"] = json!({"mode":"specific","name":client_name});

    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected a reversible tool-name probe: {error}"))?;
    let wire_name = match transport.format.as_str() {
        "antigravity" => body
            .pointer("/request/tools/0/functionDeclarations/0/name")
            .and_then(Value::as_str),
        "openai-chat" => body
            .pointer("/tools/0/function/name")
            .and_then(Value::as_str),
        "openai-responses" => body.pointer("/tools/0/name").and_then(Value::as_str),
        "anthropic" => body.pointer("/tools/0/name").and_then(Value::as_str),
        format => {
            return Err(format!(
                "{context} has no tool-name assertion for '{format}'"
            ));
        }
    }
    .ok_or_else(|| format!("{context} omitted the declared tool name"))?;
    if transport.format != "antigravity" && wire_name != client_name {
        return Err(format!(
            "{context} changed tool name '{client_name}' to '{wire_name}'"
        ));
    }

    let historical_name = match transport.format.as_str() {
        "antigravity" => body
            .pointer("/request/contents/1/parts/0/functionCall/name")
            .and_then(Value::as_str),
        "openai-chat" => body
            .pointer("/messages/1/tool_calls/0/function/name")
            .and_then(Value::as_str),
        "openai-responses" => body
            .get("input")
            .and_then(Value::as_array)
            .and_then(|items| items.iter().find(|item| item["type"] == "function_call"))
            .and_then(|item| item["name"].as_str()),
        "anthropic" => body
            .pointer("/messages/1/content/0/name")
            .and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| format!("{context} omitted the historical tool call"))?;
    if historical_name != wire_name {
        return Err(format!(
            "{context} used inconsistent declaration and history names: {wire_name} vs {historical_name}"
        ));
    }

    if transport.format == "antigravity"
        && (body.pointer("/request/toolConfig/functionCallingConfig/allowedFunctionNames/0")
            != Some(&json!(wire_name))
            || body.pointer("/request/contents/2/parts/0/functionResponse/name")
                != Some(&json!(wire_name)))
    {
        return Err(format!(
            "{context} used inconsistent tool choice or result name for '{client_name}'"
        ));
    }

    let stream = match transport.format.as_str() {
        "antigravity" => json!({"response":{"candidates":[{"content":{"parts":[{
            "functionCall":{"name":wire_name,"args":{}}
        }]}}]}}),
        "openai-chat" => json!({"choices":[{"delta":{"tool_calls":[{
            "index":0,"function":{"name":wire_name,"arguments":"{}"}
        }]}}]}),
        "openai-responses" => json!({"type":"response.output_item.added","output_index":0,"item":{
            "type":"function_call","call_id":"call_probe","name":wire_name
        }}),
        "anthropic" => json!({"type":"content_block_start","index":0,"content_block":{
            "type":"tool_use","id":"call_probe","name":wire_name,"input":{}
        }}),
        _ => unreachable!(),
    };
    let response = adapter
        .parse_stream_chunk(&stream)
        .map_err(|error| format!("{context} failed to parse its tool-name probe: {error}"))?;
    let events = unpack_response_envelope(response, context)?;
    let parsed_name = events
        .iter()
        .find(|event| event["type"] == "tool_call_start")
        .and_then(|event| event["name"].as_str())
        .ok_or_else(|| format!("{context} omitted the parsed tool call"))?;
    if parsed_name != client_name {
        return Err(format!(
            "{context} did not restore client tool name '{client_name}': {parsed_name}"
        ));
    }

    if transport.capabilities["non_streaming"] != CapabilityStatus::Supported {
        return Ok(());
    }
    let full = match transport.format.as_str() {
        "antigravity" => json!({"response":{"candidates":[{"content":{"parts":[{
            "functionCall":{"name":wire_name,"args":{}}
        }]}}]}}),
        "openai-chat" => json!({"object":"chat.completion","choices":[{"message":{"tool_calls":[{
            "index":0,"id":"call_probe","type":"function","function":{"name":wire_name,"arguments":"{}"}
        }]}}]}),
        "openai-responses" => json!({"object":"response","output":[{
            "type":"function_call","call_id":"call_probe","name":wire_name,"arguments":"{}"
        }]}),
        "anthropic" => json!({"type":"message","content":[{
            "type":"tool_use","id":"call_probe","name":wire_name,"input":{}
        }]}),
        _ => unreachable!(),
    };
    let response = adapter
        .parse_full_response(&full)
        .map_err(|error| format!("{context} failed to parse its full tool-name probe: {error}"))?;
    let events = unpack_response_envelope(response, context)?;
    let parsed_name = events
        .iter()
        .find(|event| event["type"] == "tool_call_start")
        .and_then(|event| event["name"].as_str())
        .ok_or_else(|| format!("{context} omitted its full-response tool call"))?;
    if parsed_name != client_name {
        return Err(format!(
            "{context} did not restore full-response tool name '{client_name}': {parsed_name}"
        ));
    }
    Ok(())
}

fn check_tool_result_continuation(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_TOOL_CONTINUATION);
    match transport.capabilities["tool_result_continuation"] {
        CapabilityStatus::Supported => {
            let body = adapter
                .build_body(&request, &transport.provider, &transport.model)
                .map_err(|error| {
                    format!(
                        "{context} declares tool_result_continuation supported but rejected it: {error}"
                    )
                })?;
            let preserved = match transport.format.as_str() {
                "antigravity" => {
                    body.pointer("/request/contents/1/parts/0/functionResponse/response/result")
                        .and_then(Value::as_str)
                        == Some("fn main() {}")
                        && body
                            .pointer("/request/contents/1/parts/0/functionResponse/response/error")
                            .is_none()
                        && body.pointer("/request/contents/1/parts/0/functionResponse/id")
                            == Some(&json!("call_read"))
                }
                "anthropic" => {
                    body.pointer("/messages/1/content/0/content")
                        .and_then(Value::as_str)
                        == Some("fn main() {}")
                        && body.pointer("/messages/1/content/0/tool_use_id")
                            == Some(&json!("call_read"))
                        && body.pointer("/messages/1/content/0/is_error") != Some(&json!(true))
                }
                "openai-chat" => {
                    body.pointer("/messages/1/content").and_then(Value::as_str)
                        == Some("fn main() {}")
                        && body.pointer("/messages/1/tool_call_id") == Some(&json!("call_read"))
                }
                "openai-responses" => body
                    .get("input")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|item| {
                        item.get("type").and_then(Value::as_str) == Some("function_call_output")
                            && item.get("call_id") == Some(&json!("call_read"))
                            && item.get("output").and_then(Value::as_str) == Some("fn main() {}")
                    }),
                format => {
                    return Err(format!(
                        "{context} has no tool-result continuation assertion for transport '{format}'"
                    ));
                }
            };
            if !preserved {
                return Err(format!(
                    "{context} lost successful tool-result continuation: {body}"
                ));
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            "tool_result_continuation",
            adapter.build_body(&request, &transport.provider, &transport.model),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn check_tool_result_payloads(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    if transport.capabilities["tool_result_continuation"] != CapabilityStatus::Supported {
        return Ok(());
    }

    let mut request = parse_fixture(REQUEST_TOOL_CONTINUATION);
    for value in [
        json!(null),
        json!({"exit_code":0}),
        json!([1, 2]),
        json!([{"type":"record","id":1}]),
        json!([{"type":"text","id":1}]),
        json!([{"type":"image","id":1}]),
        json!({"type":"image","data":null}),
        json!({"type":"image","mime":"image/png","id":1}),
        json!([{"type":"image","mime":"image/png","id":1}]),
        json!([]),
    ] {
        request["messages"][1]["parts"][0]["content"] = value.clone();
        request["messages"][1]["parts"][0]
            .as_object_mut()
            .unwrap()
            .remove("structured_content");
        let body = adapter
            .build_body(&request, &transport.provider, &transport.model)
            .map_err(|error| format!("{context} rejected JSON tool output {value}: {error}"))?;
        let preserved = if transport.format == "antigravity" {
            let response = body.pointer("/request/contents/1/parts/0/functionResponse/response");
            if value.is_object() {
                response == Some(&value)
            } else {
                response.and_then(|response| response.get("result")) == Some(&value)
            }
        } else {
            open_code_tool_output(&body, &transport.format)
                .and_then(|output| serde_json::from_str::<Value>(output).ok())
                == Some(value.clone())
        };
        if !preserved {
            return Err(format!(
                "{context} lost JSON tool-result payload {value}: {body}"
            ));
        }
    }

    let mut absent_request = parse_fixture(REQUEST_TOOL_CONTINUATION);
    absent_request["messages"][1]["parts"][0]
        .as_object_mut()
        .unwrap()
        .remove("content");
    let body = adapter
        .build_body(&absent_request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected a tool result with no content: {error}"))?;
    let absent_remains_empty = if transport.format == "antigravity" {
        body.pointer("/request/contents/1/parts/0/functionResponse/response/result")
            == Some(&json!(""))
    } else {
        open_code_tool_output(&body, &transport.format) == Some("")
    };
    if !absent_remains_empty {
        return Err(format!(
            "{context} changed the empty result for absent tool content: {body}"
        ));
    }

    for (label, content, structured_content, expected) in [
        ("empty content object", Some(json!({})), None, json!({})),
        ("empty structured_content", None, Some(json!({})), json!({})),
        (
            "empty JSON content part",
            Some(json!([{"type":"json","value":{}}])),
            None,
            json!([{"type":"json","value":{}}]),
        ),
    ] {
        let mut empty_request = parse_fixture(REQUEST_TOOL_CONTINUATION);
        let part = empty_request["messages"][1]["parts"][0]
            .as_object_mut()
            .unwrap();
        part.remove("content");
        part.remove("structured_content");
        if let Some(content) = content {
            part.insert("content".into(), content);
        }
        if let Some(structured_content) = structured_content {
            part.insert("structured_content".into(), structured_content);
        }

        let body = adapter
            .build_body(&empty_request, &transport.provider, &transport.model)
            .map_err(|error| format!("{context} rejected {label}: {error}"))?;
        let preserved = if transport.format == "antigravity" {
            body.pointer("/request/contents/1/parts/0/functionResponse/response")
                == Some(&json!({}))
        } else {
            open_code_tool_output(&body, &transport.format)
                .and_then(|output| serde_json::from_str::<Value>(output).ok())
                == Some(expected)
        };
        if !preserved {
            return Err(format!("{context} changed {label}: {body}"));
        }
    }

    let mixed_parts = json!([
        {"type":"record","id":1},
        {"type":"image","mime":"image/png","data":"QUJD"}
    ]);
    request["messages"][1]["parts"][0]["content"] = mixed_parts.clone();
    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected a mixed JSON array: {error}"))?;
    let preserved = if transport.format == "antigravity" {
        body.pointer("/request/contents/1/parts/0/functionResponse/response/result")
            == Some(&mixed_parts)
    } else {
        open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            == Some(mixed_parts)
    };
    if !preserved {
        return Err(format!("{context} changed a mixed JSON array: {body}"));
    }

    request["messages"][1]["parts"][0]["content"] = json!({"exit_code":0});
    request["messages"][1]["parts"][0]["structured_content"] =
        json!({"source":"structured_content"});
    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected structured_content tool output: {error}"))?;
    let preserved = if transport.format == "antigravity" {
        body.pointer("/request/contents/1/parts/0/functionResponse/response/structured_parts")
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.contains(&json!({"exit_code":0}))
                    && parts.contains(&json!({"source":"structured_content"}))
            })
    } else {
        open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            == Some(json!({
                "content":{"exit_code":0},
                "structured_content":{"source":"structured_content"}
            }))
    };
    if !preserved {
        return Err(format!("{context} lost structured_content: {body}"));
    }

    if transport.format != "antigravity" {
        let content_record = json!({"type":"file","path":"README.md"});
        request["messages"][1]["parts"][0]["content"] = content_record.clone();
        request["messages"][1]["parts"][0]
            .as_object_mut()
            .unwrap()
            .remove("structured_content");
        let body = adapter
            .build_body(&request, &transport.provider, &transport.model)
            .map_err(|error| format!("{context} rejected opaque content JSON: {error}"))?;
        if open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            != Some(content_record)
        {
            return Err(format!("{context} changed opaque content JSON: {body}"));
        }

        let structured_record = json!({"record":{"type":"image","id":1}});
        request["messages"][1]["parts"][0]["content"] = json!("result");
        request["messages"][1]["parts"][0]["structured_content"] = structured_record.clone();
        let body = adapter
            .build_body(&request, &transport.provider, &transport.model)
            .map_err(|error| format!("{context} rejected opaque structured_content: {error}"))?;
        if open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            != Some(json!({"content":"result","structured_content":structured_record}))
        {
            return Err(format!(
                "{context} changed opaque structured_content: {body}"
            ));
        }
    }

    let text_parts = json!([{"type":"text","text":"result text"}]);
    request["messages"][1]["parts"][0]["content"] = text_parts.clone();
    request["messages"][1]["parts"][0]
        .as_object_mut()
        .unwrap()
        .remove("structured_content");
    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected text-part tool output: {error}"))?;
    let preserved = if transport.format == "antigravity" {
        body.pointer("/request/contents/1/parts/0/functionResponse/response/result")
            == Some(&json!("result text"))
    } else {
        open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            == Some(text_parts)
    };
    if !preserved {
        return Err(format!("{context} lost text content parts: {body}"));
    }

    if transport.format == "antigravity" {
        request["messages"][1]["parts"][0]["content"] = json!([
            {"type":"text","text":"result text"},
            {"type":"json","value":{"exit_code":0}},
            {"type":"image","mime":"image/png","data":"QUJD"},
            {"type":"document","mime":"application/pdf","data":"JVBERi0="}
        ]);
        let body = adapter
            .build_body(&request, &transport.provider, &transport.model)
            .map_err(|error| format!("{context} rejected supported media tool output: {error}"))?;
        let function_response = body
            .pointer("/request/contents/1/parts/0/functionResponse")
            .ok_or_else(|| format!("{context} omitted the Gemini function response"))?;
        if function_response["response"]["exit_code"] != 0
            || function_response["response"]["result"] != "result text"
            || function_response["parts"][0]["inlineData"]["data"] != "QUJD"
            || function_response["parts"][0]["inlineData"]["mimeType"] != "image/png"
            || function_response["parts"][1]["inlineData"]["data"] != "JVBERi0="
            || function_response["parts"][1]["inlineData"]["mimeType"] != "application/pdf"
        {
            return Err(format!(
                "{context} lost structured or multimodal tool-result parts: {function_response}"
            ));
        }
    }

    for (kind, content) in [
        (
            "unsupported media",
            json!([{"type":"audio","mime":"audio/wav","data":"AA=="}]),
        ),
        (
            "image media",
            json!([{"type":"image","mime":"image/png","data":"QUJD"}]),
        ),
    ] {
        request["messages"][1]["parts"][0]["content"] = content;
        match adapter.build_body(&request, &transport.provider, &transport.model) {
            Err(error) if error.contains("unsupported_media") => {}
            Err(error) => {
                return Err(format!(
                    "{context} returned a non-compatibility error for {kind}: {error}"
                ))
            }
            Ok(body) if transport.format == "antigravity" && kind == "image media" => {
                if body
                    .pointer("/request/contents/1/parts/0/functionResponse/parts/0/inlineData/data")
                    != Some(&json!("QUJD"))
                {
                    return Err(format!("{context} lost supported image media: {body}"));
                }
            }
            Ok(body) => {
                return Err(format!(
                    "{context} silently accepted unsupported {kind} in a function response: {body}"
                ))
            }
        }
    }

    let nested_media = json!({
        "nested":[{"type":"image","mime":"image/png","data":"QUJD"}]
    });
    request["messages"][1]["parts"][0]["content"] = nested_media.clone();
    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected opaque nested JSON: {error}"))?;
    let preserved = if transport.format == "antigravity" {
        body.pointer("/request/contents/1/parts/0/functionResponse/response/nested/0/type")
            == Some(&json!("image"))
    } else {
        open_code_tool_output(&body, &transport.format)
            .and_then(|output| serde_json::from_str::<Value>(output).ok())
            == Some(nested_media)
    };
    if !preserved {
        return Err(format!("{context} changed opaque nested JSON: {body}"));
    }

    if transport.format == "antigravity" {
        for (kind, content) in [
            (
                "URI media",
                json!([{"type":"document_url","url":"gs://bucket/report.pdf"}]),
            ),
            ("missing MIME", json!([{"type":"image","data":"QUJD"}])),
            (
                "invalid MIME",
                json!([{"type":"image","mime":"not-a-mime","data":"QUJD"}]),
            ),
        ] {
            request["messages"][1]["parts"][0]["content"] = content;
            match adapter.build_body(&request, &transport.provider, &transport.model) {
                Err(error) if error.contains("unsupported_media") => {}
                Err(error) => {
                    return Err(format!(
                        "{context} returned a non-compatibility error for {kind}: {error}"
                    ))
                }
                Ok(body) => {
                    return Err(format!(
                        "{context} silently accepted {kind} in a function response: {body}"
                    ))
                }
            }
        }
    }
    Ok(())
}

fn open_code_tool_output<'a>(body: &'a Value, format: &str) -> Option<&'a str> {
    match format {
        "openai-chat" => body.pointer("/messages/1/content").and_then(Value::as_str),
        "openai-responses" => body
            .get("input")?
            .as_array()?
            .iter()
            .find(|item| item.get("type").and_then(Value::as_str) == Some("function_call_output"))?
            .get("output")?
            .as_str(),
        "anthropic" => body
            .pointer("/messages/1/content/0/content")
            .and_then(Value::as_str),
        _ => None,
    }
}

fn check_tool_result_errors(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_TOOL_ERROR);
    match transport.capabilities["tool_result_errors"] {
        CapabilityStatus::Supported => {
            let body = adapter
                .build_body(&request, &transport.provider, &transport.model)
                .map_err(|error| {
                    format!(
                        "{context} declares tool_result_errors supported but rejected it: {error}"
                    )
                })?;
            let error_content = request
                .pointer("/messages/1/parts/0/content")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool-result error fixture lacks content".to_string())?;
            let preserved = match transport.format.as_str() {
                "antigravity" => {
                    body.pointer("/request/contents/1/parts/0/functionResponse/response/error")
                        .and_then(Value::as_str)
                        == Some(error_content)
                        && body
                            .pointer("/request/contents/1/parts/0/functionResponse/response/result")
                            .is_none()
                        && body.pointer("/request/contents/1/parts/0/functionResponse/id")
                            == Some(&json!("call_read"))
                }
                "anthropic" => {
                    body.pointer("/messages/1/content/0/is_error") == Some(&json!(true))
                        && body
                            .pointer("/messages/1/content/0/content")
                            .and_then(Value::as_str)
                            == Some(error_content)
                        && body.pointer("/messages/1/content/0/tool_use_id")
                            == Some(&json!("call_read"))
                }
                format => {
                    return Err(format!(
                        "{context} has no tool-result error assertion for transport '{format}'"
                    ));
                }
            };
            if !preserved {
                return Err(format!(
                    "{context} silently lost failed-tool semantics for '{error_content}': {body}"
                ));
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            "tool_result_errors",
            adapter.build_body(&request, &transport.provider, &transport.model),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn check_malformed_tool_arguments(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MALFORMED_TOOL_ARGUMENTS);
    match adapter.build_body(&request, &transport.provider, &transport.model) {
        Err(error) if !error.trim().is_empty() => Ok(()),
        Err(_) => Err(format!(
            "{context} returned an empty malformed-arguments error"
        )),
        Ok(body) => Err(format!(
            "{context} forwarded malformed tool arguments upstream: {body}"
        )),
    }
}

fn check_malformed_tool_history(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MALFORMED_TOOL_HISTORY);
    match adapter.build_body(&request, &transport.provider, &transport.model) {
        Err(error) if !error.trim().is_empty() => Ok(()),
        Err(_) => Err(format!(
            "{context} returned an empty malformed-history error"
        )),
        Ok(body) => Err(format!(
            "{context} forwarded malformed tool history upstream: {body}"
        )),
    }
}

fn check_mixed_request(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MIXED);
    let required = [
        "image_input",
        "tool_calls",
        "tool_result_continuation",
        "reasoning_controls",
    ];
    if let Some(capability) = required
        .iter()
        .find(|capability| transport.capabilities[**capability] == CapabilityStatus::Unsupported)
    {
        return expect_unsupported(
            context,
            capability,
            adapter.build_body(&request, &transport.provider, &transport.model),
        );
    }
    if required
        .iter()
        .any(|capability| transport.capabilities[*capability] == CapabilityStatus::NotApplicable)
    {
        return Ok(());
    }

    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected the canonical mixed request: {error}"))?;
    let serialized = body.to_string();
    for marker in [
        "fixture:plugin-mixed inspect image",
        "QUJD",
        "read_file",
        "call_plugin_1",
        "fn main() {}",
    ] {
        if !serialized.contains(marker) {
            return Err(format!(
                "{context} silently lost canonical mixed-request marker '{marker}'"
            ));
        }
    }
    Ok(())
}

fn check_expected_response_fixture(
    context: &str,
    fixture: &Value,
    canonical_events: &[Value],
) -> Result<(), String> {
    let expected = fixture
        .get("expected")
        .ok_or_else(|| format!("{context} response fixture lacks expected events"))?;
    let canonical_thinking = canonical_events
        .iter()
        .find(|event| event["type"] == "thinking_delta" && event["text"].as_str() != Some(""))
        .and_then(|event| event["text"].as_str())
        .ok_or_else(|| "canonical response fixture lacks reasoning text".to_string())?;
    if expected["thinking"].as_str() != Some(canonical_thinking) {
        return Err(format!(
            "{context} response fixture reasoning differs from the canonical response fixture"
        ));
    }
    let canonical_calls: Vec<_> = canonical_events
        .iter()
        .filter(|event| event["type"] == "tool_call_start")
        .collect();
    let expected_calls = expected["tools"]
        .as_array()
        .ok_or_else(|| format!("{context} response fixture lacks expected tool calls"))?;
    if canonical_calls.len() != expected_calls.len() {
        return Err(format!(
            "{context} response fixture has a different tool count than the canonical response"
        ));
    }
    for canonical_call in canonical_calls {
        let name = canonical_call["name"].as_str().unwrap_or_default();
        let expected_call = expected_calls
            .iter()
            .find(|call| call["name"].as_str() == Some(name))
            .ok_or_else(|| format!("{context} response fixture lost canonical tool '{name}'"))?;
        let index = canonical_call["index"].as_u64().unwrap_or_default();
        let canonical_args = canonical_events
            .iter()
            .filter(|event| {
                event["type"] == "tool_call_args_delta" && event["index"].as_u64() == Some(index)
            })
            .filter_map(|event| event["args"].as_str())
            .collect::<String>();
        let canonical_args: Value = serde_json::from_str(&canonical_args)
            .map_err(|error| format!("canonical tool '{name}' has invalid arguments: {error}"))?;
        if expected_call["arguments"] != canonical_args {
            return Err(format!(
                "{context} response fixture arguments for '{name}' differ from the canonical response"
            ));
        }
    }

    let canonical_finish = canonical_events
        .iter()
        .find(|event| event["type"] == "finish")
        .and_then(|event| event["reason"].as_str())
        .ok_or_else(|| "canonical response fixture lacks a finish reason".to_string())?;
    if expected["finish_reason"].as_str() != Some(canonical_finish) {
        return Err(format!(
            "{context} response fixture finish reason differs from the canonical response"
        ));
    }
    let canonical_usage = canonical_events
        .iter()
        .find(|event| event["type"] == "usage")
        .ok_or_else(|| "canonical response fixture lacks usage".to_string())?;
    for field in ["input", "output", "thinking"] {
        if !canonical_usage[field].is_null() && expected["usage"][field] != canonical_usage[field] {
            return Err(format!(
                "{context} response fixture usage.{field} differs from the canonical response"
            ));
        }
    }
    Ok(())
}

fn check_response_feature(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    fixture: &Value,
    capability: &str,
    streaming: bool,
) -> Result<(), String> {
    match transport.capabilities[capability] {
        CapabilityStatus::Supported => {
            let events = parse_response(adapter, context, fixture, streaming)?;
            let events = events.as_array().ok_or_else(|| {
                format!("{context} parser must return an event array, got {events}")
            })?;
            assert_expected_events(context, fixture, events, &transport.capabilities)
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            capability,
            parse_response(adapter, context, fixture, streaming),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn parse_response(
    adapter: &impl Adapter,
    context: &str,
    fixture: &Value,
    streaming: bool,
) -> Result<Value, String> {
    if streaming {
        let chunks = fixture
            .get("stream")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{context} fixture has no stream chunks"))?;
        let mut events = Vec::new();
        for chunk in chunks {
            let envelope = adapter
                .parse_stream_chunk(chunk)
                .map_err(|error| format!("{context} stream parser failed: {error}"))?;
            events.extend(unpack_response_envelope(envelope, context)?);
        }
        Ok(Value::Array(events))
    } else {
        let response = fixture
            .get("full")
            .ok_or_else(|| format!("{context} fixture has no full response"))?;
        let envelope = adapter
            .parse_full_response(response)
            .map_err(|error| format!("{context} full-response parser failed: {error}"))?;
        Ok(Value::Array(unpack_response_envelope(envelope, context)?))
    }
}

fn unpack_response_envelope(output: Value, context: &str) -> Result<Vec<Value>, String> {
    if output.get("schema").and_then(Value::as_str) != Some("kinetix.plugin.response") {
        return Err(format!(
            "{context} parser must return a kinetix.plugin.response envelope, got {output}"
        ));
    }
    if output.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(format!(
            "{context} parser must return response schema version 1, got {output}"
        ));
    }
    let events = output
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{context} response envelope must contain an events array"))?;
    if events
        .iter()
        .any(|event| !event.is_object() || event.get("type").and_then(Value::as_str).is_none())
    {
        return Err(format!(
            "{context} response envelope contains an invalid event"
        ));
    }
    Ok(events.clone())
}

fn assert_expected_events(
    context: &str,
    fixture: &Value,
    events: &[Value],
    capabilities: &BTreeMap<String, CapabilityStatus>,
) -> Result<(), String> {
    let expected = fixture
        .get("expected")
        .ok_or_else(|| format!("{context} response fixture lacks expected events"))?;
    let event_type = |event: &&Value, expected_type: &str| {
        event.get("type").and_then(Value::as_str) == Some(expected_type)
    };

    let request_id = expected["request_id"].as_str().unwrap();
    if !events
        .iter()
        .any(|event| event_type(&event, "start") && event["upstream_request_id"] == request_id)
    {
        return Err(format!("{context} response lost upstream request id"));
    }
    for (capability, feature, event_kind, field) in [
        (
            "reasoning_output",
            "reasoning",
            "thinking_delta",
            "thinking",
        ),
        ("text_generation", "text", "text_delta", "text"),
    ] {
        if capabilities[capability] != CapabilityStatus::Supported {
            continue;
        }
        let value = expected[field].as_str().unwrap();
        let content_event = events
            .iter()
            .find(|event| event_type(event, event_kind) && event["text"].as_str() == Some(value));
        let Some(content_event) = content_event else {
            return Err(format!(
                "{context} response lost {feature} content '{value}'"
            ));
        };
        if feature == "reasoning" {
            if let Some(signature) = expected.get("thinking_signature").and_then(Value::as_str) {
                if content_event["signature"].as_str() != Some(signature)
                    && !events.iter().any(|event| {
                        event_type(&event, event_kind)
                            && event["signature"].as_str() == Some(signature)
                    })
                {
                    return Err(format!(
                        "{context} response lost reasoning signature '{signature}'"
                    ));
                }
            }
        }
    }

    let expected_calls = expected["tools"].as_array().unwrap();
    if capabilities["tool_calls"] == CapabilityStatus::Supported {
        let call_count = if capabilities["parallel_tool_calls"] == CapabilityStatus::Supported {
            expected_calls.len()
        } else {
            expected_calls.len().min(1)
        };
        for call in expected_calls.iter().take(call_count) {
            let index = call["index"].as_u64().unwrap();
            let name = call["name"].as_str().unwrap();
            let start = events.iter().find(|event| {
                event_type(event, "tool_call_start")
                    && event["index"].as_u64() == Some(index)
                    && event["name"].as_str() == Some(name)
            });
            let Some(start) = start else {
                return Err(format!(
                    "{context} response lost tool call {index} '{name}'; events: {events:?}"
                ));
            };
            if let Some(id) = call.get("id").and_then(Value::as_str) {
                if start["id"].as_str() != Some(id) {
                    return Err(format!(
                        "{context} response changed tool call id for '{name}'"
                    ));
                }
            }
            if let Some(signature) = call.get("signature").and_then(Value::as_str) {
                if start["signature"].as_str() != Some(signature) {
                    return Err(format!(
                        "{context} response lost tool call signature for '{name}'"
                    ));
                }
            }
            let args = call["arguments"].as_object().unwrap();
            let mut actual_args = String::new();
            for event in events.iter().filter(|event| {
                event_type(event, "tool_call_args_delta") && event["index"].as_u64() == Some(index)
            }) {
                if let Some(value) = event["args"].as_str() {
                    actual_args.push_str(value);
                }
            }
            let parsed_args: Value = serde_json::from_str(&actual_args).map_err(|error| {
                format!("{context} emitted invalid arguments for tool '{name}': {error}")
            })?;
            if parsed_args != Value::Object(args.clone()) {
                return Err(format!("{context} changed arguments for tool '{name}'"));
            }
        }
    }

    if capabilities["stop_reasons"] == CapabilityStatus::Supported {
        let finish_reason = expected["finish_reason"].as_str().unwrap();
        if !events.iter().any(|event| {
            event_type(&event, "finish") && event["reason"].as_str() == Some(finish_reason)
        }) {
            return Err(format!(
                "{context} changed finish reason to something other than '{finish_reason}'"
            ));
        }
    }

    if capabilities["usage_extraction"] != CapabilityStatus::Supported {
        return Ok(());
    }
    let usage = expected["usage"].as_object().unwrap();
    let usage_events: Vec<_> = events
        .iter()
        .filter(|event| event_type(event, "usage"))
        .collect();
    for (field, expected_value) in usage {
        if expected_value.is_null() {
            continue;
        }
        if !usage_events
            .iter()
            .any(|event| event[field] == *expected_value)
        {
            return Err(format!("{context} response lost usage.{field}"));
        }
    }
    Ok(())
}

fn check_stream_full_equivalence(
    adapter: &impl Adapter,
    context: &str,
    fixture: &Value,
) -> Result<(), String> {
    let streaming = parse_response(adapter, context, fixture, true)?;
    let non_streaming = parse_response(adapter, context, fixture, false)?;
    let streaming = normalize_response_semantics(&streaming)?;
    let non_streaming = normalize_response_semantics(&non_streaming)?;
    if streaming != non_streaming {
        return Err(format!(
            "{context} streaming and full-response semantics differ: stream={streaming}, full={non_streaming}"
        ));
    }
    Ok(())
}

fn normalize_response_semantics(events: &Value) -> Result<Value, String> {
    let events = events
        .as_array()
        .ok_or_else(|| "response events must be an array".to_string())?;
    let mut request_id = Value::Null;
    let mut text = String::new();
    let mut thinking = String::new();
    let mut signatures = BTreeSet::new();
    let mut calls: BTreeMap<u64, Value> = BTreeMap::new();
    let mut finish = Value::Null;
    let mut usage = json!({
        "input": null,
        "output": null,
        "cached": null,
        "cache_write": null,
        "thinking": null
    });

    for event in events {
        match event["type"].as_str().unwrap_or_default() {
            "start" => request_id = event["upstream_request_id"].clone(),
            "text_delta" => {
                if let Some(value) = event["text"].as_str() {
                    text.push_str(value);
                }
            }
            "thinking_delta" => {
                if let Some(value) = event["text"].as_str() {
                    thinking.push_str(value);
                }
                if let Some(signature) = event["signature"].as_str() {
                    signatures.insert(signature.to_string());
                }
            }
            "tool_call_start" => {
                let index = event["index"]
                    .as_u64()
                    .ok_or_else(|| "tool call start requires an index".to_string())?;
                let call = json!({
                    "id": event.get("id").cloned().unwrap_or(Value::Null),
                    "name": event.get("name").cloned().unwrap_or(Value::Null),
                    "signature": event.get("signature").cloned().unwrap_or(Value::Null),
                    "arguments": String::new()
                });
                if let Some(signature) = event["signature"].as_str() {
                    signatures.insert(signature.to_string());
                }
                if calls.insert(index, call.clone()).is_some() {
                    return Err(format!("duplicate tool call index {index}"));
                }
            }
            "tool_call_args_delta" => {
                let index = event["index"]
                    .as_u64()
                    .ok_or_else(|| "tool argument delta requires an index".to_string())?;
                let call = calls
                    .get_mut(&index)
                    .ok_or_else(|| format!("tool arguments arrived before call start {index}"))?;
                if let Some(value) = event["args"].as_str() {
                    call["arguments"] = json!(format!(
                        "{}{}",
                        call["arguments"].as_str().unwrap_or(""),
                        value
                    ));
                }
            }
            "finish" => finish = event.get("reason").cloned().unwrap_or(Value::Null),
            "usage" => {
                for field in ["input", "output", "cached", "cache_write", "thinking"] {
                    if !event[field].is_null() {
                        usage[field] = event[field].clone();
                    }
                }
            }
            _ => {}
        }
    }

    let mut normalized_calls = Vec::with_capacity(calls.len());
    for (_, mut call) in calls {
        let raw = call["arguments"].as_str().unwrap_or_default();
        let arguments = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(raw)
                .map_err(|error| format!("invalid normalized tool arguments: {error}"))?
        };
        call["arguments"] = arguments;
        normalized_calls.push(call);
    }

    Ok(json!({
        "request_id": request_id,
        "text": text,
        "thinking": thinking,
        "signatures": signatures,
        "calls": normalized_calls,
        "finish": finish,
        "usage": usage
    }))
}

fn check_stop_reasons(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    fixture: &Value,
) -> Result<(), String> {
    match transport.capabilities["stop_reasons"] {
        CapabilityStatus::Supported => {
            for probe in fixture["stop_probes"].as_array().unwrap() {
                let expected = probe["expected"].as_str().unwrap();
                let stream = adapter
                    .parse_stream_chunk(&probe["stream"])
                    .map_err(|error| format!("{context} failed to parse stop reason: {error}"))?;
                let stream = Value::Array(unpack_response_envelope(stream, context)?);
                assert_finish_reason(context, expected, &stream)?;
                let full = adapter
                    .parse_full_response(&probe["full"])
                    .map_err(|error| {
                        format!("{context} failed to parse full stop reason: {error}")
                    })?;
                let full = Value::Array(unpack_response_envelope(full, context)?);
                assert_finish_reason(context, expected, &full)?;
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => {
            for probe in fixture["stop_probes"].as_array().unwrap() {
                let stream = adapter.parse_stream_chunk(&probe["stream"]);
                expect_unsupported(context, "stop_reasons", stream)?;
                let full = adapter.parse_full_response(&probe["full"]);
                expect_unsupported(context, "stop_reasons", full)?;
            }
            Ok(())
        }
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn assert_finish_reason(context: &str, expected: &str, events: &Value) -> Result<(), String> {
    let events = events
        .as_array()
        .ok_or_else(|| format!("{context} parser must return an event array"))?;
    if events
        .iter()
        .any(|event| event["type"] == "finish" && event["reason"].as_str() == Some(expected))
    {
        Ok(())
    } else {
        Err(format!(
            "{context} failed to preserve finish reason '{expected}'"
        ))
    }
}

fn check_provider_response_tolerance(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    if transport.format != "antigravity" {
        return Ok(());
    }

    let chunk = json!({
        "response": {
            "candidates": [{
                "content": {"parts": [
                    {"text":"", "unknownPartField":true},
                    {
                        "thought":true,
                        "text":"thinking with call",
                        "thoughtSignature":"sig-call",
                        "functionCall":{"name":"read_file","args":r#"{"path":"src/main.rs"}"#,"unknownCallField":true},
                        "unknownPartField":true
                    },
                    {"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}
                ]},
                "finishReason":"FUNCTION_CALL",
                "unknownCandidateField":true
            }],
            "unknownResponseField":true
        }
    });
    let response = adapter.parse_stream_chunk(&chunk).map_err(|error| {
        format!("{context} rejected safe provider response variations: {error}")
    })?;
    let events = unpack_response_envelope(response, context)?;
    let thinking = events
        .iter()
        .find(|event| event["type"] == "thinking_delta")
        .ok_or_else(|| format!("{context} lost thinking combined with a function call"))?;
    if thinking["text"] != "thinking with call" {
        return Err(format!(
            "{context} changed mixed thinking content: {thinking}"
        ));
    }
    let calls: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "tool_call_start")
        .collect();
    if calls.len() != 2
        || calls[0]["name"] != "read_file"
        || !calls[0]["id"].is_null()
        || calls[0]["signature"] != "sig-call"
        || calls[1]["name"] != "get_weather"
    {
        return Err(format!(
            "{context} did not normalize multiple optional-ID calls: {calls:?}"
        ));
    }
    let first_arguments: Value = serde_json::from_str(
        events
            .iter()
            .find(|event| event["type"] == "tool_call_args_delta" && event["index"] == 0)
            .and_then(|event| event["args"].as_str())
            .unwrap_or_default(),
    )
    .map_err(|error| format!("{context} emitted invalid string arguments: {error}"))?;
    let second_arguments: Value = serde_json::from_str(
        events
            .iter()
            .find(|event| event["type"] == "tool_call_args_delta" && event["index"] == 1)
            .and_then(|event| event["args"].as_str())
            .unwrap_or_default(),
    )
    .map_err(|error| format!("{context} emitted invalid object arguments: {error}"))?;
    if first_arguments != json!({"path":"src/main.rs"})
        || second_arguments != json!({"city":"Paris"})
        || !events
            .iter()
            .any(|event| event["type"] == "finish" && event["reason"] == "tool_calls")
    {
        return Err(format!(
            "{context} changed normalized tool arguments or finish reason"
        ));
    }

    // Gemini may send usage in a terminal chunk without candidates or an ID.
    let terminal = json!({"response":{"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3},"unknown":true}});
    let terminal = adapter
        .parse_stream_chunk(&terminal)
        .map_err(|error| format!("{context} rejected a usage-only terminal frame: {error}"))?;
    let terminal = unpack_response_envelope(terminal, context)?;
    if !terminal
        .iter()
        .any(|event| event["type"] == "usage" && event["input"] == 7 && event["output"] == 3)
    {
        return Err(format!("{context} lost usage from a terminal-only frame"));
    }

    let call_frame = json!({"response":{"candidates":[{"content":{"parts":[{
        "functionCall":{"name":"read_file","args":{"path":"src/main.rs"}}
    }]}}]}});
    let call_events = adapter
        .parse_stream_chunk(&call_frame)
        .map_err(|error| format!("{context} rejected a split function-call frame: {error}"))?;
    let call_events = unpack_response_envelope(call_events, context)?;
    if !call_events
        .iter()
        .any(|event| event["type"] == "tool_call_start" && event["name"] == "read_file")
    {
        return Err(format!(
            "{context} lost the function call before its terminal frame"
        ));
    }
    let finish_frame = json!({"response":{
        "candidates":[{"content":{"parts":[]},"finishReason":"STOP"}],
        "usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":4}
    }});
    let finish_events = adapter
        .parse_stream_chunk(&finish_frame)
        .map_err(|error| format!("{context} rejected a split terminal frame: {error}"))?;
    let finish_events = unpack_response_envelope(finish_events, context)?;
    if !finish_events
        .iter()
        .any(|event| event["type"] == "finish" && event["reason"] == "stop")
        || !finish_events
            .iter()
            .any(|event| event["type"] == "usage" && event["input"] == 9 && event["output"] == 4)
    {
        return Err(format!(
            "{context} lost separate finish or terminal usage events: {finish_events:?}"
        ));
    }

    for (reason, expected) in [
        ("STOP_SEQUENCE", "stop"),
        ("LENGTH", "length"),
        ("CONTENT_FILTER", "content_filter"),
        ("TOOL_CALLS", "tool_calls"),
    ] {
        let chunk =
            json!({"response":{"candidates":[{"content":{"parts":[]},"finishReason":reason}]}});
        let output = adapter
            .parse_stream_chunk(&chunk)
            .map_err(|error| format!("{context} rejected finish alias {reason}: {error}"))?;
        let events = unpack_response_envelope(output, context)?;
        if !events
            .iter()
            .any(|event| event["type"] == "finish" && event["reason"] == expected)
        {
            return Err(format!("{context} did not normalize finish alias {reason}"));
        }
    }
    Ok(())
}

fn check_error_classification(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let body = json!({"error":{"message":"rate limited"}});
    let headers = json!({"retry-after":"7"});
    match transport.capabilities["error_classification"] {
        CapabilityStatus::Supported => {
            let error = adapter
                .classify_error(429, &body, &headers)
                .map_err(|error| format!("{context} failed to classify upstream error: {error}"))?;
            if error["status"].as_u64() != Some(429)
                || error["retry_after_secs"].as_u64() != Some(7)
                || error["message"].as_str() != Some("rate limited")
                || !matches!(
                    error["kind"].as_str(),
                    Some("rate_limit" | "quota_exhausted")
                )
            {
                return Err(format!("{context} lost classified error evidence: {error}"));
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            "error_classification",
            adapter.classify_error(429, &body, &headers),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_capabilities_cover_issue_scope() {
        for required in [
            "text_generation",
            "streaming",
            "non_streaming",
            "tool_calls",
            "parallel_tool_calls",
            "tool_result_continuation",
            "tool_result_errors",
            "image_input",
            "reasoning_controls",
            "reasoning_output",
            "structured_schemas",
            "schema_max_length",
            "stop_reasons",
            "usage_extraction",
            "error_classification",
            "client_cancellation",
        ] {
            assert!(REQUIRED_CAPABILITIES.contains(&required));
        }
    }
}
