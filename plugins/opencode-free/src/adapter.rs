//! OpenCode Free adapter.
//!
//! Kinetix core owns HTTP transport and SSE framing. This module only performs
//! request/response translation.

use std::collections::HashSet;

use serde_json::{json, Value};

pub(crate) const USER_AGENT: &str = "opencode/1.18.31";

#[derive(Debug, Clone)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after: Option<u64>,
}

fn err(code: &str, message: impl Into<String>) -> AdapterError {
    AdapterError {
        code: code.into(),
        message: message.into(),
        retryable: false,
        retry_after: None,
    }
}

fn base_url(provider: &Value) -> &str {
    provider
        .get("base_url")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or("https://opencode.ai")
}

fn model_id(model: &Value) -> Option<&str> {
    model
        .get("upstream_id")
        .or_else(|| model.get("id"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

fn is_responses_model(id: &str) -> bool {
    id.starts_with("muse-spark-")
}

pub fn build_url(provider_json: &str, model_json: &str) -> Result<String, AdapterError> {
    let provider: Value = serde_json::from_str(provider_json)
        .map_err(|e| err("bad_request", format!("bad provider json: {e}")))?;
    let model: Value = serde_json::from_str(model_json)
        .map_err(|e| err("bad_request", format!("bad model json: {e}")))?;
    let id = model_id(&model).ok_or_else(|| err("bad_request", "model id is required"))?;
    let base = base_url(&provider).trim_end_matches('/');

    if is_responses_model(id) {
        Ok(format!("{base}/zen/v1/responses"))
    } else {
        Ok(format!("{base}/zen/v1/chat/completions"))
    }
}

const BASE62_CHARS: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn current_time_millis() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        kinetix_plugin_sdk::helpers::now_unix_millis()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn is_valid_session_id(s: &str) -> bool {
    s.starts_with("ses_")
        && s.len() == 30
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn extract_session_id(provider_json: &str, credential: &str) -> Option<String> {
    let cred_trimmed = credential.trim();
    if !cred_trimmed.is_empty() && cred_trimmed != "public" && is_valid_session_id(cred_trimmed) {
        return Some(cred_trimmed.to_string());
    }
    if let Ok(provider) = serde_json::from_str::<Value>(provider_json) {
        if let Some(sid) = provider
            .get("session_id")
            .or_else(|| provider.get("sessionId"))
            .or_else(|| provider.get("x-opencode-session"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| is_valid_session_id(s))
        {
            return Some(sid.to_string());
        }
    }
    None
}

/// Generates an OpenCode session identifier matching OpenCode's format:
/// `ses_<12-hex-timestamp><14-base62-random>` (30 chars total).
fn generate_session_id(seed_extra: u64) -> String {
    let ts = current_time_millis();
    let ts_hex = format!("{ts:012x}");

    let mut state = ts ^ seed_extra.wrapping_mul(0x9e3779b97f4a7c15);
    if state == 0 {
        state = 0xcbf29ce484222325;
    }

    let mut suffix = [0u8; 14];
    for b in suffix.iter_mut() {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let rnd = (z ^ (z >> 31)) as usize;
        *b = BASE62_CHARS[rnd % 62];
    }
    let suffix_str = std::str::from_utf8(&suffix).unwrap_or("00000000000000");
    format!("ses_{ts_hex}{suffix_str}")
}

pub fn apply_auth(provider_json: &str, credential: &str) -> Result<String, AdapterError> {
    let session_id = extract_session_id(provider_json, credential)
        .unwrap_or_else(|| generate_session_id(fnv1a(provider_json)));

    Ok(json!([
        ["Authorization", "Bearer public"],
        ["x-opencode-client", "desktop"],
        ["x-opencode-project", "default"],
        ["x-opencode-session", session_id],
        ["Content-Type", "application/json"],
        ["Accept", "text/event-stream"],
        ["User-Agent", USER_AGENT]
    ])
    .to_string())
}

fn text_from_parts(parts: &[Value]) -> String {
    parts
        .iter()
        .filter_map(|part| {
            if part.get("type").and_then(Value::as_str) == Some("text") {
                part.get("text").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn thinking_from_parts(parts: &[Value]) -> String {
    parts
        .iter()
        .filter_map(|part| {
            if part.get("type").and_then(Value::as_str) == Some("thinking") {
                part.get("text").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn request_model(req: &Value, model: &Value) -> String {
    model_id(model)
        .or_else(|| req.get("requested_model").and_then(Value::as_str))
        .unwrap_or("big-pickle")
        .to_string()
}

fn required_non_empty_part_str<'a>(
    part: &'a Value,
    field: &str,
    location: &str,
) -> Result<&'a str, AdapterError> {
    part.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            err(
                "invalid_request",
                format!("{location} requires a non-empty {field}"),
            )
        })
}

fn validate_tool_history(req: &Value) -> Result<(), AdapterError> {
    let mut tool_call_ids = HashSet::new();
    let Some(messages) = req.get("messages").and_then(Value::as_array) else {
        return Ok(());
    };

    for (message_index, message) in messages.iter().enumerate() {
        let Some(parts) = message.get("parts").and_then(Value::as_array) else {
            continue;
        };

        for (part_index, part) in parts.iter().enumerate() {
            let location = format!("messages[{message_index}].parts[{part_index}]");
            match part.get("type").and_then(Value::as_str) {
                Some("tool_call") => {
                    let id = required_non_empty_part_str(
                        part,
                        "id",
                        &format!("{location} assistant tool_call"),
                    )?;
                    if !tool_call_ids.insert(id.to_string()) {
                        return Err(err(
                            "invalid_request",
                            format!(
                                "{location} duplicate tool_call id '{id}' makes tool-result matching ambiguous"
                            ),
                        ));
                    }
                }
                Some("tool_result") => {
                    let tool_call_id = required_non_empty_part_str(
                        part,
                        "tool_call_id",
                        &format!("{location} tool_result"),
                    )?;
                    if !tool_call_ids.contains(tool_call_id) {
                        return Err(err(
                            "invalid_request",
                            format!(
                                "{location} tool_result references unknown tool_call_id '{tool_call_id}'"
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn ensure_required_chat_tools(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let tools = obj
        .entry("tools")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(arr) = tools.as_array_mut() else {
        return;
    };

    for name in ["bash", "read"] {
        let present = arr.iter().any(|tool| {
            tool.pointer("/function/name")
                .and_then(Value::as_str)
                .is_some_and(|n| n == name)
        });
        if !present {
            arr.push(json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": "This tool is unavailable and must not be used.",
                    "parameters": {"type":"object","properties":{}}
                }
            }));
        }
    }
}

fn ensure_required_responses_tools(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let tools = obj
        .entry("tools")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(arr) = tools.as_array_mut() else {
        return;
    };

    for name in ["bash", "read"] {
        let present = arr
            .iter()
            .any(|tool| tool.get("name").and_then(Value::as_str) == Some(name));
        if !present {
            arr.push(json!({
                "type": "function",
                "name": name,
                "description": "This tool is unavailable and must not be used.",
                "parameters": {"type":"object","properties":{}}
            }));
        }
    }
    obj.entry("tool_choice").or_insert(json!("auto"));
}

fn build_chat_body(req: &Value, model: &Value) -> Result<Value, AdapterError> {
    let mut messages = Vec::new();

    if let Some(system) = req.get("system").and_then(Value::as_array) {
        let text = system
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            messages.push(json!({"role": "system", "content": text}));
        }
    }

    if let Some(input) = req.get("messages").and_then(Value::as_array) {
        for msg in input {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            let parts = msg
                .get("parts")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);

            match role {
                "assistant" => {
                    let text = text_from_parts(parts);
                    let thinking = thinking_from_parts(parts);
                    let content = if text.is_empty() {
                        Value::Null
                    } else {
                        Value::String(text)
                    };
                    let tool_calls: Vec<Value> = parts
                        .iter()
                        .filter(|part| {
                            part.get("type").and_then(Value::as_str) == Some("tool_call")
                        })
                        .map(|part| {
                            json!({
                                "id": part.get("id").and_then(Value::as_str).unwrap_or(""),
                                "type": "function",
                                "function": {
                                    "name": part.get("name").and_then(Value::as_str).unwrap_or(""),
                                    "arguments": part.get("arguments").and_then(Value::as_str).unwrap_or("")
                                }
                            })
                        })
                        .collect();

                    let mut out = json!({"role": "assistant", "content": content});
                    if !thinking.is_empty() {
                        out["reasoning_content"] = Value::String(thinking);
                    }
                    if !tool_calls.is_empty() {
                        out["tool_calls"] = Value::Array(tool_calls);
                    }
                    messages.push(out);
                }
                "tool" => {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) != Some("tool_result") {
                            continue;
                        }
                        let mut out = json!({
                            "role": "tool",
                            "tool_call_id": part.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),
                            "content": part.get("content").and_then(Value::as_str).unwrap_or("")
                        });
                        if let Some(name) = part
                            .get("name")
                            .and_then(Value::as_str)
                            .filter(|name| !name.is_empty())
                        {
                            out["name"] = json!(name);
                        }
                        messages.push(out);
                    }
                }
                _ => {
                    messages.push(json!({
                        "role": role,
                        "content": text_from_parts(parts)
                    }));
                }
            }
        }
    }

    let mut body = json!({
        "model": request_model(req, model),
        "messages": messages,
        "stream": true
    });

    for key in ["temperature", "top_p", "max_tokens", "stop", "seed"] {
        if let Some(value) = req.get(key) {
            if !value.is_null() {
                body[key] = value.clone();
            }
        }
    }

    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools.iter()
                    .map(|tool| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                                "description": tool.get("description").cloned().unwrap_or(Value::Null),
                                "parameters": tool.get("parameters").cloned().unwrap_or_else(|| json!({"type":"object","properties":{}}))
                            }
                        })
                    })
                    .collect(),
            );
        }
    }

    ensure_required_chat_tools(&mut body);
    Ok(body)
}

fn build_responses_body(req: &Value, model: &Value) -> Value {
    let mut input = Vec::new();

    if let Some(system) = req.get("system").and_then(Value::as_array) {
        let text = system
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            input.push(json!({
                "role": "system",
                "content": [{"type": "input_text", "text": text}]
            }));
        }
    }

    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            let parts = msg
                .get("parts")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);

            match role {
                "assistant" => {
                    let text = text_from_parts(parts);
                    if !text.is_empty() {
                        input.push(json!({
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": text}]
                        }));
                    }
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("tool_call") {
                            input.push(json!({
                                "type": "function_call",
                                "call_id": part.get("id").and_then(Value::as_str).unwrap_or(""),
                                "name": part.get("name").and_then(Value::as_str).unwrap_or(""),
                                "arguments": part.get("arguments").and_then(Value::as_str).unwrap_or("")
                            }));
                        }
                    }
                }
                "tool" => {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("tool_result") {
                            input.push(json!({
                                "type": "function_call_output",
                                "call_id": part.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),
                                "output": part.get("content").and_then(Value::as_str).unwrap_or("")
                            }));
                        }
                    }
                }
                _ => {
                    let text = text_from_parts(parts);
                    input.push(json!({
                        "role": role,
                        "content": [{"type": "input_text", "text": text}]
                    }));
                }
            }
        }
    }

    let mut body = json!({
        "model": request_model(req, model),
        "input": input,
        "stream": true,
        "store": false
    });

    if let Some(max) = req.get("max_tokens").and_then(Value::as_u64) {
        body["max_output_tokens"] = json!(max);
    }

    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        body["tools"] = Value::Array(
            tools.iter()
                .map(|tool| {
                    json!({
                        "type": "function",
                        "name": tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                        "description": tool.get("description").cloned().unwrap_or(Value::Null),
                        "parameters": tool.get("parameters").cloned().unwrap_or_else(|| json!({"type":"object","properties":{}}))
                    })
                })
                .collect(),
        );
    }

    ensure_required_responses_tools(&mut body);
    body
}

pub fn build_body(
    request_json: &str,
    _provider_json: &str,
    model_json: &str,
) -> Result<String, AdapterError> {
    let req: Value = serde_json::from_str(request_json)
        .map_err(|e| err("bad_request", format!("bad request json: {e}")))?;
    validate_tool_history(&req)?;
    let model: Value = serde_json::from_str(model_json)
        .map_err(|e| err("bad_request", format!("bad model json: {e}")))?;
    let id = request_model(&req, &model);

    let body = if is_responses_model(&id) {
        build_responses_body(&req, &model)
    } else {
        build_chat_body(&req, &model)?
    };

    Ok(body.to_string())
}

fn get_header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    headers.as_object().and_then(|obj| {
        obj.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| value.as_str())
    })
}

pub fn classify_error(status: u16, body: &str, headers_json: &str) -> Result<String, AdapterError> {
    let headers: Value = serde_json::from_str(headers_json).unwrap_or(Value::Null);
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .or_else(|| value.get("message").and_then(Value::as_str))
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(500).collect());

    let lower = message.to_ascii_lowercase();
    let kind = if status == 429 && lower.contains("free") {
        "quota_exhausted"
    } else if status == 429 {
        "rate_limit"
    } else if status >= 500 || status == 401 || status == 403 {
        "server_error"
    } else if status >= 400 {
        "bad_request"
    } else {
        "server_error"
    };

    Ok(json!({
        "kind": kind,
        "status": status,
        "retry_after_secs": get_header(&headers, "retry-after").and_then(|v| v.parse::<u64>().ok()),
        "message": message,
        "quota_reset_at": Value::Null
    })
    .to_string())
}

fn finish_event(reason: &str) -> Value {
    let reason = match reason {
        "length" | "max_tokens" => "length",
        "tool_calls" | "function_call" => "tool_calls",
        "content_filter" => "content_filter",
        _ => "stop",
    };
    json!({"type":"finish","reason":reason})
}

fn parse_chat(value: &Value) -> Vec<Value> {
    let mut events = Vec::new();

    if let Some(id) = value.get("id").and_then(Value::as_str) {
        events.push(json!({"type":"start","upstream_request_id":id}));
    }

    if let Some(choice) = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
    {
        if let Some(delta) = choice.get("delta").or_else(|| choice.get("message")) {
            if let Some(thinking) = delta
                .get("reasoning_content")
                .and_then(Value::as_str)
                .filter(|thinking| !thinking.is_empty())
            {
                events.push(json!({"type":"thinking_delta","text":thinking}));
            }

            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                if !text.is_empty() {
                    events.push(json!({"type":"text_delta","text":text}));
                }
            }

            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for (position, tool_call) in tool_calls.iter().enumerate() {
                    let index = tool_call
                        .get("index")
                        .and_then(Value::as_u64)
                        .unwrap_or(position as u64);
                    let id = tool_call.get("id").and_then(Value::as_str);
                    let function = tool_call.get("function");
                    let name = function
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str);
                    let arguments = function
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str);

                    if id.is_some() || name.is_some() {
                        events.push(json!({
                            "type":"tool_call_start",
                            "index":index,
                            "id":id,
                            "name":name.unwrap_or(""),
                            "signature":Value::Null
                        }));
                    }
                    if let Some(args) = arguments.filter(|args| !args.is_empty()) {
                        events.push(json!({
                            "type":"tool_call_args_delta",
                            "index":index,
                            "args":args
                        }));
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            events.push(finish_event(reason));
        }
    }

    if let Some(usage) = value.get("usage") {
        if !usage.is_null() {
            events.push(json!({
                "type":"usage",
                "input":usage.get("prompt_tokens").and_then(Value::as_u64),
                "output":usage.get("completion_tokens").and_then(Value::as_u64),
                "cached":usage.pointer("/prompt_tokens_details/cached_tokens").and_then(Value::as_u64),
                "thinking":usage.pointer("/completion_tokens_details/reasoning_tokens").and_then(Value::as_u64)
            }));
        }
    }

    events
}

fn parse_responses(value: &Value) -> Vec<Value> {
    let mut events = Vec::new();
    match value.get("type").and_then(Value::as_str).unwrap_or("") {
        "response.created" => {
            events.push(json!({
                "type":"start",
                "upstream_request_id":value.pointer("/response/id").and_then(Value::as_str)
            }));
        }
        "response.output_text.delta" => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                events.push(json!({"type":"text_delta","text":delta}));
            }
        }
        "response.output_item.added" => {
            let Some(item) = value.get("item") else {
                return events;
            };
            if item.get("type").and_then(Value::as_str) == Some("function_call") {
                let index = value
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("id").and_then(Value::as_str));
                let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                events.push(json!({
                    "type":"tool_call_start",
                    "index":index,
                    "id":id,
                    "name":name,
                    "signature":Value::Null
                }));
            }
        }
        "response.function_call_arguments.delta" => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                if !delta.is_empty() {
                    let index = value
                        .get("output_index")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    events.push(json!({
                        "type":"tool_call_args_delta",
                        "index":index,
                        "args":delta
                    }));
                }
            }
        }
        "response.completed" => {
            if let Some(usage) = value.pointer("/response/usage") {
                events.push(json!({
                    "type":"usage",
                    "input":usage.get("input_tokens").and_then(Value::as_u64),
                    "output":usage.get("output_tokens").and_then(Value::as_u64),
                    "cached":usage.pointer("/input_tokens_details/cached_tokens").and_then(Value::as_u64),
                    "thinking":usage.pointer("/output_tokens_details/reasoning_tokens").and_then(Value::as_u64)
                }));
            }
            let has_tool_calls = value
                .pointer("/response/output")
                .and_then(Value::as_array)
                .is_some_and(|output| {
                    output.iter().any(|item| {
                        item.get("type").and_then(Value::as_str) == Some("function_call")
                    })
                });
            events.push(json!({
                "type":"finish",
                "reason":if has_tool_calls { "tool_calls" } else { "stop" }
            }));
        }
        _ => {}
    }
    events
}

pub fn parse_stream_chunk(data: &str) -> Result<String, AdapterError> {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return Ok("[]".into());
    }

    let value: Value = serde_json::from_str(data)
        .map_err(|e| err("protocol_error", format!("invalid SSE JSON: {e}")))?;

    let events = if value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .starts_with("response.")
    {
        parse_responses(&value)
    } else {
        parse_chat(&value)
    };
    Ok(Value::Array(events).to_string())
}

pub fn parse_full_response(body_json: &str) -> Result<String, AdapterError> {
    let value: Value = serde_json::from_str(body_json)
        .map_err(|e| err("protocol_error", format!("invalid response JSON: {e}")))?;

    if value.get("object").and_then(Value::as_str) == Some("chat.completion") {
        return Ok(Value::Array(parse_chat(&value)).to_string());
    }

    if value.get("object").and_then(Value::as_str) == Some("response")
        || value.get("output").is_some()
    {
        let mut events = Vec::new();
        let mut has_tool_calls = false;
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            events.push(json!({"type":"start","upstream_request_id":id}));
        }
        if let Some(output) = value.get("output").and_then(Value::as_array) {
            for (index, item) in output.iter().enumerate() {
                if item.get("type").and_then(Value::as_str) == Some("function_call") {
                    has_tool_calls = true;
                    let id = item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("id").and_then(Value::as_str));
                    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                    events.push(json!({
                        "type":"tool_call_start",
                        "index":index,
                        "id":id,
                        "name":name,
                        "signature":Value::Null
                    }));
                    if let Some(args) = item
                        .get("arguments")
                        .and_then(Value::as_str)
                        .filter(|args| !args.is_empty())
                    {
                        events.push(json!({
                            "type":"tool_call_args_delta",
                            "index":index,
                            "args":args
                        }));
                    }
                    continue;
                }

                if let Some(content) = item.get("content").and_then(Value::as_array) {
                    for block in content {
                        if let Some(text) = block.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                events.push(json!({"type":"text_delta","text":text}));
                            }
                        }
                    }
                }
            }
        }
        if let Some(usage) = value.get("usage") {
            if !usage.is_null() {
                events.push(json!({
                    "type":"usage",
                    "input":usage.get("input_tokens").and_then(Value::as_u64),
                    "output":usage.get("output_tokens").and_then(Value::as_u64),
                    "cached":usage.pointer("/input_tokens_details/cached_tokens").and_then(Value::as_u64),
                    "thinking":usage.pointer("/output_tokens_details/reasoning_tokens").and_then(Value::as_u64)
                }));
            }
        }
        events.push(json!({
            "type":"finish",
            "reason":if has_tool_calls { "tool_calls" } else { "stop" }
        }));
        return Ok(Value::Array(events).to_string());
    }

    Err(err("protocol_error", "unsupported OpenCode response shape"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat_body(messages: Value) -> Result<Value, AdapterError> {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.5-free",
            "system": [],
            "messages": messages,
            "tools": [],
            "stream": true
        });
        let body = build_body(
            &request.to_string(),
            "{}",
            r#"{"upstream_id":"mimo-v2.5-free"}"#,
        )?;
        Ok(serde_json::from_str(&body).expect("adapter body must be valid JSON"))
    }

    fn mimo26_chat_body(messages: Value) -> Result<Value, AdapterError> {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.6-flash-free",
            "system": [],
            "messages": messages,
            "tools": [],
            "stream": true
        });
        let body = build_body(
            &request.to_string(),
            "{}",
            r#"{"upstream_id":"mimo-v2.6-flash-free"}"#,
        )?;
        Ok(serde_json::from_str(&body).expect("adapter body must be valid JSON"))
    }

    #[test]
    fn chooses_endpoint_by_model_family() {
        let provider = r#"{"base_url":"https://opencode.ai"}"#;
        assert!(build_url(provider, r#"{"upstream_id":"mimo-v2.5-free"}"#)
            .unwrap()
            .ends_with("/zen/v1/chat/completions"));
        assert!(build_url(
            provider,
            r#"{"upstream_id":"muse-spark-1.3-contributor-free"}"#
        )
        .unwrap()
        .ends_with("/zen/v1/responses"));
    }
    #[test]
    fn chat_body_injects_required_free_tier_tools() {
        let req = r#"{
            "requested_model":"mimo-v2.5-free",
            "system":[],
            "messages":[{"role":"user","parts":[{"type":"text","text":"hi"}]}],
            "tools":[],
            "stream":true
        }"#;
        let out: Value = serde_json::from_str(
            &build_body(req, "{}", r#"{"upstream_id":"mimo-v2.5-free"}"#).unwrap(),
        )
        .unwrap();
        let names: Vec<&str> = out["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool.pointer("/function/name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"bash"));
        assert!(names.contains(&"read"));
        assert_eq!(out["stream"], true);
    }

    #[test]
    fn chat_body_does_not_invent_mimo_thinking_wire_control() {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.6-flash-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let body = build_body(
            &request.to_string(),
            "{}",
            r#"{"upstream_id":"mimo-v2.6-flash-free"}"#,
        )
        .unwrap();
        let out: Value = serde_json::from_str(&body).unwrap();
        assert!(out.get("thinking").is_none());
        assert!(out.get("reasoning_effort").is_none());
    }

    #[test]
    fn responses_body_does_not_invent_thinking_wire_control() {
        let request = serde_json::json!({
            "requested_model": "muse-spark-1.3-contributor-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let body = build_body(
            &request.to_string(),
            "{}",
            r#"{"upstream_id":"muse-spark-1.3-contributor-free"}"#,
        )
        .unwrap();
        let out: Value = serde_json::from_str(&body).unwrap();
        assert!(out.get("thinking").is_none());
        assert!(out.get("reasoning_effort").is_none());
        assert!(out.get("reasoning").is_none());
    }

    #[test]
    fn non_toggle_chat_model_does_not_invent_thinking_wire_control() {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.5-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let body = build_body(
            &request.to_string(),
            "{}",
            r#"{"upstream_id":"mimo-v2.5-free"}"#,
        )
        .unwrap();
        let out: Value = serde_json::from_str(&body).unwrap();
        assert!(out.get("thinking").is_none());
        assert!(out.get("reasoning_effort").is_none());
    }

    #[test]
    fn chat_body_preserves_reasoning_with_tool_call_history() {
        let out = mimo26_chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"thinking","text":"checking "},
                {"type":"thinking","text":"the file"},
                {"type":"tool_call","id":"call_reason","name":"read","arguments":"{\"path\":\"README.md\"}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"call_reason","name":"read","content":"ok","is_error":false}
            ]}
        ]))
        .unwrap();

        let messages = out["messages"].as_array().unwrap();
        assert_eq!(messages[0]["reasoning_content"], "checking the file");
        assert!(messages[0]["content"].is_null());
        assert_eq!(messages[0]["tool_calls"][0]["id"], "call_reason");
        assert_eq!(messages[1]["tool_call_id"], "call_reason");
    }

    #[test]
    fn chat_body_preserves_visible_text_separately_from_reasoning() {
        let out = mimo26_chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"thinking","text":"private reasoning"},
                {"type":"text","text":"visible answer"},
                {"type":"tool_call","id":"call_text","name":"read","arguments":"{}","signature":null}
            ]}
        ]))
        .unwrap();

        let message = &out["messages"][0];
        assert_eq!(message["reasoning_content"], "private reasoning");
        assert_eq!(message["content"], "visible answer");
        assert_eq!(message["tool_calls"][0]["id"], "call_text");
    }

    #[test]
    fn chat_body_preserves_valid_sequential_tool_history() {
        let out = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_1","name":"read","arguments":"{\"path\":\"a\"}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"call_1","name":"read","content":"one","is_error":false}
            ]},
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_2","name":"read","arguments":"{\"path\":\"b\"}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"call_2","name":"read","content":"two","is_error":false}
            ]}
        ]))
        .unwrap();

        let messages = out["messages"].as_array().unwrap();
        assert_eq!(messages[0]["tool_calls"][0]["id"], "call_1");
        assert_eq!(messages[1]["tool_call_id"], "call_1");
        assert_eq!(messages[2]["tool_calls"][0]["id"], "call_2");
        assert_eq!(messages[3]["tool_call_id"], "call_2");
    }

    #[test]
    fn chat_body_rejects_empty_tool_call_id() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_1","name":"read","arguments":"{}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"","name":"read","content":"x","is_error":false}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("non-empty tool_call_id"));
    }

    #[test]
    fn chat_body_rejects_missing_tool_call_id() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_1","name":"read","arguments":"{}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","name":"read","content":"x","is_error":false}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("non-empty tool_call_id"));
    }

    #[test]
    fn chat_body_rejects_unknown_tool_call_id() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_1","name":"read","arguments":"{}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"call_missing","name":"read","content":"x","is_error":false}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("unknown tool_call_id 'call_missing'"));
    }

    #[test]
    fn chat_body_rejects_duplicate_tool_call_ids() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_1","name":"read","arguments":"{}","signature":null},
                {"type":"tool_call","id":"call_1","name":"bash","arguments":"{}","signature":null}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("duplicate tool_call id 'call_1'"));
    }

    #[test]
    fn chat_body_rejects_missing_assistant_tool_call_id() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","name":"read","arguments":"{}","signature":null}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("assistant tool_call"));
        assert!(err.message.contains("non-empty id"));
    }

    #[test]
    fn chat_body_rejects_empty_assistant_tool_call_id() {
        let err = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"","name":"read","arguments":"{}","signature":null}
            ]}
        ]))
        .unwrap_err();

        assert_eq!(err.code, "invalid_request");
        assert!(err.message.contains("assistant tool_call"));
        assert!(err.message.contains("non-empty id"));
    }

    #[test]
    fn chat_body_preserves_parallel_tool_calls_and_results() {
        let out = chat_body(serde_json::json!([
            {"role":"assistant","parts":[
                {"type":"tool_call","id":"call_a","name":"read","arguments":"{\"path\":\"a\"}","signature":null},
                {"type":"tool_call","id":"call_b","name":"bash","arguments":"{\"cmd\":\"pwd\"}","signature":null}
            ]},
            {"role":"tool","parts":[
                {"type":"tool_result","tool_call_id":"call_a","name":"read","content":"A","is_error":false},
                {"type":"tool_result","tool_call_id":"call_b","name":"bash","content":"B","is_error":false}
            ]}
        ]))
        .unwrap();

        let messages = out["messages"].as_array().unwrap();
        let calls = messages[0]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_a");
        assert_eq!(calls[1]["id"], "call_b");
        assert_eq!(messages[1]["tool_call_id"], "call_a");
        assert_eq!(messages[2]["tool_call_id"], "call_b");
    }

    #[test]
    fn responses_body_preserves_tool_call_identity() {
        let request = serde_json::json!({
            "requested_model": "muse-spark-1.3-contributor-free",
            "system": [],
            "messages": [
                {"role":"assistant","parts":[
                    {"type":"tool_call","id":"call_resp","name":"read","arguments":"{\"path\":\"README.md\"}","signature":null}
                ]},
                {"role":"tool","parts":[
                    {"type":"tool_result","tool_call_id":"call_resp","name":"read","content":"ok","is_error":false}
                ]}
            ],
            "tools": [],
            "stream": true
        });
        let out: Value = serde_json::from_str(
            &build_body(
                &request.to_string(),
                "{}",
                r#"{"upstream_id":"muse-spark-1.3-contributor-free"}"#,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(out["input"][0]["type"], "function_call");
        assert_eq!(out["input"][0]["call_id"], "call_resp");
        assert_eq!(out["input"][1]["type"], "function_call_output");
        assert_eq!(out["input"][1]["call_id"], "call_resp");
    }

    #[test]
    fn parses_chat_stream_delta() {
        let out: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(out
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["type"] == "text_delta"));
    }

    #[test]
    fn parses_chat_stream_reasoning_content() {
        let out: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"choices":[{"delta":{"reasoning_content":"checking..."},"finish_reason":null}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            out.as_array().unwrap(),
            &[serde_json::json!({"type":"thinking_delta","text":"checking..."})]
        );
    }

    #[test]
    fn parses_chat_stream_reasoning_and_visible_content_separately() {
        let out: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"choices":[{"delta":{"reasoning_content":"thinking","content":"answer"},"finish_reason":null}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let events = out.as_array().unwrap();
        assert_eq!(
            events[0],
            serde_json::json!({"type":"thinking_delta","text":"thinking"})
        );
        assert_eq!(
            events[1],
            serde_json::json!({"type":"text_delta","text":"answer"})
        );
    }

    #[test]
    fn ignores_empty_or_null_chat_reasoning_content() {
        for data in [
            r#"{"choices":[{"delta":{"reasoning_content":""},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{"reasoning_content":null},"finish_reason":null}]}"#,
        ] {
            let out: Value = serde_json::from_str(&parse_stream_chunk(data).unwrap()).unwrap();
            assert!(out.as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn parses_full_chat_reasoning_before_visible_content() {
        let out: Value = serde_json::from_str(
            &parse_full_response(
                r#"{"id":"chatcmpl-full","object":"chat.completion","choices":[{"index":0,"message":{"reasoning_content":"checking...","content":"done"},"finish_reason":"stop"}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let events = out.as_array().unwrap();

        let thinking_index = events
            .iter()
            .position(|event| event["type"] == "thinking_delta")
            .unwrap();
        let text_index = events
            .iter()
            .position(|event| event["type"] == "text_delta")
            .unwrap();
        assert!(thinking_index < text_index);
        assert_eq!(events[thinking_index]["text"], "checking...");
        assert_eq!(events[text_index]["text"], "done");
    }

    #[test]
    fn chat_reasoning_usage_stays_separate_from_output_total() {
        let out: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":12,"completion_tokens_details":{"reasoning_tokens":5}}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let usage = out
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "usage")
            .unwrap();
        assert_eq!(usage["output"], 12);
        assert_eq!(usage["thinking"], 5);
    }

    #[test]
    fn parses_chat_stream_tool_calls_across_chunks() {
        let first: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"id":"chatcmpl-tools","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"read","arguments":"{\"path\":"}},{"index":1,"id":"call_b","type":"function","function":{"name":"bash","arguments":"{\"cmd\":"}}]},"finish_reason":null}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let first = first.as_array().unwrap();

        assert!(first.iter().any(|event| {
            event["type"] == "tool_call_start"
                && event["index"] == 0
                && event["id"] == "call_a"
                && event["name"] == "read"
        }));
        assert!(first.iter().any(|event| {
            event["type"] == "tool_call_start"
                && event["index"] == 1
                && event["id"] == "call_b"
                && event["name"] == "bash"
        }));
        assert!(first.iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 0
                && event["args"] == "{\"path\":"
        }));
        assert!(first.iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 1
                && event["args"] == "{\"cmd\":"
        }));

        let second: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"README.md\"}"}},{"index":1,"function":{"arguments":"\"pwd\"}"}}]},"finish_reason":"tool_calls"}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let second = second.as_array().unwrap();

        assert!(second.iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 0
                && event["args"] == "\"README.md\"}"
        }));
        assert!(second.iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 1
                && event["args"] == "\"pwd\"}"
        }));
        assert!(second
            .iter()
            .any(|event| { event["type"] == "finish" && event["reason"] == "tool_calls" }));
    }

    #[test]
    fn parses_responses_function_call_stream() {
        let added: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"response.output_item.added","output_index":2,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read","arguments":""}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(added.as_array().unwrap().iter().any(|event| {
            event["type"] == "tool_call_start"
                && event["index"] == 2
                && event["id"] == "call_1"
                && event["name"] == "read"
        }));
        let delta: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"response.function_call_arguments.delta","output_index":2,"item_id":"fc_1","delta":"{\"path\":\"README" }"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(delta.as_array().unwrap().iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 2
                && event["args"] == "{\"path\":\"README"
        }));

        let completed: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"response.completed","response":{"id":"resp_1","output":[{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"README.md\"}"}],"usage":{"input_tokens":10,"output_tokens":4}}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(completed
            .as_array()
            .unwrap()
            .iter()
            .any(|event| { event["type"] == "finish" && event["reason"] == "tool_calls" }));
    }

    #[test]
    fn parses_full_responses_function_calls() {
        let out: Value = serde_json::from_str(
            &parse_full_response(
                r#"{"id":"resp_1","object":"response","output":[{"id":"fc_1","type":"function_call","call_id":"call_1","name":"bash","arguments":"{\"cmd\":\"pwd\"}"}],"usage":{"input_tokens":7,"output_tokens":3}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let events = out.as_array().unwrap();

        assert!(events.iter().any(|event| {
            event["type"] == "tool_call_start"
                && event["index"] == 0
                && event["id"] == "call_1"
                && event["name"] == "bash"
        }));
        assert!(events.iter().any(|event| {
            event["type"] == "tool_call_args_delta"
                && event["index"] == 0
                && event["args"] == "{\"cmd\":\"pwd\"}"
        }));
        assert!(events
            .iter()
            .any(|event| { event["type"] == "finish" && event["reason"] == "tool_calls" }));
    }

    #[test]
    fn apply_auth_generates_valid_session_and_project_headers() {
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", "").unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();

        assert_eq!(
            map.get("Authorization").map(String::as_str),
            Some("Bearer public")
        );
        assert_eq!(
            map.get("x-opencode-client").map(String::as_str),
            Some("desktop")
        );
        assert_eq!(
            map.get("x-opencode-project").map(String::as_str),
            Some("default")
        );
        assert_eq!(map.get("User-Agent").map(String::as_str), Some(USER_AGENT));

        let session = map
            .get("x-opencode-session")
            .expect("missing x-opencode-session header");
        assert!(
            is_valid_session_id(session),
            "session id {session} must be valid OpenCode format"
        );
        assert_eq!(session.len(), 30);
        assert!(session.starts_with("ses_"));
    }

    #[test]
    fn apply_auth_preserves_explicit_session_id() {
        let custom_session = "ses_01a0c1ed0d77UteRivKIZVE10s";
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", custom_session).unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(
            map.get("x-opencode-session").map(String::as_str),
            Some(custom_session)
        );

        let provider = format!(r#"{{"session_id":"{custom_session}"}}"#);
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth(&provider, "").unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(
            map.get("x-opencode-session").map(String::as_str),
            Some(custom_session)
        );
    }
}
