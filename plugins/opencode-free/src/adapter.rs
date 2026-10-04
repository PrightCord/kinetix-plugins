//! OpenCode Free adapter.
//!
//! Kinetix core owns HTTP transport and SSE framing. This module only performs
//! request/response translation.

use std::collections::HashSet;

use kinetix_plugin_sdk::model_capabilities::{
    ModelCapabilitiesV3, ModelTransportCapability, TransportFormat,
};
use kinetix_plugin_sdk::schema::{self, SchemaMode, SchemaProfile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

fn capability_value(value: &Value) -> Result<ModelCapabilitiesV3, String> {
    let raw = match value {
        Value::String(raw) => raw.clone(),
        value => serde_json::to_string(value).map_err(|error| error.to_string())?,
    };
    ModelCapabilitiesV3::from_json(&raw).map_err(|error| error.to_string())
}

fn legacy_transport(value: &Value) -> Option<ModelTransportCapability> {
    let (format, endpoint) = match value.as_str()? {
        "openai-chat" => (TransportFormat::OpenAiChat, "/zen/v1/chat/completions"),
        "openai-responses" => (TransportFormat::OpenAiResponses, "/zen/v1/responses"),
        "anthropic" => (TransportFormat::Anthropic, "/zen/v1/messages"),
        _ => return None,
    };
    Some(ModelTransportCapability::at_endpoint(format, endpoint))
}

fn model_transport(model: &Value) -> Result<ModelTransportCapability, AdapterError> {
    let mut candidates = Vec::new();
    if let Some(value) = model.get("capabilities_json") {
        candidates.push(value.clone());
    }
    if let Some(value) = model.get("capabilities") {
        candidates.push(value.clone());
    }

    let discovery = model.get("discovery").and_then(|value| match value {
        Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
        value => Some(value.clone()),
    });
    let mut legacy_transports = Vec::new();
    if let Some(discovery) = discovery {
        for pointer in [
            "/kinetix_plugin_capabilities",
            "/model_capabilities",
            "/capabilities_json",
            "/latest_observation/kinetix_plugin_capabilities",
            "/latest_observation/model_capabilities",
            "/latest_observation/capabilities_json",
            "/latest_observation/raw_metadata/kinetix_plugin_capabilities",
            "/raw_metadata/kinetix_plugin_capabilities",
        ] {
            if let Some(value) = discovery.pointer(pointer) {
                candidates.push(value.clone());
            }
        }
        for pointer in ["/transport/format", "/latest_observation/transport/format"] {
            if let Some(value) = discovery.pointer(pointer) {
                legacy_transports.push(value.clone());
            }
        }
    }

    let mut saw_candidate = false;
    let mut saw_valid_capabilities = false;
    let mut parse_error = None;
    for candidate in candidates {
        saw_candidate = true;
        match capability_value(&candidate) {
            Ok(capabilities) => {
                saw_valid_capabilities = true;
                if let Some(transport) = capabilities.transport {
                    return Ok(transport);
                }
            }
            Err(error) => parse_error = Some(error),
        }
    }

    // A valid current envelope is authoritative, including an explicit lack
    // of transport. Only use normalized legacy discovery when there is no
    // valid capability envelope to supersede it.
    if !saw_valid_capabilities {
        if let Some(transport) = legacy_transports.iter().find_map(legacy_transport) {
            return Ok(transport);
        }
    }
    if !saw_candidate && legacy_transports.is_empty() {
        return Err(err(
            "unsupported_transport",
            "model transport metadata is required",
        ));
    }
    if saw_valid_capabilities {
        return Err(err(
            "unsupported_transport",
            "model transport is not declared",
        ));
    }
    Err(err(
        "unsupported_transport",
        format!(
            "invalid model transport metadata: {}",
            parse_error.unwrap_or_else(|| "unknown metadata error".into())
        ),
    ))
}

pub fn build_url(provider_json: &str, model_json: &str) -> Result<String, AdapterError> {
    let provider: Value = serde_json::from_str(provider_json)
        .map_err(|e| err("bad_request", format!("bad provider json: {e}")))?;
    let model: Value = serde_json::from_str(model_json)
        .map_err(|e| err("bad_request", format!("bad model json: {e}")))?;
    if model_id(&model).is_none() {
        return Err(err("bad_request", "model id is required"));
    }
    let transport = model_transport(&model)?;
    match transport.format {
        TransportFormat::OpenAiChat
        | TransportFormat::OpenAiResponses
        | TransportFormat::Anthropic => {}
        _ => {
            return Err(err(
                "unsupported_transport",
                "transport is not supported by OpenCode",
            ))
        }
    }
    let endpoint = transport.endpoint.as_deref().ok_or_else(|| {
        err(
            "unsupported_transport",
            "model transport endpoint is not declared",
        )
    })?;
    Ok(format!(
        "{}{endpoint}",
        base_url(&provider).trim_end_matches('/')
    ))
}

const BASE62_CHARS: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Map Kinetix's opaque session identity into OpenCode's expected ID shape.
/// The namespace prevents this provider-native key from being reused elsewhere.
fn opencode_session_id(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"kinetix:opencode-free:session:v1\0");
    hasher.update(session_id.as_bytes());
    let digest = hasher.finalize();

    let timestamp = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let suffix = digest[6..20]
        .iter()
        .map(|byte| BASE62_CHARS[usize::from(*byte) % BASE62_CHARS.len()] as char)
        .collect::<String>();
    format!("ses_{timestamp}{suffix}")
}

fn is_valid_session_id(s: &str) -> bool {
    s.starts_with("ses_")
        && s.len() == 30
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn configured_session_id(provider_json: &str) -> Option<String> {
    let provider: Value = serde_json::from_str(provider_json).ok()?;
    provider
        .get("session_id")
        .or_else(|| provider.get("sessionId"))
        .or_else(|| provider.get("x-opencode-session"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|session_id| is_valid_session_id(session_id))
        .map(str::to_string)
}

pub fn apply_auth(
    provider_json: &str,
    _credential: &str,
    session_context: Option<&str>,
) -> Result<String, AdapterError> {
    let session_id = session_context
        .filter(|id| !id.is_empty())
        .map(opencode_session_id)
        .or_else(|| configured_session_id(provider_json));

    let mut headers = vec![
        json!(["Authorization", "Bearer public"]),
        json!(["x-api-key", "public"]),
        json!(["anthropic-version", "2023-06-01"]),
        json!(["x-opencode-client", "desktop"]),
        json!(["x-opencode-project", "default"]),
    ];
    if let Some(session_id) = session_id {
        headers.push(json!(["x-opencode-session", session_id]));
    }
    headers.extend([
        json!(["Content-Type", "application/json"]),
        json!(["Accept", "text/event-stream"]),
        json!(["User-Agent", USER_AGENT]),
    ]);

    Ok(Value::Array(headers).to_string())
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
                    required_non_empty_part_str(
                        part,
                        "name",
                        &format!("{location} assistant tool_call"),
                    )?;
                    let arguments =
                        part.get("arguments")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                err(
                                    "invalid_request",
                                    format!("{location} requires JSON tool-call arguments"),
                                )
                            })?;
                    let arguments: Value = serde_json::from_str(arguments).map_err(|error| {
                        err(
                            "invalid_request",
                            format!("{location} has invalid tool-call JSON: {error}"),
                        )
                    })?;
                    if !arguments.is_object() {
                        return Err(err(
                            "invalid_request",
                            format!("{location} tool-call arguments must be a JSON object"),
                        ));
                    }
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

fn build_chat_body(
    req: &Value,
    model: &Value,
    schema_mode: SchemaMode,
) -> Result<Value, AdapterError> {
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
                        let output = tool_result_output_text(part)?;
                        let mut out = json!({
                            "role": "tool",
                            "tool_call_id": part.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),
                            "content": output
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
            let mut declarations = Vec::with_capacity(tools.len());
            for tool in tools {
                declarations.push(json!({
                    "type": "function",
                    "function": {
                        "name": tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                        "description": tool.get("description").cloned().unwrap_or(Value::Null),
                        "parameters": translate_parameters(tool, SchemaProfile::OpenAI, schema_mode)?
                    }
                }));
            }
            body["tools"] = Value::Array(declarations);
        }
    }

    ensure_required_chat_tools(&mut body);
    Ok(body)
}

fn build_anthropic_body(
    req: &Value,
    model: &Value,
    schema_mode: SchemaMode,
) -> Result<Value, AdapterError> {
    let mut messages = Vec::new();
    let system = req
        .get("system")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    if let Some(input) = req.get("messages").and_then(Value::as_array) {
        for (message_index, message) in input.iter().enumerate() {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user");
            let parts = message
                .get("parts")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut content = Vec::new();

            match role {
                "assistant" => {
                    for (part_index, part) in parts.iter().enumerate() {
                        let location = format!("messages[{message_index}].parts[{part_index}]");
                        match part.get("type").and_then(Value::as_str) {
                            Some("text") => {
                                if let Some(text) = part.get("text").and_then(Value::as_str) {
                                    content.push(json!({"type":"text","text":text}));
                                }
                            }
                            Some("thinking") => {
                                if let (Some(text), Some(signature)) = (
                                    part.get("text").and_then(Value::as_str),
                                    part.get("signature").and_then(Value::as_str),
                                ) {
                                    content.push(json!({
                                        "type":"thinking",
                                        "thinking":text,
                                        "signature":signature
                                    }));
                                }
                            }
                            Some("tool_call") => {
                                let name = required_non_empty_part_str(part, "name", &location)?;
                                let arguments = part
                                    .get("arguments")
                                    .and_then(Value::as_str)
                                    .unwrap_or("{}");
                                let input: Value =
                                    serde_json::from_str(arguments).map_err(|error| {
                                        err(
                                            "invalid_request",
                                            format!(
                                                "{location} has invalid tool-call JSON: {error}"
                                            ),
                                        )
                                    })?;
                                content.push(json!({
                                    "type":"tool_use",
                                    "id":required_non_empty_part_str(part, "id", &location)?,
                                    "name":name,
                                    "input":input
                                }));
                            }
                            Some("image") => {
                                return Err(err(
                                    "unsupported_capability",
                                    "OpenCode Anthropic transport does not support image input",
                                ));
                            }
                            _ => {}
                        }
                    }
                }
                "tool" => {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) != Some("tool_result") {
                            continue;
                        }
                        let output = tool_result_output_text(part)?;
                        let mut result = json!({
                            "type":"tool_result",
                            "tool_use_id":required_non_empty_part_str(
                                part,
                                "tool_call_id",
                                &format!("messages[{message_index}] tool result"),
                            )?,
                            "content":output
                        });
                        if part.get("is_error").and_then(Value::as_bool) == Some(true) {
                            result["is_error"] = json!(true);
                        }
                        content.push(result);
                    }
                }
                _ => {
                    for part in parts {
                        match part.get("type").and_then(Value::as_str) {
                            Some("text") => {
                                if let Some(text) = part.get("text").and_then(Value::as_str) {
                                    content.push(json!({"type":"text","text":text}));
                                }
                            }
                            Some("image") => {
                                return Err(err(
                                    "unsupported_capability",
                                    "OpenCode Anthropic transport does not support image input",
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }

            if !content.is_empty() {
                messages.push(json!({
                    "role":if role == "assistant" { "assistant" } else { "user" },
                    "content":content
                }));
            }
        }
    }

    let max_tokens = req
        .get("max_tokens")
        .and_then(Value::as_u64)
        .or_else(|| model.get("max_output_tokens").and_then(Value::as_u64))
        .unwrap_or(4096);
    let mut body = json!({
        "model":request_model(req, model),
        "messages":messages,
        "max_tokens":max_tokens,
        "stream":true
    });
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    for (source, target) in [
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stop", "stop_sequences"),
    ] {
        if let Some(value) = req.get(source).filter(|value| !value.is_null()) {
            body[target] = value.clone();
        }
    }
    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        let mut declarations = Vec::with_capacity(tools.len());
        for tool in tools {
            let mut declaration = json!({
                "name":tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                "input_schema":translate_parameters(tool, SchemaProfile::Anthropic, schema_mode)?
            });
            if let Some(description) = tool.get("description").and_then(Value::as_str) {
                declaration["description"] = json!(description);
            }
            declarations.push(declaration);
        }
        body["tools"] = Value::Array(declarations);
    }
    ensure_required_anthropic_tools(&mut body);
    Ok(body)
}

fn ensure_required_anthropic_tools(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let tools = object
        .entry("tools")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(tools) = tools.as_array_mut() else {
        return;
    };
    for name in ["bash", "read"] {
        if !tools
            .iter()
            .any(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        {
            tools.push(json!({
                "name":name,
                "description":"This tool is unavailable and must not be used.",
                "input_schema":{"type":"object","properties":{}}
            }));
        }
    }
}

fn build_responses_body(
    req: &Value,
    model: &Value,
    schema_mode: SchemaMode,
) -> Result<Value, AdapterError> {
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
                                "output": tool_result_output_text(part)?
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
        let mut declarations = Vec::with_capacity(tools.len());
        for tool in tools {
            declarations.push(json!({
                "type": "function",
                "name": tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                "description": tool.get("description").cloned().unwrap_or(Value::Null),
                "parameters": translate_parameters(tool, SchemaProfile::OpenAIResponses, schema_mode)?
            }));
        }
        body["tools"] = Value::Array(declarations);
    }

    ensure_required_responses_tools(&mut body);
    Ok(body)
}

pub fn build_body(
    request_json: &str,
    provider_json: &str,
    model_json: &str,
) -> Result<String, AdapterError> {
    let req: Value = serde_json::from_str(request_json)
        .map_err(|e| err("bad_request", format!("bad request json: {e}")))?;
    validate_tool_history(&req)?;
    validate_supported_request_features(&req)?;
    let provider: Value = serde_json::from_str(provider_json)
        .map_err(|e| err("invalid_configuration", format!("bad provider json: {e}")))?;
    let schema_mode = schema_mode(&provider)?;
    let model: Value = serde_json::from_str(model_json)
        .map_err(|e| err("bad_request", format!("bad model json: {e}")))?;
    let transport = model_transport(&model)?;
    validate_tool_result_error_support(&req, &transport.format)?;
    let body = match transport.format {
        TransportFormat::OpenAiChat => build_chat_body(&req, &model, schema_mode)?,
        TransportFormat::OpenAiResponses => build_responses_body(&req, &model, schema_mode)?,
        TransportFormat::Anthropic => build_anthropic_body(&req, &model, schema_mode)?,
        _ => {
            return Err(err(
                "unsupported_transport",
                "transport is not supported by OpenCode",
            ))
        }
    };

    Ok(body.to_string())
}

fn schema_mode(provider: &Value) -> Result<SchemaMode, AdapterError> {
    let value = match provider.get("capability_mode") {
        None => "compatible",
        Some(Value::String(value)) => value,
        Some(_) => {
            return Err(err(
                "invalid_configuration",
                "capability_mode must be a string",
            ))
        }
    };
    value
        .parse()
        .map_err(|error: schema::SchemaError| err("invalid_configuration", error.to_string()))
}

fn translate_parameters(
    tool: &Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<Value, AdapterError> {
    let parameters = tool
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| json!({"type":"object","properties":{}}));
    schema::translate_tool_parameters(&parameters, profile, mode).map_err(|error| {
        let name = tool.get("name").and_then(Value::as_str).unwrap_or("tool");
        err(
            "invalid_request",
            format!("tool schema for '{name}' could not be translated: {error}"),
        )
    })
}

fn tool_result_output(part: &Value) -> Result<Value, AdapterError> {
    let content = part.get("content");
    let structured = part
        .get("structured_content")
        .or_else(|| part.get("structuredContent"));

    if let Some(content) = content {
        validate_tool_result_media(content)?;
    }

    Ok(match (content, structured) {
        (Some(content), Some(structured)) => json!({
            "content": content,
            "structured_content": structured
        }),
        (Some(content), None) => content.clone(),
        (None, Some(structured)) => structured.clone(),
        (None, None) => Value::Null,
    })
}

fn tool_result_output_text(part: &Value) -> Result<String, AdapterError> {
    let output = tool_result_output(part)?;
    Ok(match output {
        Value::String(text) => text,
        Value::Null
            if part.get("content").is_some()
                || part.get("structured_content").is_some()
                || part.get("structuredContent").is_some() =>
        {
            Value::Null.to_string()
        }
        Value::Null => String::new(),
        value => value.to_string(),
    })
}

fn validate_tool_result_media(value: &Value) -> Result<(), AdapterError> {
    const MEDIA_TYPES: &[&str] = &[
        "image",
        "image_url",
        "document",
        "document_url",
        "audio",
        "audio_url",
        "video",
        "video_url",
        "file",
        "file_url",
    ];

    fn is_content_part(part: &Value) -> bool {
        let Some(object) = part.as_object() else {
            return false;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return false;
        };
        let has_any = |keys: &[&str]| keys.iter().any(|key| object.contains_key(*key));
        let has_string = |keys: &[&str]| {
            keys.iter()
                .any(|key| object.get(*key).is_some_and(Value::is_string))
        };
        let source_has_string = |keys: &[&str]| {
            object
                .get("source")
                .and_then(Value::as_object)
                .is_some_and(|source| {
                    keys.iter()
                        .any(|key| source.get(*key).is_some_and(Value::is_string))
                })
        };

        match kind {
            "text" => object.get("text").is_some_and(Value::is_string),
            "json" | "structured" | "structured_json" => has_any(&["json", "value", "data"]),
            "image_url" | "document_url" | "audio_url" | "video_url" | "file_url" => {
                has_string(&["url", "uri"]) || source_has_string(&["url", "uri"])
            }
            "image" | "document" | "audio" | "video" | "file" => {
                has_string(&["data", "url", "uri"]) || source_has_string(&["data", "url", "uri"])
            }
            _ => false,
        }
    }

    fn is_content_parts(parts: &[Value]) -> bool {
        !parts.is_empty() && parts.iter().all(is_content_part)
    }

    fn validate_part(part: &Value, media_types: &[&str]) -> Result<(), AdapterError> {
        let Some(object) = part.as_object() else {
            return Ok(());
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return Ok(());
        };
        if !media_types.contains(&kind) {
            return Ok(());
        }
        let payload_keys: &[&str] = if kind.ends_with("_url") {
            &["url", "uri"]
        } else {
            &["data", "url", "uri"]
        };
        let has_direct_payload = payload_keys
            .iter()
            .any(|key| object.get(*key).is_some_and(Value::is_string));
        let has_source_payload =
            object
                .get("source")
                .and_then(Value::as_object)
                .is_some_and(|source| {
                    payload_keys
                        .iter()
                        .any(|key| source.get(*key).is_some_and(Value::is_string))
                });
        if has_direct_payload || has_source_payload {
            return Err(err(
                "unsupported_media",
                format!("OpenCode transport does not support {kind} tool-result media"),
            ));
        }
        Ok(())
    }

    match value {
        Value::Array(parts) if is_content_parts(parts) => {
            for part in parts {
                validate_part(part, MEDIA_TYPES)?;
            }
        }
        Value::Array(_) => {}
        part => validate_part(part, MEDIA_TYPES)?,
    }
    Ok(())
}

fn validate_tool_result_error_support(
    req: &Value,
    format: &TransportFormat,
) -> Result<(), AdapterError> {
    if matches!(format, TransportFormat::Anthropic) {
        return Ok(());
    }

    let has_failed_tool_result = req
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|message| {
            message
                .get("parts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .any(|part| {
            part.get("type").and_then(Value::as_str) == Some("tool_result")
                && part.get("is_error").and_then(Value::as_bool) == Some(true)
        });
    if has_failed_tool_result {
        return Err(err(
            "unsupported_capability",
            "OpenCode OpenAI transports do not support failed tool results",
        ));
    }
    Ok(())
}

fn validate_supported_request_features(req: &Value) -> Result<(), AdapterError> {
    if !req.get("thinking").unwrap_or(&Value::Null).is_null() {
        return Err(err(
            "unsupported_capability",
            "OpenCode adapter does not support canonical reasoning controls",
        ));
    }

    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for (message_index, message) in messages.iter().enumerate() {
            if let Some(parts) = message.get("parts").and_then(Value::as_array) {
                for (part_index, part) in parts.iter().enumerate() {
                    if matches!(
                        part.get("type").and_then(Value::as_str),
                        Some("image" | "image_url")
                    ) {
                        return Err(err(
                            "unsupported_capability",
                            format!("OpenCode adapter does not support image input at messages[{message_index}].parts[{part_index}]"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
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

fn parse_anthropic(value: &Value) -> Result<Vec<Value>, AdapterError> {
    let mut events = Vec::new();
    let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
    match event_type {
        "message_start" => {
            if let Some(message) = value.get("message") {
                if let Some(id) = message.get("id").and_then(Value::as_str) {
                    events.push(json!({"type":"start","upstream_request_id":id}));
                }
                if let Some(usage) = message.get("usage") {
                    events.push(json!({
                        "type":"usage",
                        "input":usage.get("input_tokens").and_then(Value::as_u64),
                        "output":Value::Null,
                        "cached":usage.get("cache_read_input_tokens").and_then(Value::as_u64),
                        "cache_write":usage.get("cache_creation_input_tokens").and_then(Value::as_u64),
                        "thinking":Value::Null
                    }));
                }
            }
        }
        "content_block_start" => {
            let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
            if let Some(block) = value.get("content_block") {
                match block.get("type").and_then(Value::as_str) {
                    Some("tool_use") => events.push(json!({
                        "type":"tool_call_start",
                        "index":index,
                        "id":block.get("id").and_then(Value::as_str),
                        "name":block.get("name").and_then(Value::as_str).unwrap_or(""),
                        "signature":Value::Null
                    })),
                    Some("thinking") => {
                        if let Some(signature) = block.get("signature").and_then(Value::as_str) {
                            events.push(json!({
                                "type":"thinking_delta",
                                "text":"",
                                "signature":signature
                            }));
                        }
                    }
                    _ => {}
                }
            }
        }
        "content_block_delta" => {
            let delta = value.get("delta").unwrap_or(&Value::Null);
            let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
            match delta.get("type").and_then(Value::as_str) {
                Some("text_delta") => {
                    if let Some(text) = delta.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            events.push(json!({"type":"text_delta","text":text}));
                        }
                    }
                }
                Some("thinking_delta") => {
                    if let Some(text) = delta.get("thinking").and_then(Value::as_str) {
                        events.push(json!({"type":"thinking_delta","text":text}));
                    }
                }
                Some("signature_delta") => {
                    if let Some(signature) = delta.get("signature").and_then(Value::as_str) {
                        events.push(json!({
                            "type":"thinking_delta",
                            "text":"",
                            "signature":signature
                        }));
                    }
                }
                Some("input_json_delta") => {
                    if let Some(args) = delta.get("partial_json").and_then(Value::as_str) {
                        if !args.is_empty() {
                            events.push(json!({
                                "type":"tool_call_args_delta",
                                "index":index,
                                "args":args
                            }));
                        }
                    }
                }
                _ => {}
            }
        }
        "message_delta" => {
            if let Some(usage) = value.get("usage") {
                events.push(json!({
                    "type":"usage",
                    "input":Value::Null,
                    "output":usage.get("output_tokens").and_then(Value::as_u64),
                    "cached":Value::Null,
                    "cache_write":Value::Null,
                    "thinking":usage.get("thinking_tokens").and_then(Value::as_u64)
                }));
            }
            if let Some(reason) = value.pointer("/delta/stop_reason").and_then(Value::as_str) {
                let reason = match reason {
                    "tool_use" => "tool_calls",
                    "max_tokens" => "length",
                    "end_turn" | "stop_sequence" => "stop",
                    _ => return Err(err("protocol_error", "unknown Anthropic finish reason")),
                };
                events.push(json!({"type":"finish","reason":reason}));
            }
        }
        "error" => {
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("Anthropic stream returned an error");
            return Err(err("upstream_error", message));
        }
        _ => {}
    }
    Ok(events)
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
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                events.push(json!({"type":"thinking_delta","text":delta}));
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
        "response.incomplete" => {
            let reason = value
                .pointer("/response/incomplete_details/reason")
                .and_then(Value::as_str);
            events.push(json!({
                "type":"finish",
                "reason":if reason == Some("max_output_tokens") { "length" } else { "stop" }
            }));
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

fn response_envelope(events: Vec<Value>) -> Value {
    json!({
        "schema": "kinetix.plugin.response",
        "schema_version": 1,
        "events": events,
    })
}

pub fn parse_stream_chunk(data: &str) -> Result<String, AdapterError> {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return Ok(response_envelope(Vec::new()).to_string());
    }

    let value: Value = serde_json::from_str(data)
        .map_err(|e| err("protocol_error", format!("invalid SSE JSON: {e}")))?;

    let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
    let events = if event_type.starts_with("response.") {
        parse_responses(&value)
    } else if matches!(
        event_type,
        "message_start"
            | "content_block_start"
            | "content_block_delta"
            | "message_delta"
            | "message_stop"
            | "error"
    ) {
        parse_anthropic(&value)?
    } else {
        parse_chat(&value)
    };
    Ok(response_envelope(events).to_string())
}

fn parse_anthropic_full(value: &Value) -> Result<Vec<Value>, AdapterError> {
    let mut events = Vec::new();
    if let Some(id) = value.get("id").and_then(Value::as_str) {
        events.push(json!({"type":"start","upstream_request_id":id}));
    }
    let mut has_tool_calls = false;
    if let Some(content) = value.get("content").and_then(Value::as_array) {
        for (index, block) in content.iter().enumerate() {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        events.push(json!({"type":"text_delta","text":text}));
                    }
                }
                Some("thinking") => {
                    events.push(json!({
                        "type":"thinking_delta",
                        "text":block.get("thinking").and_then(Value::as_str).unwrap_or(""),
                        "signature":block.get("signature").and_then(Value::as_str)
                    }));
                }
                Some("tool_use") => {
                    has_tool_calls = true;
                    events.push(json!({
                        "type":"tool_call_start",
                        "index":index,
                        "id":block.get("id").and_then(Value::as_str),
                        "name":block.get("name").and_then(Value::as_str).unwrap_or(""),
                        "signature":Value::Null
                    }));
                    events.push(json!({
                        "type":"tool_call_args_delta",
                        "index":index,
                        "args":block.get("input").cloned().unwrap_or_else(|| json!({})).to_string()
                    }));
                }
                _ => {}
            }
        }
    }
    if let Some(usage) = value.get("usage") {
        events.push(json!({
            "type":"usage",
            "input":usage.get("input_tokens").and_then(Value::as_u64),
            "output":usage.get("output_tokens").and_then(Value::as_u64),
            "cached":usage.get("cache_read_input_tokens").and_then(Value::as_u64),
            "cache_write":usage.get("cache_creation_input_tokens").and_then(Value::as_u64),
            "thinking":usage.get("thinking_tokens").and_then(Value::as_u64)
        }));
    }
    let reason = match value.get("stop_reason").and_then(Value::as_str) {
        Some("tool_use") => "tool_calls",
        Some("max_tokens") => "length",
        Some("end_turn" | "stop_sequence") => "stop",
        _ if has_tool_calls => "tool_calls",
        _ => "stop",
    };
    events.push(json!({"type":"finish","reason":reason}));
    Ok(events)
}

pub fn parse_full_response(body_json: &str) -> Result<String, AdapterError> {
    let value: Value = serde_json::from_str(body_json)
        .map_err(|e| err("protocol_error", format!("invalid response JSON: {e}")))?;

    if value.get("object").and_then(Value::as_str) == Some("chat.completion") {
        return Ok(response_envelope(parse_chat(&value)).to_string());
    }

    if value.get("type").and_then(Value::as_str) == Some("message") {
        return Ok(response_envelope(parse_anthropic_full(&value)?).to_string());
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

                if item.get("type").and_then(Value::as_str) == Some("reasoning") {
                    if let Some(summary) = item.get("summary").and_then(Value::as_array) {
                        for part in summary {
                            if let Some(text) = part.get("text").and_then(Value::as_str) {
                                if !text.is_empty() {
                                    events.push(json!({"type":"thinking_delta","text":text}));
                                }
                            }
                        }
                    }
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
        let finish_reason = if has_tool_calls {
            "tool_calls"
        } else if value.get("status").and_then(Value::as_str) == Some("incomplete")
            && value
                .pointer("/incomplete_details/reason")
                .and_then(Value::as_str)
                == Some("max_output_tokens")
        {
            "length"
        } else {
            "stop"
        };
        events.push(json!({"type":"finish","reason":finish_reason}));
        return Ok(response_envelope(events).to_string());
    }

    Err(err("protocol_error", "unsupported OpenCode response shape"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep event-focused tests concise while still checking the public envelope.
    fn unpack_test_response(response: String) -> Result<String, AdapterError> {
        let envelope: Value = serde_json::from_str(&response)
            .map_err(|error| err("protocol_error", error.to_string()))?;
        if envelope.get("schema").and_then(Value::as_str) != Some("kinetix.plugin.response")
            || envelope.get("schema_version").and_then(Value::as_u64) != Some(1)
        {
            return Err(err("protocol_error", "invalid canonical response envelope"));
        }
        let events = envelope
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| err("protocol_error", "response envelope has no events array"))?;
        Ok(Value::Array(events.clone()).to_string())
    }

    fn parse_stream_chunk(data: &str) -> Result<String, AdapterError> {
        unpack_test_response(super::parse_stream_chunk(data)?)
    }

    fn parse_full_response(data: &str) -> Result<String, AdapterError> {
        unpack_test_response(super::parse_full_response(data)?)
    }

    struct ConformanceAdapter;

    impl kinetix_adapter_conformance::Adapter for ConformanceAdapter {
        fn build_body(
            &self,
            request: &Value,
            provider: &Value,
            model: &Value,
        ) -> Result<Value, String> {
            let body = super::build_body(
                &request.to_string(),
                &provider.to_string(),
                &model.to_string(),
            )
            .map_err(|error| format!("{}: {}", error.code, error.message))?;
            serde_json::from_str(&body).map_err(|error| error.to_string())
        }

        fn parse_stream_chunk(&self, chunk: &Value) -> Result<Value, String> {
            let events = super::parse_stream_chunk(&chunk.to_string())
                .map_err(|error| format!("{}: {}", error.code, error.message))?;
            serde_json::from_str(&events).map_err(|error| error.to_string())
        }

        fn parse_full_response(&self, response: &Value) -> Result<Value, String> {
            let events = super::parse_full_response(&response.to_string())
                .map_err(|error| format!("{}: {}", error.code, error.message))?;
            serde_json::from_str(&events).map_err(|error| error.to_string())
        }

        fn classify_error(
            &self,
            status: u16,
            body: &Value,
            headers: &Value,
        ) -> Result<Value, String> {
            let evidence = super::classify_error(status, &body.to_string(), &headers.to_string())
                .map_err(|error| format!("{}: {}", error.code, error.message))?;
            serde_json::from_str(&evidence).map_err(|error| error.to_string())
        }
    }

    #[test]
    fn shared_adapter_conformance_fixtures() {
        kinetix_adapter_conformance::check(
            &ConformanceAdapter,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/adapter-conformance.json"
            )),
        )
        .unwrap();
    }

    fn test_model(id: &str, format: TransportFormat, endpoint: &str) -> String {
        let capabilities = ModelCapabilitiesV3 {
            transport: Some(ModelTransportCapability::at_endpoint(format, endpoint)),
            ..Default::default()
        };
        json!({
            "upstream_id":id,
            "capabilities_json":capabilities.to_json().unwrap()
        })
        .to_string()
    }

    fn chat_model(id: &str) -> String {
        test_model(id, TransportFormat::OpenAiChat, "/zen/v1/chat/completions")
    }

    fn responses_model(id: &str) -> String {
        test_model(id, TransportFormat::OpenAiResponses, "/zen/v1/responses")
    }

    fn anthropic_model(id: &str) -> String {
        test_model(id, TransportFormat::Anthropic, "/zen/v1/messages")
    }

    fn production_model_row(id: &str, format: TransportFormat, endpoint: &str) -> String {
        let capabilities = ModelCapabilitiesV3 {
            transport: Some(ModelTransportCapability::at_endpoint(format, endpoint)),
            ..Default::default()
        };
        json!({
            "id":"model_123",
            "provider_id":"provider_123",
            "upstream_id":id,
            "display_name":id,
            "enabled":1,
            "context_window":null,
            "max_output_tokens":null,
            "capabilities":"{}",
            "prices":"{}",
            "parameters":"{}",
            "thinking_map":"{}",
            "extra_request":"{}",
            "discovery":json!({
                "latest_observation":{
                    "raw_metadata":{
                        "id":id,
                        "kinetix_plugin_capabilities":capabilities
                    }
                }
            }).to_string(),
            "created_at":"2026-01-01T00:00:00Z",
            "opaque_state_plugin":""
        })
        .to_string()
    }

    fn chat_body(messages: Value) -> Result<Value, AdapterError> {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.5-free",
            "system": [],
            "messages": messages,
            "tools": [],
            "stream": true
        });
        let body = build_body(&request.to_string(), "{}", &chat_model("mimo-v2.5-free"))?;
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
            &chat_model("mimo-v2.6-flash-free"),
        )?;
        Ok(serde_json::from_str(&body).expect("adapter body must be valid JSON"))
    }

    #[test]
    fn uses_discovered_transport_metadata_for_endpoints() {
        let provider = r#"{"base_url":"https://opencode.ai"}"#;
        assert!(build_url(provider, &chat_model("mimo-v2.5-free"))
            .unwrap()
            .ends_with("/zen/v1/chat/completions"));
        assert!(build_url(
            provider,
            &responses_model("muse-spark-1.3-contributor-free")
        )
        .unwrap()
        .ends_with("/zen/v1/responses"));
        assert!(build_url(provider, &anthropic_model("union-alpha"))
            .unwrap()
            .ends_with("/zen/v1/messages"));

        let selected = test_model("big-pickle", TransportFormat::Anthropic, "/custom/messages");
        assert_eq!(
            build_url(provider, &selected).unwrap(),
            "https://opencode.ai/custom/messages"
        );
    }

    #[test]
    fn production_model_row_uses_capabilities_from_discovery_json_string() {
        let provider = r#"{"base_url":"https://opencode.ai"}"#;
        assert!(build_url(
            provider,
            &production_model_row(
                "union-alpha",
                TransportFormat::Anthropic,
                "/zen/v1/messages"
            )
        )
        .unwrap()
        .ends_with("/zen/v1/messages"));
    }

    #[test]
    fn pre_v3_model_rows_keep_using_normalized_transport_metadata() {
        let provider = r#"{"base_url":"https://opencode.ai"}"#;
        for discovery in [
            json!({"transport":{"format":"openai-chat"}}),
            json!({"latest_observation":{"transport":{"format":"openai-chat"}}}),
        ] {
            let model = json!({
                "id":"model_legacy",
                "provider_id":"provider_opencode",
                "upstream_id":"mimo-v2.5-free",
                "capabilities":"{}",
                "discovery":discovery.to_string(),
            })
            .to_string();
            assert_eq!(
                build_url(provider, &model).unwrap(),
                "https://opencode.ai/zen/v1/chat/completions"
            );
        }
    }

    #[test]
    fn core_persisted_model_capabilities_keep_v3_transport_endpoint() {
        let provider = r#"{"base_url":"https://opencode.ai"}"#;
        let model = json!({
            "id":"model_v3",
            "provider_id":"provider_opencode",
            "upstream_id":"muse-spark",
            "capabilities":"{}",
            "discovery":json!({
                "latest_observation": {
                    "model_capabilities": {
                        "schema_version": 3,
                        "transport": {
                            "format": "openai-responses",
                            "endpoint": "/zen/v1/custom-responses",
                            "alternatives": [{"format": "openai-chat"}]
                        }
                    }
                }
            })
            .to_string(),
        })
        .to_string();

        assert_eq!(
            build_url(provider, &model).unwrap(),
            "https://opencode.ai/zen/v1/custom-responses"
        );
    }

    #[test]
    fn unknown_models_without_transport_metadata_fail_conservatively() {
        let error = build_url("{}", r#"{"upstream_id":"new-free-model"}"#).unwrap_err();
        assert_eq!(error.code, "unsupported_transport");
        assert!(error.message.contains("transport metadata"));
    }

    #[test]
    fn anthropic_body_uses_messages_schema_and_preserves_tool_history() {
        let request = json!({
            "requested_model":"union-alpha",
            "system":["follow rules", "be concise"],
            "messages":[
                {"role":"user","parts":[{"type":"text","text":"read this"}]},
                {"role":"assistant","parts":[
                    {"type":"tool_call","id":"call_1","name":"read","arguments":r#"{"path":"README.md"}"#}
                ]},
                {"role":"tool","parts":[
                    {"type":"tool_result","tool_call_id":"call_1","name":"read","content":"contents","is_error":false}
                ]}
            ],
            "tools":[{"name":"read","description":"Read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}],
            "max_tokens":512
        });
        let body: Value = serde_json::from_str(
            &build_body(&request.to_string(), "{}", &anthropic_model("union-alpha")).unwrap(),
        )
        .unwrap();

        assert_eq!(body["model"], "union-alpha");
        assert_eq!(body["system"], "follow rules\nbe concise");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["stream"], true);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(
            body["messages"][1]["content"][0]["input"]["path"],
            "README.md"
        );
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "call_1");
        assert!(body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "bash"));
        assert!(body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "read"));
        assert!(body["tools"][0].get("function").is_none());
    }

    #[test]
    fn all_open_code_transports_translate_tool_schemas_with_the_shared_profiles() {
        let request = json!({
            "requested_model":"schema-test",
            "messages":[],
            "tools":[{"name":"schema_tool","parameters":{
                "type":"object",
                "properties":{
                    "query":{"type":"string","minLength":"2","maxLength":"32","format":"regex"},
                    "tuple":{"type":"array","prefixItems":[{"type":"integer"}],"items":false}
                }
            }}]
        });
        let cases = [
            (chat_model("schema-test"), "/tools/0/function/parameters"),
            (responses_model("schema-test"), "/tools/0/parameters"),
            (anthropic_model("schema-test"), "/tools/0/input_schema"),
        ];
        for (model, schema_path) in cases {
            let body: Value =
                serde_json::from_str(&build_body(&request.to_string(), "{}", &model).unwrap())
                    .unwrap();
            let schema = body.pointer(schema_path).unwrap();
            assert_eq!(schema["properties"]["query"]["minLength"], 2);
            assert_eq!(schema["properties"]["query"]["maxLength"], 32);
            assert_eq!(schema["properties"]["query"]["format"], "regex");
            assert_eq!(
                schema["properties"]["tuple"]["prefixItems"][0]["type"],
                "integer"
            );
            assert_eq!(schema["properties"]["tuple"]["items"], false);
        }

        let invalid_request = json!({
            "tools":[{"name":"invalid","parameters":{
                "type":"object","properties":{"value":{"x-unknown":true}}
            }}]
        });
        for model in [
            chat_model("schema-test"),
            responses_model("schema-test"),
            anthropic_model("schema-test"),
        ] {
            let error = build_body(&invalid_request.to_string(), "{}", &model).unwrap_err();
            assert_eq!(error.code, "invalid_request");
            assert!(error.message.contains("unknown JSON Schema keyword"));
        }
    }

    #[test]
    fn anthropic_body_rejects_unsupported_image_input() {
        let request = json!({
            "requested_model":"union-alpha",
            "messages":[{"role":"user","parts":[{"type":"image","data":"..."}]}]
        });
        let error =
            build_body(&request.to_string(), "{}", &anthropic_model("union-alpha")).unwrap_err();
        assert_eq!(error.code, "unsupported_capability");
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
        let out: Value =
            serde_json::from_str(&build_body(req, "{}", &chat_model("mimo-v2.5-free")).unwrap())
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
    fn chat_body_rejects_unsupported_mimo_thinking_control() {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.6-flash-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let error = build_body(
            &request.to_string(),
            "{}",
            &chat_model("mimo-v2.6-flash-free"),
        )
        .unwrap_err();
        assert_eq!(error.code, "unsupported_capability");
    }

    #[test]
    fn responses_body_rejects_unsupported_thinking_control() {
        let request = serde_json::json!({
            "requested_model": "muse-spark-1.3-contributor-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let error = build_body(
            &request.to_string(),
            "{}",
            &responses_model("muse-spark-1.3-contributor-free"),
        )
        .unwrap_err();
        assert_eq!(error.code, "unsupported_capability");
    }

    #[test]
    fn non_toggle_chat_model_rejects_unsupported_thinking_control() {
        let request = serde_json::json!({
            "requested_model": "mimo-v2.5-free",
            "system": [],
            "messages": [],
            "tools": [],
            "stream": true,
            "thinking": {"level": "high"}
        });
        let error =
            build_body(&request.to_string(), "{}", &chat_model("mimo-v2.5-free")).unwrap_err();
        assert_eq!(error.code, "unsupported_capability");
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
                &responses_model("muse-spark-1.3-contributor-free"),
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
    fn parses_anthropic_messages_stream_events() {
        let start: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":12,"output_tokens":0}}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(start[0]["type"], "start");
        assert_eq!(start[0]["upstream_request_id"], "msg_1");
        assert_eq!(start[1]["input"], 12);

        let tool_start: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"read","input":{}}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tool_start[0]["type"], "tool_call_start");
        assert_eq!(tool_start[0]["index"], 2);
        assert_eq!(tool_start[0]["id"], "toolu_1");

        let tool_args: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"README.md\"}"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tool_args[0]["type"], "tool_call_args_delta");
        assert_eq!(tool_args[0]["args"], r#"{"path":"README.md"}"#);

        let thinking: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"checking"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(thinking[0]["type"], "thinking_delta");
        assert_eq!(thinking[0]["text"], "checking");

        let signature: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig_1"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(signature[0]["signature"], "sig_1");

        let finish: Value = serde_json::from_str(
            &parse_stream_chunk(
                r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(finish[0]["output"], 7);
        assert_eq!(finish[1]["reason"], "tool_calls");
    }

    #[test]
    fn parses_full_anthropic_message_response() {
        let events: Value = serde_json::from_str(
            &parse_full_response(
                r#"{"type":"message","id":"msg_2","stop_reason":"end_turn","content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":3,"output_tokens":1}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(events[0]["type"], "start");
        assert_eq!(events[1]["text"], "hello");
        assert_eq!(events[2]["input"], 3);
        assert_eq!(events[3]["reason"], "stop");
    }

    #[test]
    fn apply_auth_omits_session_when_unavailable_and_never_uses_credential_as_identity() {
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", "ses_secret-value", None).unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();

        assert_eq!(
            map.get("Authorization").map(String::as_str),
            Some("Bearer public")
        );
        assert_eq!(map.get("x-api-key").map(String::as_str), Some("public"));
        assert_eq!(
            map.get("anthropic-version").map(String::as_str),
            Some("2023-06-01")
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
        assert!(!map.contains_key("x-opencode-session"));
    }

    #[test]
    fn apply_auth_reuses_stable_upstream_session_for_the_same_kinetix_session() {
        let identity = "opaque-kinetix-session-123";
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", "", Some(identity)).unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        let session = map
            .get("x-opencode-session")
            .expect("missing x-opencode-session header");

        assert!(is_valid_session_id(session));
        assert_eq!(session.len(), 30);
        let repeated_headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", "", Some(identity)).unwrap()).unwrap();
        let repeated_map: std::collections::HashMap<_, _> = repeated_headers.into_iter().collect();
        assert_eq!(
            map.get("x-opencode-session"),
            repeated_map.get("x-opencode-session")
        );

        let other_headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth("{}", "", Some("another-session")).unwrap()).unwrap();
        let other_map: std::collections::HashMap<_, _> = other_headers.into_iter().collect();
        assert_ne!(
            map.get("x-opencode-session"),
            other_map.get("x-opencode-session")
        );
    }

    #[test]
    fn apply_auth_preserves_explicit_session_only_when_kinetix_identity_is_unavailable() {
        let custom_session = "ses_01a0c1ed0d77UteRivKIZVE10s";
        let provider = format!(r#"{{"session_id":"{custom_session}"}}"#);
        let headers: Vec<(String, String)> =
            serde_json::from_str(&apply_auth(&provider, "", None).unwrap()).unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(
            map.get("x-opencode-session").map(String::as_str),
            Some(custom_session)
        );

        let headers: Vec<(String, String)> = serde_json::from_str(
            &apply_auth(&provider, "", Some("opaque-kinetix-session")).unwrap(),
        )
        .unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(
            map.get("x-opencode-session").map(String::as_str),
            Some(opencode_session_id("opaque-kinetix-session").as_str())
        );
    }
}
