//! Antigravity (`v1internal`) wire-format adapter — a *pure translation* plugin
//! (`plugin-adapter` world, §6.3, §7.1).
//!
//! Kinetix core owns the outbound HTTP send and the SSE framing; this plugin
//! only translates:
//!
//! * `build-url`  → `…/v1internal:streamGenerateContent?alt=sse` (or
//!   `generateContent` when the client did not ask to stream),
//! * `apply-auth` → the `Authorization: Bearer …` + Antigravity `User-Agent`,
//! * `build-body` → the `{project, model, userAgent, requestType, requestId,
//!   request:{contents, systemInstruction, generationConfig, tools, …}}`
//!   envelope, converting the internal message model to Gemini `contents`,
//! * `classify-error` / `parse-stream-chunk` / `parse-full-response` → canonical
//!   event JSON back to the host.
//!
//! Reference source: 9router `open-sse/executors/antigravity.js` and
//! `open-sse/translator/response/openai-to-antigravity.js`.

use std::collections::HashMap;

use kinetix_plugin_sdk::schema::{self, SchemaMode, SchemaProfile};
use kinetix_plugin_sdk::tool_names::ToolNameMap;
use serde_json::{json, Map, Value};

/// The IDE fingerprint Antigravity expects (macOS on purpose, even on Linux).
pub(crate) const USER_AGENT: &str = "antigravity/ide/2.11.0 darwin/arm64";

const MAX_OUTPUT_TOKENS: i64 = 64000;
const SUPPORTED_EXTRA_FIELDS: &[&str] = &["antigravity_project", "session_id", "sessionId"];

/// Transient upstream error patterns that should be retried by the host.
const TRANSIENT_PATTERNS: &[&str] = &[
    "high traffic",
    "agent execution terminated due to error",
    "agent terminated due to error",
    "capacity",
    "temporarily unavailable",
    "timeout",
    "stream ended",
    "stream closed",
    "stream terminated",
    "stream interrupted",
    "empty response",
];

/// A neutral error the host-side impl maps onto the adapter world's
/// `PluginError` (the two worlds have distinct generated types).
#[derive(Debug, Clone)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
}

fn err(code: &str, message: impl Into<String>) -> AdapterError {
    AdapterError {
        code: code.to_string(),
        message: message.into(),
    }
}

fn bad(message: impl Into<String>) -> AdapterError {
    err("bad_request", message)
}

pub fn wire_format() -> String {
    "antigravity".to_string()
}

// ---------------------------------------------------------------------------
// URL + auth
// ---------------------------------------------------------------------------

pub fn build_url(provider_json: &str, model_json: &str) -> Result<String, AdapterError> {
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let base = provider
        .get("base_url")
        .and_then(|b| b.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("https://daily-cloudcode-pa.googleapis.com")
        .trim_end_matches('/');
    // Kinetix core streams via SSE, so the streaming action is used. (Image
    // generation, which needs `generateContent`, is not yet a Kinetix route.)
    let _ = model_json;
    Ok(format!("{base}/v1internal:streamGenerateContent?alt=sse"))
}

pub fn apply_auth(_provider_json: &str, credential: &str) -> Result<String, AdapterError> {
    let headers = json!([
        ["Authorization", format!("Bearer {credential}")],
        ["Content-Type", "application/json"],
        ["User-Agent", USER_AGENT],
    ]);
    Ok(headers.to_string())
}

// ---------------------------------------------------------------------------
// Body construction
// ---------------------------------------------------------------------------

pub fn build_body(
    request_json: &str,
    provider_json: &str,
    model_json: &str,
    session_context: Option<&str>,
) -> Result<String, AdapterError> {
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let now_unix_millis = provider
        .pointer("/_kinetix/now_unix_millis")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                "invalid_configuration",
                "core adapter context is missing _kinetix.now_unix_millis",
            )
        })?;

    build_body_at(
        request_json,
        provider_json,
        model_json,
        session_context,
        now_unix_millis,
    )
}

fn build_body_at(
    request_json: &str,
    provider_json: &str,
    model_json: &str,
    session_context: Option<&str>,
    now_unix_millis: u64,
) -> Result<String, AdapterError> {
    let req: Value =
        serde_json::from_str(request_json).map_err(|e| bad(format!("bad request json: {e}")))?;
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let model: Value = serde_json::from_str(model_json).unwrap_or(Value::Null);

    validate_request_contract(&req)?;
    validate_tool_history(&req)?;
    validate_canonical_extras(&provider, &req)?;
    validate_nonportable_controls(&provider, &req)?;

    let upstream_model = model
        .get("upstream_id")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| req.get("requested_model").and_then(|m| m.as_str()))
        .unwrap_or("gemini-3-flash")
        .to_string();

    let project = project_id(&provider, &req)?;
    let session_id = session_id(&req, &provider, session_context);
    let request_id = build_request_id(session_id.as_deref(), &upstream_model, now_unix_millis);

    let system_instruction = req
        .get("system")
        .and_then(Value::as_array)
        .map(|items| {
            let parts: Vec<Value> = items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| json!({ "text": text }))
                .collect();
            json!({ "parts": parts })
        })
        .filter(|instruction| {
            instruction
                .get("parts")
                .and_then(Value::as_array)
                .map(|parts| !parts.is_empty())
                .unwrap_or(false)
        });

    let tool_names = tool_name_mapping(&req)?;
    let tool_call_names = tool_call_names(&req);
    let mut contents = Vec::new();
    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for message in messages {
            let role = match message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user")
            {
                "assistant" => "model",
                _ => "user",
            };
            let mut parts = Vec::new();
            if let Some(items) = message.get("parts").and_then(Value::as_array) {
                for part in items {
                    parts.extend(part_to_gemini(part, &tool_names, &tool_call_names)?);
                }
            }
            if !parts.is_empty() {
                contents.push(json!({ "role": role, "parts": parts }));
            }
        }
    }

    let mut generation_config = Map::new();
    if let Some(value) = req.get("temperature").and_then(Value::as_f64) {
        generation_config.insert("temperature".into(), json!(value));
    }
    if let Some(value) = req.get("top_p").and_then(Value::as_f64) {
        generation_config.insert("topP".into(), json!(value));
    }
    if let Some(value) = req.get("top_k").and_then(Value::as_f64) {
        generation_config.insert("topK".into(), json!(value));
    }
    if let Some(value) = req.get("max_tokens").and_then(Value::as_i64) {
        generation_config.insert(
            "maxOutputTokens".into(),
            json!(value.min(MAX_OUTPUT_TOKENS)),
        );
    }
    if let Some(stop) = req.get("stop").and_then(Value::as_array) {
        if !stop.is_empty() {
            generation_config.insert("stopSequences".into(), Value::Array(stop.clone()));
        }
    }
    if let Some(seed) = req.get("seed").and_then(Value::as_i64) {
        generation_config.insert("seed".into(), json!(seed));
    }
    apply_thinking(&mut generation_config, &req, &upstream_model)?;

    let declarations = build_tool_declarations_with_names(&req, &provider, &tool_names)?;

    let mut request = Map::new();
    request.insert("contents".into(), Value::Array(contents));
    if let Some(instruction) = system_instruction {
        request.insert("systemInstruction".into(), instruction);
    }
    request.insert("generationConfig".into(), Value::Object(generation_config));
    if !declarations.is_empty() {
        request.insert(
            "tools".into(),
            json!([{ "functionDeclarations": declarations }]),
        );
        if let Some(config) = build_tool_config_with_names(&req, &tool_names)? {
            request.insert("toolConfig".into(), config);
        }
    }
    if let Some(session_id) = session_id {
        request.insert("sessionId".into(), json!(session_id));
    }
    // Canonical `extra` is host/client metadata, not an Antigravity request
    // extension point. Supported values above are consumed explicitly; every
    // other value is either dropped (permissive) or rejected (strict).

    let mut envelope = Map::new();
    envelope.insert("project".into(), json!(project));
    envelope.insert("model".into(), json!(upstream_model));
    envelope.insert("userAgent".into(), json!("antigravity"));
    envelope.insert("requestType".into(), json!("agent"));
    envelope.insert("requestId".into(), json!(request_id));
    envelope.insert("request".into(), Value::Object(request));

    Ok(Value::Object(envelope).to_string())
}

fn provider_is_strict(provider: &Value) -> bool {
    provider.get("capability_mode").and_then(Value::as_str) == Some("strict")
}

// Legacy constraint regressions. Production policy lives in sdk::schema.
#[cfg(test)]
const LEGACY_CONSTRAINT_FIXTURES: &[&str] = &[
    "minLength",
    "maxLength",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minItems",
    "maxItems",
    "format",
    "multipleOf",
];

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

#[cfg(test)]
#[derive(Clone, Copy)]
enum SchemaPolicy {
    Permissive,
    Strict,
}

fn validate_request_contract(req: &Value) -> Result<(), AdapterError> {
    if let Some(schema) = req.get("schema").and_then(Value::as_str) {
        if schema != "kinetix.plugin.request" {
            return Err(bad(format!(
                "unsupported canonical request schema '{schema}'"
            )));
        }
    }
    if let Some(version) = req.get("schema_version").and_then(Value::as_u64) {
        if version != 1 {
            return Err(bad(format!(
                "unsupported kinetix.plugin.request schema_version {version}"
            )));
        }
    }
    Ok(())
}

fn validate_tool_history(req: &Value) -> Result<(), AdapterError> {
    let Some(messages) = req.get("messages").and_then(Value::as_array) else {
        return Ok(());
    };
    let mut calls = HashMap::new();

    for (message_index, message) in messages.iter().enumerate() {
        let Some(parts) = message.get("parts").and_then(Value::as_array) else {
            continue;
        };
        for (part_index, part) in parts.iter().enumerate() {
            let location = format!("messages[{message_index}].parts[{part_index}]");
            match part.get("type").and_then(Value::as_str) {
                Some("tool_call") => {
                    let id = part
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| {
                            bad(format!("{location} requires a non-empty tool_call id"))
                        })?;
                    let name = part
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| bad(format!("{location} requires a non-empty tool name")))?;
                    let arguments =
                        part.get("arguments")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                bad(format!("{location} requires JSON tool-call arguments"))
                            })?;
                    let arguments: Value = serde_json::from_str(arguments).map_err(|error| {
                        bad(format!("{location} has invalid tool-call JSON: {error}"))
                    })?;
                    if !arguments.is_object() {
                        return Err(bad(format!(
                            "{location} tool-call arguments must be a JSON object"
                        )));
                    }
                    if calls.insert(id.to_string(), name.to_string()).is_some() {
                        return Err(bad(format!("{location} has duplicate tool_call id '{id}'")));
                    }
                }
                Some("tool_result") => {
                    let id = part
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| {
                            bad(format!("{location} requires a non-empty tool_call_id"))
                        })?;
                    let Some(call_name) = calls.get(id) else {
                        return Err(bad(format!(
                            "{location} references unknown tool_call_id '{id}'"
                        )));
                    };
                    if let Some(name) = part.get("name").and_then(Value::as_str) {
                        if name != call_name {
                            return Err(bad(format!(
                                "{location} tool name does not match tool_call_id '{id}'"
                            )));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_canonical_extras(provider: &Value, req: &Value) -> Result<(), AdapterError> {
    if !provider_is_strict(provider) {
        return Ok(());
    }
    let Some(extra) = req.get("extra").and_then(Value::as_object) else {
        return Ok(());
    };
    let unknown: Vec<&str> = extra
        .keys()
        .map(String::as_str)
        .filter(|key| !SUPPORTED_EXTRA_FIELDS.contains(key))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(bad(format!(
            "unsupported Antigravity canonical extra field(s): {}",
            unknown.join(", ")
        )))
    }
}

fn validate_nonportable_controls(provider: &Value, req: &Value) -> Result<(), AdapterError> {
    if !provider_is_strict(provider) {
        return Ok(());
    }
    let mut unsupported = Vec::new();
    if !req
        .get("presence_penalty")
        .unwrap_or(&Value::Null)
        .is_null()
    {
        unsupported.push("presence_penalty");
    }
    if !req
        .get("frequency_penalty")
        .unwrap_or(&Value::Null)
        .is_null()
    {
        unsupported.push("frequency_penalty");
    }
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(bad(format!(
            "unsupported Antigravity canonical control(s): {}",
            unsupported.join(", ")
        )))
    }
}

fn ensure_max_output(generation_config: &mut Map<String, Value>, floor: i64) {
    let target = floor.min(MAX_OUTPUT_TOKENS);
    let current = generation_config
        .get("maxOutputTokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if current < target {
        generation_config.insert("maxOutputTokens".into(), json!(target));
    }
}

fn apply_thinking(
    generation_config: &mut Map<String, Value>,
    req: &Value,
    upstream_model: &str,
) -> Result<(), AdapterError> {
    let Some(level) = req.pointer("/thinking/level").and_then(Value::as_str) else {
        return Ok(());
    };
    let model = upstream_model.to_ascii_lowercase();

    if model.contains("gemini-3") {
        let (thinking_level, include_thoughts, floor) = match level {
            "off" => ("minimal", false, 4096),
            "low" => ("low", true, 8192),
            "medium" => ("medium", true, 16384),
            "high" => ("high", true, MAX_OUTPUT_TOKENS),
            other => {
                return Err(bad(format!(
                    "unsupported canonical thinking level '{other}'"
                )))
            }
        };
        generation_config.insert(
            "thinkingConfig".into(),
            json!({
                "thinkingLevel": thinking_level,
                "includeThoughts": include_thoughts,
            }),
        );
        ensure_max_output(generation_config, floor);
        return Ok(());
    }

    if model.contains("gemini-2.5") {
        let (budget, include_thoughts, floor) = match level {
            "off" => (0, false, 0),
            "low" => (1024, true, 8192),
            "medium" => (8192, true, 16384),
            "high" => (24576, true, 32768),
            other => {
                return Err(bad(format!(
                    "unsupported canonical thinking level '{other}'"
                )))
            }
        };
        generation_config.insert(
            "thinkingConfig".into(),
            json!({
                "thinkingBudget": budget,
                "includeThoughts": include_thoughts,
            }),
        );
        if floor > 0 {
            ensure_max_output(generation_config, floor);
        }
        return Ok(());
    }

    if model.contains("claude-opus-4-6-thinking") {
        let budget = match level {
            "low" => 8192,
            "max" => 32768,
            other => {
                return Err(bad(format!(
                    "unsupported canonical thinking level '{other}' for Antigravity Claude thinking model '{upstream_model}'; supported levels: low, max"
                )))
            }
        };
        generation_config.insert(
            "thinkingConfig".into(),
            json!({
                "thinkingBudget": budget,
                "includeThoughts": true,
            }),
        );
        ensure_max_output(generation_config, budget + 8192);
        return Ok(());
    }

    Err(bad(format!(
        "canonical thinking controls are unsupported for Antigravity model '{upstream_model}'"
    )))
}

fn tool_name_mapping(req: &Value) -> Result<ToolNameMap, AdapterError> {
    let mut names = Vec::new();
    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        for (index, tool) in tools.iter().enumerate() {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| bad(format!("tools[{index}] requires a non-empty name")))?;
            names.push(name);
        }
    }
    if let Some(name) = req.pointer("/tool_choice/name").and_then(Value::as_str) {
        names.push(name);
    }
    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(parts) = message.get("parts").and_then(Value::as_array) {
                for part in parts {
                    if matches!(
                        part.get("type").and_then(Value::as_str),
                        Some("tool_call" | "tool_result")
                    ) {
                        if let Some(name) = part.get("name").and_then(Value::as_str) {
                            names.push(name);
                        }
                    }
                }
            }
        }
    }
    ToolNameMap::new(names).map_err(|error| bad(error.to_string()))
}

fn tool_call_names(req: &Value) -> HashMap<String, String> {
    let mut calls = HashMap::new();
    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(parts) = message.get("parts").and_then(Value::as_array) {
                for part in parts {
                    if part.get("type").and_then(Value::as_str) == Some("tool_call") {
                        if let (Some(id), Some(name)) = (
                            part.get("id").and_then(Value::as_str),
                            part.get("name").and_then(Value::as_str),
                        ) {
                            calls.insert(id.to_owned(), name.to_owned());
                        }
                    }
                }
            }
        }
    }
    calls
}

#[cfg(test)]
fn build_tool_declarations(req: &Value, provider: &Value) -> Result<Vec<Value>, AdapterError> {
    let tool_names = tool_name_mapping(req)?;
    build_tool_declarations_with_names(req, provider, &tool_names)
}

fn build_tool_declarations_with_names(
    req: &Value,
    provider: &Value,
    tool_names: &ToolNameMap,
) -> Result<Vec<Value>, AdapterError> {
    let mode = schema_mode(provider)?;
    let mut declarations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        for tool in tools {
            let client_name = tool.get("name").and_then(Value::as_str).unwrap_or("");
            if !seen.insert(client_name) {
                return Err(bad(format!("duplicate tool name '{client_name}'")));
            }
            let name = tool_names
                .to_wire(client_name)
                .map_err(|error| bad(error.to_string()))?;
            let parameters = tool
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            declarations.push(json!({
                "name": name,
                "description": tool.get("description").cloned().unwrap_or(Value::Null),
                "parametersJsonSchema": schema::translate_tool_parameters(&parameters, SchemaProfile::Antigravity, mode)
                    .map_err(|error| tool_schema_error(error, client_name))?,
            }));
        }
    }
    Ok(declarations)
}

#[cfg(test)]
fn build_tool_config(req: &Value) -> Result<Option<Value>, AdapterError> {
    let tool_names = tool_name_mapping(req)?;
    build_tool_config_with_names(req, &tool_names)
}

fn build_tool_config_with_names(
    req: &Value,
    tool_names: &ToolNameMap,
) -> Result<Option<Value>, AdapterError> {
    let mode = req
        .pointer("/tool_choice/mode")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    let config = match mode {
        "auto" => json!({ "mode": "VALIDATED" }),
        "none" => json!({ "mode": "NONE" }),
        "required" => json!({ "mode": "ANY" }),
        "specific" => {
            let name = req
                .pointer("/tool_choice/name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| bad("specific tool choice requires a tool name"))?;
            let wire_name = tool_names
                .to_wire(name)
                .map_err(|error| bad(error.to_string()))?;
            json!({
                "mode": "ANY",
                "allowedFunctionNames": [wire_name]
            })
        }
        other => return Err(bad(format!("unsupported canonical tool choice '{other}'"))),
    };
    Ok(Some(json!({ "functionCallingConfig": config })))
}

fn project_id(provider: &Value, req: &Value) -> Result<String, AdapterError> {
    // Explicit operator override wins. Otherwise use the account-scoped
    // project resolved by the credential strategy. A client hint remains a
    // compatibility fallback for manually imported credentials.
    if let Some(project) = provider
        .get("extra_headers")
        .and_then(|e| e.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get("x-antigravity-project")
                .and_then(|p| p.as_str())
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
        })
    {
        return Ok(project);
    }
    if let Some(project) = provider
        .pointer("/_kinetix/project_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|project| !project.is_empty())
    {
        return Ok(project.to_string());
    }
    if let Some(project) = req
        .get("extra")
        .and_then(|e| e.get("antigravity_project"))
        .and_then(|p| p.as_str())
        .map(str::trim)
        .filter(|project| !project.is_empty())
    {
        return Ok(project.to_string());
    }
    Err(err(
        "invalid_configuration",
        "Antigravity account has no provisioned Google Cloud project ID; reconnect the account or configure x-antigravity-project",
    ))
}

fn session_id(req: &Value, provider: &Value, session_context: Option<&str>) -> Option<String> {
    let identity = session_context
        .filter(|session_id| !session_id.is_empty())
        .or_else(|| {
            req.get("extra")
                .and_then(|e| e.get("session_id").or_else(|| e.get("sessionId")))
                .and_then(Value::as_str)
                .filter(|session_id| !session_id.is_empty())
        })?;
    let provider_id = provider
        .get("id")
        .and_then(Value::as_str)
        .filter(|provider_id| !provider_id.is_empty())
        .unwrap_or("antigravity");
    let account_id = provider
        .pointer("/_kinetix/account_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    Some(uuid_from_seed(&format!(
        "kinetix:provider-session:v1:{}:{provider_id}:{}:{account_id}:{}:{identity}",
        provider_id.len(),
        account_id.len(),
        identity.len()
    )))
}

/// `agent/<conversationId>/<ts>/<trajectoryId>/<step>` (9router's IDE shape).
fn build_request_id(session_id: Option<&str>, model: &str, ts: u64) -> String {
    let request_seed = match session_id {
        Some(session_id) => format!("antigravity:conversation:{session_id}"),
        None => format!("antigravity:request:{ts}"),
    };
    let conversation = uuid_from_seed(&request_seed);
    let trajectory = uuid_from_seed(&format!("antigravity:trajectory:{request_seed}:{model}"));
    format!("agent/{conversation}/{ts}/{trajectory}/1")
}

fn tool_schema_error(error: schema::SchemaError, name: &str) -> AdapterError {
    bad(format!(
        "Antigravity tool schema at tool '{name}'{}: {}",
        error.path.strip_prefix('$').unwrap_or(&error.path),
        error.message
    ))
}

#[cfg(test)]
fn sanitize_schema(schema: &Value, root_path: &str) -> Result<Value, AdapterError> {
    sanitize_schema_with_policy(schema, root_path, SchemaPolicy::Strict)
}

#[cfg(test)]
fn sanitize_schema_with_policy(
    schema: &Value,
    root_path: &str,
    policy: SchemaPolicy,
) -> Result<Value, AdapterError> {
    let mode = match policy {
        SchemaPolicy::Strict => SchemaMode::Strict,
        SchemaPolicy::Permissive => SchemaMode::Compatible,
    };
    schema::translate(schema, SchemaProfile::Antigravity, mode).map_err(|error| {
        bad(format!(
            "Antigravity tool schema at {root_path}{}: {}",
            error.path.strip_prefix('$').unwrap_or(&error.path),
            error.message
        ))
    })
}

/// Convert one internal part to zero or more Gemini parts.
fn part_to_gemini(
    p: &Value,
    tool_names: &ToolNameMap,
    tool_call_names: &HashMap<String, String>,
) -> Result<Vec<Value>, AdapterError> {
    let Some(kind) = p.get("type").and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    let part = match kind {
        "text" => json!({ "text": p.get("text").and_then(Value::as_str).unwrap_or("") }),
        "thinking" => {
            let mut part = json!({
                "thought": true,
                "text": p.get("text").and_then(Value::as_str).unwrap_or("")
            });
            if let Some(signature) = p.get("signature").and_then(Value::as_str) {
                part["thoughtSignature"] = json!(signature);
            }
            part
        }
        "image" | "document" => media_part(p, kind)?,
        "image_url" | "document_url" => media_part(p, kind)?,
        "tool_call" => {
            let client_name = p
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| bad("historical tool call requires a non-empty name"))?;
            let name = tool_names
                .to_wire(client_name)
                .map_err(|error| bad(error.to_string()))?;
            let args = parse_tool_arguments(p.get("arguments"))?;
            let mut function_call = json!({ "name": name, "args": args });
            if let Some(id) = p.get("id").and_then(Value::as_str) {
                function_call["id"] = json!(id);
            }
            let mut part = json!({ "functionCall": function_call });
            if let Some(signature) = p.get("signature").and_then(Value::as_str) {
                part["thoughtSignature"] = json!(signature);
            }
            part
        }
        "tool_result" => {
            let id = p.get("tool_call_id").and_then(Value::as_str).unwrap_or("");
            let client_name = p
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or_else(|| tool_call_names.get(id).map(String::as_str))
                .ok_or_else(|| bad("tool result requires a name matching its tool call"))?;
            let name = tool_names
                .to_wire(client_name)
                .map_err(|error| bad(error.to_string()))?;
            tool_result_part(p, name, id)?
        }
        _ => return Ok(Vec::new()),
    };
    Ok(match part {
        Value::Array(parts) => parts,
        part => vec![part],
    })
}

fn parse_tool_arguments(value: Option<&Value>) -> Result<Value, AdapterError> {
    let Some(value) = value else {
        return Ok(json!({}));
    };
    let arguments = match value {
        Value::String(text) => serde_json::from_str(text)
            .map_err(|error| bad(format!("invalid historical tool-call JSON: {error}")))?,
        Value::Object(_) => value.clone(),
        _ => {
            return Err(bad(
                "historical tool-call arguments must be an object or JSON object string",
            ))
        }
    };
    if arguments.is_object() {
        Ok(arguments)
    } else {
        Err(bad("historical tool-call arguments must be a JSON object"))
    }
}

fn media_part(part: &Value, kind: &str) -> Result<Value, AdapterError> {
    let file_kind = kind.ends_with("_url");
    let uri = part
        .get("url")
        .or_else(|| part.get("uri"))
        .and_then(Value::as_str)
        .filter(|uri| !uri.is_empty());
    if file_kind || uri.is_some() {
        let uri = uri.ok_or_else(|| unsupported_media(kind, "missing a file URI"))?;
        let mut file_data = json!({ "fileUri": uri });
        if let Some(mime) = part.get("mime").and_then(Value::as_str) {
            file_data["mimeType"] = json!(mime);
        }
        return Ok(json!({ "fileData": file_data }));
    }
    let mime = part
        .get("mime")
        .and_then(Value::as_str)
        .filter(|mime| !mime.is_empty())
        .ok_or_else(|| unsupported_media(kind, "missing a MIME type"))?;
    let data = part
        .get("data")
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())
        .ok_or_else(|| unsupported_media(kind, "missing inline data"))?;
    Ok(json!({ "inlineData": { "mimeType": mime, "data": data } }))
}

fn unsupported_media(kind: &str, reason: &str) -> AdapterError {
    err(
        "unsupported_media",
        format!("Antigravity cannot translate {kind} tool-result media: {reason}"),
    )
}

fn valid_mime_type(value: &str) -> bool {
    let Some((media_type, subtype)) = value.split_once('/') else {
        return false;
    };
    let is_token = |token: &str| {
        !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    };
    !subtype.contains('/') && is_token(media_type) && is_token(subtype)
}

fn tool_result_media_part(part: &Value, kind: &str) -> Result<Value, AdapterError> {
    let source = part.get("source").unwrap_or(&Value::Null);
    let source_type = source.get("type").and_then(Value::as_str);
    if kind.ends_with("_url")
        || part.get("url").is_some()
        || part.get("uri").is_some()
        || source_type == Some("url")
        || source.get("url").is_some()
    {
        return Err(unsupported_media(
            kind,
            "URI media is not supported in Gemini function responses",
        ));
    }

    if source.is_object() && source_type != Some("base64") {
        return Err(unsupported_media(
            kind,
            "only base64-backed sources are supported in Gemini function responses",
        ));
    }

    let mime = part
        .get("mime")
        .or_else(|| source.get("media_type"))
        .and_then(Value::as_str)
        .filter(|mime| valid_mime_type(mime))
        .ok_or_else(|| unsupported_media(kind, "missing or invalid MIME type"))?;
    let data = part
        .get("data")
        .or_else(|| source.get("data"))
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())
        .ok_or_else(|| unsupported_media(kind, "missing inline data"))?;
    Ok(json!({ "inlineData": { "mimeType": mime, "data": data } }))
}

fn is_tool_result_content_part(part: &Value) -> bool {
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
    let source = object.get("source").and_then(Value::as_object);
    let source_has_string = |keys: &[&str]| {
        source.is_some_and(|source| {
            keys.iter()
                .any(|key| source.get(*key).is_some_and(Value::is_string))
        })
    };

    match kind {
        "text" => object.get("text").is_some_and(Value::is_string),
        "json" | "structured" | "structured_json" => has_any(&["json", "value", "data"]),
        "image" | "document" | "audio" | "video" => {
            has_string(&["data", "url", "uri"]) || source_has_string(&["data", "url", "uri"])
        }
        "image_url" | "document_url" | "audio_url" | "video_url" => {
            has_string(&["url", "uri"]) || source_has_string(&["url", "uri"])
        }
        _ => false,
    }
}

fn is_tool_result_content_parts(parts: &[Value]) -> bool {
    !parts.is_empty() && parts.iter().all(is_tool_result_content_part)
}

fn tool_result_part(p: &Value, name: &str, id: &str) -> Result<Value, AdapterError> {
    let mut media = Vec::new();
    let mut text = Vec::new();
    let mut structured = p
        .get("structured_content")
        .or_else(|| p.get("structuredContent"))
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(content) = p.get("content") {
        match content {
            Value::String(value) => text.push(value.clone()),
            Value::Object(_) => structured.push(content.clone()),
            Value::Array(parts) if is_tool_result_content_parts(parts) => {
                for part in parts {
                    match part.get("type").and_then(Value::as_str).unwrap_or("") {
                        "text" => {
                            if let Some(value) = part.get("text").and_then(Value::as_str) {
                                text.push(value.to_owned());
                            }
                        }
                        "json" | "structured" | "structured_json" => {
                            structured.push(
                                part.get("json")
                                    .or_else(|| part.get("value"))
                                    .or_else(|| part.get("data"))
                                    .cloned()
                                    .ok_or_else(|| {
                                        bad("structured tool-result part has no JSON value")
                                    })?,
                            );
                        }
                        kind @ ("image" | "image_url" | "document" | "document_url") => {
                            media.push(tool_result_media_part(part, kind)?);
                        }
                        _ => return Err(unsupported_media("unknown", "unrecognized content part")),
                    }
                }
            }
            Value::Array(_) => structured.push(content.clone()),
            Value::Null => structured.push(Value::Null),
            _ => structured.push(content.clone()),
        }
    }
    let structured = match structured.len() {
        0 => None,
        1 => structured.pop(),
        _ => Some(json!({"structured_parts": structured})),
    };
    let has_structured = structured.is_some();
    let is_error = p.get("is_error").and_then(Value::as_bool) == Some(true);
    let response = if is_error {
        match structured {
            Some(structured) if !text.is_empty() => {
                json!({ "error": structured, "text": text.join("") })
            }
            Some(structured) => json!({ "error": structured }),
            None => json!({ "error": text.join("") }),
        }
    } else {
        let mut object = match structured {
            Some(Value::Object(object)) => object,
            Some(value) => {
                let mut object = Map::new();
                object.insert("result".into(), value);
                object
            }
            None => Map::new(),
        };
        if !text.is_empty() {
            let key = if !object.contains_key("result") {
                "result".to_owned()
            } else if !object.contains_key("text") {
                "text".to_owned()
            } else {
                let mut index = 1;
                while object.contains_key(&format!("_kinetix_text_{index}")) {
                    index += 1;
                }
                format!("_kinetix_text_{index}")
            };
            object.insert(key, json!(text.join("")));
        }
        if object.is_empty() && !has_structured {
            object.insert("result".into(), json!(""));
        }
        Value::Object(object)
    };
    let mut function_response = json!({ "name": name, "response": response });
    if !id.is_empty() {
        function_response["id"] = json!(id);
    }
    if !media.is_empty() {
        function_response["parts"] = Value::Array(media);
    }
    Ok(json!({ "functionResponse": function_response }))
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

pub fn classify_error(status: u16, body: &str, headers_json: &str) -> Result<String, AdapterError> {
    let headers: Value = serde_json::from_str(headers_json).unwrap_or(Value::Null);
    let retry_after = parse_retry_after(&headers, body);
    let mut message =
        extract_error_message(body).unwrap_or_else(|| format!("upstream HTTP {status}"));

    let kind = if status == 429 {
        "quota_exhausted"
    } else if status == 401 || status == 403 {
        "auth_error"
    } else if (300..=399).contains(&status) {
        "unexpected_redirect"
    } else if status >= 500 {
        // Any 5xx is a server error; transient ones (high traffic, capacity,
        // stream ended) are annotated so the host's trace explains a retry.
        if is_transient(&message) {
            message = format!("transient upstream error: {message}");
        }
        "server_error"
    } else if status >= 400 {
        "bad_request"
    } else {
        "server_error"
    };

    let location = get_header(&headers, "location").map(str::to_string);
    if (300..=399).contains(&status) {
        if let Some(ref loc) = location {
            if message == format!("upstream HTTP {status}") {
                message = format!("unexpected upstream redirect ({status}) to {loc}");
            } else {
                message = format!("unexpected upstream redirect ({status}) to {loc}: {message}");
            }
        } else if message == format!("upstream HTTP {status}") {
            message = format!("unexpected upstream redirect ({status})");
        }
    }

    let mut evidence = json!({
        "kind": kind,
        "status": status,
        "retry_after_secs": retry_after,
        "message": message,
        "quota_reset_at": Value::Null,
    });
    if let Some(ref loc) = location {
        evidence["location"] = json!(loc);
    } else if (300..=399).contains(&status) {
        evidence["location"] = Value::Null;
    }
    Ok(evidence.to_string())
}

fn get_header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    if let Some(obj) = headers.as_object() {
        for (k, v) in obj {
            if k.eq_ignore_ascii_case(name) {
                return v.as_str();
            }
        }
    } else if let Some(arr) = headers.as_array() {
        for item in arr {
            if let Some(pair) = item.as_array() {
                if pair.len() == 2 {
                    if let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                        if k.eq_ignore_ascii_case(name) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Retry-after seconds from headers or a "reset after 2h7m23s" message.
fn parse_retry_after(headers: &Value, body: &str) -> Option<u64> {
    if let Some(v) = get_header(headers, "retry-after") {
        if let Ok(secs) = v.trim().parse::<u64>() {
            return Some(secs);
        }
    }
    if let Some(v) = get_header(headers, "x-ratelimit-reset-after") {
        if let Ok(secs) = v.trim().parse::<u64>() {
            return Some(secs);
        }
    }
    parse_reset_from_message(body)
}

fn parse_reset_from_message(body: &str) -> Option<u64> {
    let lower = body.to_ascii_lowercase();
    let idx = lower.find("reset after")?;
    let rest = &lower[idx + "reset after".len()..];
    let mut total: u64 = 0;
    let mut num = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else if c == 'h' || c == 'm' || c == 's' {
            let n: u64 = num.parse().unwrap_or(0);
            total += match c {
                'h' => n * 3600,
                'm' => n * 60,
                _ => n,
            };
            num.clear();
            if c == 's' {
                break;
            }
        } else if !num.is_empty() {
            break;
        }
    }
    if total > 0 {
        Some(total)
    } else {
        None
    }
}

fn extract_error_message(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.pointer("/error/message")
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .or_else(|| v.get("error").and_then(|m| m.as_str()))
        .map(str::to_string)
}

fn is_transient(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    TRANSIENT_PATTERNS.iter().any(|p| m.contains(p))
}

// ---------------------------------------------------------------------------
// Stream parsing → canonical events
// ---------------------------------------------------------------------------

fn response_envelope(events: Vec<Value>) -> Value {
    json!({
        "schema": "kinetix.plugin.response",
        "schema_version": 1,
        "events": events,
    })
}

pub fn parse_stream_chunk(data: &str) -> Result<String, AdapterError> {
    let v: Value = serde_json::from_str(data).map_err(|e| bad(format!("bad sse json: {e}")))?;
    // Antigravity wraps everything in a `response` object.
    let resp = v.get("response").unwrap_or(&v);
    let mut events: Vec<Value> = Vec::new();

    if let Some(id) = resp.get("responseId").and_then(|r| r.as_str()) {
        events.push(json!({ "type": "start", "upstream_request_id": id }));
    }

    let mut tool_index: u32 = 0;
    if let Some(candidates) = resp.get("candidates").and_then(|c| c.as_array()) {
        for c in candidates {
            let mut candidate_has_tool_calls = false;
            if let Some(parts) = c.pointer("/content/parts").and_then(|p| p.as_array()) {
                for p in parts {
                    let text = p.get("text").and_then(|t| t.as_str());
                    let signature = p.get("thoughtSignature").and_then(|s| s.as_str());
                    let function_call = p.get("functionCall");
                    let is_thought = p.get("thought").and_then(|t| t.as_bool()).unwrap_or(false);

                    if is_thought {
                        if let Some(text) = text {
                            if !text.is_empty() {
                                events.push(json!({
                                    "type": "thinking_delta",
                                    "text": text,
                                    "signature": Value::Null,
                                }));
                            }
                        }
                    } else if function_call.is_none() {
                        if let Some(text) = text {
                            if !text.is_empty() {
                                events.push(json!({ "type": "text_delta", "text": text }));
                            }
                        }
                    }

                    if let Some(fc) = function_call {
                        candidate_has_tool_calls = true;
                        let wire_name = fc.get("name").and_then(Value::as_str).unwrap_or("");
                        let name = ToolNameMap::from_wire(wire_name)
                            .map_err(|error| bad(error.to_string()))?;
                        let args = parse_tool_arguments(fc.get("args"))?;
                        events.push(json!({
                            "type": "tool_call_start",
                            "index": tool_index,
                            "id": fc.get("id").and_then(Value::as_str),
                            "name": name,
                            "signature": signature,
                        }));
                        events.push(json!({
                            "type": "tool_call_args_delta",
                            "index": tool_index,
                            "args": args.to_string(),
                        }));
                        tool_index += 1;
                    } else if signature.is_some() {
                        // Any part-level continuation signature that is not
                        // directly attached to a functionCall is normalized
                        // into the host's pending-signature contract *after*
                        // emitting the part's visible/thinking content.
                        events.push(json!({
                            "type": "thinking_delta",
                            "text": "",
                            "signature": signature,
                        }));
                    }
                }
            }
            if let Some(reason) = c.get("finishReason").and_then(|r| r.as_str()) {
                events.push(json!({
                    "type": "finish",
                    "reason": map_finish(reason, candidate_has_tool_calls)
                }));
            }
        }
    }

    if let Some(meta) = resp.get("usageMetadata") {
        events.push(json!({
            "type": "usage",
            "input": meta.get("promptTokenCount").and_then(|v| v.as_u64()),
            "output": meta.get("candidatesTokenCount").and_then(|v| v.as_u64()),
            "cached": meta.get("cachedContentTokenCount").and_then(|v| v.as_u64()),
            "thinking": meta.get("thoughtsTokenCount").and_then(|v| v.as_u64()),
        }));
    }

    Ok(response_envelope(events).to_string())
}

pub fn parse_full_response(body_json: &str) -> Result<String, AdapterError> {
    let v: Value = serde_json::from_str(body_json)
        .map_err(|error| bad(format!("bad full response json: {error}")))?;
    let resp = v.get("response").unwrap_or(&v);
    // Reuse the streaming parser on a synthesized single chunk.
    parse_stream_chunk(&resp.to_string())
}

fn map_finish(reason: &str, has_tool_calls: bool) -> &'static str {
    match reason.to_ascii_uppercase().as_str() {
        "STOP" | "STOP_SEQUENCE" if has_tool_calls => "tool_calls",
        "STOP" | "STOP_SEQUENCE" => "stop",
        "MAX_TOKENS" | "LENGTH" => "length",
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "CONTENT_FILTER" => {
            "content_filter"
        }
        "TOOL_CALLS" | "FUNCTION_CALL" => "tool_calls",
        _ => "stop",
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Deterministic RFC-4122-shaped UUID seeded by SHA-256 (no rng in the guest).
fn uuid_from_seed(seed: &str) -> String {
    let digest = sha256(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Minimal SHA-256 (the guest has no crypto crate; this is not secret material).
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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
            let body = super::build_body_at(
                &request.to_string(),
                &provider.to_string(),
                &model.to_string(),
                None,
                1_700_000_000_000,
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

    #[test]
    fn build_url_uses_daily_endpoint_as_default_and_from_provider() {
        // Fallback when empty or no base_url
        let empty_url = build_url("{}", "{}").unwrap();
        assert_eq!(
            empty_url,
            "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );

        // Integration provider setting
        let provider = json!({
            "base_url": "https://daily-cloudcode-pa.googleapis.com"
        });
        let url = build_url(&provider.to_string(), "{}").unwrap();
        assert_eq!(
            url,
            "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );

        // Handles trailing slashes cleanly
        let provider_slash = json!({
            "base_url": "https://daily-cloudcode-pa.googleapis.com/"
        });
        let url_slash = build_url(&provider_slash.to_string(), "{}").unwrap();
        assert_eq!(
            url_slash,
            "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn project_id_prefers_account_project_over_client_hint() {
        let provider = json!({
            "_kinetix": {
                "account_id": "account-1",
                "project_id": "provisioned-project"
            }
        });
        let req = json!({
            "extra": { "antigravity_project": "client-project" }
        });
        assert_eq!(project_id(&provider, &req).unwrap(), "provisioned-project");
    }

    #[test]
    fn project_id_operator_override_wins() {
        let provider = json!({
            "extra_headers": r#"{"x-antigravity-project":"operator-project"}"#,
            "_kinetix": { "project_id": "provisioned-project" }
        });
        assert_eq!(
            project_id(&provider, &json!({})).unwrap(),
            "operator-project"
        );
    }

    #[test]
    fn build_body_uses_core_owned_project_and_time_context() {
        let provider = json!({
            "id": "antigravity",
            "_kinetix": {
                "project_id": "core-project",
                "now_unix_millis": 1_700_000_000_123_u64
            }
        });
        let body = super::build_body(
            r#"{"schema":"kinetix.plugin.request","schema_version":1,"messages":[]}"#,
            &provider.to_string(),
            r#"{"upstream_id":"gemini-3-flash"}"#,
            None,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["project"], "core-project");
        assert!(body["requestId"]
            .as_str()
            .unwrap()
            .contains("/1700000000123/"));
    }

    #[test]
    fn build_body_requires_core_owned_time_context() {
        let error = super::build_body(
            r#"{"messages":[]}"#,
            r#"{"_kinetix":{"project_id":"core-project"}}"#,
            "{}",
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_configuration");
        assert!(error.message.contains("_kinetix.now_unix_millis"));
    }

    #[test]
    fn project_id_fails_without_real_identity() {
        let error = project_id(&json!({}), &json!({})).unwrap_err();
        assert_eq!(error.code, "invalid_configuration");
        assert!(error
            .message
            .contains("no provisioned Google Cloud project ID"));
    }

    #[test]
    fn permissive_extra_fields_are_dropped_not_forwarded() {
        let provider = json!({
            "id": "antigravity",
            "capability_mode": "permissive",
            "_kinetix": { "account_id": "account-1" }
        });
        let req = json!({
            "schema": "kinetix.plugin.request",
            "schema_version": 1,
            "extra": {
                "session_id": "sess-1",
                "antigravity_project": "project-1",
                "service_tier": "auto",
                "parallel_tool_calls": true,
                "claude_code_session": "cc-1"
            }
        });

        assert!(validate_canonical_extras(&provider, &req).is_ok());
        let native_session_id = session_id(&req, &provider, None).unwrap();
        let host_session_id = session_id(&req, &provider, Some("host-session")).unwrap();
        assert_ne!(native_session_id, host_session_id);
        assert_eq!(
            host_session_id,
            session_id(&json!({}), &provider, Some("host-session")).unwrap()
        );
        assert_eq!(project_id(&provider, &req).unwrap(), "project-1");
    }

    #[test]
    fn provider_session_ids_are_account_scoped_and_do_not_expose_identity() {
        let req = json!({});
        let provider_a = json!({ "id": "antigravity", "_kinetix": { "account_id": "account-a" } });
        let provider_b = json!({ "id": "antigravity", "_kinetix": { "account_id": "account-b" } });
        let session_a = session_id(&req, &provider_a, Some("opaque-session")).unwrap();
        let session_b = session_id(&req, &provider_b, Some("opaque-session")).unwrap();

        assert_ne!(session_a, session_b);
        assert!(!session_a.contains("account-a"));
        assert!(!session_a.contains("opaque-session"));
    }

    #[test]
    fn session_is_not_fabricated_when_unavailable() {
        assert_eq!(session_id(&json!({}), &json!({}), None), None);
    }

    #[test]
    fn strict_extra_fields_are_rejected() {
        let provider = json!({ "capability_mode": "strict" });
        let req = json!({
            "extra": {
                "session_id": "sess-1",
                "service_tier": "auto"
            }
        });
        let error = validate_canonical_extras(&provider, &req).unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(error.message.contains("service_tier"));
    }

    #[test]
    fn canonical_tool_choice_maps_to_antigravity_modes() {
        let auto = json!({ "tool_choice": { "mode": "auto", "name": null } });
        assert_eq!(
            build_tool_config(&auto).unwrap().unwrap(),
            json!({ "functionCallingConfig": { "mode": "VALIDATED" } })
        );

        let required = json!({ "tool_choice": { "mode": "required", "name": null } });
        assert_eq!(
            build_tool_config(&required).unwrap().unwrap(),
            json!({ "functionCallingConfig": { "mode": "ANY" } })
        );

        let none = json!({ "tool_choice": { "mode": "none", "name": null } });
        assert_eq!(
            build_tool_config(&none).unwrap().unwrap(),
            json!({ "functionCallingConfig": { "mode": "NONE" } })
        );

        let specific = json!({
            "tool_choice": { "mode": "specific", "name": "read file!" }
        });
        assert_eq!(
            build_tool_config(&specific).unwrap().unwrap(),
            json!({
                "functionCallingConfig": {
                    "mode": "ANY",
                    "allowedFunctionNames": ["_ktx_726561642066696c6521"]
                }
            })
        );
    }

    #[test]
    fn canonical_thinking_maps_to_gemini_native_config() {
        let mut gemini3 = Map::new();
        apply_thinking(
            &mut gemini3,
            &json!({ "thinking": { "level": "high" } }),
            "gemini-3.7-flash-tiered",
        )
        .unwrap();
        assert_eq!(
            gemini3["thinkingConfig"],
            json!({ "thinkingLevel": "high", "includeThoughts": true })
        );
        assert_eq!(gemini3["maxOutputTokens"], MAX_OUTPUT_TOKENS);

        let mut gemini25 = Map::new();
        apply_thinking(
            &mut gemini25,
            &json!({ "thinking": { "level": "medium" } }),
            "gemini-2.5-pro",
        )
        .unwrap();
        assert_eq!(
            gemini25["thinkingConfig"],
            json!({ "thinkingBudget": 8192, "includeThoughts": true })
        );
        assert_eq!(gemini25["maxOutputTokens"], 16384);

        let mut off = Map::new();
        apply_thinking(
            &mut off,
            &json!({ "thinking": { "level": "off" } }),
            "gemini-3.8-flash",
        )
        .unwrap();
        assert_eq!(
            off["thinkingConfig"],
            json!({ "thinkingLevel": "minimal", "includeThoughts": false })
        );

        let mut unsupported = Map::new();
        assert!(apply_thinking(
            &mut unsupported,
            &json!({ "thinking": { "level": "high" } }),
            "claude-sonnet-4-5",
        )
        .is_err());
    }

    #[test]
    fn antigravity_claude_thinking_uses_budget_and_preserves_output_reserve() {
        let mut low = Map::new();
        apply_thinking(
            &mut low,
            &json!({ "thinking": { "level": "low" } }),
            "provider/claude-opus-4-6-thinking@latest",
        )
        .unwrap();
        assert_eq!(
            low["thinkingConfig"],
            json!({ "thinkingBudget": 8192, "includeThoughts": true })
        );
        assert_eq!(low["maxOutputTokens"], 16384);

        let mut max = Map::new();
        apply_thinking(
            &mut max,
            &json!({ "thinking": { "level": "max" } }),
            "claude-opus-4-6-thinking",
        )
        .unwrap();
        assert_eq!(
            max["thinkingConfig"],
            json!({ "thinkingBudget": 32768, "includeThoughts": true })
        );
        assert_eq!(max["maxOutputTokens"], 40960);

        let mut preserved = Map::new();
        preserved.insert("maxOutputTokens".into(), json!(50000));
        apply_thinking(
            &mut preserved,
            &json!({ "thinking": { "level": "max" } }),
            "claude-opus-4-6-thinking",
        )
        .unwrap();
        assert_eq!(preserved["maxOutputTokens"], 50000);

        for level in ["off", "medium", "high"] {
            let mut unsupported = Map::new();
            let error = apply_thinking(
                &mut unsupported,
                &json!({ "thinking": { "level": level } }),
                "claude-opus-4-6-thinking",
            )
            .unwrap_err();
            assert_eq!(error.code, "bad_request");
            assert!(error.message.contains(level));
            assert!(!unsupported.contains_key("thinkingConfig"));
        }

        let mut non_thinking = Map::new();
        let error = apply_thinking(
            &mut non_thinking,
            &json!({ "thinking": { "level": "low" } }),
            "claude-opus-4-6",
        )
        .unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(!non_thinking.contains_key("thinkingConfig"));
    }

    #[test]
    fn shared_schema_policy_default_and_aliases() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../sdk/tests/fixtures/schema-compat/corpus.json"
        ))
        .unwrap();
        let case = &corpus["cases"][0];
        let request = json!({"tools": [{"name": case["name"], "parameters": case["schema"]}]});
        for provider in [
            json!({}),
            json!({"capability_mode": "compatible"}),
            json!({"capability_mode": "permissive"}),
        ] {
            let declarations = build_tool_declarations(&request, &provider).unwrap();
            assert_eq!(declarations[0]["parametersJsonSchema"], case["expected"]);
        }
        let error =
            build_tool_declarations(&request, &json!({"capability_mode": "strict"})).unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(error.message.contains("tool 'jev_evaluate'"));
        for value in [json!("mystery"), json!(7)] {
            let error =
                build_tool_declarations(&request, &json!({"capability_mode": value})).unwrap_err();
            assert_eq!(error.code, "invalid_configuration");
        }
    }

    #[test]
    fn tool_schema_preserves_existing_normalization() {
        let schema = json!({
            "$ref": "#/definitions/Envelope",
            "definitions": {
                "Envelope": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "payload": { "$ref": "#/definitions/Payload" }
                    },
                    "required": ["payload"]
                },
                "Payload": {
                    "type": "object",
                    "properties": {
                        "kind": { "const": "ok" },
                        "value": { "type": ["string", "null"] },
                        "choice": {
                            "oneOf": [
                                { "type": "string" },
                                { "type": "number" }
                            ]
                        },
                        "list": {
                            "type": "array",
                            "items": { "type": "integer" }
                        }
                    }
                }
            }
        });
        let got = sanitize_schema(&schema, "tool 'fixture'").unwrap();

        assert!(got.get("$ref").is_none());
        assert!(got.get("$defs").is_none());
        assert_eq!(got.pointer("/additionalProperties"), Some(&json!(false)));
        assert_eq!(
            got.pointer("/properties/payload/properties/kind/enum"),
            Some(&json!(["ok"]))
        );
        assert_eq!(
            got.pointer("/properties/payload/properties/choice/anyOf/1/type"),
            Some(&json!("number"))
        );
        assert_eq!(
            got.pointer("/properties/payload/properties/list/items/type"),
            Some(&json!("integer"))
        );
    }

    #[test]
    fn permissive_tool_schema_preserves_pi_subagent_workflow_pattern() {
        let provider = json!({ "capability_mode": "permissive" });
        let request = json!({
            "tools": [{
                "name": "SubagentWorkflow",
                "description": "Run a deterministic workflow",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "script": { "type": "string" },
                        "scriptPath": { "type": "string" },
                        "name": { "type": "string" },
                        "resumeFromRunId": {
                            "type": "string",
                            "pattern": "^wf_[a-z0-9-]{6,}$",
                            "description": "Replay an earlier workflow run"
                        }
                    }
                }
            }]
        });

        let declarations = build_tool_declarations(&request, &provider).unwrap();
        let schema = declarations[0].get("parametersJsonSchema").unwrap();
        assert_eq!(
            schema.pointer("/properties/resumeFromRunId/pattern"),
            Some(&json!("^wf_[a-z0-9-]{6,}$"))
        );
    }

    #[test]
    fn strict_tool_schema_preserves_supported_pattern() {
        let provider = json!({ "capability_mode": "strict" });
        let request = json!({
            "tools": [{
                "name": "fixture",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "pattern": "^[a-z]+$"
                        }
                    }
                }
            }]
        });

        let declarations = build_tool_declarations(&request, &provider).unwrap();
        let schema = declarations[0].get("parametersJsonSchema").unwrap();
        assert_eq!(
            schema.pointer("/properties/value/pattern"),
            Some(&json!("^[a-z]+$"))
        );
    }

    #[test]
    fn tool_schema_preserves_pattern_recursively() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^id_[0-9]+$"
                    }
                }
            }
        });

        let got = sanitize_schema(&schema, "tool 'fixture'").unwrap();
        assert_eq!(
            got.pointer("/items/properties/id/pattern"),
            Some(&json!("^id_[0-9]+$"))
        );
    }

    #[test]
    fn tool_schema_rejects_non_string_pattern_with_path() {
        let schema = json!({
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "pattern": 42
                }
            }
        });

        let error = sanitize_schema(&schema, "tool 'fixture'").unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(error
            .message
            .contains("tool 'fixture'.properties.value.pattern"));
        assert!(error.message.contains("must be a string"));
    }

    #[test]
    fn permissive_open_tuple_keywords_do_not_narrow_tail() {
        let schema = json!({
            "type": "object",
            "properties": {
                "legacy_tuple": {
                    "type": "array",
                    "items": [
                        { "type": "string" },
                        { "type": "integer" }
                    ]
                },
                "explicit_tuple": {
                    "type": "array",
                    "prefixItems": [
                        { "type": "string" },
                        { "type": "integer" }
                    ]
                }
            }
        });

        let got = sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
            .unwrap();

        assert_eq!(
            got.pointer("/properties/legacy_tuple/items"),
            Some(&json!({}))
        );
        assert_eq!(
            got.pointer("/properties/explicit_tuple/items"),
            Some(&json!({}))
        );
        assert!(got
            .pointer("/properties/explicit_tuple/prefixItems")
            .is_none());
    }

    #[test]
    fn permissive_open_prefix_items_with_true_tail_stays_unrestricted() {
        let schema = json!({
            "type": "array",
            "prefixItems": [{
                "type": "string",
                "pattern": "^wf_"
            }],
            "items": true
        });

        let got = sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
            .unwrap();

        assert_eq!(got.pointer("/items"), Some(&json!({})));
        assert!(got.pointer("/prefixItems").is_none());
    }

    #[test]
    fn permissive_prefix_items_combines_trailing_items_schema() {
        let schema = json!({
            "type": "array",
            "prefixItems": [
                { "type": "string" },
                { "type": "integer" }
            ],
            "items": {
                "type": "boolean"
            }
        });

        let got = sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
            .unwrap();

        assert_eq!(got.pointer("/items/anyOf/0/type"), Some(&json!("string")));
        assert_eq!(got.pointer("/items/anyOf/1/type"), Some(&json!("integer")));
        assert_eq!(got.pointer("/items/anyOf/2/type"), Some(&json!("boolean")));
        assert!(got.pointer("/prefixItems").is_none());
    }

    #[test]
    fn permissive_closed_prefix_tuple_handles_items_false() {
        let schema = json!({
            "type": "array",
            "prefixItems": [
                { "type": "string" },
                { "type": "integer" }
            ],
            "items": false,
            "maxItems": 99
        });

        let got = sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
            .unwrap();

        assert_eq!(got.pointer("/items/anyOf/0/type"), Some(&json!("string")));
        assert_eq!(got.pointer("/items/anyOf/1/type"), Some(&json!("integer")));
        assert_eq!(
            got.pointer("/items/anyOf")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert!(got.pointer("/maxItems").is_none());
        assert!(got.pointer("/prefixItems").is_none());
    }

    #[test]
    fn strict_tool_schema_rejects_tuple_keywords_with_path() {
        for (keyword, value) in [
            (
                "items",
                json!([{ "type": "string" }, { "type": "integer" }]),
            ),
            (
                "prefixItems",
                json!([{ "type": "string" }, { "type": "integer" }]),
            ),
        ] {
            let mut array_schema = json!({ "type": "array" });
            array_schema
                .as_object_mut()
                .unwrap()
                .insert(keyword.to_string(), value);
            let schema = json!({
                "type": "object",
                "properties": {
                    "tuple": array_schema
                }
            });

            let error = sanitize_schema(&schema, "tool 'fixture'").unwrap_err();
            assert_eq!(error.code, "bad_request");
            assert!(error
                .message
                .contains(&format!("tool 'fixture'.properties.tuple.{keyword}")));
        }
    }

    #[test]
    fn permissive_tool_schema_drops_max_length_recursively() {
        let provider = json!({ "capability_mode": "permissive" });
        let request = json!({
            "tools": [{
                "name": "chrome_devtools_load",
                "description": "Load Chrome DevTools data",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Query to execute",
                            "maxLength": 2000
                        },
                        "nested": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "value": {
                                        "type": "string",
                                        "maxLength": 128
                                    }
                                },
                                "required": ["value"]
                            }
                        }
                    },
                    "required": ["query"]
                }
            }]
        });

        let out = Value::Array(build_tool_declarations(&request, &provider).unwrap()).to_string();
        assert!(!out.contains("maxLength"));
        assert!(out.contains("Query to execute"));
        assert!(out.contains("nested"));
    }

    fn droppable_fixture(keyword: &str) -> Value {
        let value = match keyword {
            "minLength" | "maxLength" | "minItems" | "maxItems" => json!(3),
            "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf" => json!(2),
            "format" => json!("uri"),
            other => panic!("unexpected keyword {other}"),
        };
        let mut property = json!({ "type": "string" });
        property
            .as_object_mut()
            .unwrap()
            .insert(keyword.to_string(), value);
        json!({
            "type": "object",
            "properties": {
                "outer": {
                    "type": "array",
                    "items": { "type": "object", "properties": { "value": property } }
                }
            }
        })
    }

    #[test]
    fn permissive_drops_known_unsupported_schema_constraints() {
        for keyword in LEGACY_CONSTRAINT_FIXTURES {
            let schema = droppable_fixture(keyword);
            let got =
                sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
                    .unwrap();
            let value = got
                .pointer("/properties/outer/items/properties/value")
                .unwrap();
            assert!(value.get(*keyword).is_none(), "{keyword} not dropped");
            assert_eq!(value["type"], "string");
        }
    }

    #[test]
    fn strict_rejects_known_unsupported_schema_constraints_with_path() {
        for keyword in LEGACY_CONSTRAINT_FIXTURES {
            let schema = droppable_fixture(keyword);
            let error = sanitize_schema(&schema, "tool 'fixture'").unwrap_err();
            assert_eq!(error.code, "bad_request");
            assert!(
                error.message.contains(&format!(
                    "tool 'fixture'.properties.outer.items.properties.value.{keyword}"
                )),
                "{}",
                error.message
            );
        }
    }

    #[test]
    fn permissive_still_rejects_unknown_schema_keywords() {
        for keyword in ["unknownKeyword", "futureConstraint", "vendorMagic"] {
            let schema = json!({
                "type": "object",
                "properties": { "v": { "type": "string", keyword: { "type": "string" } } }
            });
            let error =
                sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
                    .unwrap_err();
            assert!(error.message.contains(keyword));
        }
    }

    #[test]
    fn supported_schema_constraints_are_preserved() {
        let schema = json!({
            "type": "object",
            "description": "d",
            "properties": {
                "n": { "type": "number", "minimum": 1, "maximum": 5 },
                "s": { "type": "string", "pattern": "^a+$", "enum": ["a", "aa"] }
            },
            "required": ["n"]
        });
        for policy in [SchemaPolicy::Permissive, SchemaPolicy::Strict] {
            let got = sanitize_schema_with_policy(&schema, "tool 'fixture'", policy).unwrap();
            assert_eq!(got, schema);
        }
    }

    #[test]
    fn strict_tool_schema_rejects_max_length_with_path() {
        let provider = json!({ "capability_mode": "strict" });
        let request = json!({
            "tools": [{
                "name": "chrome_devtools_load",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "maxLength": 2000
                        }
                    },
                    "required": ["query"]
                }
            }]
        });

        let error = build_tool_declarations(&request, &provider).unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(error
            .message
            .contains("tool 'chrome_devtools_load'.properties.query.maxLength"));
    }

    #[test]
    fn permissive_tool_schema_still_rejects_unknown_keywords() {
        let schema = json!({
            "type": "object",
            "vendorMagic": { "type": "string" }
        });
        let error =
            sanitize_schema_with_policy(&schema, "tool 'fixture'", SchemaPolicy::Permissive)
                .unwrap_err();
        assert_eq!(error.code, "bad_request");
        assert!(error.message.contains("vendorMagic"));
    }

    #[test]
    fn tool_schema_rejects_unsupported_keywords() {
        {
            let (keyword, value) = ("propertyNames", json!({ "type": "string" }));
            let mut property = json!({ "type": "string" });
            property
                .as_object_mut()
                .unwrap()
                .insert(keyword.to_string(), value);
            let schema = json!({
                "type": "object",
                "properties": { "value": property }
            });

            let error = sanitize_schema(&schema, "tool 'fixture'").unwrap_err();
            assert_eq!(error.code, "bad_request");
            assert!(error.message.contains(keyword));
        }
    }

    #[test]
    fn signed_non_empty_thought_emits_content_then_pending_signature_marker() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "thought": true,
                            "text": "internal reasoning",
                            "thoughtSignature": "sig-1"
                        }]
                    }
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 2);
        assert_eq!(events[0]["type"], "thinking_delta");
        assert_eq!(events[0]["text"], "internal reasoning");
        assert!(events[0]["signature"].is_null());
        assert_eq!(events[1]["type"], "thinking_delta");
        assert_eq!(events[1]["text"], "");
        assert_eq!(events[1]["signature"], "sig-1");
    }

    #[test]
    fn signed_non_empty_visible_text_emits_text_then_pending_signature_marker() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": "visible response",
                            "thoughtSignature": "sig-visible"
                        }]
                    }
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 2);
        assert_eq!(events[0]["type"], "text_delta");
        assert_eq!(events[0]["text"], "visible response");
        assert_eq!(events[1]["type"], "thinking_delta");
        assert_eq!(events[1]["text"], "");
        assert_eq!(events[1]["signature"], "sig-visible");
    }

    #[test]
    fn function_call_preserves_same_part_thought_signature() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "functionCall": {"name": "bash", "args": {"command": "pwd"}},
                            "thoughtSignature": "SIG"
                        }]
                    }
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        assert_eq!(events[0]["type"], "tool_call_start");
        assert_eq!(events[0]["name"], "bash");
        assert_eq!(events[0]["signature"], "SIG");
    }

    #[test]
    fn standalone_signature_is_emitted_as_empty_thinking_delta() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {"parts": [{"thoughtSignature": "SIG"}]}
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 1);
        assert_eq!(events[0]["type"], "thinking_delta");
        assert_eq!(events[0]["text"], "");
        assert_eq!(events[0]["signature"], "SIG");
    }

    #[test]
    fn empty_text_signature_is_emitted_as_empty_thinking_delta() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {"parts": [{"text": "", "thoughtSignature": "SIG"}]}
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 1);
        assert_eq!(events[0]["type"], "thinking_delta");
        assert_eq!(events[0]["text"], "");
        assert_eq!(events[0]["signature"], "SIG");
    }

    #[test]
    fn parallel_function_calls_do_not_duplicate_first_signature() {
        let chunk = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [
                            {
                                "functionCall": {"name": "first", "args": {}},
                                "thoughtSignature": "SIG-A"
                            },
                            {"functionCall": {"name": "second", "args": {}}},
                            {"functionCall": {"name": "third", "args": {}}}
                        ]
                    }
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_stream_chunk(&chunk.to_string()).unwrap()).unwrap();
        let starts: Vec<_> = events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["type"] == "tool_call_start")
            .collect();
        assert_eq!(starts.len(), 3);
        assert_eq!(starts[0]["signature"], "SIG-A");
        assert!(starts[1]["signature"].is_null());
        assert!(starts[2]["signature"].is_null());
    }

    #[test]
    fn full_response_matches_stream_signature_behavior() {
        let response = json!({
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "functionCall": {"name": "bash", "args": {}},
                            "thoughtSignature": "SIG"
                        }]
                    }
                }]
            }
        });
        let events: Value =
            serde_json::from_str(&parse_full_response(&response.to_string()).unwrap()).unwrap();
        assert_eq!(events[0]["type"], "tool_call_start");
        assert_eq!(events[0]["signature"], "SIG");
    }

    fn convert_part(part: &Value) -> Value {
        let names = part
            .get("name")
            .and_then(Value::as_str)
            .into_iter()
            .collect::<Vec<_>>();
        let tool_names = ToolNameMap::new(names).unwrap();
        part_to_gemini(part, &tool_names, &HashMap::new())
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn tool_call_history_replays_signature_as_thought_signature() {
        let part = convert_part(&json!({
            "type": "tool_call",
            "id": "call_1",
            "name": "bash",
            "arguments": "{\"command\":\"pwd\"}",
            "signature": "SIG"
        }));
        assert_eq!(part["functionCall"]["name"], "bash");
        assert_eq!(part["functionCall"]["args"]["command"], "pwd");
        assert_eq!(part["thoughtSignature"], "SIG");
    }

    #[test]
    fn tool_names_round_trip_without_sanitizing_collisions() {
        let req = json!({
            "tools": [
                {"name": "read file!", "parameters": {"type": "object", "properties": {}}},
                {"name": "read_file_", "parameters": {"type": "object", "properties": {}}},
                {"name": "?read file!", "parameters": {"type": "object", "properties": {}}}
            ],
            "tool_choice": {"mode": "specific", "name": "read file!"},
            "messages": [{"role": "assistant", "parts": [{
                "type": "tool_call", "id": "call_1", "name": "read file!", "arguments": "{}"
            }]}]
        });
        let names = tool_name_mapping(&req).unwrap();
        let declarations = build_tool_declarations(&req, &json!({})).unwrap();
        let wire_names = declarations
            .iter()
            .map(|declaration| declaration["name"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(wire_names.len(), 3);
        assert!(wire_names.iter().all(|name| name.len() <= 64));
        for name in ["read file!", "read_file_", "?read file!"] {
            assert_eq!(
                ToolNameMap::from_wire(names.to_wire(name).unwrap()).unwrap(),
                name
            );
        }
        let config = build_tool_config(&req).unwrap().unwrap();
        assert_eq!(
            config["functionCallingConfig"]["allowedFunctionNames"][0],
            names.to_wire("read file!").unwrap()
        );

        let wire = names.to_wire("read file!").unwrap();
        let events: Value = serde_json::from_str(
            &parse_stream_chunk(
                &json!({
                    "response": {"candidates": [{"content": {"parts": [{
                        "functionCall": {"name": wire, "args": r#"{"path":"src"}"#}
                    }]}, "finishReason": "FUNCTION_CALL", "safeUnknownField": true}]}
                })
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(events[0]["name"], "read file!");
        assert_eq!(events[1]["args"], "{\"path\":\"src\"}");
        assert_eq!(events[2]["reason"], "tool_calls");
    }

    #[test]
    fn antigravity_thinking_tool_result_next_message_continuation() {
        let request: Value = serde_json::from_str(include_str!(
            "../../../wit/fixtures/plugin-request/v1/antigravity-tool-result-multimodal.json"
        ))
        .unwrap();
        let body: Value = serde_json::from_str(
            &build_body_at(
                &request.to_string(),
                r#"{"_kinetix":{"project_id":"project"}}"#,
                r#"{"upstream_id":"gemini-3.7-flash"}"#,
                None,
                1,
            )
            .unwrap(),
        )
        .unwrap();
        let wire_name = body["request"]["tools"][0]["functionDeclarations"][0]["name"].clone();
        assert_eq!(
            body["request"]["toolConfig"]["functionCallingConfig"]["mode"],
            "VALIDATED"
        );
        assert_eq!(wire_name, "bash");
        let contents = body["request"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[0]["parts"][0]["thought"], true);
        assert_eq!(
            contents[0]["parts"][0]["thoughtSignature"],
            "opaque-signature"
        );
        assert_eq!(contents[0]["parts"][1]["functionCall"]["name"], wire_name);
        assert!(contents[0]["parts"][1].get("thoughtSignature").is_none());
        assert_eq!(
            contents[1]["parts"][0]["functionResponse"]["name"],
            wire_name
        );
        assert_eq!(
            contents[1]["parts"][0]["functionResponse"]["response"]["exit_code"],
            0
        );
        assert_eq!(
            contents[1]["parts"][0]["functionResponse"]["response"]["result"],
            "done"
        );
        assert_eq!(
            contents[1]["parts"][0]["functionResponse"]["parts"][0]["inlineData"]["data"],
            "QUJD"
        );
        assert_eq!(contents[2]["parts"][0]["text"], "next message");

        let events: Value = serde_json::from_str(
            &parse_stream_chunk(
                &json!({
                    "response": {"candidates": [{"content": {"parts": [{
                        "functionCall": {"name": wire_name, "args": {"command": "pwd"}}
                    }]}}]}
                })
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(events[0]["name"], "bash");
        assert_eq!(events[1]["args"], "{\"command\":\"pwd\"}");
    }

    #[test]
    fn structured_error_tool_result_preserves_explanatory_text() {
        let names = ToolNameMap::new(["read"]).unwrap();
        let calls = HashMap::from([("call_1".to_string(), "read".to_string())]);
        let result = json!({
            "type": "tool_result", "tool_call_id": "call_1", "name": "read",
            "is_error": true,
            "content": [
                {"type": "text", "text": "permission denied"},
                {"type": "json", "value": {"code": "EACCES"}}
            ]
        });
        let translated = part_to_gemini(&result, &names, &calls).unwrap();
        assert_eq!(
            translated[0]["functionResponse"]["response"]["error"],
            json!({"code":"EACCES"})
        );
        assert_eq!(
            translated[0]["functionResponse"]["response"]["text"],
            "permission denied"
        );
    }

    #[test]
    fn unsupported_tool_result_media_returns_compatibility_error() {
        let names = ToolNameMap::new(["read"]).unwrap();
        let calls = HashMap::from([("call_1".to_string(), "read".to_string())]);
        let result = json!({
            "type": "tool_result", "tool_call_id": "call_1",
            "content": [{"type": "audio", "mime": "audio/wav", "data": "AA=="}]
        });
        let error = part_to_gemini(&result, &names, &calls).unwrap_err();
        assert_eq!(error.code, "unsupported_media");
    }

    #[test]
    fn thinking_history_preserves_signature() {
        let part = convert_part(&json!({
            "type": "thinking",
            "text": "",
            "signature": "sig-1"
        }));
        assert_eq!(part["thought"], true);
        assert_eq!(part["thoughtSignature"], "sig-1");
    }

    #[test]
    fn classify_error_handles_redirects_with_and_without_location() {
        // 302 with Location header (object shape)
        let headers = json!({
            "Location": "https://accounts.google.com/o/oauth2/v2/auth?client_id=..."
        });
        let evidence_json =
            classify_error(302, "<html>Moved</html>", &headers.to_string()).unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "unexpected_redirect");
        assert_eq!(evidence["status"], 302);
        assert_eq!(
            evidence["location"],
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=..."
        );
        assert!(evidence["message"]
            .as_str()
            .unwrap()
            .contains("unexpected upstream redirect (302) to https://accounts.google.com"));

        // 301 without Location header
        let evidence_json = classify_error(301, "", "{}").unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "unexpected_redirect");
        assert_eq!(evidence["status"], 301);
        assert!(evidence["location"].is_null());
        assert_eq!(evidence["message"], "unexpected upstream redirect (301)");

        // 307 with array-of-pairs headers
        let headers_pairs = json!([
            ["Content-Type", "text/html"],
            [
                "location",
                "https://daily-cloudcode-pa.googleapis.com/redirected"
            ]
        ]);
        let evidence_json = classify_error(307, "", &headers_pairs.to_string()).unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "unexpected_redirect");
        assert_eq!(evidence["status"], 307);
        assert_eq!(
            evidence["location"],
            "https://daily-cloudcode-pa.googleapis.com/redirected"
        );
    }

    #[test]
    fn classify_error_other_statuses() {
        let headers = json!({ "retry-after": "30" });
        let evidence_json =
            classify_error(429, r#"{"error": "rate limited"}"#, &headers.to_string()).unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "quota_exhausted");
        assert_eq!(evidence["retry_after_secs"], 30);
        assert_eq!(evidence["message"], "rate limited");

        let evidence_json = classify_error(401, "unauthorized", "{}").unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "auth_error");

        let evidence_json = classify_error(500, "internal server error", "{}").unwrap();
        let evidence: Value = serde_json::from_str(&evidence_json).unwrap();
        assert_eq!(evidence["kind"], "server_error");
    }

    #[test]
    fn plugin_manifest_verifies_daily_endpoint_integration() {
        let manifest = include_str!("../plugin.toml");
        assert!(
            manifest.contains("base_url = \"https://daily-cloudcode-pa.googleapis.com\""),
            "plugin.toml must configure daily-cloudcode-pa.googleapis.com as the integration provider base_url"
        );
        assert!(
            !manifest.contains("autopush-alkalimakersuite-pa"),
            "plugin.toml must not contain the obsolete autopush endpoint"
        );
        assert!(
            manifest.contains("\"daily-cloudcode-pa.googleapis.com\""),
            "plugin.toml permissions must include daily-cloudcode-pa.googleapis.com"
        );
    }
}
