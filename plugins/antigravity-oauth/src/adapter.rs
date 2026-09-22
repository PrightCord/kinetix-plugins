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
) -> Result<String, AdapterError> {
    let req: Value =
        serde_json::from_str(request_json).map_err(|e| bad(format!("bad request json: {e}")))?;
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let model: Value = serde_json::from_str(model_json).unwrap_or(Value::Null);

    validate_request_contract(&req)?;
    validate_canonical_extras(&provider, &req)?;
    validate_nonportable_controls(&provider, &req)?;

    let upstream_model = model
        .get("upstream_id")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| req.get("requested_model").and_then(|m| m.as_str()))
        .unwrap_or("gemini-3-flash")
        .to_string();

    let project = project_id(&provider, &req);
    let session_id = session_id(&req);
    let request_id = build_request_id(&session_id, &upstream_model);

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

    let mut contents = Vec::new();
    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for message in messages {
            let role = match message.get("role").and_then(Value::as_str).unwrap_or("user") {
                "assistant" => "model",
                _ => "user",
            };
            let mut parts = Vec::new();
            if let Some(items) = message.get("parts").and_then(Value::as_array) {
                for part in items {
                    if let Some(part) = part_to_gemini(part) {
                        parts.push(part);
                    }
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

    let mut declarations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        for tool in tools {
            let name =
                sanitize_function_name(tool.get("name").and_then(Value::as_str).unwrap_or(""));
            if !seen.insert(name.clone()) {
                continue;
            }
            let parameters = tool
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            declarations.push(json!({
                "name": name,
                "description": tool.get("description").cloned().unwrap_or(Value::Null),
                "parametersJsonSchema": sanitize_schema(
                    &parameters,
                    &format!("tool '{}'", tool.get("name").and_then(Value::as_str).unwrap_or(""))
                )?,
            }));
        }
    }

    let mut request = Map::new();
    request.insert("contents".into(), Value::Array(contents));
    if let Some(instruction) = system_instruction {
        request.insert("systemInstruction".into(), instruction);
    }
    request.insert(
        "generationConfig".into(),
        Value::Object(generation_config),
    );
    if !declarations.is_empty() {
        request.insert(
            "tools".into(),
            json!([{ "functionDeclarations": declarations }]),
        );
        if let Some(config) = build_tool_config(&req)? {
            request.insert("toolConfig".into(), config);
        }
    }
    request.insert("sessionId".into(), json!(session_id));
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

fn validate_request_contract(req: &Value) -> Result<(), AdapterError> {
    if let Some(schema) = req.get("schema").and_then(Value::as_str) {
        if schema != "kinetix.plugin.request" {
            return Err(bad(format!("unsupported canonical request schema '{schema}'")));
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
    if !req.get("presence_penalty").unwrap_or(&Value::Null).is_null() {
        unsupported.push("presence_penalty");
    }
    if !req.get("frequency_penalty").unwrap_or(&Value::Null).is_null() {
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
            other => return Err(bad(format!("unsupported canonical thinking level '{other}'"))),
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
            other => return Err(bad(format!("unsupported canonical thinking level '{other}'"))),
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

    Err(bad(format!(
        "canonical thinking controls are unsupported for Antigravity model '{upstream_model}'"
    )))
}

fn build_tool_config(req: &Value) -> Result<Option<Value>, AdapterError> {
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
            json!({
                "mode": "ANY",
                "allowedFunctionNames": [sanitize_function_name(name)]
            })
        }
        other => return Err(bad(format!("unsupported canonical tool choice '{other}'"))),
    };
    Ok(Some(json!({ "functionCallingConfig": config })))
}

fn project_id(provider: &Value, req: &Value) -> String {
    // Prefer an operator-configured project (provider extra_headers), then a
    // client-supplied hint, then a deterministic fallback (the API accepts a
    // generated id when the account has no explicit project).
    if let Some(project) = provider
        .get("extra_headers")
        .and_then(|e| e.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get("x-antigravity-project")
                .and_then(|p| p.as_str())
                .map(str::to_string)
        })
    {
        return project;
    }
    if let Some(project) = req
        .get("extra")
        .and_then(|e| e.get("antigravity_project"))
        .and_then(|p| p.as_str())
    {
        return project.to_string();
    }
    let seed = format!(
        "{}:{}",
        req.get("requested_model")
            .and_then(|m| m.as_str())
            .unwrap_or(""),
        session_id(req)
    );
    let h = fnv1a(&seed);
    format!("kinetix-{h:08x}")
}

fn session_id(req: &Value) -> String {
    req.get("extra")
        .and_then(|e| e.get("session_id").or_else(|| e.get("sessionId")))
        .and_then(|s| s.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{:016x}", fnv1a("antigravity:default")))
}

/// `agent/<conversationId>/<ts>/<trajectoryId>/<step>` (9router's IDE shape).
fn build_request_id(session_id: &str, model: &str) -> String {
    let conversation = uuid_from_seed(&format!("antigravity:conversation:{session_id}"));
    let trajectory = uuid_from_seed(&format!("antigravity:trajectory:{session_id}:{model}"));
    let ts = kinetix_plugin_sdk::helpers::now_unix_millis();
    format!("agent/{conversation}/{ts}/{trajectory}/1")
}

/// Gemini function-name rule: `[a-zA-Z_][a-zA-Z0-9_.:\-]{0,63}`.
fn sanitize_function_name(name: &str) -> String {
    if name.is_empty() {
        return "_unknown".to_string();
    }
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false)
    {
        s.insert(0, '_');
    }
    s.truncate(64);
    s
}

fn schema_error(path: &str, message: impl Into<String>) -> AdapterError {
    bad(format!("Gemini tool schema at {path}: {}", message.into()))
}

fn sanitize_schema_list(value: &Value, path: &str) -> Result<Vec<Value>, AdapterError> {
    value
        .as_array()
        .ok_or_else(|| schema_error(path, "expected an array of schemas"))?
        .iter()
        .enumerate()
        .map(|(index, schema)| sanitize_schema_node(schema, &format!("{path}[{index}]")))
        .collect()
}

fn merge_schema_maps(
    target: &mut Map<String, Value>,
    incoming: &Map<String, Value>,
    path: &str,
) -> Result<(), AdapterError> {
    for (key, value) in incoming {
        match key.as_str() {
            "properties" | "$defs" => {
                let source = value
                    .as_object()
                    .ok_or_else(|| schema_error(&format!("{path}.{key}"), "must be an object"))?;
                let destination = target
                    .entry(key.clone())
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .expect("schema map initialized as object");
                for (name, schema) in source {
                    if let Some(previous) = destination.get(name) {
                        if previous != schema {
                            return Err(schema_error(
                                &format!("{path}.{key}.{name}"),
                                "conflicting allOf schemas cannot be represented safely",
                            ));
                        }
                    } else {
                        destination.insert(name.clone(), schema.clone());
                    }
                }
            }
            "required" => {
                let source = value
                    .as_array()
                    .ok_or_else(|| schema_error(&format!("{path}.required"), "must be an array"))?;
                let destination = target
                    .entry("required".to_string())
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .expect("required initialized as array");
                for item in source {
                    if !destination.contains(item) {
                        destination.push(item.clone());
                    }
                }
            }
            "title" | "description" => {
                target.entry(key.clone()).or_insert_with(|| value.clone());
            }
            _ => {
                if let Some(previous) = target.get(key) {
                    if previous != value {
                        return Err(schema_error(
                            &format!("{path}.{key}"),
                            "conflicting allOf constraints cannot be represented safely",
                        ));
                    }
                } else {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
    }
    Ok(())
}

fn add_nullable_type(schema: &mut Map<String, Value>, path: &str) -> Result<(), AdapterError> {
    if let Some(kind) = schema.get_mut("type") {
        match kind {
            Value::String(existing) if existing != "null" => {
                *kind = json!([existing.clone(), "null"]);
                return Ok(());
            }
            Value::Array(types) => {
                if !types.iter().any(|value| value.as_str() == Some("null")) {
                    types.push(json!("null"));
                }
                return Ok(());
            }
            Value::String(_) => return Ok(()),
            _ => return Err(schema_error(path, "nullable requires a string or array type")),
        }
    }

    if let Some(any_of) = schema.get_mut("anyOf").and_then(Value::as_array_mut) {
        if !any_of
            .iter()
            .any(|branch| branch.get("type").and_then(Value::as_str) == Some("null"))
        {
            any_of.push(json!({ "type": "null" }));
        }
        return Ok(());
    }

    Err(schema_error(
        path,
        "nullable without type or anyOf cannot be normalized safely",
    ))
}

fn sanitize_schema(schema: &Value, root_path: &str) -> Result<Value, AdapterError> {
    sanitize_schema_node(schema, root_path)
}

fn sanitize_schema_node(node: &Value, path: &str) -> Result<Value, AdapterError> {
    let map = node
        .as_object()
        .ok_or_else(|| schema_error(path, "schema nodes must be JSON objects"))?;
    let mut out = Map::new();
    let mut nullable = false;
    let mut const_value: Option<Value> = None;
    let mut all_of: Option<&Value> = None;

    for (key, value) in map {
        match key.as_str() {
            "$schema" | "$comment" | "strict" | "default" | "examples" | "example"
            | "deprecated" | "readOnly" | "writeOnly" => {}

            "definitions" | "$defs" => {
                let definitions = value
                    .as_object()
                    .ok_or_else(|| schema_error(&format!("{path}.{key}"), "must be an object"))?;
                let mut sanitized = Map::new();
                for (name, schema) in definitions {
                    sanitized.insert(
                        name.clone(),
                        sanitize_schema_node(schema, &format!("{path}.{key}.{name}"))?,
                    );
                }
                let mut incoming = Map::new();
                incoming.insert("$defs".into(), Value::Object(sanitized));
                merge_schema_maps(&mut out, &incoming, path)?;
            }

            "$ref" => {
                let reference = value
                    .as_str()
                    .ok_or_else(|| schema_error(&format!("{path}.$ref"), "must be a string"))?;
                let reference = reference
                    .strip_prefix("#/definitions/")
                    .map(|suffix| format!("#/$defs/{suffix}"))
                    .unwrap_or_else(|| reference.to_string());
                out.insert("$ref".into(), json!(reference));
            }

            "properties" => {
                let properties = value.as_object().ok_or_else(|| {
                    schema_error(&format!("{path}.properties"), "must be an object")
                })?;
                let mut sanitized = Map::new();
                for (name, schema) in properties {
                    sanitized.insert(
                        name.clone(),
                        sanitize_schema_node(schema, &format!("{path}.properties.{name}"))?,
                    );
                }
                out.insert("properties".into(), Value::Object(sanitized));
            }

            "items" => {
                if let Some(items) = value.as_array() {
                    let sanitized: Result<Vec<_>, _> = items
                        .iter()
                        .enumerate()
                        .map(|(index, schema)| {
                            sanitize_schema_node(schema, &format!("{path}.items[{index}]"))
                        })
                        .collect();
                    out.insert("prefixItems".into(), Value::Array(sanitized?));
                } else {
                    out.insert(
                        "items".into(),
                        sanitize_schema_node(value, &format!("{path}.items"))?,
                    );
                }
            }

            "prefixItems" | "anyOf" => {
                out.insert(
                    key.clone(),
                    Value::Array(sanitize_schema_list(value, &format!("{path}.{key}"))?),
                );
            }

            "oneOf" => {
                if out.contains_key("anyOf") {
                    return Err(schema_error(
                        &format!("{path}.oneOf"),
                        "cannot combine oneOf and anyOf safely",
                    ));
                }
                out.insert(
                    "anyOf".into(),
                    Value::Array(sanitize_schema_list(value, &format!("{path}.oneOf"))?),
                );
            }

            "allOf" => all_of = Some(value),
            "const" => const_value = Some(value.clone()),

            "additionalProperties" => {
                let normalized = match value {
                    Value::Bool(_) => value.clone(),
                    Value::Object(_) => {
                        sanitize_schema_node(value, &format!("{path}.additionalProperties"))?
                    }
                    _ => {
                        return Err(schema_error(
                            &format!("{path}.additionalProperties"),
                            "must be a boolean or schema object",
                        ))
                    }
                };
                out.insert("additionalProperties".into(), normalized);
            }

            "nullable" => {
                nullable = value.as_bool().ok_or_else(|| {
                    schema_error(&format!("{path}.nullable"), "must be a boolean")
                })?;
            }

            "$id" | "$anchor" | "type" | "format" | "title" | "description" | "enum"
            | "minItems" | "maxItems" | "minimum" | "maximum" | "required"
            | "propertyOrdering" => {
                out.insert(key.clone(), value.clone());
            }

            other => {
                return Err(schema_error(
                    &format!("{path}.{other}"),
                    format!("unsupported JSON Schema keyword '{other}'"),
                ));
            }
        }
    }

    if let Some(value) = const_value {
        if let Some(existing) = out.get("enum").and_then(Value::as_array) {
            if !existing.contains(&value) {
                return Err(schema_error(
                    &format!("{path}.const"),
                    "const conflicts with enum",
                ));
            }
        }
        out.insert("enum".into(), Value::Array(vec![value]));
    }

    if let Some(branches) = all_of {
        let sanitized = sanitize_schema_list(branches, &format!("{path}.allOf"))?;
        let mut merged = Map::new();
        for (index, branch) in sanitized.iter().enumerate() {
            let branch = branch.as_object().ok_or_else(|| {
                schema_error(
                    &format!("{path}.allOf[{index}]"),
                    "allOf branch must be an object schema",
                )
            })?;
            merge_schema_maps(&mut merged, branch, &format!("{path}.allOf[{index}]"))?;
        }
        merge_schema_maps(&mut out, &merged, path)?;
    }

    if nullable {
        add_nullable_type(&mut out, path)?;
    }

    if out.contains_key("$ref") && out.keys().any(|key| !key.starts_with('$')) {
        return Err(schema_error(
            path,
            "$ref cannot be combined with non-$ sibling constraints",
        ));
    }

    Ok(Value::Object(out))
}

/// Convert one internal part to a Gemini part.
fn part_to_gemini(p: &Value) -> Option<Value> {
    match p.get("type").and_then(|t| t.as_str())? {
        "text" => Some(json!({ "text": p.get("text").and_then(|t| t.as_str()).unwrap_or("") })),
        "thinking" => {
            let mut part = json!({
                "thought": true,
                "text": p.get("text").and_then(|t| t.as_str()).unwrap_or("")
            });
            if let Some(signature) = p.get("signature").and_then(Value::as_str) {
                part["thoughtSignature"] = json!(signature);
            }
            Some(part)
        },
        "image" => Some(json!({
            "inlineData": {
                "mimeType": p.get("mime").and_then(|m| m.as_str()).unwrap_or("image/png"),
                "data": p.get("data").and_then(|d| d.as_str()).unwrap_or("")
            }
        })),
        "image_url" => Some(json!({
            "fileData": { "fileUri": p.get("url").and_then(|u| u.as_str()).unwrap_or("") }
        })),
        "tool_call" => {
            let name = sanitize_function_name(p.get("name").and_then(|n| n.as_str()).unwrap_or(""));
            let args: Value = p
                .get("arguments")
                .and_then(|a| a.as_str())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| json!({}));
            let mut part = json!({ "functionCall": { "name": name, "args": args } });
            if let Some(sig) = p.get("signature").and_then(|s| s.as_str()) {
                if let Some(obj) = part.as_object_mut() {
                    obj.insert("thoughtSignature".into(), json!(sig));
                }
            }
            Some(part)
        }
        "tool_result" => {
            let name = sanitize_function_name(p.get("name").and_then(|n| n.as_str()).unwrap_or(""));
            let content = p.get("content").and_then(|c| c.as_str()).unwrap_or("");
            Some(json!({
                "functionResponse": { "name": name, "response": { "result": content } }
            }))
        }
        _ => None,
    }
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
            if let Some(parts) = c.pointer("/content/parts").and_then(|p| p.as_array()) {
                for p in parts {
                    if let Some(text) = p.get("text").and_then(|t| t.as_str()) {
                        if p.get("thought").and_then(|t| t.as_bool()).unwrap_or(false) {
                            events.push(json!({
                                "type": "thinking_delta",
                                "text": text,
                                "signature": p.get("thoughtSignature").and_then(|s| s.as_str()),
                            }));
                        } else {
                            events.push(json!({ "type": "text_delta", "text": text }));
                        }
                    }
                    if let Some(fc) = p.get("functionCall") {
                        let name = sanitize_function_name(
                            fc.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                        );
                        let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                        events.push(json!({
                            "type": "tool_call_start",
                            "index": tool_index,
                            "id": Value::Null,
                            "name": name,
                            "signature": p.get("thoughtSignature").and_then(|s| s.as_str()),
                        }));
                        events.push(json!({
                            "type": "tool_call_args_delta",
                            "index": tool_index,
                            "args": args.to_string(),
                        }));
                        tool_index += 1;
                    }
                }
            }
            if let Some(reason) = c.get("finishReason").and_then(|r| r.as_str()) {
                events.push(json!({ "type": "finish", "reason": map_finish(reason) }));
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

    Ok(Value::Array(events).to_string())
}

pub fn parse_full_response(body_json: &str) -> Result<String, AdapterError> {
    let v: Value = serde_json::from_str(body_json).unwrap_or(Value::Null);
    let resp = v.get("response").unwrap_or(&v);
    // Reuse the streaming parser on a synthesized single chunk.
    parse_stream_chunk(&resp.to_string())
}

fn map_finish(reason: &str) -> &'static str {
    match reason {
        "STOP" => "stop",
        "MAX_TOKENS" => "length",
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => "content_filter",
        _ => "stop",
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

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
    fn permissive_extra_fields_are_dropped_not_forwarded() {
        let provider = json!({ "capability_mode": "permissive" });
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
        assert_eq!(session_id(&req), "sess-1");
        assert_eq!(project_id(&provider, &req), "project-1");
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
                    "allowedFunctionNames": ["read_file_"]
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
    fn tool_schema_matches_core_gemini_subset() {
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
                        "tuple": {
                            "type": "array",
                            "items": [
                                { "type": "string" },
                                { "type": "integer" }
                            ]
                        }
                    }
                }
            }
        });
        let got = sanitize_schema(&schema, "tool 'fixture'").unwrap();

        assert_eq!(got["$ref"], "#/$defs/Envelope");
        assert_eq!(
            got.pointer("/$defs/Envelope/additionalProperties"),
            Some(&json!(false))
        );
        assert_eq!(
            got.pointer("/$defs/Payload/properties/kind/enum"),
            Some(&json!(["ok"]))
        );
        assert_eq!(
            got.pointer("/$defs/Payload/properties/choice/anyOf/1/type"),
            Some(&json!("number"))
        );
        assert_eq!(
            got.pointer("/$defs/Payload/properties/tuple/prefixItems/1/type"),
            Some(&json!("integer"))
        );
    }

    #[test]
    fn tool_schema_rejects_unsupported_keywords() {
        for (keyword, value) in [
            ("exclusiveMinimum", json!(0)),
            ("exclusiveMaximum", json!(10)),
            ("propertyNames", json!({ "type": "string" })),
            ("pattern", json!("^[a-z]+$")),
        ] {
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
    fn thinking_history_preserves_signature() {
        let part = part_to_gemini(&json!({
            "type": "thinking",
            "text": "",
            "signature": "sig-1"
        }))
        .unwrap();
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
