//! Kinetix OpenCode Free plugin.
//!
//! User authentication is intentionally absent. The only Authorization header
//! used by the adapter is OpenCode's fixed `Bearer public` transport marker.
//!
//! Model discovery follows the live `/zen/v1/models` endpoint and filters the
//! returned OpenAI-style model list down to free-tier ids.

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::{export, exports, kinetix};
use serde_json::{json, Value};

mod adapter;

const DEFAULT_BASE_URL: &str = "https://opencode.ai";
const DEFAULT_MODELS_PATH: &str = "/zen/v1/models";
const CLIENT_HEADER_VALUE: &str = "desktop";

const KNOWN_FREE_IDS: &[&str] = &[
    "big-pickle",
    // Keep this in the allow-list if OpenCode re-exposes it dynamically.
    "union-alpha",
];

const DEAD_FREE_IDS: &[&str] = &[
    // 9router currently suppresses this because the upstream reports
    // "Model is unavailable".
    "deepseek-v4-flash-free",
];

struct Component;

fn unsupported() -> PluginError {
    kinetix_plugin_sdk::helpers::error("unknown", "capability not provided by this plugin")
}

fn discovery_error(code: &str, message: impl Into<String>, retryable: bool) -> PluginError {
    PluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn join_url(base_url: &str, path: &str) -> String {
    let base = if base_url.trim().is_empty() {
        DEFAULT_BASE_URL
    } else {
        base_url.trim()
    };
    let path = if path.trim().is_empty() {
        DEFAULT_MODELS_PATH
    } else {
        path.trim()
    };
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

fn is_free_model(id: &str) -> bool {
    (id.ends_with("-free") || KNOWN_FREE_IDS.contains(&id)) && !DEAD_FREE_IDS.contains(&id)
}

fn target_format(id: &str) -> &'static str {
    if id.starts_with("muse-spark-") {
        "openai-responses"
    } else if id == "union-alpha" {
        "claude"
    } else {
        "openai"
    }
}

fn parse_model_list(value: &Value) -> Vec<DiscoveredModel> {
    let Some(data) = value.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut models: Vec<DiscoveredModel> = data
        .iter()
        .filter_map(|item| {
            let id = item.get("id")?.as_str()?.trim();
            if id.is_empty() || !is_free_model(id) {
                return None;
            }

            let display_name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(id)
                .to_string();

            let capabilities_json = json!({
                "target_format": target_format(id),
                "free": true,
                "auth": "none"
            })
            .to_string();

            Some(DiscoveredModel {
                id: id.to_string(),
                display_name: Some(display_name),
                context_window: item
                    .get("context_length")
                    .or_else(|| item.get("contextWindow"))
                    .and_then(Value::as_u64),
                max_output_tokens: item
                    .get("max_output_tokens")
                    .or_else(|| item.get("maxOutputTokens"))
                    .and_then(Value::as_u64),
                capabilities_json: Some(capabilities_json),
                raw_metadata: serde_json::to_string(item).ok(),
            })
        })
        .collect();

    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

impl exports::model_source::Guest for Component {
    fn discover(
        provider_id: String,
        base_url: String,
        models_path: String,
    ) -> Result<Vec<DiscoveredModel>, PluginError> {
        if provider_id != "opencode-free" && provider_id != "opencode" {
            return Err(discovery_error(
                "invalid_configuration",
                format!("unsupported provider id '{provider_id}'"),
                false,
            ));
        }

        let url = join_url(&base_url, &models_path);
        let req = HttpRequest {
            method: "GET".into(),
            url,
            headers: vec![
                ("accept".into(), "application/json".into()),
                ("x-opencode-client".into(), CLIENT_HEADER_VALUE.into()),
                ("user-agent".into(), adapter::USER_AGENT.into()),
            ],
            body: Vec::new(),
            credential: None,
        };

        let resp = kinetix::plugin::host_http::send(&req).map_err(|e| PluginError {
            code: e.code,
            message: e.message,
            retryable: e.retryable,
            retry_after: e.retry_after,
            reset_at: e.reset_at,
        })?;

        if resp.body_truncated {
            return Err(discovery_error(
                "upstream_unavailable",
                "OpenCode model catalog response was truncated",
                true,
            ));
        }

        let body = String::from_utf8(resp.body).map_err(|_| {
            discovery_error(
                "protocol_error",
                "OpenCode model catalog is not UTF-8",
                false,
            )
        })?;

        if resp.status != 200 {
            let retryable = resp.status == 429 || resp.status >= 500;
            return Err(discovery_error(
                if resp.status == 429 {
                    "rate_limited"
                } else {
                    "upstream_unavailable"
                },
                format!("OpenCode model catalog returned HTTP {}", resp.status),
                retryable,
            ));
        }

        let value: Value = serde_json::from_str(&body).map_err(|e| {
            discovery_error(
                "protocol_error",
                format!("invalid OpenCode model catalog JSON: {e}"),
                false,
            )
        })?;

        let models = parse_model_list(&value);
        if models.is_empty() {
            return Err(discovery_error(
                "protocol_error",
                "OpenCode model catalog contained no usable free models",
                false,
            ));
        }

        Ok(models)
    }
}

impl exports::credential_strategy::Guest for Component {
    fn resolve(
        _provider_id: String,
        _account_id: String,
        _account_label: String,
    ) -> Result<CredentialLease, PluginError> {
        Err(unsupported())
    }

    fn health(_provider_id: String, _account_id: String) -> Result<String, PluginError> {
        Err(unsupported())
    }

    fn rotate(_provider_id: String, _account_id: String) -> Result<(), PluginError> {
        Err(unsupported())
    }
}

impl exports::health_probe::Guest for Component {
    fn probe(_provider_id: String, _account_id: String) -> Result<HealthObservation, PluginError> {
        Err(unsupported())
    }
}

impl exports::routing_facts::Guest for Component {
    fn facts(_request_json: String) -> Result<Vec<RoutingFact>, PluginError> {
        Ok(Vec::new())
    }
}

impl exports::hooks::Guest for Component {
    fn on_request_normalized(_request_json: String) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_target_candidate(_target_json: String) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_usage_finalized(_usage_json: String) -> Result<(), PluginError> {
        Ok(())
    }
}

use kinetix_plugin_sdk::adapter as adapter_world;

fn adapter_error(
    e: adapter::AdapterError,
) -> adapter_world::kinetix::plugin::types::PluginError {
    adapter_world::kinetix::plugin::types::PluginError {
        code: e.code,
        message: e.message,
        retryable: e.retryable,
        retry_after: e.retry_after,
        reset_at: None,
    }
}

impl adapter_world::exports::provider_adapter::Guest for Component {
    fn wire_format() -> String {
        "opencode-free".into()
    }

    fn build_url(
        provider_json: String,
        model_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::build_url(&provider_json, &model_json).map_err(adapter_error)
    }

    fn apply_auth(
        provider_json: String,
        credential: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::apply_auth(&provider_json, &credential).map_err(adapter_error)
    }

    fn build_body(
        request_json: String,
        provider_json: String,
        model_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::build_body(&request_json, &provider_json, &model_json).map_err(adapter_error)
    }

    fn classify_error(
        status: u16,
        body: String,
        headers_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::classify_error(status, &body, &headers_json).map_err(adapter_error)
    }

    fn parse_stream_chunk(
        data: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::parse_stream_chunk(&data).map_err(adapter_error)
    }

    fn parse_full_response(
        body_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        adapter::parse_full_response(&body_json).map_err(adapter_error)
    }
}

adapter_world::export!(Component with_types_in kinetix_plugin_sdk::adapter);
export!(Component with_types_in kinetix_plugin_sdk);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_openai_model_list_shape_and_filters_to_free() {
        let value = serde_json::json!({
            "object": "list",
            "data": [
                {"id": "gpt-5.6-luna", "object": "model", "owned_by": "opencode"},
                {"id": "big-pickle", "object": "model", "owned_by": "opencode"},
                {"id": "mimo-v2.5-free", "object": "model", "owned_by": "opencode"},
                {"id": "muse-spark-1.3-contributor-free", "object": "model", "owned_by": "opencode"},
                {"id": "deepseek-v4-flash-free", "object": "model", "owned_by": "opencode"}
            ]
        });

        let models = parse_model_list(&value);
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();

        assert_eq!(
            ids,
            vec![
                "big-pickle",
                "mimo-v2.5-free",
                "muse-spark-1.3-contributor-free"
            ]
        );
    }

    #[test]
    fn tags_muse_models_as_responses() {
        let value = serde_json::json!({
            "data": [
                {"id": "muse-spark-1.2-contributor-free"},
                {"id": "nemotron-3-ultra-free"}
            ]
        });

        let models = parse_model_list(&value);
        let muse = models
            .iter()
            .find(|m| m.id.starts_with("muse-spark"))
            .unwrap();
        let caps: Value = serde_json::from_str(muse.capabilities_json.as_deref().unwrap()).unwrap();
        assert_eq!(caps["target_format"], "openai-responses");
    }

    #[test]
    fn joins_custom_and_default_model_paths() {
        assert_eq!(
            join_url("https://opencode.ai/", "/zen/v1/models"),
            "https://opencode.ai/zen/v1/models"
        );
        assert_eq!(
            join_url("", ""),
            "https://opencode.ai/zen/v1/models"
        );
    }
}
