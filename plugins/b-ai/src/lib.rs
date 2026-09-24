//! Kinetix B.AI provider integration.
//!
//! The plugin owns authenticated model discovery and B.AI-specific metadata.
//! Inference continues to use Kinetix's native OpenAI adapter.

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::model_capabilities::{
    ModelCapabilitiesV1, ReasoningCapability, ReasoningLevel, ReasoningMode, SupportCapability,
    TransportCapability, VisionCapability,
};
use kinetix_plugin_sdk::{export, exports, kinetix};
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://api.b.ai/v1";
const DEFAULT_MODELS_PATH: &str = "/models";
const MODEL_CATALOG: &str = include_str!("../models.json");

struct Component;

fn unsupported() -> PluginError {
    kinetix_plugin_sdk::helpers::error("unknown", "capability not provided by this plugin")
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

impl exports::model_source::Guest for Component {
    fn discover(
        _provider_id: String,
        _base_url: String,
        _models_path: String,
    ) -> Result<Vec<DiscoveredModel>, PluginError> {
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

export!(Component with_types_in kinetix_plugin_sdk);

#[derive(Clone, Debug, Deserialize)]
struct Catalog {
    models: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct CatalogEntry {
    ids: Vec<String>,
    display_name: Option<String>,
    context_window: Option<u64>,
    max_output_tokens: Option<u64>,
    reasoning: Option<CatalogReasoning>,
    tools: Option<bool>,
    vision: Option<bool>,
    structured_output: Option<bool>,
    #[serde(rename = "source")]
    _source: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CatalogReasoning {
    supported: bool,
    mode: Option<String>,
    #[serde(default)]
    levels: Vec<String>,
    default: Option<String>,
    can_disable: Option<bool>,
}

fn catalog_entry(id: &str) -> Result<Option<CatalogEntry>, String> {
    let catalog: Catalog = serde_json::from_str(MODEL_CATALOG)
        .map_err(|error| format!("invalid models.json: {error}"))?;
    Ok(catalog
        .models
        .into_iter()
        .find(|entry| entry.ids.iter().any(|known| known == id)))
}

fn catalog_reasoning(value: &CatalogReasoning) -> Result<ReasoningCapability, String> {
    if !value.supported {
        return Ok(ReasoningCapability::unsupported());
    }
    match value.mode.as_deref() {
        None => Ok(ReasoningCapability::supported_unknown()),
        Some("level") => {
            let levels = value
                .levels
                .iter()
                .map(|level| {
                    ReasoningLevel::parse(level).ok_or_else(|| {
                        format!("unsupported reasoning level in models.json: {level}")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let default = value
                .default
                .as_deref()
                .map(|level| {
                    ReasoningLevel::parse(level).ok_or_else(|| {
                        format!("unsupported reasoning default in models.json: {level}")
                    })
                })
                .transpose()?;
            Ok(ReasoningCapability {
                supported: true,
                mode: Some(ReasoningMode::Level),
                levels: Some(levels),
                default,
                can_disable: value.can_disable,
            })
        }
        Some(mode) => Err(format!("unsupported reasoning mode in models.json: {mode}")),
    }
}

fn normalized_capabilities(entry: Option<&CatalogEntry>) -> Result<String, String> {
    let mut capabilities = ModelCapabilitiesV1::default();
    capabilities.transport = Some(TransportCapability::new("openai"));
    if let Some(entry) = entry {
        capabilities.reasoning = entry
            .reasoning
            .as_ref()
            .map(catalog_reasoning)
            .transpose()?;
        capabilities.tools = entry.tools.map(SupportCapability::new);
        capabilities.vision = entry.vision.map(VisionCapability::new);
        capabilities.structured_output = entry.structured_output.map(SupportCapability::new);
    }
    capabilities.to_json().map_err(|error| error.to_string())
}

use kinetix_plugin_sdk::model_source as model_world;

type ModelPluginError = model_world::kinetix::plugin::types::PluginError;
type ModelAccountRef = model_world::kinetix::plugin::types::AccountRef;
type ModelCredentialRef = model_world::kinetix::plugin::types::CredentialRef;
type ModelDiscoveredModel = model_world::kinetix::plugin::types::DiscoveredModel;
type ModelHttpRequest = model_world::kinetix::plugin::types::HttpRequest;
type ModelHttpResponse = model_world::kinetix::plugin::types::HttpResponse;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(not(test))]
fn send_request(request: &ModelHttpRequest) -> Result<ModelHttpResponse, ModelPluginError> {
    model_world::kinetix::plugin::host_http::send(request)
        .map_err(|error| model_error(&error.code, error.message, error.retryable))
}

#[cfg(test)]
thread_local! {
    static TEST_RESPONSE: RefCell<Option<ModelHttpResponse>> = const { RefCell::new(None) };
    static TEST_REQUEST: RefCell<Option<(String, bool)>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn send_request(request: &ModelHttpRequest) -> Result<ModelHttpResponse, ModelPluginError> {
    TEST_REQUEST.with(|slot| {
        *slot.borrow_mut() = Some((request.url.clone(), request.credential.is_some()));
    });
    TEST_RESPONSE.with(|slot| {
        slot.borrow_mut()
            .take()
            .ok_or_else(|| model_error("plugin_internal", "missing test response", false))
    })
}

fn model_error(code: &str, message: impl Into<String>, retryable: bool) -> ModelPluginError {
    ModelPluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn join_url(base_url: &str, models_path: &str) -> String {
    let base = if base_url.trim().is_empty() {
        DEFAULT_BASE_URL
    } else {
        base_url.trim()
    };
    let path = if models_path.trim().is_empty() {
        DEFAULT_MODELS_PATH
    } else {
        models_path.trim()
    };
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn parse_model_list(value: &Value) -> Result<Vec<ModelDiscoveredModel>, ModelPluginError> {
    let Some(items) = value.get("data").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut models = Vec::new();
    for item in items {
        let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };

        let entry =
            catalog_entry(id).map_err(|error| model_error("plugin_internal", error, false))?;
        let display_name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| entry.as_ref().and_then(|entry| entry.display_name.clone()))
            .or_else(|| Some(id.to_string()));

        let capabilities_json = normalized_capabilities(entry.as_ref())
            .map_err(|error| model_error("plugin_internal", error, false))?;

        models.push(ModelDiscoveredModel {
            id: id.to_string(),
            display_name,
            context_window: item
                .get("context_length")
                .and_then(Value::as_u64)
                .or_else(|| entry.as_ref().and_then(|entry| entry.context_window)),
            max_output_tokens: item
                .get("max_output_tokens")
                .and_then(Value::as_u64)
                .or_else(|| entry.as_ref().and_then(|entry| entry.max_output_tokens)),
            capabilities_json: Some(capabilities_json),
            raw_metadata: serde_json::to_string(item).ok(),
        });
    }

    models.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(models)
}

impl model_world::exports::account_model_source::Guest for Component {
    fn discover(
        provider_id: String,
        account: ModelAccountRef,
        base_url: String,
        models_path: String,
    ) -> Result<Vec<ModelDiscoveredModel>, ModelPluginError> {
        if account.provider_id != provider_id {
            return Err(model_error(
                "invalid_configuration",
                "model discovery account does not belong to the requested provider",
                false,
            ));
        }

        let request = ModelHttpRequest {
            method: "GET".into(),
            url: join_url(&base_url, &models_path),
            headers: vec![("accept".into(), "application/json".into())],
            body: Vec::new(),
            credential: Some(ModelCredentialRef::Account(account)),
        };

        let response = send_request(&request)?;
        if response.body_truncated {
            return Err(model_error(
                "upstream_unavailable",
                "B.AI model catalog response was truncated",
                true,
            ));
        }

        let body = String::from_utf8(response.body)
            .map_err(|_| model_error("protocol_error", "B.AI model catalog is not UTF-8", false))?;
        if response.status != 200 {
            let (code, retryable) = match response.status {
                401 | 403 => ("credential_expired", false),
                429 => ("rate_limited", true),
                status if status >= 500 => ("upstream_unavailable", true),
                _ => ("protocol_error", false),
            };
            return Err(model_error(
                code,
                format!("B.AI model catalog returned HTTP {}", response.status),
                retryable,
            ));
        }

        let value: Value = serde_json::from_str(&body).map_err(|error| {
            model_error(
                "protocol_error",
                format!("invalid B.AI model catalog JSON: {error}"),
                false,
            )
        })?;
        let models = parse_model_list(&value)?;
        if models.is_empty() {
            return Err(model_error(
                "protocol_error",
                "B.AI model catalog contained no usable models",
                false,
            ));
        }
        Ok(models)
    }
}

model_world::export!(Component with_types_in kinetix_plugin_sdk::model_source);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_discovery_uses_live_bai_models_endpoint_with_account_credential() {
        TEST_RESPONSE.with(|slot| {
            *slot.borrow_mut() = Some(ModelHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({
                    "object": "list",
                    "data": [{"id": "DeepSeek-V4.1-Flash", "object": "model"}]
                })
                .to_string()
                .into_bytes(),
                body_truncated: false,
            });
        });

        let models = <Component as model_world::exports::account_model_source::Guest>::discover(
            "provider-1".into(),
            ModelAccountRef {
                provider_id: "provider-1".into(),
                account_id: "account-1".into(),
            },
            "".into(),
            "".into(),
        )
        .unwrap();

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "DeepSeek-V4.1-Flash");
        TEST_REQUEST.with(|slot| {
            let request = slot.borrow();
            let (url, has_credential) = request.as_ref().unwrap();
            assert_eq!(url, "https://api.b.ai/v1/models");
            assert!(*has_credential);
        });
    }

    #[test]
    fn enriches_deepseek_v41_flash_from_exact_catalog_match() {
        let value = serde_json::json!({
            "object": "list",
            "data": [{"id": "DeepSeek-V4.1-Flash", "object": "model"}]
        });
        let models = parse_model_list(&value).unwrap();
        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model.context_window, Some(1_000_000));
        assert_eq!(model.max_output_tokens, Some(384_000));

        let capabilities =
            ModelCapabilitiesV1::from_json(model.capabilities_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            capabilities
                .reasoning
                .as_ref()
                .and_then(|reasoning| reasoning.default),
            Some(ReasoningLevel::High)
        );
        assert_eq!(
            capabilities.tools.as_ref().map(|tools| tools.supported),
            Some(true)
        );
        assert_eq!(
            capabilities.vision.as_ref().map(|vision| vision.input),
            Some(true)
        );
    }

    #[test]
    fn documented_routed_ids_keep_alias_specific_metadata() {
        let text = catalog_entry("DeepSeek-V4-Flash").unwrap().unwrap();
        let vision = catalog_entry("DeepSeek-V4-Flash-Vision-Exp")
            .unwrap()
            .unwrap();
        let current = catalog_entry("DeepSeek-V4.1-Flash").unwrap().unwrap();

        assert_eq!(text.vision, Some(false));
        assert_eq!(vision.vision, Some(true));
        assert_eq!(current.vision, Some(true));
        assert!(text.structured_output.is_none());
        assert_eq!(vision.structured_output, Some(true));
        assert_eq!(current.structured_output, Some(true));
        assert!(catalog_entry("deepseek-v4.1-flash").unwrap().is_none());
    }

    #[test]
    fn legacy_text_alias_does_not_inherit_v41_vision() {
        let value = serde_json::json!({
            "data": [{"id": "DeepSeek-V4-Flash"}]
        });

        let models = parse_model_list(&value).unwrap();
        let capabilities =
            ModelCapabilitiesV1::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();

        assert_eq!(
            capabilities.vision.as_ref().map(|vision| vision.input),
            Some(false)
        );
        assert!(capabilities.structured_output.is_none());
    }

    #[test]
    fn unknown_live_models_stay_available_and_unknown() {
        let value = serde_json::json!({
            "data": [{"id": "future-model"}]
        });
        let models = parse_model_list(&value).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "future-model");
        assert!(models[0].context_window.is_none());
        assert!(models[0].max_output_tokens.is_none());

        let capabilities =
            ModelCapabilitiesV1::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        assert!(capabilities.reasoning.is_none());
        assert!(capabilities.tools.is_none());
        assert!(capabilities.vision.is_none());
        assert!(capabilities.structured_output.is_none());
    }

    #[test]
    fn catalog_does_not_create_availability() {
        let value = serde_json::json!({"object": "list", "data": []});
        assert!(parse_model_list(&value).unwrap().is_empty());
    }

    #[test]
    fn manifest_reuses_native_openai_adapter() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains("wire_format = \"openai\""));
        assert!(!manifest.contains("provider_adapters"));
    }
}
