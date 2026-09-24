//! Kinetix Google AI Studio provider integration.
//!
//! The plugin owns authenticated model discovery only. Inference continues to
//! use Kinetix's native Gemini adapter.

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::model_capabilities::{
    ModelCapabilitiesV1, ReasoningCapability, TransportCapability,
};
use kinetix_plugin_sdk::{export, exports, kinetix};
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";
const DEFAULT_MODELS_PATH: &str = "/models?pageSize=1000";

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
fn read_api_key(credential: &ModelCredentialRef) -> Result<String, ModelPluginError> {
    model_world::kinetix::plugin::host_credential::read(credential).map_err(|error| {
        model_error(
            "credential_expired",
            format!("reading AI Studio API key: {}", error.message),
            error.retryable,
        )
    })
}

#[cfg(not(test))]
fn send_request(request: &ModelHttpRequest) -> Result<ModelHttpResponse, ModelPluginError> {
    model_world::kinetix::plugin::host_http::send(request)
        .map_err(|error| model_error(&error.code, error.message, error.retryable))
}

#[cfg(test)]
thread_local! {
    static TEST_API_KEY: RefCell<String> = RefCell::new("test-key".into());
    static TEST_RESPONSE: RefCell<Option<ModelHttpResponse>> = const { RefCell::new(None) };
    static TEST_REQUEST: RefCell<Option<(String, Vec<(String, String)>)>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
fn read_api_key(_credential: &ModelCredentialRef) -> Result<String, ModelPluginError> {
    TEST_API_KEY.with(|value| Ok(value.borrow().clone()))
}

#[cfg(test)]
fn send_request(request: &ModelHttpRequest) -> Result<ModelHttpResponse, ModelPluginError> {
    TEST_REQUEST.with(|slot| {
        *slot.borrow_mut() = Some((request.url.clone(), request.headers.clone()));
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

fn normalized_capabilities(item: &Value) -> Result<String, ModelPluginError> {
    let mut capabilities = ModelCapabilitiesV1::default();
    capabilities.transport = Some(TransportCapability::new("gemini"));
    if let Some(thinking) = item.get("thinking").and_then(Value::as_bool) {
        capabilities.reasoning = Some(if thinking {
            ReasoningCapability::supported_unknown()
        } else {
            ReasoningCapability::unsupported()
        });
    }
    capabilities.to_json().map_err(|error| {
        model_error(
            "plugin_internal",
            format!("invalid normalized model capabilities: {error}"),
            false,
        )
    })
}

fn supports_generate_content(item: &Value) -> bool {
    item.get("supportedGenerationMethods")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .any(|method| method.as_str() == Some("generateContent"))
        })
}

fn parse_model_list(value: &Value) -> Result<Vec<ModelDiscoveredModel>, ModelPluginError> {
    let Some(items) = value.get("models").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut models = Vec::new();
    for item in items {
        if !supports_generate_content(item) {
            continue;
        }

        let Some(resource_name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let id = resource_name
            .strip_prefix("models/")
            .unwrap_or(resource_name);
        if id.trim().is_empty() {
            continue;
        }

        let display_name = item
            .get("displayName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or(id)
            .to_string();

        models.push(ModelDiscoveredModel {
            id: id.to_string(),
            display_name: Some(display_name),
            context_window: item.get("inputTokenLimit").and_then(Value::as_u64),
            max_output_tokens: item.get("outputTokenLimit").and_then(Value::as_u64),
            capabilities_json: Some(normalized_capabilities(item)?),
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

        let credential_ref = ModelCredentialRef::Account(account);
        let api_key = read_api_key(&credential_ref)?;
        if api_key.trim().is_empty() {
            return Err(model_error(
                "credential_expired",
                "AI Studio API key is empty",
                false,
            ));
        }

        let request = ModelHttpRequest {
            method: "GET".into(),
            url: join_url(&base_url, &models_path),
            headers: vec![
                ("accept".into(), "application/json".into()),
                ("x-goog-api-key".into(), api_key),
            ],
            body: Vec::new(),
            credential: None,
        };

        let response = send_request(&request)?;
        if response.body_truncated {
            return Err(model_error(
                "upstream_unavailable",
                "AI Studio model catalog response was truncated",
                true,
            ));
        }

        let body = String::from_utf8(response.body).map_err(|_| {
            model_error(
                "protocol_error",
                "AI Studio model catalog is not UTF-8",
                false,
            )
        })?;
        if response.status != 200 {
            let (code, retryable) = match response.status {
                401 | 403 => ("credential_expired", false),
                429 => ("rate_limited", true),
                status if status >= 500 => ("upstream_unavailable", true),
                _ => ("protocol_error", false),
            };
            return Err(model_error(
                code,
                format!("AI Studio model catalog returned HTTP {}", response.status),
                retryable,
            ));
        }

        let value: Value = serde_json::from_str(&body).map_err(|error| {
            model_error(
                "protocol_error",
                format!("invalid AI Studio model catalog JSON: {error}"),
                false,
            )
        })?;
        let models = parse_model_list(&value)?;
        if models.is_empty() {
            return Err(model_error(
                "protocol_error",
                "AI Studio model catalog contained no usable models",
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
    fn account_discovery_uses_google_endpoint_and_api_key_header() {
        TEST_RESPONSE.with(|slot| {
            *slot.borrow_mut() = Some(ModelHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({
                    "models": [{
                        "name": "models/gemini-3.8-flash",
                        "displayName": "Gemini 3.8 Flash",
                        "inputTokenLimit": 1048576,
                        "outputTokenLimit": 65536,
                        "supportedGenerationMethods": ["generateContent", "countTokens"],
                        "thinking": true
                    }]
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
        TEST_REQUEST.with(|slot| {
            let request = slot.borrow();
            let (url, headers) = request.as_ref().unwrap();
            assert_eq!(
                url,
                "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"
            );
            assert!(headers
                .iter()
                .any(|(name, value)| name == "x-goog-api-key" && value == "test-key"));
        });
    }

    #[test]
    fn parses_gemini_38_flash_style_fixture_without_inventing_capabilities() {
        let value = serde_json::json!({
            "models": [{
                "name": "models/gemini-3.8-flash",
                "displayName": "Gemini 3.8 Flash",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 65536,
                "supportedGenerationMethods": ["generateContent", "countTokens"],
                "thinking": true
            }]
        });

        let models = parse_model_list(&value).unwrap();
        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model.id, "gemini-3.8-flash");
        assert_eq!(model.context_window, Some(1_048_576));
        assert_eq!(model.max_output_tokens, Some(65_536));

        let capabilities =
            ModelCapabilitiesV1::from_json(model.capabilities_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            capabilities
                .transport
                .as_ref()
                .map(|transport| transport.format.as_str()),
            Some("gemini")
        );
        assert_eq!(
            capabilities
                .reasoning
                .as_ref()
                .map(|reasoning| reasoning.supported),
            Some(true)
        );
        assert!(capabilities.tools.is_none());
        assert!(capabilities.vision.is_none());
        assert!(capabilities.structured_output.is_none());
    }

    #[test]
    fn filters_out_non_generate_content_models() {
        let value = serde_json::json!({
            "models": [
                {
                    "name": "models/gemini-chat",
                    "supportedGenerationMethods": ["generateContent", "countTokens"]
                },
                {
                    "name": "models/text-embedding-004",
                    "supportedGenerationMethods": ["embedContent"]
                }
            ]
        });

        let models = parse_model_list(&value).unwrap();
        let ids: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();

        assert_eq!(ids, vec!["gemini-chat"]);
    }

    #[test]
    fn provider_metadata_is_preserved_verbatim() {
        let value = serde_json::json!({
            "models": [{
                "name": "models/gemini-test",
                "displayName": "Gemini Test",
                "supportedGenerationMethods": ["generateContent"],
                "vendorField": {"future": true}
            }]
        });
        let models = parse_model_list(&value).unwrap();
        let raw: Value = serde_json::from_str(models[0].raw_metadata.as_deref().unwrap()).unwrap();
        assert_eq!(raw["vendorField"]["future"], true);
    }

    #[test]
    fn manifest_reuses_native_gemini_and_google_api_key_header() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains("wire_format = \"gemini\""));
        assert!(manifest.contains("auth_scheme = \"custom_header\""));
        assert!(manifest.contains("custom_header_name = \"x-goog-api-key\""));
        assert!(!manifest.contains("provider_adapters"));
    }

    #[test]
    fn joins_default_google_models_endpoint() {
        assert_eq!(
            join_url("", ""),
            "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"
        );
    }
}
