//! Kinetix plugin: Claude Code OAuth credential strategy.
//!
//! Implements Anthropic's Claude Code OAuth authorization-code flow with PKCE,
//! access-token refresh, and refresh-token rotation. This plugin is deliberately
//! scoped to OAuth/credential lifecycle only.

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::{export, exports, kinetix};

const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
const TOKEN_URL: &str = "https://api.anthropic.com/v1/oauth/token";
const SCOPES: &[&str] = &["org:create_api_key", "user:profile", "user:inference"];

/// 9router refreshes Claude credentials four hours before expiry.
const REFRESH_LEAD_MS: u64 = 14_400_000;
const LEASE_KEY_PREFIX: &str = "lease:";
const STATE_KEY_PREFIX: &str = "cred:";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Credential {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

struct Component;

fn handle_for(provider_id: &str, account_id: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{provider_id}:{account_id}").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn credential_state_key(provider_id: &str, account_id: &str) -> String {
    format!("{STATE_KEY_PREFIX}{}", handle_for(provider_id, account_id))
}

fn credential_from_host(provider_id: &str, account_id: &str) -> Result<Credential, PluginError> {
    let cred_ref = CredentialRef::Account(AccountRef {
        provider_id: provider_id.to_string(),
        account_id: account_id.to_string(),
    });
    let raw = kinetix::plugin::host_credential::read(&cred_ref)
        .map_err(|e| kinetix_plugin_sdk::helpers::error("credential_expired", e.message))?;
    serde_json::from_str(&raw).map_err(|e| {
        kinetix_plugin_sdk::helpers::error(
            "invalid_configuration",
            format!("invalid Claude Code OAuth credential JSON: {e}"),
        )
    })
}

fn load_credential(provider_id: &str, account_id: &str) -> Result<Credential, PluginError> {
    let key = credential_state_key(provider_id, account_id);
    if let Some(raw) = kinetix_plugin_sdk::helpers::kv_get_string(&key) {
        if let Ok(saved) = serde_json::from_str::<Credential>(&raw) {
            if saved
                .refresh_token
                .as_deref()
                .is_some_and(|v| !v.is_empty())
                || saved.access_token.as_deref().is_some_and(|v| !v.is_empty())
            {
                return Ok(saved);
            }
        }
    }
    credential_from_host(provider_id, account_id)
}

fn persist_credential(
    provider_id: &str,
    account_id: &str,
    cred: &Credential,
) -> Result<(), PluginError> {
    let raw = serde_json::to_string(cred).map_err(|e| {
        kinetix_plugin_sdk::helpers::error("plugin_internal", format!("encoding credential: {e}"))
    })?;
    kinetix_plugin_sdk::helpers::kv_put_string(&credential_state_key(provider_id, account_id), &raw)
        .map_err(|e| kinetix_plugin_sdk::helpers::error("plugin_internal", e))
}

fn access_token_valid(cred: &Credential, now_ms: u64) -> bool {
    let Some(token) = cred.access_token.as_deref().filter(|v| !v.is_empty()) else {
        return false;
    };
    let _ = token;
    match cred.expires_at_ms {
        Some(expiry) => expiry.saturating_sub(now_ms) > REFRESH_LEAD_MS,
        None => true,
    }
}

fn format_unix_ms_rfc3339(ms: u64) -> Option<String> {
    const SECONDS_PER_DAY: u64 = 86_400;

    let total_seconds = ms / 1_000;
    let millis = ms % 1_000;
    let days = i64::try_from(total_seconds / SECONDS_PER_DAY).ok()?;
    let seconds_of_day = total_seconds % SECONDS_PER_DAY;

    // Howard Hinnant's civil-from-days conversion, with Unix epoch offset.
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    // RFC3339's date production uses a four-digit year.
    if !(0..=9_999).contains(&year) {
        return None;
    }

    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

fn lease_timing(cred: &Credential) -> (Option<String>, Option<String>) {
    let Some(expiry_ms) = cred.expires_at_ms else {
        return (None, None);
    };

    (
        format_unix_ms_rfc3339(expiry_ms),
        format_unix_ms_rfc3339(expiry_ms.saturating_sub(REFRESH_LEAD_MS)),
    )
}

fn parse_token_response(body: &str, previous_refresh: Option<&str>) -> Result<Credential, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid token JSON: {e}"))?;

    let access_token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "token response missing access_token".to_string())?
        .to_string();

    let refresh_token = value
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| previous_refresh.map(str::to_string));

    let expires_in = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    Ok(Credential {
        access_token: Some(access_token),
        refresh_token,
        expires_at_ms: Some(
            kinetix_plugin_sdk::helpers::now_unix_millis().saturating_add(expires_in * 1000),
        ),
        scope: value
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        token_type: value
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

fn refresh(cred: &Credential) -> Result<Credential, PluginError> {
    let refresh_token = cred
        .refresh_token
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            kinetix_plugin_sdk::helpers::error(
                "credential_expired",
                "Claude Code OAuth credential has no refresh_token",
            )
        })?;

    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    })
    .to_string();

    let req = HttpRequest {
        method: "POST".into(),
        url: TOKEN_URL.into(),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("accept".into(), "application/json".into()),
        ],
        body: body.into_bytes(),
        credential: None,
    };

    let resp = kinetix::plugin::host_http::send(&req).map_err(|e| {
        kinetix_plugin_sdk::helpers::retryable_error(&e.code, e.message, e.retry_after)
    })?;

    if resp.body_truncated {
        return Err(kinetix_plugin_sdk::helpers::retryable_error(
            "upstream_unavailable",
            "Claude OAuth token response was truncated",
            Some(5),
        ));
    }

    let text = String::from_utf8(resp.body).map_err(|_| {
        kinetix_plugin_sdk::helpers::error(
            "protocol_error",
            "Claude OAuth token response is not UTF-8",
        )
    })?;

    if resp.status != 200 {
        let retryable = resp.status >= 500 || resp.status == 429;
        let message = format!("Claude OAuth refresh returned HTTP {}", resp.status);
        return Err(if retryable {
            kinetix_plugin_sdk::helpers::retryable_error("upstream_unavailable", message, Some(5))
        } else {
            kinetix_plugin_sdk::helpers::error("credential_expired", message)
        });
    }

    parse_token_response(&text, Some(refresh_token))
        .map_err(|e| kinetix_plugin_sdk::helpers::error("protocol_error", e))
}

impl exports::credential_strategy::Guest for Component {
    fn resolve(
        provider_id: String,
        account_id: String,
        _account_label: String,
    ) -> Result<CredentialLease, PluginError> {
        let mut cred = load_credential(&provider_id, &account_id)?;
        let now = kinetix_plugin_sdk::helpers::now_unix_millis();

        if !access_token_valid(&cred, now) {
            cred = refresh(&cred)?;
            persist_credential(&provider_id, &account_id, &cred)?;
        }

        let (expires_at, refresh_after) = lease_timing(&cred);

        let access = cred
            .access_token
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                kinetix_plugin_sdk::helpers::error(
                    "credential_expired",
                    "Claude Code OAuth credential has no access_token",
                )
            })?;

        let handle = handle_for(&provider_id, &account_id);
        kinetix_plugin_sdk::helpers::kv_put_string(&format!("{LEASE_KEY_PREFIX}{handle}"), access)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("plugin_internal", e))?;

        Ok(CredentialLease {
            handle,
            expires_at,
            refresh_after,
            health: "healthy".into(),
        })
    }

    fn health(provider_id: String, account_id: String) -> Result<String, PluginError> {
        let cred = load_credential(&provider_id, &account_id)?;
        let now = kinetix_plugin_sdk::helpers::now_unix_millis();
        if access_token_valid(&cred, now)
            || cred.refresh_token.as_deref().is_some_and(|v| !v.is_empty())
        {
            Ok("healthy".into())
        } else {
            Ok("unusable".into())
        }
    }

    fn rotate(provider_id: String, account_id: String) -> Result<(), PluginError> {
        let cred = load_credential(&provider_id, &account_id)?;
        let refreshed = refresh(&cred)?;
        persist_credential(&provider_id, &account_id, &refreshed)
    }
}

// --- Browser/account authorization world ------------------------------------

use kinetix_plugin_sdk::auth as auth_world;

type AuthPluginError = auth_world::kinetix::plugin::types::PluginError;
type AuthHttpRequest = auth_world::kinetix::plugin::types::HttpRequest;
type AuthResult = auth_world::kinetix::plugin::types::AuthResult;

fn auth_error(code: &str, message: impl Into<String>, retryable: bool) -> AuthPluginError {
    AuthPluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn require_flow(flow_name: &str) -> Result<(), AuthPluginError> {
    if flow_name == "claude-code" {
        Ok(())
    } else {
        Err(auth_error(
            "invalid_configuration",
            format!("unknown auth flow '{flow_name}'"),
            false,
        ))
    }
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl auth_world::exports::auth_flow::Guest for Component {
    fn begin(
        flow_name: String,
        redirect_uri: String,
        state: String,
        pkce_challenge: Option<String>,
    ) -> Result<String, AuthPluginError> {
        require_flow(&flow_name)?;
        let challenge = pkce_challenge.filter(|v| !v.is_empty()).ok_or_else(|| {
            auth_error(
                "invalid_configuration",
                "Claude Code OAuth requires PKCE",
                false,
            )
        })?;

        Ok(format!(
            "{AUTHORIZE_URL}?code=true&client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
            url_encode(CLIENT_ID),
            url_encode(&redirect_uri),
            url_encode(&SCOPES.join(" ")),
            url_encode(&challenge),
            url_encode(&state),
        ))
    }

    fn exchange(
        flow_name: String,
        code: String,
        redirect_uri: String,
        pkce_verifier: Option<String>,
    ) -> Result<AuthResult, AuthPluginError> {
        require_flow(&flow_name)?;
        let verifier = pkce_verifier.filter(|v| !v.is_empty()).ok_or_else(|| {
            auth_error(
                "invalid_configuration",
                "Claude Code OAuth requires a PKCE verifier",
                false,
            )
        })?;

        let (auth_code, inline_state) = code
            .split_once('#')
            .map(|(c, s)| (c.to_string(), Some(s.to_string())))
            .unwrap_or((code, None));

        let state = inline_state.ok_or_else(|| {
            auth_error(
                "invalid_configuration",
                "missing OAuth state for Claude token exchange",
                false,
            )
        })?;

        let body = serde_json::json!({
            "code": auth_code,
            "state": state,
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        })
        .to_string();

        let req = AuthHttpRequest {
            method: "POST".into(),
            url: TOKEN_URL.into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("accept".into(), "application/json".into()),
            ],
            body: body.into_bytes(),
            credential: None,
        };

        let resp = auth_world::kinetix::plugin::host_http::send(&req)
            .map_err(|e| auth_error(&e.code, e.message, e.retryable))?;

        if resp.body_truncated {
            return Err(auth_error(
                "upstream_unavailable",
                "Claude OAuth token response was truncated",
                true,
            ));
        }

        let text = String::from_utf8(resp.body).map_err(|_| {
            auth_error(
                "protocol_error",
                "Claude OAuth token response is not UTF-8",
                false,
            )
        })?;

        if resp.status != 200 {
            return Err(auth_error(
                "credential_expired",
                format!("Claude OAuth token exchange returned HTTP {}", resp.status),
                false,
            ));
        }

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| auth_error("protocol_error", format!("invalid token JSON: {e}"), false))?;

        let access_token = value
            .get("access_token")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                auth_error(
                    "protocol_error",
                    "token response missing access_token",
                    false,
                )
            })?
            .to_string();

        let refresh_token = value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                auth_error(
                    "credential_expired",
                    "token response missing refresh_token",
                    false,
                )
            })?
            .to_string();

        let expires_in = value
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let credential = Credential {
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            expires_at_ms: Some(
                auth_world::kinetix::plugin::host_clock::now_unix_millis()
                    .saturating_add(expires_in * 1000),
            ),
            scope: value
                .get("scope")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            token_type: value
                .get("token_type")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };

        let secret_json = serde_json::to_string(&credential).map_err(|e| {
            auth_error(
                "plugin_internal",
                format!("encoding credential: {e}"),
                false,
            )
        })?;

        let metadata_json = serde_json::json!({
            "scope": credential.scope,
            "token_type": credential.token_type,
        })
        .to_string();

        Ok(AuthResult {
            secret_json,
            account_label: Some("Claude Code".into()),
            metadata_json: Some(metadata_json),
        })
    }
}

auth_world::export!(Component with_types_in kinetix_plugin_sdk::auth);

// The base plugin world requires all interfaces to exist even when the manifest
// advertises only credential_strategy.
fn unsupported() -> PluginError {
    kinetix_plugin_sdk::helpers::error("unknown", "capability not provided by this plugin")
}

impl exports::model_source::Guest for Component {
    fn discover(_p: String, _b: String, _m: String) -> Result<Vec<DiscoveredModel>, PluginError> {
        Err(unsupported())
    }
}

impl exports::health_probe::Guest for Component {
    fn probe(_p: String, _a: String) -> Result<HealthObservation, PluginError> {
        Err(unsupported())
    }
}

impl exports::routing_facts::Guest for Component {
    fn facts(_r: String) -> Result<Vec<RoutingFact>, PluginError> {
        Err(unsupported())
    }
}

impl exports::hooks::Guest for Component {
    fn on_request_normalized(_r: String) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_target_candidate(_t: String) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_usage_finalized(_u: String) -> Result<(), PluginError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential_with_expiry(expires_at_ms: Option<u64>) -> Credential {
        Credential {
            access_token: Some("access".into()),
            refresh_token: Some("refresh".into()),
            expires_at_ms,
            scope: None,
            token_type: None,
        }
    }

    #[test]
    fn known_expiry_produces_exact_lease_timing() {
        let cred = credential_with_expiry(Some(1_790_438_400_000));

        let (expires_at, refresh_after) = lease_timing(&cred);

        assert_eq!(expires_at.as_deref(), Some("2026-09-26T16:00:00.000Z"));
        assert_eq!(refresh_after.as_deref(), Some("2026-09-26T12:00:00.000Z"));
    }

    #[test]
    fn missing_expiry_produces_no_lease_timing() {
        let cred = credential_with_expiry(None);

        assert_eq!(lease_timing(&cred), (None, None));
    }

    #[test]
    fn refresh_threshold_matches_access_token_validity() {
        let now = 1_790_400_000_000;
        let expiry = now + 8 * 60 * 60 * 1_000;
        let refresh_after = expiry - REFRESH_LEAD_MS;
        let cred = credential_with_expiry(Some(expiry));

        assert!(access_token_valid(&cred, refresh_after - 1));
        assert!(!access_token_valid(&cred, refresh_after));
        assert!(!access_token_valid(&cred, refresh_after + 1));
    }

    #[test]
    fn short_expiry_saturates_without_underflow() {
        let cred = credential_with_expiry(Some(60 * 60 * 1_000));

        let (expires_at, refresh_after) = lease_timing(&cred);

        assert_eq!(expires_at.as_deref(), Some("1970-01-01T01:00:00.000Z"));
        assert_eq!(refresh_after.as_deref(), Some("1970-01-01T00:00:00.000Z"));
    }

    #[test]
    fn out_of_range_expiry_is_not_fabricated() {
        let cred = credential_with_expiry(Some(u64::MAX));

        assert_eq!(lease_timing(&cred), (None, None));
    }
}

export!(Component with_types_in kinetix_plugin_sdk);
