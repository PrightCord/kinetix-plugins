//! Boilerplate helpers shared by plugins.
//!
//! Nothing here changes host-enforced policy; these are conveniences for the
//! plugin author.

use crate::kinetix::plugin::types::PluginError;

/// Build a structured [`PluginError`] with no retry hints.
pub fn error(code: &str, message: impl Into<String>) -> PluginError {
    PluginError {
        code: code.to_string(),
        message: message.into(),
        retryable: false,
        retry_after: None,
        reset_at: None,
    }
}

/// Build a retryable [`PluginError`] with an optional retry-after hint (seconds).
pub fn retryable_error(
    code: &str,
    message: impl Into<String>,
    retry_after_secs: Option<u64>,
) -> PluginError {
    PluginError {
        code: code.to_string(),
        message: message.into(),
        retryable: true,
        retry_after: retry_after_secs,
        reset_at: None,
    }
}

/// A quota/rate-limit error with a reset hint (§17 vocabulary).
pub fn rate_limited(message: impl Into<String>, retry_after_secs: Option<u64>) -> PluginError {
    retryable_error("rate_limited", message, retry_after_secs)
}

/// Read a UTF-8 string from host KV, returning `None` when absent.
pub fn kv_get_string(key: &str) -> Option<String> {
    crate::kinetix::plugin::host_storage::get(key).and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Write a UTF-8 string to host KV.
pub fn kv_put_string(key: &str, value: &str) -> Result<(), String> {
    crate::kinetix::plugin::host_storage::put(key, value.as_bytes())
}

/// Publish a cached routing fact under the reserved `_cache:` namespace (§6.4).
/// The host stamps `observed_at` and enforces `max_age_ms`.
pub fn cache_fact(name: &str, value_json: &str, max_age_ms: u64) -> Result<(), String> {
    crate::kinetix::plugin::host_storage::cache_set(name, value_json, max_age_ms)
}

/// Current Unix time in milliseconds, from the host clock (§4).
pub fn now_unix_millis() -> u64 {
    crate::kinetix::plugin::host_clock::now_unix_millis()
}

/// Emit a redacted, namespaced log line (§18).
pub fn log_info(message: &str) {
    crate::kinetix::plugin::host_log::log(crate::kinetix::plugin::host_log::Level::Info, message);
}

/// Emit a warning log line.
pub fn log_warn(message: &str) {
    crate::kinetix::plugin::host_log::log(crate::kinetix::plugin::host_log::Level::Warn, message);
}
