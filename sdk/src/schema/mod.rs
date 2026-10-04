//! Tool-schema compatibility belongs to plugins, not the host's canonical schema.
//! See `sdk/README.md` for policy and profile contracts.

mod normalize;
mod policy;
mod profiles;
mod repair;
mod transform;
mod validate;
mod walk;

pub use policy::{SchemaMode, SchemaProfile};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "schema at {}: {}", self.path, self.message)
    }
}
impl std::error::Error for SchemaError {}

pub(super) fn error(path: &str, message: impl Into<String>) -> SchemaError {
    SchemaError {
        path: path.into(),
        message: message.into(),
    }
}

/// Translate without mutating the client's schema. Unknown keywords fail closed
/// in both modes. `Strict` is translation policy, not an upstream strict-tool flag.
pub fn translate(
    schema: &Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<Value, SchemaError> {
    translate_with_context(schema, profile, mode, false)
}

/// Translate function parameters, whose root must describe an argument object.
/// Unlike `translate`, an untyped root is treated as an object. Nested schemas
/// retain their original value domains. Explicit non-object roots are rejected.
pub fn translate_tool_parameters(
    schema: &Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<Value, SchemaError> {
    translate_with_context(schema, profile, mode, true)
}

fn translate_with_context(
    schema: &Value,
    profile: SchemaProfile,
    mode: SchemaMode,
    tool_parameters: bool,
) -> Result<Value, SchemaError> {
    validate::validate_source(schema)?;
    let mut schema = normalize::normalize(schema, profile, mode)?;
    transform::translate(&mut schema, profile, mode)?;
    if tool_parameters {
        repair::tool_root(&mut schema, mode)?;
    }
    repair::repair(&mut schema, profile, mode)?;
    validate::validate(&schema, profile)?;
    Ok(schema)
}
