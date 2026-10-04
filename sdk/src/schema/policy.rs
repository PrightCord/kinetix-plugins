use super::{error, SchemaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMode {
    /// Preserve semantics, translate losslessly, or reject.
    Strict,
    /// Permit the profile's documented lossy compatibility transformations.
    Compatible,
}

impl std::str::FromStr for SchemaMode {
    type Err = SchemaError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "compatible" | "permissive" => Ok(Self::Compatible),
            _ => Err(error("$", format!("unknown schema mode '{value}'"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaProfile {
    Antigravity,
    /// Gemini's parametersJsonSchema surface, not the legacy OpenAPI parameters field.
    Gemini,
    /// Non-strict function parameters; upstream strict-output rules are separate.
    OpenAI,
    /// Responses API function parameters.
    OpenAIResponses,
    /// Non-strict input_schema; does not inherit Gemini degradation.
    Anthropic,
    /// JSON Schema protocol baseline. Endpoint-specific extensions need a new profile.
    OpenAICompatible,
}
