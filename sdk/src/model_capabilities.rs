//! Versioned normalized metadata for `DiscoveredModel.capabilities_json`.
//!
//! Plugin API v1 still carries capability metadata as an optional JSON string.
//! These types give producers and consumers a strict shared schema without
//! changing the WIT ABI.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

pub const MODEL_CAPABILITIES_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilitiesV1 {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<SupportCapability>,
}

impl Default for ModelCapabilitiesV1 {
    fn default() -> Self {
        Self {
            schema_version: MODEL_CAPABILITIES_SCHEMA_VERSION,
            transport: None,
            reasoning: None,
            tools: None,
            vision: None,
            structured_output: None,
        }
    }
}

impl ModelCapabilitiesV1 {
    pub fn is_empty(&self) -> bool {
        self.transport.is_none()
            && self.reasoning.is_none()
            && self.tools.is_none()
            && self.vision.is_none()
            && self.structured_output.is_none()
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if self.schema_version != MODEL_CAPABILITIES_SCHEMA_VERSION {
            return Err(CapabilityMetadataError::validation(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, MODEL_CAPABILITIES_SCHEMA_VERSION
            )));
        }

        if let Some(transport) = &self.transport {
            if transport.format.trim().is_empty() {
                return Err(CapabilityMetadataError::validation(
                    "transport.format must not be empty",
                ));
            }
        }

        if let Some(reasoning) = &self.reasoning {
            reasoning.validate()?;
        }

        Ok(())
    }

    pub fn to_json(&self) -> Result<String, CapabilityMetadataError> {
        self.validate()?;
        serde_json::to_string(self).map_err(CapabilityMetadataError::Json)
    }

    pub fn from_json(value: &str) -> Result<Self, CapabilityMetadataError> {
        let metadata: Self =
            serde_json::from_str(value).map_err(CapabilityMetadataError::Json)?;
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportCapability {
    pub format: String,
}

impl TransportCapability {
    pub fn new(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportCapability {
    pub supported: bool,
}

impl SupportCapability {
    pub fn new(supported: bool) -> Self {
        Self { supported }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisionCapability {
    pub input: bool,
}

impl VisionCapability {
    pub fn new(input: bool) -> Self {
        Self { input }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningMode {
    Toggle,
    Level,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasoningLevel {
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "xhigh")]
    XHigh,
}

impl ReasoningLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minimal" => Some(Self::Minimal),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::XHigh),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningCapability {
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ReasoningMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub levels: Option<Vec<ReasoningLevel>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<ReasoningLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_disable: Option<bool>,
}

impl ReasoningCapability {
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            mode: None,
            levels: None,
            default: None,
            can_disable: None,
        }
    }

    pub fn supported_unknown() -> Self {
        Self {
            supported: true,
            mode: None,
            levels: None,
            default: None,
            can_disable: None,
        }
    }

    pub fn toggle(can_disable: bool) -> Self {
        Self {
            supported: true,
            mode: Some(ReasoningMode::Toggle),
            levels: None,
            default: None,
            can_disable: Some(can_disable),
        }
    }

    pub fn level(
        levels: Vec<ReasoningLevel>,
        default: Option<ReasoningLevel>,
        can_disable: bool,
    ) -> Self {
        Self {
            supported: true,
            mode: Some(ReasoningMode::Level),
            levels: Some(levels),
            default,
            can_disable: Some(can_disable),
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if !self.supported {
            if self.mode.is_some()
                || self.levels.is_some()
                || self.default.is_some()
                || self.can_disable.is_some()
            {
                return Err(CapabilityMetadataError::validation(
                    "unsupported reasoning must not declare mode, levels, default, or can_disable",
                ));
            }
            return Ok(());
        }

        match self.mode {
            None => {
                if self.levels.is_some() || self.default.is_some() {
                    return Err(CapabilityMetadataError::validation(
                        "reasoning levels/default require mode=level",
                    ));
                }
            }
            Some(ReasoningMode::Toggle) => {
                if self.levels.is_some() || self.default.is_some() {
                    return Err(CapabilityMetadataError::validation(
                        "toggle reasoning must not declare levels or default",
                    ));
                }
            }
            Some(ReasoningMode::Level) => {
                let levels = self.levels.as_ref().ok_or_else(|| {
                    CapabilityMetadataError::validation(
                        "level reasoning requires a non-empty levels list",
                    )
                })?;
                if levels.is_empty() {
                    return Err(CapabilityMetadataError::validation(
                        "level reasoning requires a non-empty levels list",
                    ));
                }
                let unique: HashSet<ReasoningLevel> = levels.iter().copied().collect();
                if unique.len() != levels.len() {
                    return Err(CapabilityMetadataError::validation(
                        "reasoning levels must not contain duplicates",
                    ));
                }
                if let Some(default) = self.default {
                    if !levels.contains(&default) {
                        return Err(CapabilityMetadataError::validation(
                            "reasoning default must be present in levels",
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum CapabilityMetadataError {
    Json(serde_json::Error),
    Validation(String),
}

impl CapabilityMetadataError {
    fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
}

impl fmt::Display for CapabilityMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid capability metadata JSON: {error}"),
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CapabilityMetadataError {}
