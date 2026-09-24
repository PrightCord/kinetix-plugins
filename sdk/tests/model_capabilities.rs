use kinetix_plugin_sdk::model_capabilities::{
    ModelCapabilitiesV1, ReasoningCapability, ReasoningLevel, SupportCapability,
    TransportCapability, VisionCapability,
};

#[test]
fn round_trips_full_v1_metadata() {
    let mut capabilities = ModelCapabilitiesV1::default();
    capabilities.transport = Some(TransportCapability::new("openai-responses"));
    capabilities.reasoning = Some(ReasoningCapability::level(
        vec![
            ReasoningLevel::Minimal,
            ReasoningLevel::Low,
            ReasoningLevel::Medium,
            ReasoningLevel::High,
            ReasoningLevel::XHigh,
        ],
        Some(ReasoningLevel::Medium),
        true,
    ));
    capabilities.tools = Some(SupportCapability::new(true));
    capabilities.vision = Some(VisionCapability::new(true));
    capabilities.structured_output = Some(SupportCapability::new(false));

    let encoded = capabilities.to_json().unwrap();
    let decoded = ModelCapabilitiesV1::from_json(&encoded).unwrap();
    assert_eq!(decoded, capabilities);
}

#[test]
fn supported_reasoning_without_mode_stays_unknown() {
    let mut capabilities = ModelCapabilitiesV1::default();
    capabilities.reasoning = Some(ReasoningCapability::supported_unknown());

    let encoded = capabilities.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["reasoning"]["supported"], true);
    assert!(value["reasoning"].get("mode").is_none());
    assert!(value["reasoning"].get("levels").is_none());
    assert!(value["reasoning"].get("default").is_none());
}

#[test]
fn toggle_reasoning_is_distinct_from_level_reasoning() {
    let mut capabilities = ModelCapabilitiesV1::default();
    capabilities.reasoning = Some(ReasoningCapability::toggle(true));

    let encoded = capabilities.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["reasoning"]["mode"], "toggle");
    assert!(value["reasoning"].get("levels").is_none());
}

#[test]
fn rejects_invalid_or_unknown_v1_metadata() {
    for invalid in [
        r#"{"schema_version":2}"#,
        r#"{"schema_version":1,"unknown":true}"#,
        r#"{"schema_version":1,"reasoning":{"supported":true,"mode":"level"}}"#,
        r#"{"schema_version":1,"reasoning":{"supported":true,"mode":"toggle","levels":["low"]}}"#,
        r#"{"schema_version":1,"reasoning":{"supported":true,"mode":"level","levels":["low"],"default":"high"}}"#,
        r#"{"schema_version":1,"reasoning":{"supported":true,"mode":"level","levels":["ultra"]}}"#,
    ] {
        assert!(ModelCapabilitiesV1::from_json(invalid).is_err(), "{invalid}");
    }
}
