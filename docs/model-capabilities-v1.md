# Model capability metadata v1

`DiscoveredModel.capabilities_json` is a versioned, normalized description of model semantics. It is not a bag for provider-native fields. Provider discovery payloads belong in `raw_metadata`.

## Shape

```json
{
  "schema_version": 1,
  "transport": {
    "format": "openai-responses"
  },
  "reasoning": {
    "supported": true,
    "mode": "level",
    "levels": ["minimal", "low", "medium", "high", "xhigh"],
    "default": "medium",
    "can_disable": true
  },
  "tools": {
    "supported": true
  },
  "vision": {
    "input": true
  },
  "structured_output": {
    "supported": false
  }
}
```

Every section except `schema_version` is optional. Omission means unknown/not reported; it does **not** mean false.

### Transport

`transport.format` is a non-empty canonical transport identifier for this model, such as `openai`, `openai-responses`, or `claude`. It is per-model metadata.

### Reasoning

- `supported`: whether reasoning is known to be supported.
- `mode`: optional `toggle` or `level`.
- `levels`: only valid with `mode: "level"`; canonical values are `minimal`, `low`, `medium`, `high`, and `xhigh`.
- `default`: optional member of `levels`.
- `can_disable`: whether reasoning can be explicitly disabled.

`{"supported": true}` is valid and means only that reasoning exists. It must not be expanded into an invented effort ladder. Toggle-only reasoning uses `mode: "toggle"` and has no `levels`.

### Other sections

- `tools.supported`: tool/function calling support when known.
- `vision.input`: image/vision input support when known.
- `structured_output.supported`: structured-output support when known.

## Validation

The Rust SDK exposes `ModelCapabilitiesV1::to_json()` and `ModelCapabilitiesV1::from_json()`. Both enforce the v1 invariants:

- `schema_version` must be exactly `1`;
- unknown v1 fields and enum values are rejected;
- `transport.format` must be non-empty;
- unsupported reasoning cannot carry mode/level details;
- toggle reasoning cannot carry levels/default;
- level reasoning requires a non-empty, duplicate-free level list;
- a reasoning default must exist in the level list.

Provider-specific values that cannot be mapped confidently are omitted from normalized metadata and remain available in `raw_metadata`.

## API compatibility

This schema does not change the WIT ABI. Plugin API v1 still carries `capabilities_json` and `raw_metadata` as optional strings, so existing API-v1 components remain loadable. Producers opt into the normalized schema by emitting `schema_version: 1`; consumers can then enrich Kinetix models without provider-specific parsing.
