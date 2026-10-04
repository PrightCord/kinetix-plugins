# Kinetix Plugin SDK (Rust)

Author-facing Rust bindings for the Kinetix plugin ABI. The canonical ABI lives at `../wit/kinetix-plugin.wit`; the SDK keeps a synchronized copy in `sdk/wit/` for `wit-bindgen`.

Host/runtime architecture is documented in the main [Kinetix repository](https://github.com/PrightCord/kinetix/blob/main/docs/KINETIX-PLUGIN-ARCHITECTURE.md). Host imports, permissions, limits, and adversarial consumer fixtures follow the [WASM capability security contract](../docs/wasm-capability-security-v1.md).

## Build a plugin component

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Use `scripts/build-plugin.sh plugins/<plugin>` from the repository root to wrap the compiled component into a deterministic `.kxp` package.

The ABI is the WIT interface, not this crate. Breaking changes require a new `plugin_api` major; deployed API v1 and v2 packages retain their existing contracts.

## Plugin/core ownership

Plugins implement provider mechanisms: authorization steps, credential resolution, discovery, health observations, request/response translation, and deterministic routing facts. They report results; they do not choose accounts, models, or runtime targets.

Kinetix core owns scheduling, observation and credential persistence, health interpretation, retry/fallback, concurrency, cache affinity, and target selection. `host-storage` holds plugin-private state; core persists account health, model inventory, and credentials. `health-observation` and `quota-snapshot` are evidence, and `routing-fact` informs core policy without selecting a target. Adapter inputs describe the provider/model already selected by core. API v1 and v2 retain their existing host-import contracts. API v3 adapters have no host imports; core supplies reserved `_kinetix` context in `provider-json` (account ID, host time, and a non-secret project ID when available) rather than letting adapters read storage or a clock.

`sdk/tests/policy_boundary.rs` guards versioned WIT operations and import contracts. `scripts/test_adapter_component_runtime.sh` invokes the compiled Antigravity v3 adapter with every host import set to trap. Provider conformance tests live in `adapter-conformance/`.

## Session-aware adapter APIs v2 and v3

Keep existing plugins on `plugin_api = "1"` and the `adapter` bindings. Existing session-aware API v2 packages keep `kinetix_plugin_sdk::adapter_v2` (`plugin-adapter-v2` in `kinetix:plugin@2.0.0`) and their host imports. New plugins that need the import-free adapter contract use `kinetix_plugin_sdk::adapter_v3` (`plugin-adapter-v3` in `kinetix:plugin@3.0.0`) and declare `plugin_api = "3"`. API v3 retains the session-aware adapter signatures, removes host imports, and receives reserved `_kinetix` context from core. Hosts can support API v1, v2, and v3 concurrently; older hosts reject API majors they do not support.

## Capability metadata

Use the SDK's versioned model capability types for `DiscoveredModel.capabilities_json`, and declare integration-wide features and protocols in `plugin.toml`. See [plugin capability contracts](../docs/plugin-capabilities.md) for scope, validation, and compatibility details. The WIT field remains an optional string, so plugin API v1 is unchanged.

## Tool-schema compatibility

Protocol translation belongs to plugins. Core retains the canonical client schema; adapters select an SDK profile and policy:

```rust,ignore
use kinetix_plugin_sdk::schema::{self, SchemaMode, SchemaProfile};
let parameters = schema::translate_tool_parameters(&parameters, SchemaProfile::Antigravity, SchemaMode::Compatible)?;
```

`Strict` preserves or translates losslessly, otherwise rejects. `Compatible` allows the profile's lossy transformations. `permissive` parses as a backwards-compatible alias. This policy is independent of an upstream `strict: true` tool flag.

Antigravity's `v1internal` profile inlines root-local references, converts `const` to `enum`, normalizes nullable schemas and safely merges `allOf`. Conflicting intersections and scoped references are rejected. Compatible mode widens recursive-reference edges, widens `oneOf` to `anyOf` and positional tuples to homogeneous items, strips unsupported validation features (including string/object/array bounds and `patternProperties`), cleans invalid required entries, and repairs typed empty objects with an optional `_placeholder` boolean property. Stripping `patternProperties` also removes its `additionalProperties` fallback so formerly matching dynamic keys are not newly forbidden. Such repairs can weaken validation or change available argument shapes; clients must still validate tool arguments against their original schema. Strict mode rejects recursive inlining, overlapping exclusive unions, tuple approximation and placeholder repairs.

Missing array items become `{}`, preserving unrestricted elements. `translate_tool_parameters` enforces a root argument object, including no-argument schemas `{}`; explicit non-object roots are rejected. Nested unconstrained value schemas `{}` remain unrestricted. Use `translate` when translating a general value schema rather than function parameters. Names under `properties` and values inside `enum`, defaults and examples are data, never schema keywords. Both modes reject unknown keywords and invalid keyword values. Reference expansion and traversal are bounded.

`Gemini` targets Google's JSON Schema `parametersJsonSchema`, not its legacy OpenAPI `parameters` field. `OpenAI` and `OpenAIResponses` target their respective APIs' function parameters; `Anthropic` and `OpenAICompatible` target ordinary, non-strict JSON Schema tool inputs. These profiles currently preserve known JSON Schema validation features and recursive local references; they do not inherit Antigravity's degradation. They are not certifications of every model's accepted subset. Constrained-decoding modes and endpoint-specific restrictions need separately verified profiles, not guessed stripping rules. Antigravity and OpenCode Free use the shared translator; host-native adapters are unchanged.

Profile references: [Gemini function declarations](https://ai.google.dev/api/generate-content#FunctionDeclaration), [OpenAI function calling](https://platform.openai.com/docs/guides/function-calling), [Anthropic tool definitions](https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/implement-tool-use). Antigravity's compatibility passes draw on [OmniRoute's Gemini helper](https://github.com/diegosouzapw/OmniRoute/blob/main/open-sse/translator/helpers/geminiHelper.ts), but retain the existing adapter's JSON Schema behavior for `pattern`, `anyOf`, type unions and `additionalProperties` instead of copying legacy OpenAPI-field degradation.

`sdk/tests/schema_compat.rs` tests exact upstream schemas and forbidden fields using `sdk/tests/fixtures/schema-compat/corpus.json`. Fixture provenance distinguishes real tool contracts from representative generated shapes. The compiled v3 adapter replays the same corpus in `scripts/test_adapter_component_runtime.sh`.

## OAuth lifecycle

`kinetix_plugin_sdk::oauth` provides provider-neutral helpers for checked expiry arithmetic, RFC3339 expiry parsing, token-response validation and rotation, persisted credential state, and refresh-error classification. Providers still own their authorization protocol and KV key selection.

```rust,ignore
let tokens = kinetix_plugin_sdk::oauth::parse_token_response(body, previous_refresh, now_ms)?;
if kinetix_plugin_sdk::oauth::needs_refresh(expires_at_ms, now_ms, refresh_lead_ms) {
    // Refresh using the provider-specific endpoint, then persist the full state.
}
```

## Versioned health quota observations

The optional `plugin-health-v2` world exposes `HealthObservationV2` and multiple `QuotaSnapshotV1` values without changing the legacy health-probe ABI. Plugins can export both worlds; hosts must opt into v2 to read snapshots, while older plugins continue using `plugin`.

Quota is evidence, not a routing decision. Missing fields and an empty snapshot list mean unknown, never zero or full. Use account scope only when the provider establishes it; model scope requires the exact provider model ID. Preserve provider groups and bucket IDs without inferring scope. Report only provider-supplied amounts, units, windows, and RFC3339 reset times. Amounts are finite, non-negative, and may be fractional; `remaining_fraction` is in `[0, 1]`.
