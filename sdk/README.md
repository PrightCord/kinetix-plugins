# Kinetix Plugin SDK (Rust)

Author-facing Rust bindings for the Kinetix plugin ABI. The canonical ABI lives at `../wit/kinetix-plugin.wit`; the SDK keeps a synchronized copy in `sdk/wit/` for `wit-bindgen`.

Host/runtime architecture is documented in the main [Kinetix repository](https://github.com/PrightCord/kinetix/blob/main/docs/KINETIX-PLUGIN-ARCHITECTURE.md).

## Build a plugin component

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Use `scripts/build-plugin.sh plugins/<plugin>` from the repository root to wrap the compiled component into a deterministic `.kxp` package.

The ABI is the WIT interface, not this crate.

## Normalized model capabilities

Model-source plugins should encode `DiscoveredModel.capabilities_json` with the SDK's strict `ModelCapabilitiesV1` types instead of provider-specific JSON. See [Model capability metadata v1](../docs/model-capabilities-v1.md).

`ModelCapabilitiesV1::to_json()` and `from_json()` validate the schema version and reasoning invariants. The WIT field remains an optional string, so plugin API v1 is unchanged.
