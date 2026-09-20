# Kinetix Plugins

Official plugin collection, plugin SDK, catalog metadata, build tooling, and release artifacts for [Kinetix](https://github.com/PrightCord/kinetix).

This repository is split out of the Kinetix monorepo so plugin development, testing, signing, and distribution can evolve independently from the host runtime.

## Repository layout

```text
.
├── plugins/                  # First-party plugin sources
├── sdk/                      # Rust guest SDK
├── wit/                      # Canonical plugin WIT ABI
├── catalog.json              # Authoritative marketplace metadata
├── trusted-publishers.json   # Publisher trust metadata
├── scripts/                  # Build/signing helpers
└── .github/workflows/        # Plugin CI and release automation
```

The Kinetix host runtime, dashboard integration, database migrations, and host-side plugin tests remain in `PrightCord/kinetix`.

## Build plugins

Prerequisites:

- Rust
- `wasm32-unknown-unknown`
- `wasm-tools`

Build one plugin:

```sh
rustup target add wasm32-unknown-unknown
bash scripts/build-plugin.sh plugins/antigravity-oauth
```

That produces two versioned artifacts beside the plugin source:

```text
dev.kinetix.antigravity-oauth-0.1.0.kxp
dev.kinetix.antigravity-oauth-0.1.0.wasm
```

The `.kxp` is the canonical installable Kinetix package. The `.wasm` file is the standalone WebAssembly Component binary contained by that package.

Build every first-party plugin into one output directory:

```sh
bash scripts/build-all.sh --out-dir dist
```

CI performs this full build on pushes and pull requests and uploads the unsigned `.kxp`, `.wasm`, and `SHA256SUMS` files as short-lived workflow artifacts.

## Releases

Plugins are versioned and released independently. Release tags use:

```text
<plugin-directory>-v<semver>
```

For example:

```sh
git tag antigravity-oauth-v0.1.0
git push origin antigravity-oauth-v0.1.0
```

The release workflow verifies that the tag version matches `plugin.toml`, rebuilds from the tagged source, requires the official Ed25519 signing key, and publishes:

- `<plugin-id>-<version>.kxp` — signed installable package;
- `<plugin-id>-<version>.wasm` — standalone component binary;
- `SHA256SUMS` — hashes for both artifacts;
- GitHub build-provenance attestations for the package and component.

Official releases require the repository secret `KINETIX_PLUGIN_SIGNING_KEY_PEM`. Keep the corresponding public key in `trusted-publishers.json`; never commit the private key.

A release does **not** automatically make a catalog entry installable. After the signed release exists, update `catalog.json` with its exact distribution URL, SHA-256, publisher key id, and allowed hosts before setting `installable = true`.

## Current plugins

- **Google Antigravity** (`dev.kinetix.antigravity-oauth`) — OAuth credential strategy, account model discovery, and `v1internal` provider adapter.

## Compatibility

The plugin ABI is defined by `wit/kinetix-plugin.wit`. Host-side ABI changes must be coordinated with the Kinetix repository before plugins are released against them.

See [MIGRATION.md](MIGRATION.md) for the original extraction boundary and source revision.
