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

GitHub Actions is validation-only. Production plugin artifacts are built and published locally by maintainers.

## Releases

Plugins are released locally and independently. The release command derives the version from `plugin.toml` and uses a tag in the form:

```text
<plugin-directory>-v<semver>
```

Dry-run the full build/sign/validation path first:

```sh
export KINETIX_PLUGIN_SIGNING_KEY_FILE=~/.config/kinetix/plugin-signing.pem
bash scripts/release-plugin.sh antigravity-oauth
```

Publish after the dry run succeeds:

```sh
bash scripts/release-plugin.sh antigravity-oauth --publish
```

The local release script requires an authenticated `gh` CLI for publishing. It builds from a clean detached source worktree, signs the package locally, validates the WebAssembly component, generates `SHA256SUMS`, creates/pushes the annotated tag, and uploads immutable release assets:

- `<plugin-id>-<version>.kxp` — signed installable package;
- `<plugin-id>-<version>.wasm` — standalone component binary;
- `SHA256SUMS` — hashes for both artifacts.

The signing private key stays on the maintainer machine and never enters GitHub Actions.

A release does **not** automatically make a catalog entry installable. After the signed release exists, update `catalog.json` with its exact distribution URL, SHA-256, publisher key id, and allowed hosts before setting `installable = true`.

## Current plugins

- **Google Antigravity** (`dev.kinetix.antigravity-oauth`) — OAuth credential strategy, account model discovery, and `v1internal` provider adapter.

## Compatibility

The plugin ABI is defined by `wit/kinetix-plugin.wit`. Host-side ABI changes must be coordinated with the Kinetix repository before plugins are released against them.

See [MIGRATION.md](MIGRATION.md) for the original extraction boundary and source revision.
