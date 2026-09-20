# Kinetix Plugins

Official plugin collection, plugin SDK, catalog metadata, and packaging tooling for [Kinetix](https://github.com/PrightCord/kinetix).

This repository is split out of the Kinetix monorepo so plugin development and distribution can evolve independently from the host runtime.

## Repository layout

```text
.
├── plugins/
│   └── antigravity-oauth/
├── sdk/
├── wit/
├── catalog.json
├── trusted-publishers.json
└── scripts/
```

The Kinetix host runtime, dashboard integration, database migrations, and host-side plugin tests remain in `PrightCord/kinetix`.

## Build a plugin

```sh
rustup target add wasm32-unknown-unknown
scripts/build-plugin.sh plugins/antigravity-oauth
```

## Current plugins

- **Google Antigravity** (`dev.kinetix.antigravity-oauth`) — OAuth credential strategy, account model discovery, and `v1internal` provider adapter.

## Compatibility

The plugin ABI is defined by `wit/kinetix-plugin.wit`. Host-side ABI changes must be coordinated with the Kinetix repository before plugins are released against them.

See [MIGRATION.md](MIGRATION.md) for the extraction boundary and source revision.
