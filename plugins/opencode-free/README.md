# OpenCode Free

Kinetix plugin for OpenCode's anonymous free tier.

This integration does **not** require an API key or OAuth account. The plugin:

- discovers currently available free models from `https://opencode.ai/zen/v1/models`;
- keeps only models whose ids end in `-free`, plus known free ids such as `big-pickle`;
- excludes models known to be unavailable upstream;
- routes Muse Spark contributor models to the OpenAI Responses endpoint;
- routes the remaining discovered free models to Chat Completions;
- sends the fixed public OpenCode transport headers expected by the free endpoint.

## Model discovery

The authoritative discovery endpoint is:

```text
GET https://opencode.ai/zen/v1/models
```

OpenCode returns the standard OpenAI list shape:

```json
{
  "object": "list",
  "data": [
    { "id": "mimo-v2.5-free", "object": "model", "owned_by": "opencode" }
  ]
}
```

The plugin never treats the full endpoint catalog as free. Only explicitly free ids are returned.

## Provider-specific metadata

Live discovery remains authoritative. `models.json` only enriches a model after OpenCode returns it, so a removed SKU is never resurrected by the local catalog.

`mimo-v2.6-flash-free` is enriched from sourced MiMo V2.6 Flash metadata for context/output limits, thinking support, tools, and structured output. Fields the plugin cannot source confidently remain unknown.

## Pricing

Every model returned by this plugin is an explicitly free OpenCode model, so discovery emits zero input, output, cache-read, cache-write, and thinking prices through the v1 metadata envelope. Live discovery still controls availability.

## Build

```sh
rustup target add wasm32-unknown-unknown
bash scripts/build-plugin.sh plugins/opencode-free
```

## Authentication & Transport Headers

There is no user credential. `Authorization: Bearer public` is a fixed protocol header used by OpenCode's anonymous transport and is not an API key or account secret.

The adapter automatically injects the required transport headers expected by OpenCode's free endpoint:
- `Authorization: Bearer public`
- `x-opencode-client: desktop`
- `x-opencode-project: default`
- `x-opencode-session: ses_<12-hex-timestamp><14-base62-random>` (synthesized or forwarded)
- `User-Agent: opencode/1.18.31`
