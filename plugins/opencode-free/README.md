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
