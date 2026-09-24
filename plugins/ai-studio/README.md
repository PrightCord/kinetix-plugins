# Google AI Studio

First-party Kinetix integration for the Gemini API exposed by Google AI Studio.

- Base URL: `https://generativelanguage.googleapis.com/v1beta`
- Wire format: Kinetix native `gemini`
- Authentication: API key in `x-goog-api-key`
- Discovery: live `GET /models?pageSize=1000`, limited to models advertising `generateContent`
- Metadata: provider-native model limits/reasoning observations first, then Kinetix can enrich remaining fields from models.dev
- Custom provider adapter: none

The plugin owns provider setup and discovery only. Generic Gemini request/response translation stays in Kinetix core.

## Credential permission

Plugin API v1 can host-inject account credentials only as Bearer authorization. AI Studio requires `x-goog-api-key`, so this discovery plugin requests plaintext credential read and writes the API key only to that header for the provider's approved Google host. The provider itself still uses Kinetix's `custom_header` auth scheme for inference.

## Pricing

The plugin does not emit a static price override. Google AI Studio can bill the same model differently on free, standard paid, batch/flex, and priority tiers, and Gemini 3.8 Flash pricing changes on January 1, 2027. Kinetix should therefore use provider metadata when available, then models.dev/admin pricing instead of letting this plugin pin a tier-specific rate.

## Build

```sh
rustup target add wasm32-unknown-unknown
bash scripts/build-plugin.sh plugins/ai-studio
```
