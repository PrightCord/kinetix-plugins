# B.AI

First-party Kinetix integration for B.AI's OpenAI-compatible API.

- Base URL: `https://api.b.ai/v1`
- Wire format: Kinetix native `openai`
- Authentication: Bearer API key
- Discovery: live `GET /models` using the configured account
- Metadata: live availability plus exact-match provider metadata from `models.json`
- Custom provider adapter: none

The local catalog never creates availability. A model must first appear in B.AI's live model list, then the plugin may enrich it. Unknown values remain unknown.

`DeepSeek-V4.1-Flash`, `DeepSeek-V4-Flash`, and `DeepSeek-V4-Flash-Vision-Exp` have separate catalog entries. B.AI documents progressive routing of the older names to V4.1 Flash, so the plugin preserves each documented model's own capabilities until that routing is guaranteed for a request.

## Pricing

The plugin does not flatten B.AI pricing into one static token rate. DeepSeek V4.1 Flash uses time-based Idle/Busy pricing and B.AI may apply promotions or account benefits, which the current Kinetix v1 pricing envelope cannot represent without losing billing semantics. Pricing therefore remains available for lower-priority enrichment/admin configuration instead of overriding it with an inaccurate fixed value.

## Build

```sh
rustup target add wasm32-unknown-unknown
bash scripts/build-plugin.sh plugins/b-ai
```
