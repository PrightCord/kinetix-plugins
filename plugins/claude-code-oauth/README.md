# Claude Code OAuth

Official Kinetix credential plugin for Anthropic's Claude Code OAuth flow.

This plugin is intentionally scoped to **OAuth only**. It provides:

- Claude Code Authorization Code flow with PKCE (S256);
- token exchange at `https://api.anthropic.com/v1/oauth/token`;
- access-token refresh with refresh-token rotation;
- an opaque Kinetix credential lease for the active access token;
- an Anthropic provider template using `https://api.anthropic.com/v1` and carrying the OAuth beta header.

It does **not** modify local Claude Code settings and does not implement request
cloaking, model translation, or a custom provider adapter.

## OAuth contract

The implementation follows the Claude OAuth behavior used by
[`decolua/9router`](https://github.com/decolua/9router):

- client id: `9d1c250a-e61b-44d9-88ed-5944d1962f5e`;
- authorize URL: `https://claude.ai/oauth/authorize`;
- token URL: `https://api.anthropic.com/v1/oauth/token`;
- scopes: `org:create_api_key user:profile user:inference`;
- token exchange and refresh use JSON payloads;
- PKCE method: `S256`;
- refresh begins four hours before expiry;
- a newly returned refresh token replaces the previous one.

## Network permissions

The plugin requires outbound access to:

- `claude.ai` for the browser authorization flow;
- `api.anthropic.com` for token exchange, refresh, and Anthropic API requests.

## Build

```sh
bash scripts/build-plugin.sh plugins/claude-code-oauth
```

The resulting package is `dev.kinetix.claude-code-oauth-0.1.3.kxp`.
