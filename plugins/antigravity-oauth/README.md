# Antigravity OAuth

Kinetix plugin for Google Antigravity / Cloud Code Assist. It provides:

- the `antigravity-oauth` credential strategy;
- the `antigravity` AuthFlow;
- account-aware model discovery;
- the `antigravity` (`v1internal`) provider adapter.

## Connect from Kinetix

For the bundled desktop/native Google OAuth client, use a loopback public base URL such as `http://127.0.0.1:8080`, bind the provider to this plugin, then use **Connect** from Plugins & Integrations.

For a remote deployment behind a reverse proxy or Cloudflare Tunnel, configure both **Google OAuth Client ID** and **Google OAuth Client Secret** in the plugin settings using a Google OAuth **Web application** client. Register Kinetix's callback URL exactly as an authorized redirect URI, for example:

```text
https://kinetix.example.com/admin/api/plugins/auth/callback
```

Custom credentials are treated as a pair. If only one value is configured, authorization fails with an `invalid_configuration` error. The bundled client continues to require a loopback redirect.

```text
provider.credential_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth"
provider.wire_plugin       = "plugin:dev.kinetix.antigravity-oauth/antigravity"
```

## Permissions

The manifest requests:

- outbound HTTP to `accounts.google.com`, `oauth2.googleapis.com`, `www.googleapis.com`, and `daily-cloudcode-pa.googleapis.com`;
- credential scope `credential_strategy:antigravity-oauth`;
- plaintext credential read for OAuth refresh-token exchange.

`credential_read = true` is a materially higher-risk permission and should remain visible in Kinetix permission review.

## Build

```sh
rustup target add wasm32-unknown-unknown
scripts/build-plugin.sh plugins/antigravity-oauth
```
