# Plugin repository extraction

This repository is prepared from `PrightCord/kinetix` at source commit:

```
b6d8fcd408a7865bf176f1dd7bd81d6139a84bc7
```

That commit corresponds to Kinetix v0.3.0 and is the compatibility baseline for this extraction.

## Moved into kinetix-plugins

- `plugins/antigravity-oauth/**`
- `plugins/sdk/**` → `sdk/**`
- plugin workspace files → repository root
- plugin catalog/trust metadata → repository root
- plugin packaging/signing scripts → `scripts/**`
- plugin WIT ABI → `wit/**`

## Stays in kinetix

- `src/plugins/**`
- dashboard plugin UI
- plugin database migrations
- host-side plugin tests
- host-side pinned WIT ABI until an explicit external ABI dependency replaces it
- host architecture/user documentation

After this repository lands and CI passes, a follow-up Kinetix PR can remove duplicated plugin source/SDK/catalog tooling and update links.
