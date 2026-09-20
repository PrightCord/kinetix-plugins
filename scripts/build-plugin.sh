#!/usr/bin/env bash
# Build one Kinetix plugin into a WebAssembly component and installable .kxp.
#
# Usage:
#   scripts/build-plugin.sh <plugin-dir> [--out-dir <dir>]
#
# By default artifacts are written beside the plugin source. CI/releases pass
# --out-dir so all artifacts are collected under one directory.
set -euo pipefail

PLUGIN_DIR="${1:?usage: build-plugin.sh <plugin-dir> [--out-dir <dir>]}"
shift
PLUGIN_DIR="${PLUGIN_DIR%/}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_DIR="$ROOT/$PLUGIN_DIR"
OUT_DIR="$PLUGIN_DIR"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || { echo "--out-dir requires a directory" >&2; exit 2; }
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

case "$OUT_DIR" in
  /*) ;;
  *) OUT_DIR="$ROOT/$OUT_DIR" ;;
esac
mkdir -p "$OUT_DIR"

PKG_NAME="$(grep -m1 '^name' "$PLUGIN_DIR/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
CRATE_VERSION="$(grep -m1 '^version' "$PLUGIN_DIR/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
PLUGIN_ID="$(grep -m1 '^id' "$PLUGIN_DIR/plugin.toml" | sed -E 's/.*"(.*)".*/\1/')"
MANIFEST_VERSION="$(grep -m1 '^version' "$PLUGIN_DIR/plugin.toml" | sed -E 's/.*"(.*)".*/\1/')"

[ "$CRATE_VERSION" = "$MANIFEST_VERSION" ] || {
  echo "Cargo.toml version ($CRATE_VERSION) does not match plugin.toml version ($MANIFEST_VERSION)" >&2
  exit 1
}
VERSION="$MANIFEST_VERSION"

command -v wasm-tools >/dev/null || { echo "wasm-tools is required" >&2; exit 1; }

SIGNING_KEY_FILE="${KINETIX_PLUGIN_SIGNING_KEY_FILE:-}"
if [ -n "$SIGNING_KEY_FILE" ]; then
  command -v openssl >/dev/null || { echo "openssl is required for plugin signing" >&2; exit 1; }
  [ -f "$SIGNING_KEY_FILE" ] || { echo "plugin signing key not found: $SIGNING_KEY_FILE" >&2; exit 1; }
fi

rustup target list --installed | grep -q '^wasm32-unknown-unknown$' \
  || { echo "run: rustup target add wasm32-unknown-unknown" >&2; exit 1; }

echo "==> building $PKG_NAME $VERSION ($PLUGIN_ID)"
(
  cd "$ROOT"
  cargo build --locked --release --target wasm32-unknown-unknown -p "$PKG_NAME"
)

WASM_MODULE="$ROOT/target/wasm32-unknown-unknown/release/${PKG_NAME//-/_}.wasm"
[ -f "$WASM_MODULE" ] || { echo "expected $WASM_MODULE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> encoding component"
wasm-tools component new "$WASM_MODULE" -o "$WORK/plugin.wasm"
wasm-tools validate --features component-model "$WORK/plugin.wasm"

cp "$PLUGIN_DIR/plugin.toml" "$WORK/plugin.toml"
[ -f "$PLUGIN_DIR/README.md" ] && cp "$PLUGIN_DIR/README.md" "$WORK/README.md"
[ -f "$PLUGIN_DIR/LICENSE" ] && cp "$PLUGIN_DIR/LICENSE" "$WORK/LICENSE"

if [ -n "$SIGNING_KEY_FILE" ]; then
  echo "==> signing package payload"
  cat "$WORK/plugin.wasm" "$WORK/plugin.toml" \
    | openssl dgst -sha256 -binary > "$WORK/signing-digest.bin"
  openssl pkeyutl -sign -rawin \
    -inkey "$SIGNING_KEY_FILE" \
    -in "$WORK/signing-digest.bin" \
    -out "$WORK/signature.ed25519"
  [ "$(wc -c < "$WORK/signature.ed25519")" -eq 64 ] \
    || { echo "Ed25519 signature must be exactly 64 bytes" >&2; exit 1; }
fi

COMPONENT_OUT="$OUT_DIR/${PLUGIN_ID}-${VERSION}.wasm"
PACKAGE_OUT="$OUT_DIR/${PLUGIN_ID}-${VERSION}.kxp"
cp "$WORK/plugin.wasm" "$COMPONENT_OUT"

FILES=(plugin.toml plugin.wasm)
[ -f "$WORK/README.md" ] && FILES+=(README.md)
[ -f "$WORK/LICENSE" ] && FILES+=(LICENSE)
[ -f "$WORK/signature.ed25519" ] && FILES+=(signature.ed25519)

tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$WORK" -cf "$PACKAGE_OUT" "${FILES[@]}" 2>/dev/null \
  || tar -C "$WORK" -cf "$PACKAGE_OUT" "${FILES[@]}"

echo "==> wrote $COMPONENT_OUT"
sha256sum "$COMPONENT_OUT" | awk '{print "    sha256 " $1}'
echo "==> wrote $PACKAGE_OUT"
sha256sum "$PACKAGE_OUT" | awk '{print "    sha256 " $1}'
