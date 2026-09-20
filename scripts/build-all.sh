#!/usr/bin/env bash
# Build every first-party Kinetix plugin.
#
# Usage:
#   scripts/build-all.sh [--out-dir <dir>]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/dist"

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

mapfile -t MANIFESTS < <(find "$ROOT/plugins" -mindepth 2 -maxdepth 2 -name plugin.toml -print | sort)
[ "${#MANIFESTS[@]}" -gt 0 ] || { echo "no plugin manifests found" >&2; exit 1; }

for MANIFEST in "${MANIFESTS[@]}"; do
  DIR="$(dirname "$MANIFEST")"
  RELATIVE="${DIR#"$ROOT/"}"
  "$ROOT/scripts/build-plugin.sh" "$RELATIVE" --out-dir "$OUT_DIR"
done

echo "==> built ${#MANIFESTS[@]} plugin(s) into $OUT_DIR"
