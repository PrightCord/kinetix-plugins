#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_ROOT="$ROOT/target/dist"

usage() {
  echo "usage: $0 <plugin-slug> [--publish] [--draft]" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
SLUG="$1"
shift

[[ "$SLUG" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "invalid plugin slug: $SLUG" >&2; exit 2; }

PUBLISH=0
DRAFT_FLAG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --publish) PUBLISH=1; shift ;;
    --draft) DRAFT_FLAG="--draft"; shift ;;
    *) usage ;;
  esac
done

PLUGIN_DIR="$ROOT/plugins/$SLUG"
MANIFEST="$PLUGIN_DIR/plugin.toml"
CARGO_TOML="$PLUGIN_DIR/Cargo.toml"
[ -f "$MANIFEST" ] || { echo "plugin not found: $SLUG" >&2; exit 1; }

PLUGIN_ID="$(grep -m1 '^id' "$MANIFEST" | sed -E 's/.*"(.*)".*/\1/')"
VERSION="$(grep -m1 '^version' "$MANIFEST" | sed -E 's/.*"(.*)".*/\1/')"
CRATE_VERSION="$(grep -m1 '^version' "$CARGO_TOML" | sed -E 's/.*"(.*)".*/\1/')"
NAME="$(grep -m1 '^name' "$MANIFEST" | sed -E 's/.*"(.*)".*/\1/')"
TAG="$SLUG-v$VERSION"

[ "$VERSION" = "$CRATE_VERSION" ] || {
  echo "plugin.toml version $VERSION != Cargo.toml version $CRATE_VERSION" >&2
  exit 1
}

for cmd in git cargo rustup wasm-tools openssl sha256sum tar; do
  command -v "$cmd" >/dev/null || { echo "$cmd is required" >&2; exit 1; }
done

[ -n "${KINETIX_PLUGIN_SIGNING_KEY_FILE:-}" ] || {
  echo "KINETIX_PLUGIN_SIGNING_KEY_FILE is required for official releases" >&2
  exit 1
}
[ -f "$KINETIX_PLUGIN_SIGNING_KEY_FILE" ] || {
  echo "signing key not found: $KINETIX_PLUGIN_SIGNING_KEY_FILE" >&2
  exit 1
}

cd "$ROOT"
git rev-parse --is-inside-work-tree >/dev/null
git diff --quiet
git diff --cached --quiet
[ -z "$(git ls-files --others --exclude-standard)" ] || {
  echo "working tree has untracked files" >&2
  exit 1
}

rustup target list --installed | grep -q '^wasm32-unknown-unknown$' || {
  echo "run: rustup target add wasm32-unknown-unknown" >&2
  exit 1
}

if git rev-parse --verify --quiet "refs/tags/$TAG^{commit}" >/dev/null; then
  SOURCE_SHA="$(git rev-parse "refs/tags/$TAG^{commit}")"
  echo "==> rebuilding existing tag $TAG at $SOURCE_SHA"
else
  SOURCE_SHA="$(git rev-parse HEAD)"
  echo "==> preparing new release $TAG from $SOURCE_SHA"
fi

WORK="$(mktemp -d)"
BUILD_ROOT="$WORK/source"
cleanup() {
  git -C "$ROOT" worktree remove --force "$BUILD_ROOT" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

git worktree add --detach "$BUILD_ROOT" "$SOURCE_SHA" >/dev/null
OUT="$DIST_ROOT/$SLUG/$VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

(
  cd "$BUILD_ROOT"
  KINETIX_PLUGIN_SIGNING_KEY_FILE="$KINETIX_PLUGIN_SIGNING_KEY_FILE"     bash scripts/build-plugin.sh "plugins/$SLUG" --out-dir "$OUT"
)

PACKAGE="$OUT/$PLUGIN_ID-$VERSION.kxp"
COMPONENT="$OUT/$PLUGIN_ID-$VERSION.wasm"
[ -f "$PACKAGE" ] && [ -f "$COMPONENT" ]
tar -tf "$PACKAGE" | grep -qx 'signature.ed25519'
wasm-tools validate --features component-model "$COMPONENT"

(
  cd "$OUT"
  sha256sum "$PLUGIN_ID-$VERSION.kxp" "$PLUGIN_ID-$VERSION.wasm" > SHA256SUMS
)

echo "==> release artifacts"
ls -lh "$PACKAGE" "$COMPONENT" "$OUT/SHA256SUMS"

if [ "$PUBLISH" -eq 0 ]; then
  echo "==> dry run complete; publish with: $0 $SLUG --publish"
  exit 0
fi

command -v gh >/dev/null || { echo "gh is required for --publish" >&2; exit 1; }
gh auth status >/dev/null

git fetch --tags origin
if git rev-parse --verify --quiet "refs/tags/$TAG^{commit}" >/dev/null; then
  TAG_SHA="$(git rev-parse "refs/tags/$TAG^{commit}")"
  [ "$TAG_SHA" = "$SOURCE_SHA" ] || {
    echo "tag $TAG already points to $TAG_SHA, expected $SOURCE_SHA" >&2
    exit 1
  }
else
  git tag -a "$TAG" "$SOURCE_SHA" -m "$NAME v$VERSION"
  git push origin "refs/tags/$TAG"
fi

NOTES="$OUT/RELEASE_NOTES.md"
cat > "$NOTES" <<EOF
Official Kinetix plugin release for **$NAME** (\`$PLUGIN_ID\`) v$VERSION.

Artifacts:
- \`$PLUGIN_ID-$VERSION.kxp\` — signed installable Kinetix package.
- \`$PLUGIN_ID-$VERSION.wasm\` — standalone WebAssembly Component.
- \`SHA256SUMS\` — SHA-256 hashes for both artifacts.
EOF

if gh release view "$TAG" --repo PrightCord/kinetix-plugins >/dev/null 2>&1; then
  echo "release $TAG already exists; refusing to overwrite immutable release assets" >&2
  exit 1
fi

gh release create "$TAG" "$PACKAGE" "$COMPONENT" "$OUT/SHA256SUMS"   --verify-tag   --title "$NAME v$VERSION"   --notes-file "$NOTES"   $DRAFT_FLAG   --repo PrightCord/kinetix-plugins

echo "==> published $TAG"
