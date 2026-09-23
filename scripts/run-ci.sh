#!/usr/bin/env bash
# Local replica of .github/workflows/plugin-ci.yml's "validate" job. Runs the
# same steps, in the same order, so failures surface locally before pushing:
#   1. cargo fmt --all -- --check
#   2. cargo test --workspace
#   3. validate response contract fixtures (wit/fixtures/plugin-response/v1)
#   4. cargo check --locked --workspace --target wasm32-unknown-unknown
#   5. validate catalog.json / trusted-publishers.json
#   6. validate plugins/*/plugin.toml manifests
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  CYAN=$'\033[36m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""
  RED=""
  CYAN=""
  DIM=""
  RESET=""
fi

format_duration() {
  local seconds="$1"
  printf '%dm %02ds' "$((seconds / 60))" "$((seconds % 60))"
}

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kinetix-plugins-ci.XXXXXX")"
trap 'rm -rf "$LOG_DIR"' EXIT

STEP_NAMES=()
STEP_RESULTS=()

run_step() {
  local name="$1"
  shift
  local log="$LOG_DIR/${#STEP_NAMES[@]}.log"
  local start end rc duration

  printf '%s●%s %s\n' "$CYAN" "$RESET" "$name"
  start="$(date +%s)"

  if "$@" >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi

  end="$(date +%s)"
  duration="$((end - start))"

  if (( rc == 0 )); then
    printf '%s✓%s %s  %s%s%s\n' "$GREEN" "$RESET" "$name" "$DIM" "$(format_duration "$duration")" "$RESET"
  else
    printf '%s✗%s %s  %s%s%s\n' "$RED" "$RESET" "$name" "$DIM" "$(format_duration "$duration")" "$RESET"
    printf '\n----- output: %s -----\n' "$name"
    cat "$log"
    printf -- '-----\n\n'
  fi

  STEP_NAMES+=("$name")
  STEP_RESULTS+=("$rc")

  return "$rc"
}

validate_json() {
  python3 -m json.tool catalog.json >/dev/null &&
    python3 -m json.tool trusted-publishers.json >/dev/null
}

validate_response_contract() {
  python3 - <<'PY' || python3 -m pip install --disable-pip-version-check --quiet jsonschema==4.25.1
import jsonschema
assert jsonschema.__version__ == "4.25.1"
PY
  python3 scripts/validate_response_contract.py
}

validate_manifests() {
  python3 - <<'PY'
import pathlib, tomllib
required = {"manifest_version", "id", "name", "version", "plugin_api"}
manifests = sorted(pathlib.Path("plugins").glob("*/plugin.toml"))
assert manifests, "no plugin manifests found"
ids = set()
for path in manifests:
    data = tomllib.loads(path.read_text())
    missing = required - data.keys()
    assert not missing, f"{path}: missing {sorted(missing)}"
    assert data["manifest_version"] == 1
    assert data["id"] not in ids, f"{path}: duplicate plugin id {data['id']}"
    ids.add(data["id"])
print(f"validated {len(manifests)} plugin manifest(s)")
PY
}

printf '%sLocal plugin-ci%s\n' "$CYAN" "$RESET"
printf 'Repo: %s\n\n' "$ROOT_DIR"

overall=0

run_step "Check formatting" cargo fmt --all -- --check || overall=1
run_step "Run plugin unit tests" cargo test --workspace || overall=1
run_step "Validate response contract fixtures" validate_response_contract || overall=1
run_step "Check plugin workspace" cargo check --locked --workspace --target wasm32-unknown-unknown || overall=1
run_step "Validate catalog JSON" validate_json || overall=1
run_step "Validate plugin manifests" validate_manifests || overall=1

printf '\n%sSummary%s\n' "$CYAN" "$RESET"
printf '%-28s %s\n' "Step" "Status"
printf '%-28s %s\n' "----------------------------" "--------"
for i in "${!STEP_NAMES[@]}"; do
  if [[ "${STEP_RESULTS[$i]}" == "0" ]]; then
    printf '%-28s %s✓ passed%s\n' "${STEP_NAMES[$i]}" "$GREEN" "$RESET"
  else
    printf '%-28s %s✗ failed%s\n' "${STEP_NAMES[$i]}" "$RED" "$RESET"
  fi
done

if (( overall != 0 )); then
  printf '\n%sCI failed%s\n' "$RED" "$RESET"
  exit 1
fi

printf '\n%s✓ CI passed%s\n' "$GREEN" "$RESET"
