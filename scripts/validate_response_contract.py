#!/usr/bin/env python3
"""Validate the shared Kinetix plugin response fixtures against the v1 schema."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "wit/contracts/kinetix.plugin.response.v1.schema.json"
FIXTURE_DIR = ROOT / "wit/fixtures/plugin-response/v1"

VALID_FIXTURES = (
    "all-events.json",
    "warning.json",
    "terminal-error.json",
)

INVALID_FIXTURES = (
    "invalid-version.json",
    "invalid-missing-text.json",
    "invalid-error-not-terminal.json",
)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    schema = load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for name in VALID_FIXTURES:
        errors = sorted(validator.iter_errors(load_json(FIXTURE_DIR / name)), key=lambda e: list(e.path))
        assert not errors, f"{name} should be valid: {errors}"

    for name in INVALID_FIXTURES:
        errors = list(validator.iter_errors(load_json(FIXTURE_DIR / name)))
        assert errors, f"{name} should be rejected by the response schema"

    print(
        f"validated {len(VALID_FIXTURES)} valid and "
        f"{len(INVALID_FIXTURES)} invalid plugin response fixtures"
    )


if __name__ == "__main__":
    main()
