#!/usr/bin/env python3
"""Validate that every Sigma rule parses and has the required fields.

Run in CI so a malformed rule can never reach main. Zero external dependencies
beyond pyyaml, which keeps the CI job fast.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REQUIRED = {"title", "id", "level", "detection", "mitre"}
RULES_DIR = Path("detections/sigma")


def main() -> int:
    errors = 0
    rules = sorted(RULES_DIR.rglob("*.y*ml"))
    for path in rules:
        if path.name.lower() == "readme.md":
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"[FAIL] {path}: invalid YAML: {exc}")
            errors += 1
            continue
        if not isinstance(data, dict):
            continue
        missing = REQUIRED - data.keys()
        if missing:
            print(f"[FAIL] {path}: missing fields {sorted(missing)}")
            errors += 1
        else:
            print(f"[ok]   {path.name} -> {', '.join(data['mitre'])}")
    print(f"\n{len(rules)} rule file(s) checked, {errors} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
