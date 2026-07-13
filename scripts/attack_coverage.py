#!/usr/bin/env python3
"""Print MITRE ATT&CK coverage across all Sigma rules.

A one-line answer to the interview question "how do you measure your detection
coverage?" It counts unique techniques and can be extended to emit an ATT&CK
Navigator layer JSON later.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml


def main() -> None:
    techniques: Counter[str] = Counter()
    for path in sorted(Path("detections/sigma").rglob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for t in data.get("mitre", []):
                techniques[t] += 1
    print(f"Unique techniques covered: {len(techniques)}")
    for tech, count in techniques.most_common():
        print(f"  {tech}: {count} rule(s)")


if __name__ == "__main__":
    main()
