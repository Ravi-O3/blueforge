"""A small, explainable Sigma-style detection engine.

WHY build a mini engine instead of pulling in a full Sigma library: so you can
explain EXACTLY how a detection fires in an interview. A rule is a YAML file with
field matchers. The engine loads rules once, then checks every event against them.

Supported matcher syntax (a deliberate subset of Sigma):

    detection:
      command_line|contains: ["-enc", "-EncodedCommand"]   # field|operator: values
      process|endswith: "\\powershell.exe"
      condition: any        # 'any' (OR) or 'all' (AND) across the matchers above

Operators: equals (default), contains, startswith, endswith. Matching is
case-insensitive because attackers vary casing to evade naive rules (an important
lesson: never write a case-sensitive detection for command lines).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from blueforge.schema import Event


@dataclass
class Detection:
    """A single loaded rule."""

    id: str
    title: str
    level: str
    mitre: list[str]
    logsource_category: str | None
    matchers: dict[str, Any]
    condition: str
    description: str = ""
    falsepositives: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Detection":
        detection = dict(d.get("detection", {}))
        condition = str(detection.pop("condition", "all")).lower()
        return cls(
            id=str(d.get("id", "")),
            title=str(d.get("title", "untitled")),
            level=str(d.get("level", "medium")),
            mitre=list(d.get("mitre", [])),
            logsource_category=(d.get("logsource") or {}).get("category"),
            matchers=detection,
            condition=condition,
            description=str(d.get("description", "")),
            falsepositives=list(d.get("falsepositives", [])),
        )


@dataclass
class Match:
    """The result of a rule firing on an event."""

    detection: Detection
    event: Event


def _op_match(value: Any, operator: str, expected: Any) -> bool:
    if value is None:
        return False
    v = str(value).lower()
    candidates = expected if isinstance(expected, list) else [expected]
    for c in candidates:
        c = str(c).lower()
        if operator == "contains" and c in v:
            return True
        if operator == "startswith" and v.startswith(c):
            return True
        if operator == "endswith" and v.endswith(c):
            return True
        if operator == "equals" and v == c:
            return True
    return False


class DetectionEngine:
    def __init__(self, rules: list[Detection]) -> None:
        self.rules = rules

    def evaluate(self, event: Event) -> list[Match]:
        matches: list[Match] = []
        for rule in self.rules:
            if rule.logsource_category and event.category.value != rule.logsource_category:
                continue
            results = []
            for key, expected in rule.matchers.items():
                field_name, _, operator = key.partition("|")
                operator = operator or "equals"
                results.append(_op_match(event.get(field_name), operator, expected))
            if not results:
                continue
            fired = any(results) if rule.condition == "any" else all(results)
            if fired:
                matches.append(Match(detection=rule, event=event))
        return matches


def load_rules(rules_dir: str | Path) -> list[Detection]:
    """Load every .yml/.yaml Sigma-style rule under a directory."""
    rules: list[Detection] = []
    for path in sorted(Path(rules_dir).rglob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "detection" in data:
            rules.append(Detection.from_dict(data))
    return rules
