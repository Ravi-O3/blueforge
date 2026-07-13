# Sigma detections

Vendor-neutral detection rules. Each file is one rule with a MITRE mapping,
documented false positives, and a matching test in `tests/`. The BlueForge engine
(`src/blueforge/detections/engine.py`) runs a documented subset of Sigma so you can
explain exactly how each rule fires.

Rule IDs use the `bf-000N` scheme. See `docs/08-detection-engineering-plan.md` for
the full backlog of 20 Sigma + 20 Wazuh detection ideas.
