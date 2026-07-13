# 09. Python Software Design

The package is small on purpose. You should be able to read every file in an afternoon and explain
any of them in an interview. This section is the map.

## Package architecture

```
src/blueforge/
  schema.py            The Event model. The contract every other module depends on.
  config.py            Config dataclass loaded from environment variables.
  logging_config.py    One function to set up consistent logging.
  cli.py               click CLI. The glue that runs the pipeline.
  __main__.py          Enables `python -m blueforge`.
  collectors/          Acquire raw logs.
    base.py            Collector ABC with one method: collect() -> Iterator[dict].
    sample.py          SampleCollector reads JSON Lines.
  normalizer/
    normalize.py       _map_* functions: one per raw format -> Event.
  detections/
    engine.py          Detection, DetectionEngine, load_rules. The documented mini-Sigma.
  enrichment/
    ioc.py             extract_iocs(): regex IOC extraction, no network.
    threatintel.py     Optional reputation lookups; degrade to "unknown" without a key.
  reporting/
    incident_report.py build_report(): matches -> Markdown via jinja2.
  utils/
    io.py              read_jsonl, write_text.
```

## Key classes and responsibilities

**`schema.Event` (pydantic BaseModel).** The single normalized event. Only timestamp, source, and
category are required; everything else is optional so partial logs still validate. `get(field)`
lets the detection engine read either a typed attribute or a raw field by name. This one class is
why detections do not care about log formats.

**`collectors.base.Collector` (ABC).** Defines the one method every collector implements:
`collect()`. Using an abstract base class documents the interface and makes new sources drop-in.

**`detections.engine.Detection` (dataclass).** A loaded rule: id, title, level, MITRE list, log
source category, matchers, condition. Built from a YAML dict via `from_dict`.

**`detections.engine.DetectionEngine`.** Holds the loaded rules and exposes `evaluate(event) ->
list[Match]`. The matching logic is deliberately simple and fully documented: for each rule, check
the log-source category, evaluate each `field|operator: values` matcher (equals/contains/starts/
ends, case-insensitive), then combine with `any` or `all`.

**`reporting.incident_report`.** A jinja2 template plus `build_report(matches)`. Format lives in the
template, logic in the function. The `extract` filter pulls IOCs into the report automatically.

## Interfaces and data flow

The whole system is three interfaces:
1. `Collector.collect() -> Iterator[dict]` (raw records).
2. `normalize(dict) -> Event` (the contract boundary).
3. `DetectionEngine.evaluate(Event) -> list[Match]` (findings).

Everything downstream (enrichment, reporting, hunting) consumes `Event` and `Match`. Because the
boundaries are typed, each stage is unit-testable in isolation, which is exactly what the test
suite does.

## Testing approach

- **Unit tests per module**, using the small synthetic logs in `examples/` as fixtures.
- The normalizer and the engine get the most tests because they are the contract and the core.
- Tests assert behavior a reviewer cares about: benign events do not fire rules, casing does not
  evade detection, every rule is MITRE-mapped, private IPs are not treated as public IOCs.
- Target: keep the suite fast (under a second) so it runs on every commit via pre-commit and CI.

## Coding standards

- Type hints everywhere; `from __future__ import annotations` for clean modern syntax.
- ruff for lint + format, mypy for types. Both run in CI and pre-commit.
- Docstrings explain *why*, not just *what*, because this codebase is also a teaching artifact.
- Small functions, single responsibility, no cleverness that you cannot explain out loud.
- Secrets only from environment variables. No network calls in the core path. Fail gracefully.

## What was deliberately left out (and why)

No database (files + git suffice at this scale). No web UI (the CLI plus Markdown reports are
enough and stay explainable). No async (log volumes here do not need it). No plugin framework
(YAGNI). Each omission is a defensible design decision, which is more impressive than an
over-engineered stack you cannot justify.
