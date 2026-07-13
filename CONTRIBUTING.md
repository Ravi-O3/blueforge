# Contributing to BlueForge

This is primarily a solo portfolio project, but it follows real open-source conventions so the
workflow is interview-ready and reproducible.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
make install
pre-commit install
```

## Workflow

1. Create a branch from `main`: `feat/<short-name>`, `fix/<short-name>`, or `detection/<technique>`.
2. Make the change. Keep pull requests small and focused.
3. Run `make lint` and `make test` locally. CI must pass.
4. Open a PR using the template. Link the issue and the MITRE technique if it is a detection.

## Commit convention (Conventional Commits)

```
<type>(<scope>): <summary>

feat(detections): add Sigma rule for LSASS access (T1003.001)
fix(normalizer): handle missing EventID field
docs(architecture): add data-flow diagram
test(enrichment): cover IOC regex edge cases
chore(ci): pin ruff version
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `detection`.

## Adding a detection

Every detection is a small file plus a short doc. Follow
[`docs/detection-guide.md`](docs/detection-guide.md) and use
[`docs/templates/detection-template.md`](docs/templates/detection-template.md). A detection is
not "done" until it has: a MITRE mapping, a test with sample logs, documented false positives,
and investigation steps.

## Coding standards

Python is formatted and linted with ruff, type-checked with mypy, and tested with pytest.
See [`docs/09-python-software-design.md`](docs/09-python-software-design.md).
