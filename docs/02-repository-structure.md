# 02. Repository Structure

The layout follows conventions a reviewer expects from a professional open-source security
project, so it reads as credible at a glance. Every folder has one job.

```
blueforge/
  README.md                 Front door: what, why, quickstart, architecture summary
  LICENSE                   MIT
  SECURITY.md               Responsible-use policy for detection/offensive content
  CONTRIBUTING.md           Workflow, commit convention, how to add a detection
  CODE_OF_CONDUCT.md        Standard conduct statement
  CHANGELOG.md              Keep a Changelog format, SemVer
  Makefile                  make install / lint / test / run
  pyproject.toml            Package metadata, ruff/mypy/pytest config, CLI entry point
  requirements.txt          Runtime deps (intentionally small)
  requirements-dev.txt      Dev/test/lint deps
  .env.example              Documented env vars; copy to .env (never committed)
  .gitignore                Excludes secrets, raw logs, caches
  .pre-commit-config.yaml   Lint/format/secret-scan before every commit

  .github/
    workflows/ci.yml        Lint + type-check + test on push/PR; validate detections
    ISSUE_TEMPLATE/         bug, feature, and new-detection templates
    PULL_REQUEST_TEMPLATE.md
    labels.yml              Label taxonomy (type/area/phase)

  src/blueforge/            The Python package (see docs/09)
    schema.py               The common Event model (the platform contract)
    config.py               Env-based configuration
    logging_config.py       Central logging
    cli.py                  Command line interface (the glue)
    collectors/             Acquire raw logs (sample file, later evtx/syslog/wazuh-api)
    normalizer/             Map raw formats -> Event
    detections/             The Sigma-style detection engine
    enrichment/             IOC extraction + threat intel lookups
    reporting/              Incident report generation
    utils/                  Small shared helpers

  detections/               Detection CONTENT (data, not code)
    sigma/                  Vendor-neutral rules (bf-000N.yml) + README
    wazuh/                  local_rules.xml for the Wazuh manager
    sentinel/               KQL analytics rules for the Microsoft stack

  docs/                     This blueprint + guides, playbooks, templates
    diagrams-source (../diagrams)   Mermaid sources for architecture/data-flow/network
    templates/             Reusable templates (detection, playbook, lab, lessons)

  diagrams/                 Mermaid: architecture, data-flow, network, component
  labs/                     Reproducible attack/detection labs + Wazuh docker lab
  examples/                 Small synthetic sample logs (used by tests and demos)
  tests/                    pytest suite
  scripts/                  validate_detections.py, attack_coverage.py
  screenshots/              Portfolio evidence (lab runs, alerts, dashboards)
```

## Why split `src/blueforge/detections/` (code) from `detections/` (content)?

Because they change for different reasons and by different skills. The *engine* is Python that
rarely changes. The *rules* are security content you add to constantly. Keeping content out of
the package means you can browse, diff, and review detections on GitHub like the security
artifacts they are, and a non-Python reviewer can still read them.

## Why `src/` layout instead of a flat package?

The `src/` layout forces you to install the package to import it, which catches "works on my
machine because of the current directory" bugs and matches how the code runs in CI and for a
real user. It is the current Python packaging best practice.
