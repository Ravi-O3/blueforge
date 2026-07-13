# 04. Technology Stack

Every choice below is optimized for one thing: that Ravi can understand it and defend it in an
interview. Nothing is included because it is trendy.

## Language: Python 3.10+

Why: it is the SOC automation lingua franca, it is what Ravi is already learning, and it reads
close to pseudocode so the whole codebase stays explainable. Why not Go or Rust: faster at
runtime, but slower to write, less common in SOC tooling, and a worse fit for a beginner-to-
intermediate author. Why 3.10+: modern type hints (`X | None`) that make the code self-documenting.

## Core libraries (kept small on purpose)

| Library | Job | Why this one |
|---------|-----|--------------|
| pydantic v2 | Validate the `Event` schema and config | Industry standard, great errors, fast |
| PyYAML | Load Sigma rules and config | Sigma is YAML; ubiquitous |
| click | Build the CLI | Simplest way to a clean, documented CLI |
| rich | Readable tables and logs in the terminal | Makes demos and screenshots look professional |
| jinja2 | Render incident report templates | Standard templating; separates format from logic |
| requests | Threat-intel HTTP calls | The most widely understood HTTP client |
| python-evtx | Parse Windows .evtx (Phase 2+) | Pure-Python evtx reader, no Windows needed |

Why so few dependencies: every dependency is something you must be able to explain and a potential
supply-chain risk. A short list is a feature, not a limitation.

## Security tooling

- **Wazuh** (SIEM/XDR core): collection, agents, rules, MITRE mapping, dashboard.
- **Sysmon** (Windows endpoint telemetry): the richest free source of process/network/registry
  events; the foundation of most endpoint detections.
- **Sigma**: the vendor-neutral rule format the detection content is written in.
- **MITRE ATT&CK**: the framework every detection maps to.
- **Atomic Red Team style tests**: safe, documented attack simulations to generate telemetry.
- **Microsoft Sentinel / Defender XDR + KQL** (optional track): cloud SIEM parity for SC-200.

## Storage

Files, not a database. Detections are YAML/XML files in git. Sample logs are JSON Lines. Reports
are Markdown. Why: for this scale, the filesystem plus git *is* the database, and it gives free
versioning, diffing, and review. A database would add operational weight with no benefit at the
portfolio scale. If volume ever demanded it, the natural next step is SQLite (still one file, still
in git-adjacent tooling), and that is a good thing to mention as "what I would do at scale."

## Testing

- **pytest** for unit tests, **pytest-cov** for coverage.
- Why: it is the default in modern Python, fixtures keep tests readable, and green tests on GitHub
  are a credibility signal.

## Quality tooling

- **ruff** (lint + format): one fast tool replacing flake8, isort, and black.
- **mypy** (static types): catches whole classes of bugs before runtime and documents intent.
- **pre-commit**: runs the above plus a private-key scanner before each commit, so the public-
  facing history stays clean.

## CI/CD

**GitHub Actions.** Why: native to GitHub, free for this use, and the green check on every PR is
visible proof the project is maintained. The pipeline lints, type-checks, tests on Python 3.10 to
3.12, and validates that every detection rule parses. No CD (deployment) because there is nothing
to deploy; this is a toolkit and a lab, not a hosted service. Saying "I deliberately did not add
deployment because it would be complexity without value" is a stronger answer than a fake pipeline.

## Deployment / run model

Run locally in a virtualenv (`make install`), or point it at logs exported from the Wazuh lab.
The Wazuh stack itself runs either on VMs or via the docker lab in `labs/`. There is no cloud
requirement for the core, which keeps cost at zero.
