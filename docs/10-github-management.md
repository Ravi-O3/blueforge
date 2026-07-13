# 10. GitHub Management

The repository is run like a real project so the *process* is part of the portfolio. A reviewer
looks at issues, milestones, commit messages, and CI to judge whether you work like an engineer.

## Milestones (one per roadmap phase)

`Phase 0: Foundation`, `Phase 1: MVP`, `Phase 2: Detection Engine`, `Phase 3: Threat Hunting`,
`Phase 4: Automation`, `Phase 5: AI Assistant`, `Phase 6: v1.0`. Each issue is assigned to a
milestone so progress is visible on the milestones page.

## Labels (defined in `.github/labels.yml`)

Three axes: **type** (detection, feature, bug, docs, test), **area** (collectors, normalizer,
detections, enrichment, reporting, hunting), and **phase** (0 to 4). Plus `priority: high` and
`good first task`. Labeling every issue makes the board readable and shows intent.

## Issue templates (in `.github/ISSUE_TEMPLATE/`)

- **bug_report** - what happened, repro, environment.
- **feature_request** - problem, proposed solution, roadmap phase.
- **detection_request** - MITRE technique, attacker behavior, log source, expected false positives.
  This one is the tell that a detection engineer runs this repo.

## Pull request template

Every PR states its type, links an issue, names the MITRE technique for detections, and carries a
checklist (lint passes, tests pass, detection has a test and FP notes, no secrets). Even solo, you
open PRs from feature branches so the history reads professionally and CI gates every change.

## Commit conventions (Conventional Commits)

`type(scope): summary`, imperative mood, under ~72 chars. Types: feat, fix, docs, test, refactor,
chore, and `detection` for new/updated rules. Examples:

```
detection(sigma): add certutil download rule (T1105)
feat(normalizer): map Windows 4625 to authentication events
fix(engine): make command-line matching case-insensitive
docs(architecture): add data-flow diagram
test(enrichment): cover private vs public IP separation
```

Why it matters: consistent history lets you (and a reviewer) scan what changed, and it enables
automatic changelogs later.

## Branching and release strategy

- `main` is always green and demoable. Work happens on short-lived `feat/`, `fix/`, or
  `detection/` branches, merged via PR after CI passes.
- **Semantic Versioning.** Tag `v0.1.0` at the end of Phase 0/1, bump minor per phase, tag `v1.0.0`
  at Phase 6. Each release gets notes generated from the changelog.
- The `CHANGELOG.md` follows Keep a Changelog and is updated in the same PR as the change.

## CI as a quality gate

`.github/workflows/ci.yml` runs on every push and PR: ruff, mypy, pytest across Python 3.10 to
3.12, and a detection-validation job that parses every Sigma rule. A red check blocks merge. The
green badge in the README is honest evidence the project builds.
