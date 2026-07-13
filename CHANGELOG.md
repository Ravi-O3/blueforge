# Changelog

All notable changes to BlueForge are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Four new Sigma rules: schtasks persistence (bf-0005, T1053.005), LSASS credential
  dump (bf-0006, T1003.001), local account creation (bf-0007, T1136.001), and
  curl/wget piped to shell on Linux (bf-0008, T1105 + T1059.004), each with firing
  and false-positive tests.
- Four new Wazuh rules (100204-100206, 100211): schtasks persistence, LSASS dump,
  net.exe account creation, and successful root SSH login.
- ATT&CK Navigator layer export: `scripts/attack_coverage.py --layer` writes
  `docs/attack_navigator_layer.json`.
- Detection engine: repeated same-field matchers via `field|operator|N` keys, so a
  rule can AND two `contains` clauses on one field.
- Normalizer: Linux records carrying a `command` are categorized as process events.

### Fixed
- Removed a committed MS Word lock file (`~$*.docx`) and added the pattern to
  `.gitignore`.
- Initial project scaffold: package structure, docs, CI, and lab layout.
- Master blueprint and 12-section design documentation under `docs/`.
- Starter Python package with collectors, normalizer, detection engine, enrichment, and reporting stubs.
- Example Sigma and Wazuh detection rules with MITRE ATT&CK mapping.
- pytest suite and GitHub Actions CI.

## [0.1.0] - 2026-07-12
### Added
- Repository created. Phase 0 (Foundation) in progress.
