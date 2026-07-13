# Security Policy

BlueForge is a defensive security project. It contains detection logic and lab notes that
describe attacker techniques so that they can be detected. Use it only in environments you own.

## Scope and intent

- All offensive content (attack simulations in `labs/`) exists to generate telemetry for
  building and testing detections. It targets local, isolated lab virtual machines only.
- This project does not distribute malware, exploits, or weaponized payloads. Attack
  simulations reference well-known, publicly documented techniques (for example, Atomic Red
  Team style tests) and safe, reversible commands.

## Handling data

- Never commit real logs, packet captures, credentials, API keys, or customer data.
- `.gitignore` excludes `.env`, keys, `data/`, `*.evtx`, and `*.pcap` by default. Do not
  override this.
- Enrichment API keys are read from environment variables, never hard-coded.

## Reporting an issue

This is a private portfolio repository. If you are reviewing it and spot a security concern
(a leaked secret, an unsafe default, a dangerous lab step), open a GitHub issue using the
`bug_report` template or contact the author directly.

## Supported versions

The project is pre-1.0. Only the latest `main` is maintained.
