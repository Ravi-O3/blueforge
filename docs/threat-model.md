# Threat Model

A lightweight threat model, because a security project should be able to reason about its own risk.
This uses the four-question framing: what are we protecting, what can go wrong, what are we doing
about it, and did we do a good job.

## What are we building and protecting?

BlueForge is a defensive tool plus a lab. The assets are: the detection content (valuable IP), any
API keys used for enrichment (secrets), the lab VMs, and the analyst's host machine. The lab
intentionally contains offensive activity, so containment is itself an asset.

## What can go wrong (threats)?

1. **Secret leakage.** An API key committed to git. Impact: abuse of your key, cost, exposure.
2. **Lab breakout.** A simulated attack reaching the real network or the internet.
3. **Malicious data.** A crafted log file exploiting a parser, or IOC lookups leaking data to third
   parties.
4. **Supply chain.** A compromised Python dependency.
5. **Over-trust of automation.** The tool marking a real incident as benign, or vice versa.

## What are we doing about it (mitigations)?

1. Secrets only via environment variables; `.gitignore` excludes `.env` and keys; pre-commit runs a
   private-key scanner; enrichment degrades gracefully without keys.
2. Lab runs on an isolated host-only network with no internet route; VMs are snapshotted and
   restored; attack steps are documented, reversible, and never use real malware.
3. Parsers use safe loaders (`yaml.safe_load`, JSON), treat all log content as untrusted data, and
   never execute it; enrichment only sends indicators (not raw logs) to third parties, and only when
   a key is configured.
4. A deliberately small dependency list, pinned minimums, and CI that fails on issues.
5. Automation assists, it does not decide. Reports recommend next steps; a human triages. Detections
   document false positives so the analyst stays in the loop.

## Did we do a good job (validation)?

CI enforces the technical controls on every change. The lab's isolation is verifiable (no default
route to the internet). The honest limit: this is a portfolio lab, not a production system, and the
threat model is scoped to that. Stating that scope is part of doing the job well.

## Out of scope

Multi-user access control, production data retention, compliance frameworks, and high availability.
These are named here on purpose so a reviewer sees the boundary was a choice, not an oversight.
