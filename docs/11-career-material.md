# 11. Career Application Material

This section turns the work into interviews and offers. Use it as raw material; adapt to each job.
Never claim a phase you have not actually shipped. Honesty is the whole point of a portfolio.

## Resume bullets by phase

Use strong verbs and concrete numbers. Only add a bullet once the phase is genuinely done.

**Phase 0 (Foundation)**
- Built and documented a self-hosted detection lab (Wazuh SIEM, Sysmon, Windows/Linux VMs) on an
  isolated network, with CI (GitHub Actions) enforcing lint, type-checks, and tests.

**Phase 1 (MVP)**
- Designed a normalized event schema and a tested Python detection pipeline that ingests raw logs,
  normalizes them, and fires MITRE-mapped detections, producing automated Markdown incident reports.

**Phase 2 (Detection Engine)**
- Authored 20+ detections (Sigma + Wazuh) mapped to MITRE ATT&CK, each with unit tests, documented
  false positives, and investigation steps; built an ATT&CK coverage report.

**Phase 3 (Threat Hunting)**
- Ran safe, reversible attack simulations to validate detections and wrote hypothesis-driven hunts
  and event timelines for multi-stage scenarios.

**Phase 4 (Automation)**
- Automated alert triage end to end (IOC extraction, threat-intel enrichment, report generation)
  and built KQL parity detections in Microsoft Sentinel, aligned with SC-200.

**Phase 5 / 6**
- Prototyped a local-LLM alert-explanation assistant (no data leaving the host) and shipped a
  documented v1.0 with ATT&CK coverage visualization.

## LinkedIn announcement examples

Keep them plain, specific, and free of hype. No em dashes, no buzzword soup.

**Kickoff post:**
"I'm building BlueForge, a detection engineering and SOC automation platform, to learn the blue-team
craft by doing. Week one: Wazuh + Sysmon lab running on an isolated network, first Sigma rules
firing, and a CI pipeline keeping it honest. I'll share what I learn as I go."

**Milestone post (Phase 2):**
"BlueForge update: 20 detections now mapped to MITRE ATT&CK, each with tests and documented false
positives. The interesting part was tuning out benign PowerShell without missing the malicious
encoded-command pattern. Repo and write-ups in the comments."

**Reflection post:**
"Lesson from BlueForge this week: a LOLBIN like certutil is invisible if you detect the tool. You
have to detect the behavior (download flags plus an external URL). Detection engineering is mostly
thinking like an attacker, then writing the smallest rule that still catches them."

## The 90-second project explanation (interview opener)

"BlueForge is a detection engineering platform I built to practice the full SOC loop. Logs from a
Wazuh and Sysmon lab flow through a Python pipeline: collectors grab the raw events, a normalizer
converts every format into one common schema, and a small Sigma-style engine runs my detections,
each mapped to MITRE ATT&CK. Matches get enriched with IOC extraction and threat-intel lookups, and
the tool generates an incident report automatically. I built it dual-stack, so the same detections
also exist as KQL for Microsoft Sentinel, which lines up with my SC-200 work. I kept it deliberately
small so I can explain every component, and everything is tested with green CI."

## Technical questions recruiters and interviewers may ask

- "Walk me through what happens from a log arriving to an alert." (Answer: the data-flow diagram.)
- "Why normalize logs? What is a common schema?" (Format independence; ECS/ASIM analogy.)
- "Pick one detection and explain it, including its false positives."
- "How do you know your detection coverage is good?" (ATT&CK mapping + coverage script; and its
  limits: coverage is breadth, not depth.)
- "How would you tune a noisy rule without going blind?" (Baseline, add context, narrow the matcher,
  measure FP rate, never just delete the alert.)
- "What is a LOLBIN and why do they matter?" (certutil/mshta/regsvr32 example.)
- "Difference between a detection and a hunt?" (Known-bad rule vs hypothesis-driven search.)
- "How do you handle secrets and untrusted data safely?" (env vars, no secrets in git, graceful
  degradation, isolated lab network.)
- "What would you change at enterprise scale?" (Storage to a real datastore, streaming ingestion,
  case management integration, alert deduplication.)

## How to explain the architecture

Draw the pipeline: sources -> collectors -> normalizer -> detection engine -> enrichment ->
reporting/hunting. Emphasize the two design decisions that carry the most weight: the common schema
(so detections are format-independent) and the documented mini-engine (so nothing is a black box).
Then name one trade-off you made on purpose, for example choosing files over a database, and why.

## How to explain challenges (the part that lands offers)

Have two or three real stories ready, structured as situation, problem, what you tried, and what you
learned. Good candidates from this project: making command-line matching case-insensitive after a
rule missed an upper-cased payload; separating public from private IPs so enrichment did not waste
lookups on RFC1918 addresses; deciding not to use the full pySigma library because you could not yet
explain it. Interviewers trust "here is what broke and how I reasoned about it" far more than a
flawless demo.
