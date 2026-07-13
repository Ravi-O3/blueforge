# 12. Senior Engineer Review

A blunt review of BlueForge from four perspectives, as requested. Read this as the bar to clear, not
as flattery. The whole point is to fix the weaknesses before a real reviewer finds them.

## As a Microsoft Security hiring manager

**Strengths.** The dual-stack decision is smart for this market: Wazuh proves you can self-host and
reason about a SIEM, and the Sentinel/KQL parity plus SC-200 alignment maps directly to the job.
Clean repo, CI, and tests signal you can work on a team. The common-schema design shows you
understand normalization, which is exactly the ASIM concept in Sentinel.

**Weaknesses.** Right now the Microsoft side is the thinnest part (a couple of KQL files). For a
Microsoft role that is the part I care about most. The AI phase risks looking like resume-driven
development if it appears before the fundamentals are deep.

**To stand out:** get real telemetry into a Sentinel trial, show one analytics rule with a working
automation playbook (Logic App), and screenshot an incident in the Defender portal. Depth on the
Microsoft stack beats breadth everywhere else for this specific employer.

## As a CrowdStrike detection engineer

**Strengths.** You detect behavior, not tools (the certutil and LOLBIN framing is correct). Rules are
versioned, tested, and MITRE-mapped, with documented false positives. That is genuinely how a
detection content team works. The "smallest rule that still catches them" instinct is the right one.

**Weaknesses.** The detection set is entry-level so far: single-event, command-line string matches.
Real adversaries evade those. There is little behavioral or correlation logic, no consideration of
detection evasion beyond casing, and no data volume to prove the rules survive contact with noise.

**To stand out:** add multi-event correlation and parent-child logic, write one rule that survives a
deliberate evasion attempt you document, and measure false-positive rate against a realistic noisy
dataset. Show a rule's whole lifecycle: hypothesis, telemetry, rule, test, evasion, tuning.

## As a SOC manager

**Strengths.** The triage and reporting automation solves a real analyst pain. Playbooks, incident
reports, and investigation steps show you think about the human workflow, not just the tech. The
isolated-lab and secrets discipline says you can be trusted with access.

**Weaknesses.** No alerting/notification path, no case tracking, and no metrics on analyst time
saved. As a manager I want to know it reduces mean-time-to-triage, and that is not measured yet.

**To stand out:** add one metric (for example, time from log to report) and a simple notification
(a webhook to a chat channel). Frame the value in SOC terms: fewer clicks, faster triage, consistent
reports.

## As a general senior engineer

**Strengths.** Small, typed, tested, documented, and honest about its own scope. The deliberate
omissions (no DB, no web UI, no async) are defensible and show maturity. The docs are unusually good
for a portfolio project.

**Weaknesses.** The custom engine is a subset of Sigma and could drift from the real spec; the
threat-intel layer is stubbed; there is no end-to-end integration test that runs the whole CLI.

**To improve:** add one integration test that exercises `blueforge detect` on sample logs and asserts
the report, and be explicit in the README about what the engine does and does not support versus
full Sigma.

## What makes this stand out vs look like a student project

**Stands out:** real detections mapped to ATT&CK with tests and tuning; a normalized schema; CI and
clean git history; documentation that explains *why*; dual-stack parity; honest scoping decisions;
lab evidence (screenshots, simulations) proving it actually runs.

**Looks like a student project (avoid these):** a pile of scripts with no tests or structure;
detections copied without understanding or MITRE mapping; a README that is only an install list; no
evidence it ran (no screenshots, no sample outputs); over-engineering (microservices, a database, a
web UI) with nothing behind it; and inflated claims that do not match the commit history. The
single biggest tell is the inability to explain a component you wrote. Every line here should pass
the "explain it out loud" test, which is exactly what this project is optimized for.

## The one-sentence verdict

If Phases 0 to 4 are actually completed, tested, and documented as described, BlueForge is a
top-decile junior portfolio project for the Canadian SOC/detection market, provided you deepen the
Microsoft side and add correlation and evasion-aware detections before calling it done.
