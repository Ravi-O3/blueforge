# 05. Development Roadmap

Assumptions: Ravi works full time, roughly 1 to 2 hours on weekdays and more on weekends. Estimates
are honest ranges of focused hours, not calendar time. The rule is that the project is shippable and
demoable at the end of every phase. Never leave `main` broken.

## Phase 0 - Foundation
- **Goals:** stand up the repo, docs, CI, and a working lab that produces logs.
- **Skills learned:** git/GitHub workflow, project structure, Wazuh + Sysmon install, VM networking.
- **Estimated hours:** 12 to 18.
- **Deliverables:** this repo scaffold pushed; Wazuh manager + one agent running; Sysmon logging;
  first sample logs captured; CI green.
- **Definition of done:** `make install && make test` passes locally and in CI; a Sysmon event from
  the Windows VM is visible in the Wazuh dashboard; README quickstart works from a clean clone.
- **GitHub milestone:** `Phase 0: Foundation`.
- **Resume value:** "Built and documented a self-hosted Wazuh + Sysmon detection lab with CI."

## Phase 1 - MVP
- **Goals:** collect one log source, normalize it, and fire the first three detections end to end.
- **Skills learned:** log normalization, common schema design, first Sigma rules, pytest.
- **Estimated hours:** 15 to 20.
- **Deliverables:** SampleCollector + normalizer for Sysmon; 3 to 5 Sigma rules with tests;
  `blueforge detect` prints matches; first auto-generated report.
- **Definition of done:** running `blueforge detect` on sample logs fires the expected rules and
  writes a Markdown report; every rule has a passing test and a MITRE mapping.
- **GitHub milestone:** `Phase 1: MVP`.
- **Resume value:** "Designed a normalized event schema and a tested detection pipeline in Python."

## Phase 2 - Detection Engine
- **Goals:** grow to 20+ detections across sources, formalize the engine, add ATT&CK coverage.
- **Skills learned:** detection engineering at volume, false-positive tuning, ATT&CK mapping, .evtx parsing.
- **Estimated hours:** 25 to 35.
- **Deliverables:** 20 Sigma rules + Wazuh `local_rules.xml`; evtx collector; `attack_coverage.py`
  report; documented FP notes per rule.
- **Definition of done:** coverage script reports 15+ unique techniques; each rule documents at least
  one false positive and an investigation step; Wazuh rules tested with `wazuh-logtest`.
- **GitHub milestone:** `Phase 2: Detection Engine`.
- **Resume value:** "Authored 20+ MITRE-mapped detections with documented tuning and tests."

## Phase 3 - Threat Hunting
- **Goals:** turn detections into hunts; simulate attacks; build timelines.
- **Skills learned:** hypothesis-driven hunting, attack simulation, timeline reconstruction.
- **Estimated hours:** 20 to 30.
- **Deliverables:** hunting query pack; 3 to 5 documented attack simulations (safe, reversible);
  timeline generator that orders events for an incident; investigation guides.
- **Definition of done:** each simulation has a matching detection and a written hunt with expected
  logs and steps; a timeline is generated from a multi-event scenario.
- **GitHub milestone:** `Phase 3: Threat Hunting`.
- **Resume value:** "Ran attack simulations and built hunts and timelines to validate detections."

## Phase 4 - Automation
- **Goals:** automate triage: IOC extraction, enrichment, report generation, and Sentinel/KQL parity.
- **Skills learned:** SOAR-style automation, API integration, threat intel, KQL, SC-200 topics.
- **Estimated hours:** 25 to 35.
- **Deliverables:** enrichment with real threat-intel lookups; end-to-end "logs in, report out"
  automation; KQL parity rules in `detections/sentinel/`.
- **Definition of done:** one command takes raw logs and produces an enriched incident report; at
  least 5 KQL rules mirror Sigma rules; API keys handled via env only.
- **GitHub milestone:** `Phase 4: Automation`.
- **Resume value:** "Automated alert triage (IOC extraction, enrichment, reporting) and built KQL parity in Sentinel."

## Phase 5 - AI Integration (optional)
- **Goals:** add a local LLM assistant for alert explanation and natural-language queries.
- **Skills learned:** local LLM integration, prompt design, safe AI-in-security patterns.
- **Estimated hours:** 15 to 25.
- **Deliverables:** optional module that summarizes an alert in plain English and suggests next
  steps, running against a local model; clearly isolated so the core never depends on it.
- **Definition of done:** the assistant explains a real alert usefully; it is off by default and the
  rest of the platform works without it.
- **GitHub milestone:** `Phase 5: AI Assistant`.
- **Resume value:** "Prototyped a local-LLM alert-explanation assistant with no data leaving the host."

## Phase 6 - Enterprise Features
- **Goals:** polish toward how a real team would run it: coverage dashboard, richer reporting, docs.
- **Skills learned:** metrics, dashboards, documentation at product quality.
- **Estimated hours:** 20 to 30.
- **Deliverables:** ATT&CK Navigator layer export; a simple coverage/metrics dashboard; hardened docs
  and a demo GIF; tagged v1.0 release.
- **Definition of done:** Navigator layer renders; README shows a demo; v1.0 tagged with release notes.
- **GitHub milestone:** `Phase 6: v1.0`.
- **Resume value:** "Shipped a documented v1.0 with ATT&CK coverage visualization and metrics."

## Total
Roughly 130 to 190 focused hours to reach a strong v1.0. At about 8 to 10 hours a week that is a
four to five month project, which is exactly the "continue improving for months" horizon you want on
a resume and in interviews.
