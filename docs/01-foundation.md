# 01. Project Foundation

## Name

**BlueForge** (repository: `blueforge`).

"Blue" for blue team (defense). "Forge" because the project is about *building* detections,
not just consuming them. The name reads like an internal enterprise security tool, which is
the positioning: BlueForge is the kind of platform a small SOC builds in-house to glue their
SIEM, detection content, and automation together.

## Vision

A single, understandable platform that takes raw security logs and turns them into detections,
alerts, investigations, and reports the way a real SOC does, built and operated by one analyst
who can explain every line of it.

## Mission

Give a transitioning analyst (Ravi) a working, growable environment to practice the full
detection engineering loop: collect, normalize, detect, enrich, hunt, report, and measure
coverage against MITRE ATT&CK, using both an open-source SIEM (Wazuh) and the Microsoft stack
(Sentinel / Defender XDR / KQL).

## Problem statement

Most junior candidates can talk about tools but cannot show the loop that connects them. They
have watched a Wazuh install video and written one Sigma rule, but they cannot answer "what
happens between a log line arriving and an analyst deciding it is an incident?" BlueForge exists
to make that loop concrete, versioned, and demonstrable.

Concretely, it solves four gaps:

1. **Format chaos.** Windows, Sysmon, Linux, and Wazuh all describe the same events with
   different field names. Without normalization, every detection is tied to one log format.
2. **Detection sprawl.** Rules get written in an ad-hoc way with no IDs, no MITRE mapping, no
   tests, and no record of false positives. BlueForge treats detections as versioned code.
3. **Manual triage.** Pulling IOCs out of an alert, looking them up, and writing a report is
   repetitive. That is exactly what automation should own.
4. **No coverage story.** "How good is your detection coverage?" is unanswerable without a way
   to map rules to ATT&CK. BlueForge produces a coverage count from the rules themselves.

## Target users

Primarily the author, as a learning and portfolio platform. Secondarily, the archetype it is
modeled on: a junior SOC analyst or detection engineer at a small-to-mid organization who owns
detection content and light automation on top of an existing SIEM.

## Why this project matters (for the career goal)

The Canadian entry-level market (Toronto, Waterloo, Ottawa) is competitive and Microsoft-heavy.
Employers screen for people who can do the work, not just name the tools. BlueForge is evidence
of exactly the day-one skills a SOC wants: reading logs, writing and testing detections, mapping
to ATT&CK, triaging with structure, and automating the boring parts. It also pairs directly with
the SC-200 certification through the Sentinel/KQL parity track.

## Similar industry tools (and where BlueForge sits)

BlueForge is not trying to replace these; it borrows their good ideas at a scale one person can
own and explain.

| Tool | What it is | What BlueForge borrows |
|------|-----------|------------------------|
| Wazuh | Open-source SIEM/XDR | Log collection, agent model, rule + MITRE mapping |
| Sigma | Generic detection rule format | The rule structure and the "write once" philosophy |
| Microsoft Sentinel | Cloud SIEM with KQL | Analytics rules, ASIM-style normalization, automation playbooks |
| Elastic / ELK | Search + detections | Common schema idea (ECS) |
| TheHive / Cortex | Case management + enrichment | Enrichment and report generation patterns |
| Atomic Red Team | Attack simulation library | Safe, documented attack tests to generate telemetry |

## What makes BlueForge different

It is deliberately small enough for one person to understand end to end, but structured like real
software: a normalized schema, versioned detections with tests and MITRE mappings, a documented
mini detection engine (so nothing is a black box), automation for triage, and dual-stack parity
between open-source (Wazuh) and Microsoft (Sentinel/KQL). The optimization target is not feature
count. It is understanding, explainability, demonstrable skill, and a clean GitHub presence.
