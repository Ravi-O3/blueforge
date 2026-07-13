# Detection Authoring Guide

How to add a detection to BlueForge so it is consistent, tested, and explainable. A detection is not
"done" until every step here is complete.

## The lifecycle of a detection

1. **Hypothesis.** Name the attacker behavior and the ATT&CK technique. Ask: what does the adversary
   do, and what artifact does it leave?
2. **Telemetry.** Identify the log source and exact fields (for example Sysmon EventID 1: Image,
   CommandLine, ParentImage). If you cannot see it, you cannot detect it.
3. **Simulate.** Generate the behavior safely in the lab (Atomic Red Team style, reversible) and
   capture the real log. Save a sample to `examples/`.
4. **Write the rule.** Start from `docs/templates/detection-template.md`. Keep it to one behavior.
5. **Map to MITRE.** Add the technique id(s). No mapping, no merge.
6. **Test.** Add a pytest case: the rule fires on the malicious sample and does not fire on a benign
   one.
7. **Tune.** Document at least one false positive and how to distinguish it. Narrow the matcher if
   needed. Never ship a rule you know is noisy without a note.
8. **Document investigation steps.** What an analyst does when it fires.

## Rule anatomy (BlueForge Sigma subset)

```yaml
title: Certutil Used to Download a File
id: bf-0002
level: high
mitre: [T1105, T1218]
logsource:
  category: process
detection:
  process|endswith: certutil.exe
  command_line|contains: ["urlcache", "http"]
  condition: all
falsepositives:
  - Legitimate certificate operations (which do not use urlcache against an external http host).
description: >
  certutil is a signed LOLBIN abused to download payloads while looking legitimate.
```

Supported operators: `equals` (default), `contains`, `startswith`, `endswith`. Matching is
case-insensitive. `condition` is `any` (OR) or `all` (AND) across the matchers. This is a documented
subset of Sigma; the files remain valid Sigma for later use with pySigma.

## Good rule hygiene

- Detect behavior, not tools. `certutil.exe` alone is not malicious; the download flags plus an
  external URL are.
- Assume evasion: never rely on exact casing or a single easily-changed string.
- One behavior per rule keeps tests and tuning simple.
- Prefer high-signal fields (parent process, command-line flags) over noisy ones.

## Wazuh and Sentinel parity

For a behavior worth detecting, add the Wazuh rule (`detections/wazuh/local_rules.xml`, test with
`wazuh-logtest`) and, where it applies, the KQL parity rule (`detections/sentinel/`). Parity is what
demonstrates you can work across an open-source and a Microsoft SOC.
