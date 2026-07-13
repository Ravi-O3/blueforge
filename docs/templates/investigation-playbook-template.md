# Playbook: <alert or scenario name>

**Trigger:** <which detection(s) start this playbook>
**MITRE:** <techniques involved>
**Severity guidance:** <when to treat as an incident>

## 1. Triage (first 5 minutes)
- Confirm the alert is not a known false positive (see the detection's FP notes).
- Identify host, user, process, and timestamp.
- Extract IOCs (IPs, domains, hashes) from the event.

## 2. Scope
- Has this host/user done this before? Check the baseline.
- Are the IOCs seen on other hosts?
- What is the parent process / how did this start?

## 3. Enrich
- Reputation lookups on public IOCs.
- Map observed behavior to ATT&CK to anticipate next steps.

## 4. Decide and act
- Benign: document why and close.
- Suspicious: escalate with the report.
- Malicious: contain (isolate host, disable account), then follow IR process.

## 5. Document
- Generate the incident report.
- Record a lessons-learned entry and any detection tuning needed.
