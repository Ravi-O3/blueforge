# 06. First 30 Days

A concrete day-by-day plan for Phase 0 into early Phase 2. Weekdays assume about 1 to 2 hours;
weekend days assume more. If a day slips, shift the plan, do not skip the commit habit. The goal of
month one is a green, documented repo with a running lab and the first real detections.

Legend: **Task** / **Learn** / **Output** / **Commit message**.

| Day | Task | Learn | Output | Commit |
|-----|------|-------|--------|--------|
| 1 | Clone repo, read README + docs/00, run `make install` and `make test` | Project layout, venvs | Working local env | `chore: local dev environment set up` |
| 2 | Read `schema.py` and `normalizer/` end to end | Common schema idea | Notes in `docs/lessons` | `docs(lessons): notes on the common event schema` |
| 3 | Install VirtualBox, create Windows 10 VM | VM basics, host-only net | Windows VM snapshot | `docs(labs): windows vm build notes` |
| 4 | Install Sysmon with a good config (SwiftOnSecurity base) | Endpoint telemetry | Sysmon logging events | `docs(labs): sysmon install + config` |
| 5 | Stand up Wazuh manager (docker lab in `labs/`) | SIEM architecture | Wazuh dashboard up | `feat(labs): wazuh docker lab compose` |
| 6 (wknd) | Enroll the Windows VM as a Wazuh agent | Agent enrollment | Agent reporting | `docs(labs): agent enrollment walkthrough` |
| 7 (wknd) | Generate + export sample Sysmon events to JSONL | Log formats | `examples/` real capture | `feat(examples): captured sysmon samples` |
| 8 | Run `blueforge detect` on your capture | The pipeline | First real detections firing | `docs(lessons): first detection run` |
| 9 | Read `detections/engine.py`; explain it in your own words | Sigma subset | Written explanation | `docs: annotate detection engine walkthrough` |
| 10 | Write Sigma rule for T1059.001 (PowerShell) yourself | Rule authoring | New rule + test | `detection: powershell suspicious flags (T1059.001)` |
| 11 | Add a test for your rule with a sample log | pytest fixtures | Passing test | `test(detections): cover powershell rule` |
| 12 | Tune a false positive out of a rule | FP handling | Updated rule + FP note | `detection: reduce FPs on powershell rule` |
| 13 (wknd) | Simulate certutil download in the lab, capture logs | LOLBINs, T1105 | Telemetry + detection | `detection: certutil download (T1105)` |
| 14 (wknd) | Write the investigation steps for that alert | Triage workflow | Playbook draft | `docs(playbooks): certutil download triage` |
| 15 | Map all current rules to ATT&CK, run `attack_coverage.py` | ATT&CK navigation | Coverage output | `docs: attack coverage snapshot` |
| 16 | Read Wazuh `local_rules.xml`; test with `wazuh-logtest` | Wazuh rules | Verified custom rule | `detection(wazuh): powershell encoded command` |
| 17 | Add a Linux sshd brute-force correlation rule (Wazuh) | Correlation rules | Firing brute-force alert | `detection(wazuh): ssh brute force (T1110.001)` |
| 18 | Capture a brute-force in the lab (hydra against a lab VM) | Attack simulation | Alert + screenshot | `docs(labs): ssh brute force simulation` |
| 19 | Write a lessons-learned entry for week 3 | Reflection | `docs/lessons` entry | `docs(lessons): week 3 review` |
| 20 (wknd) | Build the timeline idea: order events for one incident | Timelines | Timeline draft output | `feat(hunting): naive event timeline` |
| 21 (wknd) | Write a full incident report for the certutil scenario | Reporting | Sample report in `docs` | `docs: sample incident report` |
| 22 | Add IOC extraction to your workflow, test it | Regex, IOCs | Passing IOC tests | `test(enrichment): ioc extraction edge cases` |
| 23 | Threat intel: wire AbuseIPDB (env key), handle "no key" | API integration | Enrichment verdict | `feat(enrichment): abuseipdb ip reputation` |
| 24 | Write a detection for T1218 (LOLBIN, e.g. mshta/rundll32) | Defense evasion | New rule + test | `detection: lolbin execution (T1218)` |
| 25 | Screenshot the Wazuh dashboard + a firing alert | Evidence | `screenshots/` images | `docs: add lab screenshots` |
| 26 (wknd) | Polish README: architecture image, badges, quickstart | Presentation | Stronger README | `docs: polish readme and add diagram` |
| 27 (wknd) | Open GitHub milestones + labels; file issues for backlog | Project mgmt | Organized board | `chore: seed milestones, labels, issues` |
| 28 | Add 2 more Sigma rules toward the 20-rule goal | Volume | 2 rules + tests | `detection: two new sysmon rules` |
| 29 | Write the "how I explain this project" interview note | Communication | `docs/11` personalized | `docs(career): interview walkthrough notes` |
| 30 | Retrospective: what worked, what is next (Phase 2 plan) | Reflection | Month-1 review | `docs(lessons): 30-day retrospective` |

By day 30 you have: a running lab, 8 to 12 tested detections mapped to ATT&CK, one Wazuh
correlation rule, IOC extraction and one live enrichment source, a sample incident report, lab
screenshots, and a green, well-presented repo. That is already interview-worthy.
