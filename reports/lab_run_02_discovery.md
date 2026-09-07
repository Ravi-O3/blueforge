# Incident Report: Automated triage

**Generated:** 2026-09-07T01:52:05Z
**Detections fired:** 1

## Summary

1 detection(s) fired. Highest severity: **medium**.

## Findings

### 1. Whoami Execution (Discovery)  (`bf-0003`)

- **Severity:** medium
- **MITRE ATT&CK:** T1033
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 01:41:33.225000+00:00
- **Process:** `C:\\Windows\\System32\\whoami.exe`
- **Command line:** `\"C:\\WINDOWS\\system32\\whoami.exe\"`
> whoami is run by attackers right after gaining access to understand their privileges. Rare on user workstations outside of IT activity.

## Recommended next steps

1. Validate whether the activity is expected for this host and user.
2. Pivot on the extracted IOCs (reputation lookups, other hosts touching them).
3. If confirmed malicious, isolate the host and follow the relevant playbook in `docs/`.