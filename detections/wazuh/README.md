# Wazuh detection content

Custom rules for the Wazuh manager, mapped to MITRE ATT&CK.

- `local_rules.xml` goes into `/var/ossec/etc/rules/local_rules.xml`.
- Sysmon rules rely on the Wazuh Sysmon decoders (Sysmon channel forwarded by the agent).
- The SSH brute-force rule is a correlation rule: it fires only when the base
  "failed password" rule (SID 5710) repeats from the same source IP.

| ID | Level | Detects | ATT&CK |
|--------|-------|---------------------------------------------|-----------|
| 100201 | 12 | PowerShell encoded command | T1059.001 |
| 100202 | 12 | Certutil remote file download | T1105 |
| 100203 | 6 | whoami discovery | T1033 |
| 100204 | 10 | Scheduled task created via schtasks | T1053.005 |
| 100205 | 14 | Possible LSASS credential dump | T1003.001 |
| 100206 | 10 | Local account created / added to admins | T1136.001 |
| 100210 | 10 | SSH brute-force (correlation, 6 in 120s) | T1110.001 |
| 100211 | 10 | Successful SSH login as root | T1078.003 |

The same file is deployed in the docker lab at `labs/wazuh-docker/config/local_rules.xml`;
keep the two copies in sync.

Test each rule with `/var/ossec/bin/wazuh-logtest` before committing. Document the
test input and expected alert in the matching lab under `labs/`.
