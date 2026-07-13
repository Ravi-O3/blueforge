# Wazuh detection content

Custom rules for the Wazuh manager, mapped to MITRE ATT&CK.

- `local_rules.xml` goes into `/var/ossec/etc/rules/local_rules.xml`.
- Sysmon rules rely on the Wazuh Sysmon decoders (Sysmon channel forwarded by the agent).
- The SSH brute-force rule is a correlation rule: it fires only when the base
  "failed password" rule (SID 5710) repeats from the same source IP.

Test each rule with `/var/ossec/bin/wazuh-logtest` before committing. Document the
test input and expected alert in the matching lab under `labs/`.
