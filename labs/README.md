# Labs

Reproducible attack and detection exercises. Each lab documents its objective, the safe/reversible
attack steps, the telemetry produced, and which detection catches it. Use
`docs/templates/lab-template.md` for new labs.

Safety rules for every lab: isolated host-only network only, snapshot before and restore after, no
real malware, no internet route. See `docs/threat-model.md`.

- `wazuh-docker/` spins up a single-node Wazuh stack for the SIEM side of the lab.
