# Installation Guide

Two parts: the BlueForge Python tool (fast) and the lab that produces logs (takes longer, optional
at first). You can use the tool against the bundled `examples/` logs before building the lab.

## 1. BlueForge tool

Requirements: Python 3.10+ and git.

```bash
git clone https://github.com/Ravi-O3/blueforge.git
cd blueforge
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
make install                       # installs deps + the package (editable)
cp .env.example .env               # optional: add API keys later
make test                          # should be all green
blueforge --help
```

Try it immediately on the sample logs:

```bash
blueforge detect --logs examples/sample_sysmon.jsonl --rules detections/sigma --report report.md
blueforge iocs --text "certutil -urlcache -f http://45.77.12.9/a.exe evil.com"
```

## 2. The lab (Wazuh + Sysmon)

Network: create a host-only network (for example 192.168.56.0/24) in VirtualBox or KVM so nothing
touches your real network. Suggested IPs: Wazuh 192.168.56.20, Windows 192.168.56.30, Kali
192.168.56.40.

### Wazuh manager (docker lab)
```bash
cd labs/wazuh-docker
docker compose up -d
# Dashboard: https://<host>:5601  (default creds are set in the compose file; change them)
```

### Windows endpoint
1. Install Sysmon with a vetted config (for example the SwiftOnSecurity base config).
2. Install the Wazuh agent and point it at the manager IP.
3. Enable forwarding of the Sysmon channel to Wazuh.

### Verify
Generate a test event (run `whoami` on the Windows VM) and confirm it appears in the Wazuh
dashboard, then export events to JSON Lines and run `blueforge detect` on them.

## Troubleshooting

- `blueforge: command not found` -> activate the venv and run `make install` again.
- Agent not reporting -> check the manager IP, firewall, and that ports 1514/1515 are open on the
  host-only network.
- Tests fail on a fresh clone -> ensure you ran `pip install -e .` (the Makefile does this).
