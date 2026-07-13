# Wazuh docker lab

A single-node Wazuh stack (manager + indexer + dashboard) to practice against.

```bash
cd labs/wazuh-docker
# EDIT docker-compose.yml first: change every CHANGE_ME password.
docker compose up -d
# Dashboard: https://localhost:5601
```

The BlueForge custom rules are mounted from `config/local_rules.xml` (a copy of
`detections/wazuh/local_rules.xml`). After changing rules, restart the manager:

```bash
docker compose restart wazuh.manager
```

This lab is for learning only. It uses default single-node settings and must not be exposed to an
untrusted network.
