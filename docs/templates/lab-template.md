# Lab: <name>

**Objective:** <what detection or behavior this lab exercises>
**MITRE:** <techniques>
**Blast radius:** isolated host-only network only. No internet, no production.

## Setup
- VMs and IPs used.
- Preconditions (agent installed, Sysmon config, etc.).

## Attack steps (safe / reversible)
1. <Command or action on the attacker VM.>
2. <What it does and why an attacker would do it.>

## What the attacker sees
<Output on the attacker side.>

## What the defender sees (telemetry)
- Raw log fields produced.
- Wazuh alert (rule id, level, description).

## Detection
- Which BlueForge / Wazuh / Sentinel rule catches it.
- Screenshot reference.

## Cleanup
<How to restore VMs to a clean snapshot.>
