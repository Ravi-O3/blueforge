# Detection: <title>

- **ID:** bf-00NN
- **MITRE ATT&CK:** T#### (tactic: <tactic>)
- **Severity:** low | medium | high | critical
- **Status:** experimental | test | stable
- **Log source:** <e.g. Sysmon EventID 1 (process create)>
- **Key fields:** <Image, CommandLine, ParentImage>

## What it detects
<Plain-English description of the attacker behavior and why it matters.>

## Logic
<The rule in words, then the rule file link. Explain each matcher.>

## False positives
- <Known benign cause 1 and how to distinguish it.>

## Investigation steps
1. <First pivot: is this expected for the host/user?>
2. <Correlate parent process, timing, and IOCs.>
3. <Decision: close as benign / escalate / contain.>

## Test
- Sample log: <path in examples/>
- Expected result: rule fires / does not fire.
