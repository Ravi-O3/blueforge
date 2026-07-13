# Example logs

Small JSON Lines samples used by tests and demos. Each line is one raw event with a
`_source` key telling the normalizer which mapping to apply.

- `sample_sysmon.jsonl` triggers several Sigma rules (encoded PowerShell, certutil download, whoami recon).
- `sample_windows_auth.jsonl` shows a failed then successful logon from a Tor exit node IP.
- `sample_linux_auth.jsonl` shows SSH brute-force followed by success.
- `sample_wazuh_alert.jsonl` is a pre-built Wazuh alert (already normalized as category `alert`).

These are synthetic. Never commit real logs.
