"""Threat intel lookups (VirusTotal, AbuseIPDB).

Kept as a thin, optional layer: if no API key is configured, it returns an
'unknown' verdict instead of failing. That keeps the core pipeline runnable with
zero external dependencies, which matters for a demo and for tests.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from blueforge.config import Config


@dataclass
class Verdict:
    indicator: str
    source: str
    malicious: bool | None  # None = unknown / not looked up
    detail: str = ""


def check_ip_abuseipdb(ip: str, config: Config, timeout: int = 10) -> Verdict:
    """Look up an IP reputation. Returns 'unknown' if no key is set."""
    if not config.abuseipdb_api_key:
        return Verdict(ip, "abuseipdb", None, "no API key configured")
    params: dict[str, str | int] = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.abuseipdb_api_key, "Accept": "application/json"},
            params=params,
            timeout=timeout,
        )
        resp.raise_for_status()
        score = resp.json().get("data", {}).get("abuseConfidenceScore", 0)
        return Verdict(ip, "abuseipdb", score >= 50, f"abuse score {score}")
    except requests.RequestException as exc:  # pragma: no cover - network path
        return Verdict(ip, "abuseipdb", None, f"lookup failed: {exc}")
