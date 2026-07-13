"""IOC (Indicator of Compromise) extraction from text.

WHY: an alert often contains the useful artifacts (an IP, a domain, a hash) buried
in a command line or message. Pulling them out is the first step of enrichment and
of any investigation. This is pure regex, no network calls, so it is fast and
testable.
"""

from __future__ import annotations

import re

# Deliberately readable patterns. Not RFC-perfect, but correct for SOC triage.
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# Private ranges are noise for threat intel; flag them separately.
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.")

# File/script extensions that look like domains (e.g. "powershell.exe") but are not.
# Keeping this list explicit and short makes the heuristic easy to explain and tune.
_FILE_EXTENSIONS = {
    "exe",
    "dll",
    "ps1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "sys",
    "tmp",
    "dat",
    "log",
    "txt",
    "lnk",
    "scr",
    "hta",
    "msi",
}


def _is_domain(candidate: str) -> bool:
    """A candidate is a domain only if it has a dot and its TLD is not a file extension."""
    if "." not in candidate:
        return False
    tld = candidate.rsplit(".", 1)[-1].lower()
    return tld not in _FILE_EXTENSIONS


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Return a dict of IOC type -> sorted unique values found in `text`."""
    if not text:
        return {"ipv4": [], "public_ipv4": [], "domain": [], "url": [], "md5": [], "sha256": []}

    ipv4 = sorted(set(_IPV4.findall(text)))
    public = [
        ip for ip in ipv4 if not ip.startswith(_PRIVATE_PREFIXES) and not ip.startswith("172.")
    ]
    return {
        "ipv4": ipv4,
        "public_ipv4": public,
        "domain": sorted({d for d in _DOMAIN.findall(text) if _is_domain(d)}),
        "url": sorted(set(_URL.findall(text))),
        "md5": sorted(set(_MD5.findall(text))),
        "sha256": sorted(set(_SHA256.findall(text))),
    }
