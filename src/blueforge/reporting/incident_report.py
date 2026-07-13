"""Render a Markdown incident report from detection matches.

WHY Markdown: it renders on GitHub, pastes into a ticket, and converts to PDF.
A SOC analyst's real output is a clear write-up, so the tool produces one
automatically. The template lives inline to keep the module self-contained.
"""

from __future__ import annotations

from datetime import datetime

from jinja2 import Environment

from blueforge.detections.engine import Match
from blueforge.enrichment.ioc import extract_iocs

# Register the `extract` filter on the Environment BEFORE compiling the template,
# because Jinja resolves filter names at compile time, not render time.
_ENV = Environment(trim_blocks=True, lstrip_blocks=True)
_ENV.filters["extract"] = lambda t: extract_iocs(t or "")

_TEMPLATE = _ENV.from_string(
    """# Incident Report: {{ title }}

**Generated:** {{ generated }}
**Detections fired:** {{ matches|length }}

## Summary

{{ matches|length }} detection(s) fired across the analyzed events. Highest severity: **{{ max_level }}**.

## Findings

{% for m in matches %}
### {{ loop.index }}. {{ m.detection.title }}  (`{{ m.detection.id }}`)

- **Severity:** {{ m.detection.level }}
- **MITRE ATT&CK:** {{ m.detection.mitre|join(', ') if m.detection.mitre else 'unmapped' }}
- **Host / User:** {{ m.event.host or 'n/a' }} / {{ m.event.user or 'n/a' }}
- **Timestamp:** {{ m.event.timestamp }}
- **Process:** `{{ m.event.process or 'n/a' }}`
- **Command line:** `{{ m.event.command_line or 'n/a' }}`
{% set iocs = m.event.command_line | extract %}
{% if iocs.public_ipv4 or iocs.domain or iocs.url %}
- **Extracted IOCs:** {{ (iocs.public_ipv4 + iocs.domain + iocs.url)|join(', ') }}
{% endif %}
{% if m.detection.description %}> {{ m.detection.description }}{% endif %}
{% endfor %}

## Recommended next steps

1. Validate whether the activity is expected for this host and user.
2. Pivot on the extracted IOCs (reputation lookups, other hosts touching them).
3. If confirmed malicious, isolate the host and follow the relevant playbook in `docs/`.
"""
)

_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_report(matches: list[Match], title: str = "Automated triage") -> str:
    max_level = "none"
    if matches:
        max_level = max(
            matches, key=lambda m: _LEVEL_ORDER.get(m.detection.level, 0)
        ).detection.level
    return _TEMPLATE.render(
        title=title,
        generated=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        matches=matches,
        max_level=max_level,
    )
