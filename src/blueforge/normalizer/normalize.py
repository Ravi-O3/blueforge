"""Field mapping from raw log formats to the common `Event` schema.

Each `_map_*` function knows ONE raw format. This is the only place in the codebase
that understands vendor-specific field names. Add a new log source? Add one function
here, and nothing downstream changes. That is the payoff of a common schema.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

from blueforge.schema import Event, EventCategory


def _ts(value: Any) -> datetime:
    """Best-effort timestamp parse. Falls back to now if the format is unknown."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def _map_sysmon(r: dict[str, Any]) -> Event:
    """Sysmon EventID 1 = process create. This is the workhorse of endpoint detection."""
    return Event(
        timestamp=_ts(r.get("UtcTime") or r.get("timestamp")),
        source="sysmon",
        category=EventCategory.PROCESS,
        host=r.get("Computer"),
        user=r.get("User"),
        process=r.get("Image"),
        command_line=r.get("CommandLine"),
        parent_process=r.get("ParentImage"),
        event_id=str(r.get("EventID", "")),
        raw=r,
    )


def _map_windows(r: dict[str, Any]) -> Event:
    """Windows Security log. 4624 = logon success, 4625 = logon failure."""
    eid = str(r.get("EventID", ""))
    category = EventCategory.AUTHENTICATION if eid in {"4624", "4625"} else EventCategory.OTHER
    return Event(
        timestamp=_ts(r.get("TimeCreated") or r.get("timestamp")),
        source="windows",
        category=category,
        host=r.get("Computer"),
        user=r.get("TargetUserName"),
        logon_type=str(r.get("LogonType")) if r.get("LogonType") is not None else None,
        src_ip=r.get("IpAddress"),
        event_id=eid,
        raw=r,
    )


def _map_linux(r: dict[str, Any]) -> Event:
    """Linux auth/syslog. sshd accepted/failed password lines, sudo, etc."""
    return Event(
        timestamp=_ts(r.get("timestamp")),
        source="linux",
        category=EventCategory.AUTHENTICATION if r.get("program") == "sshd" else EventCategory.OTHER,
        host=r.get("host"),
        user=r.get("user"),
        src_ip=r.get("src_ip"),
        command_line=r.get("command"),
        raw=r,
    )


def _map_wazuh(r: dict[str, Any]) -> Event:
    """A Wazuh alert is already an alert. We keep its rule id and level in raw."""
    return Event(
        timestamp=_ts(r.get("timestamp")),
        source="wazuh",
        category=EventCategory.ALERT,
        host=(r.get("agent") or {}).get("name") if isinstance(r.get("agent"), dict) else r.get("agent"),
        user=r.get("user"),
        src_ip=r.get("src_ip"),
        event_id=str((r.get("rule") or {}).get("id", "")) if isinstance(r.get("rule"), dict) else None,
        raw=r,
    )


_MAPPERS = {
    "sysmon": _map_sysmon,
    "windows": _map_windows,
    "linux": _map_linux,
    "wazuh": _map_wazuh,
}


def normalize(raw: dict[str, Any]) -> Event:
    """Normalize one raw record. Uses the `_source` key to pick the mapper."""
    source = str(raw.get("_source", "other")).lower()
    mapper = _MAPPERS.get(source)
    if mapper is None:
        return Event(timestamp=_ts(raw.get("timestamp")), source=source, raw=raw)
    return mapper(raw)


def normalize_many(records: Iterable[dict[str, Any]]) -> Iterator[Event]:
    for r in records:
        yield normalize(r)
