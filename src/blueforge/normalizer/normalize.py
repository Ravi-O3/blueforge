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
        cleaned = value.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(cleaned)
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ):
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
    """Linux auth/syslog. sshd accepted/failed password lines, sudo, etc.

    Category logic: sshd lines are authentication; anything carrying a `command`
    (auditd execve, sudo, shell history shippers) is a process event so that
    process detections (e.g. bf-0008 curl-pipe-shell) can see it.
    """
    if r.get("program") == "sshd":
        category = EventCategory.AUTHENTICATION
    elif r.get("command"):
        category = EventCategory.PROCESS
    else:
        category = EventCategory.OTHER
    return Event(
        timestamp=_ts(r.get("timestamp")),
        source="linux",
        category=category,
        process=r.get("program"),
        host=r.get("host"),
        user=r.get("user"),
        src_ip=r.get("src_ip"),
        command_line=r.get("command"),
        raw=r,
    )


def _map_wazuh(r: dict[str, Any]) -> Event:
    """Map a Wazuh alert to our common Event schema, extracting process/user if present."""
    raw_rule = r.get("rule")
    rule: dict[str, Any] = raw_rule if isinstance(raw_rule, dict) else {}

    raw_agent = r.get("agent")
    agent: dict[str, Any] = raw_agent if isinstance(raw_agent, dict) else {}

    raw_data = r.get("data")
    data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}

    raw_win = data.get("win")
    win_data: dict[str, Any] = raw_win if isinstance(raw_win, dict) else {}

    raw_event = win_data.get("eventdata")
    event_data: dict[str, Any] = raw_event if isinstance(raw_event, dict) else {}

    process = event_data.get("image") or r.get("process")
    command_line = event_data.get("commandLine") or r.get("command") or r.get("full_log")
    parent_process = event_data.get("parentImage") or r.get("parent_process")
    user = event_data.get("user") or data.get("dstuser") or data.get("srcuser") or r.get("user")
    src_ip = r.get("src_ip") or data.get("srcip")

    category = EventCategory.PROCESS if (process or command_line) else EventCategory.ALERT
    host_name = agent.get("name") if agent else (str(raw_agent) if raw_agent else None)

    return Event(
        timestamp=_ts(r.get("timestamp")),
        source="wazuh",
        category=category,
        host=host_name,
        user=user,
        process=process,
        command_line=command_line,
        parent_process=parent_process,
        src_ip=src_ip,
        event_id=str(rule.get("id", "")) if rule else None,
        raw=r,
    )


_MAPPERS = {
    "sysmon": _map_sysmon,
    "windows": _map_windows,
    "linux": _map_linux,
    "wazuh": _map_wazuh,
}


def normalize(raw: dict[str, Any]) -> Event:
    """Normalize one raw record. Auto-detects source if _source is not provided."""
    source = str(raw.get("_source", "")).lower()
    if not source:
        if "rule" in raw and ("agent" in raw or "manager" in raw):
            source = "wazuh"
        elif any(k in raw for k in ("EventID", "UtcTime", "CommandLine", "TargetUserName")):
            sysmon_ids = {
                1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 22,
                "1", "2", "3", "5", "7", "8", "9", "10", "11", "12", "13", "22",
            }
            if "UtcTime" in raw or raw.get("EventID") in sysmon_ids:
                source = "sysmon"
            else:
                source = "windows"
        elif "program" in raw or "syslog" in raw:
            source = "linux"
        else:
            source = "other"

    mapper = _MAPPERS.get(source)
    if mapper is None:
        return Event(timestamp=_ts(raw.get("timestamp")), source=source, raw=raw)
    return mapper(raw)


def normalize_many(records: Iterable[dict[str, Any]]) -> Iterator[Event]:
    for r in records:
        yield normalize(r)
