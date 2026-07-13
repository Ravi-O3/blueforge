"""The normalized event schema. This is the contract of the whole platform.

WHY: Windows logs, Sysmon, Linux syslog, and Wazuh alerts all describe the same
kinds of things (a process started, a login happened, a network connection opened)
but with totally different field names. If every detection had to understand every
raw format, the code would be unmaintainable.

SOLUTION: Every collector converts its raw log into ONE shape, `Event`. Detections
only ever read `Event`. This is exactly what a SIEM does with a common schema
(think Elastic Common Schema or the Sentinel/ASIM normalized tables).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    """High-level category so detections can filter quickly."""

    PROCESS = "process"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    ALERT = "alert"  # a pre-built alert from Wazuh
    OTHER = "other"


class Event(BaseModel):
    """One normalized security event.

    Only `timestamp`, `source`, and `category` are always present. Everything else
    is optional because not every log type has every field. Raw, un-mapped fields
    are preserved in `raw` so nothing is ever lost.
    """

    timestamp: datetime
    source: str = Field(description="Where this came from, e.g. 'sysmon', 'linux', 'wazuh'")
    category: EventCategory = EventCategory.OTHER
    host: str | None = None
    user: str | None = None

    # Process fields (Sysmon EventID 1, Windows 4688, Linux execve)
    process: str | None = None
    command_line: str | None = None
    parent_process: str | None = None

    # Auth fields (Windows 4624/4625, Linux sshd)
    logon_type: str | None = None
    src_ip: str | None = None

    # Network fields
    dst_ip: str | None = None
    dst_port: int | None = None

    # File / registry
    target: str | None = None

    # Original event id and everything else
    event_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def get(self, field: str) -> Any:
        """Read a field by name (used by the detection engine)."""
        if hasattr(self, field):
            return getattr(self, field)
        return self.raw.get(field)
