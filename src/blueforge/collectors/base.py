"""Collector interface. Every collector implements `collect()`."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any


class Collector(ABC):
    """A source of raw log records.

    Each record is a plain dict. It must carry a `_source` key so the normalizer
    knows which mapping to apply (e.g. 'sysmon', 'linux', 'wazuh').
    """

    @abstractmethod
    def collect(self) -> Iterator[dict[str, Any]]:  # pragma: no cover - interface
        ...
