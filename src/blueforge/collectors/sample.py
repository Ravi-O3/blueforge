"""Reads sample JSON Lines logs from disk. Used for tests, demos, and the MVP.

This is the collector you run in the lab: point it at a file of events exported
from your Wazuh/Sysmon lab and it feeds the pipeline.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from blueforge.collectors.base import Collector
from blueforge.utils.io import read_jsonl


class SampleCollector(Collector):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from read_jsonl(self.path)
