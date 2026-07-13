"""Central logging setup. Import and call `setup_logging()` once at startup.

WHY: consistent, timestamped, level-controlled logs make the tool debuggable and
look professional. A SOC tool that cannot log about itself is a red flag.
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
