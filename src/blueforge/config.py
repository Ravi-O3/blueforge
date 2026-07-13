"""Configuration loaded from environment variables (see .env.example).

WHY env vars: secrets never live in code or git. This mirrors 12-factor apps and
keeps API keys out of the repo. Everything has a safe default so the tool runs even
with nothing configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    log_dir: str = os.getenv("BLUEFORGE_LOG_DIR", "./data/logs")
    output_dir: str = os.getenv("BLUEFORGE_OUTPUT_DIR", "./data/reports")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY") or None
    geoip_db_path: str | None = os.getenv("GEOIP_DB_PATH") or None


def load_config() -> Config:
    """Single entry point so the rest of the code never touches os.environ directly."""
    return Config()
