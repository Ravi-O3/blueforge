"""Shared test fixtures and paths."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"
SIGMA_RULES = REPO_ROOT / "detections" / "sigma"


@pytest.fixture
def sysmon_log() -> Path:
    return EXAMPLES / "sample_sysmon.jsonl"


@pytest.fixture
def sigma_dir() -> Path:
    return SIGMA_RULES
