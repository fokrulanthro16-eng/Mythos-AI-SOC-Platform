"""
utils/config.py — Environment-driven configuration loader.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")


class MythosConfig:
    LOG_LEVEL: str = os.getenv("MYTHOS_LOG_LEVEL", "INFO")
    PROJECT_NAME: str = os.getenv("MYTHOS_PROJECT_NAME", "Project Mythos")
    INCIDENT_DATA_PATH: str = os.getenv(
        "MYTHOS_INCIDENT_DATA",
        str(ROOT_DIR / "data" / "sample_incidents.json"),
    )
    CONFIDENCE_THRESHOLD: float = float(os.getenv("MYTHOS_CONFIDENCE_THRESHOLD", "0.5"))
    RISK_CRITICAL_THRESHOLD: float = float(os.getenv("MYTHOS_RISK_CRITICAL_THRESHOLD", "0.8"))


config = MythosConfig()
