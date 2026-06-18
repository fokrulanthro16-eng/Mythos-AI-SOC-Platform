"""
core/logger.py — Centralised logging and state-transition persistence.
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path

# Ensure stdout handles UTF-8 on Windows (cp1252 default can't render special chars)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = ROOT_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

JSONL_LOG = LOGS_DIR / "attribution_log.jsonl"
CSV_LOG   = LOGS_DIR / "attribution_log.csv"

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s :: %(message)s"
_configured = False

_CSV_FIELDS = [
    "incident_id", "status", "threat_name", "severity",
    "confidence_score", "risk_score", "attribution_confidence", "campaign_id",
    "indicators", "ioc_enrichments", "suspected_actor", "mitigation_actions",
    "threat_summary", "enrichment_data", "created_at", "updated_at",
]
_EXPECTED_HEADER = ",".join(_CSV_FIELDS)


def setup_logging(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger("mythos")
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"mythos.{name}")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def persist(state: object) -> None:
    _append_jsonl(state)
    _append_csv(state)


def _append_jsonl(state: object) -> None:
    with JSONL_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(state.to_log_dict()) + "\n")  # type: ignore[attr-defined]


def _append_csv(state: object) -> None:
    need_header = _ensure_csv_schema()
    with CSV_LOG.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
        if need_header:
            writer.writeheader()
        writer.writerow(state.to_log_dict())  # type: ignore[attr-defined]


def _ensure_csv_schema() -> bool:
    """
    Return True (and signal that a header must be written) if:
      - the CSV does not exist yet, OR
      - the existing CSV header doesn't match the current _CSV_FIELDS schema
        (in which case the stale file is archived before a fresh one is started).
    """
    if not CSV_LOG.exists() or CSV_LOG.stat().st_size == 0:
        return True

    with CSV_LOG.open("r", encoding="utf-8") as fh:
        first_line = fh.readline().strip()

    if first_line != _EXPECTED_HEADER:
        # Archive the stale log so we don't lose history
        from datetime import datetime, timezone
        ts = int(datetime.now(timezone.utc).timestamp())
        archive = LOGS_DIR / f"attribution_log_v{ts}.csv"
        CSV_LOG.rename(archive)
        return True

    return False
