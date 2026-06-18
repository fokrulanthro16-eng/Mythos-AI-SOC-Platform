"""
dashboard/data_loader.py — Centralised data loading for the Mythos Command Center.

All functions accept an optional `path` argument so they can be tested with
temp files without touching the real log/data directories.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

ROOT_DIR      = Path(__file__).resolve().parent.parent
JSONL_PATH    = ROOT_DIR / "logs"  / "attribution_log.jsonl"
CSV_PATH      = ROOT_DIR / "logs"  / "attribution_log.csv"
PROFILES_PATH = ROOT_DIR / "data"  / "threat_profiles.json"
INCIDENTS_PATH= ROOT_DIR / "data"  / "sample_incidents.json"

_EXPECTED_COLS: list[str] = [
    "incident_id", "status", "threat_name", "severity",
    "confidence_score", "risk_score", "attribution_confidence", "campaign_id",
    "indicators", "ioc_enrichments", "suspected_actor", "mitigation_actions",
    "threat_summary", "enrichment_data", "created_at", "updated_at",
]

_NUMERIC_COLS = ("confidence_score", "risk_score", "attribution_confidence")
_TIME_COLS    = ("created_at", "updated_at")


# ---------------------------------------------------------------------------
# Primary loaders
# ---------------------------------------------------------------------------


def load_jsonl(path: Path | None = None) -> pd.DataFrame:
    """Load attribution_log.jsonl into a DataFrame (one row per state transition)."""
    p = path or JSONL_PATH
    if not p.exists():
        return _empty_df()
    rows: list[dict] = []
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not rows:
        return _empty_df()

    df = pd.DataFrame(rows)
    for col in _TIME_COLS:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    for col in _NUMERIC_COLS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    for col in _EXPECTED_COLS:
        if col not in df.columns:
            df[col] = ""
    return df


def load_profiles(path: Path | None = None) -> dict:
    """Load threat_profiles.json."""
    p = path or PROFILES_PATH
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_sample_incidents(path: Path | None = None) -> list[dict]:
    """Load sample_incidents.json."""
    p = path or INCIDENTS_PATH
    if not p.exists():
        return []
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Derived views
# ---------------------------------------------------------------------------


def latest_per_incident(df: pd.DataFrame) -> pd.DataFrame:
    """Return the last-known row for each unique incident_id."""
    if df.empty:
        return df
    col = "updated_at"
    if col in df.columns and not df[col].isna().all():
        return df.sort_values(col).groupby("incident_id", as_index=False).last()
    return df.groupby("incident_id", as_index=False).last()


def parse_ioc_enrichments(df: pd.DataFrame) -> pd.DataFrame:
    """
    Explode pipe-separated ioc_enrichments into individual rows with columns:
        incident_id | ioc | ioc_type | confidence
    """
    pattern = re.compile(r"^(.+)\s+\[type=(\w+)\s+conf=([\d.]+)\]$")
    rows: list[dict] = []
    for _, row in df.iterrows():
        raw = str(row.get("ioc_enrichments", ""))
        for entry in raw.split("|"):
            entry = entry.strip()
            if not entry:
                continue
            m = pattern.match(entry)
            if m:
                rows.append({
                    "incident_id": row.get("incident_id", ""),
                    "ioc":         m.group(1),
                    "ioc_type":    m.group(2),
                    "confidence":  float(m.group(3)),
                })
    return (
        pd.DataFrame(rows)
        if rows
        else pd.DataFrame(columns=["incident_id", "ioc", "ioc_type", "confidence"])
    )


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def filter_df(
    df: pd.DataFrame,
    severities:  list[str] | None = None,
    actors:      list[str] | None = None,
    campaigns:   list[str] | None = None,
    conf_range:  tuple[float, float] | None = None,
) -> pd.DataFrame:
    """Apply sidebar filters to the incidents DataFrame."""
    result = df.copy()
    if severities:
        result = result[result["severity"].isin(severities)]
    if actors:
        result = result[result["suspected_actor"].isin(actors)]
    if campaigns:
        result = result[result["campaign_id"].isin(campaigns)]
    if conf_range:
        lo, hi = conf_range
        result = result[
            (result["attribution_confidence"] >= lo) &
            (result["attribution_confidence"] <= hi)
        ]
    return result


# ---------------------------------------------------------------------------
# KPI computation
# ---------------------------------------------------------------------------


def compute_kpis(df: pd.DataFrame) -> dict[str, Any]:
    """Derive the four headline KPI metrics."""
    if df.empty:
        return {
            "total_incidents":            0,
            "active_campaigns":           0,
            "high_risk_incidents":        0,
            "avg_attribution_confidence": 0.0,
        }
    latest = latest_per_incident(df)
    camp_series = latest["campaign_id"].replace("", pd.NA).dropna()
    return {
        "total_incidents":            int(len(latest)),
        "active_campaigns":           int(camp_series.nunique()),
        "high_risk_incidents":        int((latest["risk_score"] >= 0.70).sum()),
        "avg_attribution_confidence": round(float(latest["attribution_confidence"].mean()), 4),
    }


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------


def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def df_to_json_bytes(df: pd.DataFrame) -> bytes:
    return df.to_json(orient="records", indent=2, date_format="iso", default_handler=str).encode("utf-8")


def _empty_df() -> pd.DataFrame:
    return pd.DataFrame(columns=_EXPECTED_COLS)
