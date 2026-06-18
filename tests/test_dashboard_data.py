"""tests/test_dashboard_data.py — Unit tests for dashboard/data_loader.py"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from dashboard.data_loader import (
    _empty_df,
    compute_kpis,
    df_to_csv_bytes,
    df_to_json_bytes,
    filter_df,
    latest_per_incident,
    load_jsonl,
    load_profiles,
    load_sample_incidents,
    parse_ioc_enrichments,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ROW_DETECTED = {
    "incident_id": "INC-001",
    "status": "DETECTED",
    "threat_name": "APT-SHADOW-VIPER",
    "severity": "CRITICAL",
    "confidence_score": 0.0,
    "risk_score": 0.0,
    "attribution_confidence": 0.0,
    "campaign_id": "",
    "indicators": "C2:1.2.3.4|hash:abc",
    "ioc_enrichments": "",
    "suspected_actor": "",
    "mitigation_actions": "",
    "threat_summary": "",
    "enrichment_data": "{}",
    "created_at": "2026-06-17T00:00:00+00:00",
    "updated_at": "2026-06-17T00:00:00+00:00",
}

_ROW_MITIGATED_001 = {
    "incident_id": "INC-001",
    "status": "MITIGATED",
    "threat_name": "APT-SHADOW-VIPER",
    "severity": "CRITICAL",
    "confidence_score": 0.87,
    "risk_score": 0.909,
    "attribution_confidence": 0.673,
    "campaign_id": "CAMP-TA50-2026-F1DF6A",
    "indicators": "C2:185.220.101.47",
    "ioc_enrichments": "C2:185.220.101.47 [type=C2_INFRASTRUCTURE conf=0.88]",
    "suspected_actor": "TA505",
    "mitigation_actions": "Block C2 IP",
    "threat_summary": "APT activity detected",
    "enrichment_data": '{"profile_match": true}',
    "created_at": "2026-06-17T00:00:00+00:00",
    "updated_at": "2026-06-17T00:01:00+00:00",
}

_ROW_MITIGATED_002 = {
    "incident_id": "INC-002",
    "status": "MITIGATED",
    "threat_name": "RANSOMWARE-LOCKBIT3",
    "severity": "HIGH",
    "confidence_score": 0.91,
    "risk_score": 0.862,
    "attribution_confidence": 0.795,
    "campaign_id": "CAMP-LOCK-2026-5939CB",
    "indicators": "hash:abc123",
    "ioc_enrichments": "hash:abc123 [type=MALWARE_HASH conf=0.95]",
    "suspected_actor": "LOCKBIT",
    "mitigation_actions": "Isolate endpoints",
    "threat_summary": "Ransomware detected",
    "enrichment_data": '{"profile_match": true}',
    "created_at": "2026-06-17T01:00:00+00:00",
    "updated_at": "2026-06-17T01:01:00+00:00",
}

_ROW_LOW = {
    "incident_id": "INC-003",
    "status": "MITIGATED",
    "threat_name": "ADWARE-BUNDLER",
    "severity": "LOW",
    "confidence_score": 0.40,
    "risk_score": 0.355,
    "attribution_confidence": 0.16,
    "campaign_id": "CAMP-UNKN-2026-6EA434",
    "indicators": "registry:HKCU",
    "ioc_enrichments": "registry:HKCU [type=PERSISTENCE_KEY conf=0.65]",
    "suspected_actor": "UNKNOWN-CRIMINAL-RING",
    "mitigation_actions": "Remove adware",
    "threat_summary": "Adware detected",
    "enrichment_data": "{}",
    "created_at": "2026-06-17T02:00:00+00:00",
    "updated_at": "2026-06-17T02:01:00+00:00",
}


def _write_jsonl(rows: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


@pytest.fixture
def sample_jsonl(tmp_path: Path) -> Path:
    p = tmp_path / "test.jsonl"
    _write_jsonl([_ROW_DETECTED, _ROW_MITIGATED_001, _ROW_MITIGATED_002, _ROW_LOW], p)
    return p


@pytest.fixture
def sample_df(sample_jsonl: Path) -> pd.DataFrame:
    return load_jsonl(sample_jsonl)


# ---------------------------------------------------------------------------
# load_jsonl
# ---------------------------------------------------------------------------


def test_load_jsonl_nonexistent_returns_empty(tmp_path: Path):
    df = load_jsonl(tmp_path / "missing.jsonl")
    assert isinstance(df, pd.DataFrame)
    assert df.empty


def test_load_jsonl_empty_file_returns_empty(tmp_path: Path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert load_jsonl(p).empty


def test_load_jsonl_returns_dataframe(sample_jsonl: Path):
    df = load_jsonl(sample_jsonl)
    assert isinstance(df, pd.DataFrame)
    assert not df.empty


def test_load_jsonl_row_count(sample_jsonl: Path):
    df = load_jsonl(sample_jsonl)
    assert len(df) == 4


def test_load_jsonl_has_required_columns(sample_df: pd.DataFrame):
    required = ["incident_id", "status", "threat_name", "severity",
                 "confidence_score", "risk_score", "attribution_confidence"]
    for col in required:
        assert col in sample_df.columns, f"Missing: {col}"


def test_load_jsonl_numeric_columns_are_float(sample_df: pd.DataFrame):
    for col in ("confidence_score", "risk_score", "attribution_confidence"):
        assert pd.api.types.is_float_dtype(sample_df[col]), f"{col} is not float"


def test_load_jsonl_timestamps_parsed(sample_df: pd.DataFrame):
    assert pd.api.types.is_datetime64_any_dtype(sample_df["created_at"])
    assert pd.api.types.is_datetime64_any_dtype(sample_df["updated_at"])


def test_load_jsonl_skips_malformed_lines(tmp_path: Path):
    p = tmp_path / "bad.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(_ROW_DETECTED) + "\n")
        fh.write("not json at all\n")
        fh.write(json.dumps(_ROW_MITIGATED_002) + "\n")
    df = load_jsonl(p)
    assert len(df) == 2


# ---------------------------------------------------------------------------
# load_profiles
# ---------------------------------------------------------------------------


def test_load_profiles_returns_dict():
    profiles = load_profiles()
    assert isinstance(profiles, dict)


def test_load_profiles_has_required_actors():
    profiles = load_profiles()
    for actor in ("TA505", "APT28", "APT29", "LOCKBIT4", "FIN7"):
        assert actor in profiles, f"Missing actor profile: {actor}"


def test_load_profiles_nonexistent_returns_empty(tmp_path: Path):
    result = load_profiles(tmp_path / "missing.json")
    assert result == {}


def test_load_profiles_actor_has_required_keys():
    profiles = load_profiles()
    for actor_id, profile in profiles.items():
        assert "ttps" in profile, f"{actor_id} missing ttps"
        assert "known_tools" in profile, f"{actor_id} missing known_tools"
        assert "severity" in profile, f"{actor_id} missing severity"


# ---------------------------------------------------------------------------
# load_sample_incidents
# ---------------------------------------------------------------------------


def test_load_sample_incidents_returns_list():
    incidents = load_sample_incidents()
    assert isinstance(incidents, list)


def test_load_sample_incidents_has_four_entries():
    incidents = load_sample_incidents()
    assert len(incidents) >= 4


def test_load_sample_incidents_nonexistent_returns_empty(tmp_path: Path):
    result = load_sample_incidents(tmp_path / "missing.json")
    assert result == []


# ---------------------------------------------------------------------------
# latest_per_incident
# ---------------------------------------------------------------------------


def test_latest_per_incident_deduplicates(sample_df: pd.DataFrame):
    latest = latest_per_incident(sample_df)
    assert latest["incident_id"].nunique() == len(latest)


def test_latest_per_incident_keeps_mitigated_status(sample_df: pd.DataFrame):
    latest = latest_per_incident(sample_df)
    inc001 = latest[latest["incident_id"] == "INC-001"].iloc[0]
    assert inc001["status"] == "MITIGATED"


def test_latest_per_incident_empty_df():
    result = latest_per_incident(_empty_df())
    assert result.empty


# ---------------------------------------------------------------------------
# filter_df
# ---------------------------------------------------------------------------


def test_filter_by_severity(sample_df: pd.DataFrame):
    result = filter_df(sample_df, severities=["CRITICAL"])
    assert all(result["severity"] == "CRITICAL")


def test_filter_by_actor(sample_df: pd.DataFrame):
    result = filter_df(sample_df, actors=["TA505"])
    assert all(result["suspected_actor"] == "TA505")


def test_filter_by_campaign(sample_df: pd.DataFrame):
    result = filter_df(sample_df, campaigns=["CAMP-TA50-2026-F1DF6A"])
    assert all(result["campaign_id"] == "CAMP-TA50-2026-F1DF6A")


def test_filter_by_conf_range(sample_df: pd.DataFrame):
    result = filter_df(sample_df, conf_range=(0.5, 1.0))
    assert all(result["attribution_confidence"] >= 0.5)


def test_filter_no_args_returns_all(sample_df: pd.DataFrame):
    result = filter_df(sample_df)
    assert len(result) == len(sample_df)


def test_filter_empty_lists_treated_as_no_filter(sample_df: pd.DataFrame):
    # None is treated as "no filter"; empty lists passed explicitly also
    result = filter_df(sample_df, severities=None, actors=None)
    assert len(result) == len(sample_df)


def test_filter_combination(sample_df: pd.DataFrame):
    result = filter_df(sample_df, severities=["CRITICAL"], actors=["TA505"])
    assert len(result) <= len(sample_df)
    if not result.empty:
        assert all(result["severity"] == "CRITICAL")
        assert all(result["suspected_actor"] == "TA505")


# ---------------------------------------------------------------------------
# compute_kpis
# ---------------------------------------------------------------------------


def test_compute_kpis_returns_dict(sample_df: pd.DataFrame):
    kpis = compute_kpis(sample_df)
    assert isinstance(kpis, dict)


def test_compute_kpis_required_keys(sample_df: pd.DataFrame):
    kpis = compute_kpis(sample_df)
    for key in ("total_incidents", "active_campaigns", "high_risk_incidents",
                 "avg_attribution_confidence"):
        assert key in kpis


def test_compute_kpis_total_incidents(sample_df: pd.DataFrame):
    kpis = compute_kpis(sample_df)
    assert kpis["total_incidents"] == 3  # 3 unique incidents


def test_compute_kpis_active_campaigns(sample_df: pd.DataFrame):
    kpis = compute_kpis(sample_df)
    assert kpis["active_campaigns"] == 3


def test_compute_kpis_empty_df():
    kpis = compute_kpis(_empty_df())
    assert kpis["total_incidents"] == 0
    assert kpis["avg_attribution_confidence"] == 0.0


def test_compute_kpis_avg_confidence_in_bounds(sample_df: pd.DataFrame):
    kpis = compute_kpis(sample_df)
    assert 0.0 <= kpis["avg_attribution_confidence"] <= 1.0


# ---------------------------------------------------------------------------
# parse_ioc_enrichments
# ---------------------------------------------------------------------------


def test_parse_ioc_enrichments_returns_dataframe(sample_df: pd.DataFrame):
    result = parse_ioc_enrichments(sample_df)
    assert isinstance(result, pd.DataFrame)


def test_parse_ioc_enrichments_has_columns(sample_df: pd.DataFrame):
    result = parse_ioc_enrichments(sample_df)
    for col in ("ioc", "ioc_type", "confidence"):
        assert col in result.columns


def test_parse_ioc_enrichments_confidence_numeric(sample_df: pd.DataFrame):
    result = parse_ioc_enrichments(sample_df)
    if not result.empty:
        assert pd.api.types.is_float_dtype(result["confidence"])


def test_parse_ioc_enrichments_empty_df():
    result = parse_ioc_enrichments(_empty_df())
    assert result.empty


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------


def test_df_to_csv_bytes_returns_bytes(sample_df: pd.DataFrame):
    data = df_to_csv_bytes(sample_df)
    assert isinstance(data, bytes)
    assert b"incident_id" in data


def test_df_to_json_bytes_returns_valid_json(sample_df: pd.DataFrame):
    import json as _json
    data = df_to_json_bytes(sample_df)
    assert isinstance(data, bytes)
    parsed = _json.loads(data.decode("utf-8"))
    assert isinstance(parsed, list)
