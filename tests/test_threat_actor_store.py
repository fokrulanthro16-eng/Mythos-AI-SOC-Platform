"""tests/test_threat_actor_store.py — Unit tests for dashboard/threat_actor_store.py.

All tests that touch the file system monkeypatch _PROFILES_PATH and
_CAMPAIGNS_PATH so they do not depend on the real data files.
Tests for pure compute functions (_compute_*) do not require monkeypatching.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import dashboard.threat_actor_store as ts
from dashboard.threat_actor_store import (
    FEATURED_ACTOR_IDS,
    _compute_attribution_confidence,
    _compute_campaign_stats,
    _compute_comparison_row,
    _compute_region_matrix,
    _compute_risk_score,
    _compute_sector_matrix,
    _compute_technique_frequency,
    _enrich_profile,
    filter_actors,
    get_actor,
    get_actor_campaigns,
    get_all_actors,
    get_comparison_data,
    get_featured_actors,
    get_region_matrix,
    get_sector_matrix,
    get_technique_frequency_for_actors,
    search_actors,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PROFILES = {
    "TESTACTOR-A": {
        "actor_id":      "TESTACTOR-A",
        "aliases":       ["Alpha Group", "Shadow Alpha"],
        "origin":        "Russia",
        "motivation":    ["financial", "espionage"],
        "sophistication":"advanced",
        "severity":      "CRITICAL",
        "ttps":          ["T1566.001", "T1059.001", "T1071.001", "T1486", "T1041", "T1078"],
        "known_tools":   ["Cobalt Strike", "Mimikatz", "Rclone"],
        "known_ioc_patterns": ["test-ioc.example", "192.0.2.1"],
        "description":   "Test actor Alpha used in unit tests.",
    },
    "TESTACTOR-B": {
        "actor_id":      "TESTACTOR-B",
        "aliases":       ["Beta Crew"],
        "origin":        "China",
        "motivation":    ["espionage"],
        "sophistication":"nation-state",
        "severity":      "CRITICAL",
        "ttps":          ["T1195.002", "T1059.001", "T1027", "T1041", "T1078", "T1550", "T1036", "T1074"],
        "known_tools":   ["ShadowPad", "Cobalt Strike"],
        "known_ioc_patterns": ["cdn-update-test.io"],
        "description":   "Test actor Beta, nation-state espionage.",
    },
    "TESTACTOR-C": {
        "actor_id":      "TESTACTOR-C",
        "aliases":       ["Gamma Ops"],
        "origin":        "North Korea",
        "motivation":    ["financial"],
        "sophistication":"intermediate",
        "severity":      "HIGH",
        "ttps":          ["T1566.001", "T1041"],
        "known_tools":   ["Custom C2"],
        "description":   "Test actor Gamma, intermediate.",
    },
}

_CAMPAIGNS = [
    {
        "campaign_id":             "CAMP-TEST-A-1",
        "name":                    "Test Campaign Alpha 1",
        "threat_actor":            "TESTACTOR-A",
        "tactic_category":         "Ransomware",
        "sophistication":          "advanced",
        "first_seen":              "2026-01-01",
        "last_seen":               "2026-06-01",
        "target_sectors":          ["Finance", "Healthcare"],
        "target_regions":          ["United States", "Europe"],
        "ttps":                    ["T1566.001", "T1486"],
        "tools":                   ["Cobalt Strike"],
        "description":             "Alpha campaign 1.",
        "ioc_domains":             ["a1.example.com"],
        "ioc_ips":                 ["192.0.2.10"],
        "status":                  "ACTIVE",
        "estimated_victims":       20,
        "known_ransom_demands_usd": 1000000,
    },
    {
        "campaign_id":             "CAMP-TEST-A-2",
        "name":                    "Test Campaign Alpha 2",
        "threat_actor":            "TESTACTOR-A",
        "tactic_category":         "Data Exfiltration",
        "sophistication":          "advanced",
        "first_seen":              "2026-02-01",
        "last_seen":               "2026-05-15",
        "target_sectors":          ["Government"],
        "target_regions":          ["Europe"],
        "ttps":                    ["T1041", "T1078"],
        "tools":                   ["Rclone"],
        "description":             "Alpha campaign 2.",
        "ioc_domains":             [],
        "ioc_ips":                 [],
        "status":                  "CONTAINED",
        "estimated_victims":       8,
        "known_ransom_demands_usd": 0,
    },
    {
        "campaign_id":             "CAMP-TEST-B-1",
        "name":                    "Test Campaign Beta",
        "threat_actor":            "TESTACTOR-B",
        "tactic_category":         "Espionage",
        "sophistication":          "nation-state",
        "first_seen":              "2025-11-01",
        "last_seen":               "2026-06-17",
        "target_sectors":          ["Technology", "Defence"],
        "target_regions":          ["United States", "Japan"],
        "ttps":                    ["T1195.002", "T1078"],
        "tools":                   ["ShadowPad"],
        "description":             "Beta espionage campaign.",
        "ioc_domains":             [],
        "ioc_ips":                 [],
        "status":                  "ACTIVE",
        "estimated_victims":       5,
        "known_ransom_demands_usd": 0,
    },
]


@pytest.fixture
def patch_data(tmp_path, monkeypatch):
    """Write test JSON files and point store at them."""
    profiles_file  = tmp_path / "threat_profiles.json"
    campaigns_file = tmp_path / "campaigns.json"
    profiles_file.write_text(json.dumps(_PROFILES), encoding="utf-8")
    campaigns_file.write_text(json.dumps(_CAMPAIGNS), encoding="utf-8")
    monkeypatch.setattr(ts, "_PROFILES_PATH",  profiles_file)
    monkeypatch.setattr(ts, "_CAMPAIGNS_PATH", campaigns_file)
    return {"profiles": profiles_file, "campaigns": campaigns_file}


# ---------------------------------------------------------------------------
# _compute_risk_score
# ---------------------------------------------------------------------------


def test_risk_score_nation_state_critical():
    p = {"sophistication": "nation-state", "severity": "CRITICAL", "ttps": ["T1"] * 10}
    score = _compute_risk_score(p)
    assert 0.90 <= score <= 1.00


def test_risk_score_intermediate_high():
    p = {"sophistication": "intermediate", "severity": "HIGH", "ttps": ["T1"] * 5}
    score = _compute_risk_score(p)
    assert 0.50 <= score <= 0.80


def test_risk_score_basic_low():
    p = {"sophistication": "basic", "severity": "LOW", "ttps": []}
    score = _compute_risk_score(p)
    assert score < 0.30


def test_risk_score_range():
    for soph in ("nation-state", "advanced", "intermediate", "basic"):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            p = {"sophistication": soph, "severity": sev, "ttps": ["T1"] * 5}
            s = _compute_risk_score(p)
            assert 0.0 <= s <= 1.0, f"Out of range for {soph}/{sev}: {s}"


def test_risk_score_missing_keys_no_crash():
    assert 0.0 <= _compute_risk_score({}) <= 1.0


def test_risk_score_ttp_breadth_contributes():
    base = _compute_risk_score({"sophistication": "advanced", "severity": "HIGH", "ttps": []})
    rich = _compute_risk_score({"sophistication": "advanced", "severity": "HIGH", "ttps": ["T1"] * 10})
    assert rich > base


# ---------------------------------------------------------------------------
# _compute_attribution_confidence
# ---------------------------------------------------------------------------


def test_attribution_confidence_nation_state_base():
    p = {"sophistication": "nation-state"}
    assert _compute_attribution_confidence(p, 0) >= 0.85


def test_attribution_confidence_incident_boost():
    p = {"sophistication": "advanced"}
    base    = _compute_attribution_confidence(p, 0)
    boosted = _compute_attribution_confidence(p, 5)
    assert boosted > base


def test_attribution_confidence_capped_at_098():
    p = {"sophistication": "nation-state"}
    assert _compute_attribution_confidence(p, 100) <= 0.98


def test_attribution_confidence_range():
    for soph in ("nation-state", "advanced", "intermediate", "basic"):
        p = {"sophistication": soph}
        c = _compute_attribution_confidence(p)
        assert 0.0 <= c <= 1.0


# ---------------------------------------------------------------------------
# _compute_campaign_stats
# ---------------------------------------------------------------------------


def test_campaign_stats_empty():
    s = _compute_campaign_stats([])
    assert s["total"] == 0
    assert s["active"] == 0
    assert s["victims"] == 0


def test_campaign_stats_counts():
    camps = [
        {"status": "ACTIVE",    "estimated_victims": 10, "known_ransom_demands_usd": 500000},
        {"status": "CONTAINED", "estimated_victims": 5,  "known_ransom_demands_usd": 0},
    ]
    s = _compute_campaign_stats(camps)
    assert s["total"]          == 2
    assert s["active"]         == 1
    assert s["victims"]        == 15
    assert s["max_demand_usd"] == 500000
    assert s["total_demand_usd"] == 500000


def test_campaign_stats_none_demand_treated_as_zero():
    camps = [{"status": "ACTIVE", "estimated_victims": 3, "known_ransom_demands_usd": None}]
    s = _compute_campaign_stats(camps)
    assert s["max_demand_usd"] == 0


# ---------------------------------------------------------------------------
# _enrich_profile
# ---------------------------------------------------------------------------


def test_enrich_adds_derived_fields():
    p = _PROFILES["TESTACTOR-A"].copy()
    enriched = _enrich_profile(p, _CAMPAIGNS[:2], incident_count=3)
    assert "risk_score" in enriched
    assert "attribution_confidence" in enriched
    assert "campaign_stats" in enriched
    assert "campaign_list" in enriched


def test_enrich_does_not_mutate_input():
    p = _PROFILES["TESTACTOR-A"].copy()
    original_keys = set(p.keys())
    _enrich_profile(p, [], 0)
    assert set(p.keys()) == original_keys


def test_enrich_campaign_list_set():
    p = _PROFILES["TESTACTOR-A"].copy()
    camps = _CAMPAIGNS[:1]
    enriched = _enrich_profile(p, camps, 0)
    assert enriched["campaign_list"] == camps


# ---------------------------------------------------------------------------
# _compute_technique_frequency
# ---------------------------------------------------------------------------


def test_technique_frequency_empty():
    assert _compute_technique_frequency([]) == {}


def test_technique_frequency_counts():
    actors = [
        {"ttps": ["T1566.001", "T1059.001"]},
        {"ttps": ["T1566.001", "T1078"]},
    ]
    freq = _compute_technique_frequency(actors)
    assert freq["T1566.001"] == 2
    assert freq["T1059.001"] == 1
    assert freq["T1078"]     == 1


def test_technique_frequency_no_ttps_field():
    freq = _compute_technique_frequency([{"actor_id": "X"}])
    assert freq == {}


# ---------------------------------------------------------------------------
# _compute_region_matrix / _compute_sector_matrix
# ---------------------------------------------------------------------------


def test_region_matrix_filters_by_actor_ids():
    matrix = _compute_region_matrix(_CAMPAIGNS, ["TESTACTOR-A"])
    assert "TESTACTOR-B" not in str(matrix)


def test_region_matrix_counts():
    matrix = _compute_region_matrix(_CAMPAIGNS, ["TESTACTOR-A", "TESTACTOR-B"])
    assert matrix.get("United States", {}).get("TESTACTOR-A", 0) >= 1


def test_sector_matrix_counts():
    matrix = _compute_sector_matrix(_CAMPAIGNS, ["TESTACTOR-A"])
    assert "Finance" in matrix or "Healthcare" in matrix or "Government" in matrix


# ---------------------------------------------------------------------------
# _compute_comparison_row
# ---------------------------------------------------------------------------


def test_comparison_row_keys():
    actor = _enrich_profile(_PROFILES["TESTACTOR-A"].copy(), _CAMPAIGNS[:2], 3)
    row = _compute_comparison_row(actor)
    required = {
        "actor_id", "risk_score", "attribution_confidence", "ttp_count",
        "campaign_count", "active_campaigns", "victim_count", "tool_count",
        "sophistication", "origin", "severity", "total_demand_usd",
    }
    assert required.issubset(row.keys())


def test_comparison_row_values_from_actor():
    actor = _enrich_profile(_PROFILES["TESTACTOR-A"].copy(), _CAMPAIGNS[:2], 3)
    row = _compute_comparison_row(actor)
    assert row["actor_id"]    == "TESTACTOR-A"
    assert row["ttp_count"]   == len(_PROFILES["TESTACTOR-A"]["ttps"])
    assert row["tool_count"]  == len(_PROFILES["TESTACTOR-A"]["known_tools"])


# ---------------------------------------------------------------------------
# File-backed public API (uses patch_data fixture)
# ---------------------------------------------------------------------------


def test_get_all_actors_returns_all(patch_data):
    actors = get_all_actors()
    assert len(actors) == 3
    ids = {a["actor_id"] for a in actors}
    assert ids == {"TESTACTOR-A", "TESTACTOR-B", "TESTACTOR-C"}


def test_get_all_actors_enriched(patch_data):
    for actor in get_all_actors():
        assert "risk_score"             in actor
        assert "attribution_confidence" in actor
        assert "campaign_stats"         in actor


def test_get_actor_found(patch_data):
    actor = get_actor("TESTACTOR-A")
    assert actor is not None
    assert actor["actor_id"] == "TESTACTOR-A"


def test_get_actor_not_found(patch_data):
    assert get_actor("DOES-NOT-EXIST") is None


def test_get_actor_campaigns_linked(patch_data):
    actor = get_actor("TESTACTOR-A")
    assert actor is not None
    assert actor["campaign_stats"]["total"] == 2
    assert actor["campaign_stats"]["active"] == 1


def test_get_actor_campaigns_function(patch_data):
    camps = get_actor_campaigns("TESTACTOR-A")
    assert len(camps) == 2
    assert all(c["threat_actor"] == "TESTACTOR-A" for c in camps)


def test_get_actor_campaigns_empty_for_unknown(patch_data):
    assert get_actor_campaigns("UNKNOWN-ACTOR") == []


def test_get_featured_actors_subset(patch_data, monkeypatch):
    monkeypatch.setattr(ts, "FEATURED_ACTOR_IDS", ["TESTACTOR-A", "TESTACTOR-B"])
    featured = get_featured_actors()
    assert len(featured) == 2
    assert featured[0]["actor_id"] == "TESTACTOR-A"
    assert featured[1]["actor_id"] == "TESTACTOR-B"


def test_get_featured_actors_skips_missing(patch_data, monkeypatch):
    monkeypatch.setattr(ts, "FEATURED_ACTOR_IDS", ["TESTACTOR-A", "NO-SUCH-ACTOR"])
    featured = get_featured_actors()
    assert len(featured) == 1


def test_search_empty_returns_all(patch_data):
    assert len(search_actors("")) == 3


def test_search_by_actor_id(patch_data):
    results = search_actors("TESTACTOR-A")
    assert any(a["actor_id"] == "TESTACTOR-A" for a in results)


def test_search_by_origin(patch_data):
    results = search_actors("Russia")
    assert all("russia" in a.get("origin", "").lower() for a in results)


def test_search_by_tool(patch_data):
    results = search_actors("Mimikatz")
    assert any(a["actor_id"] == "TESTACTOR-A" for a in results)


def test_search_by_ttp(patch_data):
    results = search_actors("T1486")
    assert any(a["actor_id"] == "TESTACTOR-A" for a in results)


def test_search_no_match_returns_empty(patch_data):
    results = search_actors("ZZZNOMATCH12345")
    assert results == []


def test_filter_by_origin(patch_data):
    results = filter_actors(origins=["Russia"])
    assert all("russia" in a.get("origin", "").lower() for a in results)


def test_filter_by_sophistication(patch_data):
    results = filter_actors(sophistication_levels=["nation-state"])
    assert all(a.get("sophistication") == "nation-state" for a in results)


def test_filter_by_motivation(patch_data):
    results = filter_actors(motivations=["espionage"])
    assert all(any("espionage" in m for m in a.get("motivation", [])) for a in results)


def test_filter_by_severity(patch_data):
    results = filter_actors(severities=["HIGH"])
    assert all(a.get("severity") == "HIGH" for a in results)


def test_filter_no_criteria_returns_all(patch_data):
    assert len(filter_actors()) == 3


def test_filter_combined(patch_data):
    results = filter_actors(origins=["China"], sophistication_levels=["nation-state"])
    assert all(
        "china" in a.get("origin", "").lower() and a.get("sophistication") == "nation-state"
        for a in results
    )


def test_get_comparison_data(patch_data):
    rows = get_comparison_data(["TESTACTOR-A", "TESTACTOR-B"])
    assert len(rows) == 2
    ids = {r["actor_id"] for r in rows}
    assert ids == {"TESTACTOR-A", "TESTACTOR-B"}


def test_get_comparison_data_skips_unknown(patch_data):
    rows = get_comparison_data(["TESTACTOR-A", "NO-SUCH"])
    assert len(rows) == 1


def test_get_technique_frequency(patch_data):
    freq = get_technique_frequency_for_actors(["TESTACTOR-A", "TESTACTOR-B"])
    assert "T1566.001" in freq
    assert "T1059.001" in freq
    assert freq["T1059.001"] >= 2  # present in both A and B


def test_get_region_matrix(patch_data):
    matrix = get_region_matrix(["TESTACTOR-A"])
    assert "United States" in matrix or "Europe" in matrix


def test_get_sector_matrix(patch_data):
    matrix = get_sector_matrix(["TESTACTOR-A"])
    assert "Finance" in matrix or "Healthcare" in matrix or "Government" in matrix


def test_featured_actor_ids_constant():
    assert "LOCKBIT4"      in FEATURED_ACTOR_IDS
    assert "APT29"         in FEATURED_ACTOR_IDS
    assert "LAZARUS-GROUP" in FEATURED_ACTOR_IDS
    assert len(FEATURED_ACTOR_IDS) == 6


def test_get_all_actors_empty_files(tmp_path, monkeypatch):
    pf = tmp_path / "threat_profiles.json"
    cf = tmp_path / "campaigns.json"
    pf.write_text("{}", encoding="utf-8")
    cf.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(ts, "_PROFILES_PATH",  pf)
    monkeypatch.setattr(ts, "_CAMPAIGNS_PATH", cf)
    assert get_all_actors() == []


def test_get_all_actors_missing_profiles_file(tmp_path, monkeypatch):
    cf = tmp_path / "campaigns.json"
    cf.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(ts, "_PROFILES_PATH",  tmp_path / "nonexistent.json")
    monkeypatch.setattr(ts, "_CAMPAIGNS_PATH", cf)
    assert get_all_actors() == []
