"""tests/test_attack_engine.py — Unit tests for the ATT&CK lookup engine."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from intelligence.attack_engine import AttackEngine, _slim

# ---------------------------------------------------------------------------
# Required technique IDs (spec-mandated)
# ---------------------------------------------------------------------------

REQUIRED_IDS = {"T1056", "T1059", "T1071", "T1041", "T1110", "T1566", "T1486", "T1027"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine() -> AttackEngine:
    return AttackEngine()


@pytest.fixture
def empty_engine(tmp_path: Path) -> AttackEngine:
    db = tmp_path / "empty.json"
    db.write_text("[]", encoding="utf-8")
    return AttackEngine(db_path=db)


@pytest.fixture
def minimal_engine(tmp_path: Path) -> AttackEngine:
    db = tmp_path / "mini.json"
    db.write_text(
        json.dumps([
            {
                "technique_id": "T9001",
                "technique_name": "Test Technique",
                "display_name": "Test Thing",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "url": "https://attack.mitre.org/techniques/T9001/",
                "keywords": ["test", "example keyword"],
                "subtechniques": ["T9001.001"],
                "platforms": ["Windows"],
                "severity_weight": 0.5,
            }
        ]),
        encoding="utf-8",
    )
    return AttackEngine(db_path=db)


# ---------------------------------------------------------------------------
# Database coverage tests
# ---------------------------------------------------------------------------

def test_engine_loads_techniques(engine):
    assert len(engine.all_techniques()) >= 8


def test_all_required_ids_present(engine):
    loaded_ids = {t["technique_id"] for t in engine.all_techniques()}
    missing = REQUIRED_IDS - loaded_ids
    assert missing == set(), f"Missing required techniques: {missing}"


def test_all_techniques_have_required_fields(engine):
    required = ("technique_id", "technique_name", "tactic", "url")
    for tech in engine.all_techniques():
        for field in required:
            assert field in tech, f"{tech.get('technique_id')} missing field '{field}'"


def test_technique_ids_start_with_t(engine):
    for tech in engine.all_techniques():
        assert tech["technique_id"].startswith("T"), (
            f"Unexpected technique_id format: {tech['technique_id']}"
        )


def test_urls_point_to_attack_mitre(engine):
    for tech in engine.all_techniques():
        assert "attack.mitre.org" in tech["url"], (
            f"{tech['technique_id']} has unexpected URL: {tech['url']}"
        )


# ---------------------------------------------------------------------------
# Lookup tests
# ---------------------------------------------------------------------------

def test_lookup_known_id(engine):
    t = engine.lookup("T1059")
    assert t is not None
    assert t["technique_id"] == "T1059"


def test_lookup_case_insensitive(engine):
    assert engine.lookup("t1059") is not None
    assert engine.lookup("T1059") is not None
    assert engine.lookup("t1059") == engine.lookup("T1059")


def test_lookup_with_spaces(engine):
    t = engine.lookup("  T1059  ")
    assert t is not None


def test_lookup_unknown_id_returns_none(engine):
    assert engine.lookup("T9999") is None


def test_lookup_empty_string_returns_none(engine):
    assert engine.lookup("") is None


def test_lookup_each_required_technique(engine):
    for tid in REQUIRED_IDS:
        t = engine.lookup(tid)
        assert t is not None, f"lookup({tid!r}) returned None"
        assert t["technique_id"] == tid


# ---------------------------------------------------------------------------
# Search tests
# ---------------------------------------------------------------------------

def test_search_by_technique_id(engine):
    results = engine.search("T1059")
    ids = [t["technique_id"] for t in results]
    assert "T1059" in ids


def test_search_by_keyword(engine):
    results = engine.search("ransomware")
    ids = [t["technique_id"] for t in results]
    assert "T1486" in ids


def test_search_by_tactic(engine):
    results = engine.search("execution")
    tactics = [t["tactic"].lower() for t in results]
    assert any("execution" in tac for tac in tactics)


def test_search_empty_query_returns_all(engine):
    all_techs = engine.all_techniques()
    results = engine.search("")
    assert len(results) == len(all_techs[:50])  # default limit


def test_search_limit_respected(engine):
    results = engine.search("", limit=3)
    assert len(results) <= 3


def test_search_no_match_returns_empty(engine):
    results = engine.search("zzz_no_match_xyz_qrs")
    assert results == []


def test_search_phishing_finds_t1566(engine):
    results = engine.search("phishing")
    ids = [t["technique_id"] for t in results]
    assert "T1566" in ids


def test_search_brute_force_finds_t1110(engine):
    results = engine.search("brute force")
    ids = [t["technique_id"] for t in results]
    assert "T1110" in ids


# ---------------------------------------------------------------------------
# map_threat tests
# ---------------------------------------------------------------------------

def test_map_threat_ransomware(engine):
    results = engine.map_threat("RANSOMWARE-LOCKBIT3")
    ids = [t["technique_id"] for t in results]
    assert "T1486" in ids


def test_map_threat_phishing(engine):
    results = engine.map_threat("PHISH-CREDENTIAL-HARVEST")
    ids = [t["technique_id"] for t in results]
    # Should match at least one of phishing or credential harvesting
    assert "T1566" in ids or "T1056" in ids


def test_map_threat_powershell_indicators(engine):
    results = engine.map_threat("Malware", indicators=["powershell.exe", "cmd.exe"])
    ids = [t["technique_id"] for t in results]
    assert "T1059" in ids


def test_map_threat_exfil_keywords(engine):
    results = engine.map_threat("data exfiltration campaign")
    ids = [t["technique_id"] for t in results]
    assert "T1041" in ids


def test_map_threat_no_match_returns_empty(engine):
    results = engine.map_threat("zzz_no_such_threat_xyz")
    assert results == []


def test_map_threat_returns_at_most_5(engine):
    results = engine.map_threat(
        "ransomware phishing credential harvest exfil brute force powershell"
    )
    assert len(results) <= 5


def test_map_threat_returns_dicts(engine):
    results = engine.map_threat("ransomware")
    for t in results:
        assert isinstance(t, dict)
        assert "technique_id" in t


# ---------------------------------------------------------------------------
# enrich_state tests
# ---------------------------------------------------------------------------

class _FakeState:
    def __init__(self, threat_name, indicators=None):
        self.threat_name = threat_name
        self.indicators = indicators or []
        self.enrichment_data: dict = {}


def test_enrich_state_adds_attack_techniques(engine):
    state = _FakeState("RANSOMWARE-LOCKBIT3")
    engine.enrich_state(state)
    assert "attack_techniques" in state.enrichment_data
    assert len(state.enrichment_data["attack_techniques"]) > 0


def test_enrich_state_slim_format(engine):
    state = _FakeState("ransomware encrypt")
    engine.enrich_state(state)
    for t in state.enrichment_data.get("attack_techniques", []):
        assert "technique_id" in t
        assert "technique_name" in t
        assert "tactic" in t
        assert "url" in t


def test_enrich_state_no_match_leaves_no_key(engine):
    state = _FakeState("zzz_no_match_xyz")
    engine.enrich_state(state)
    assert "attack_techniques" not in state.enrichment_data


# ---------------------------------------------------------------------------
# stats tests
# ---------------------------------------------------------------------------

def test_stats_returns_dict(engine):
    s = engine.stats()
    assert isinstance(s, dict)


def test_stats_total_techniques(engine):
    s = engine.stats()
    assert s["total_techniques"] == len(engine.all_techniques())


def test_stats_total_tactics_positive(engine):
    s = engine.stats()
    assert s["total_tactics"] > 0


def test_stats_by_tactic_keys_match_techniques(engine):
    s = engine.stats()
    expected_tactics = {t["tactic"] for t in engine.all_techniques()}
    assert set(s["techniques_by_tactic"].keys()) == expected_tactics


def test_stats_subtechnique_count(engine):
    s = engine.stats()
    expected = sum(len(t.get("subtechniques", [])) for t in engine.all_techniques())
    assert s["total_subtechniques"] == expected


# ---------------------------------------------------------------------------
# Empty / error handling tests
# ---------------------------------------------------------------------------

def test_empty_engine_returns_empty_list(empty_engine):
    assert empty_engine.all_techniques() == []


def test_empty_engine_lookup_returns_none(empty_engine):
    assert empty_engine.lookup("T1059") is None


def test_empty_engine_search_returns_empty(empty_engine):
    assert empty_engine.search("ransomware") == []


def test_empty_engine_map_threat_returns_empty(empty_engine):
    assert empty_engine.map_threat("ransomware") == []


def test_empty_engine_stats_zeros(empty_engine):
    s = empty_engine.stats()
    assert s["total_techniques"] == 0
    assert s["total_tactics"] == 0


def test_missing_db_file_returns_empty():
    eng = AttackEngine(db_path=Path("/nonexistent/path/attack.json"))
    assert eng.all_techniques() == []


# ---------------------------------------------------------------------------
# _slim helper
# ---------------------------------------------------------------------------

def test_slim_extracts_required_fields():
    tech = {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "display_name": "PowerShell Abuse",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "keywords": ["powershell"],
    }
    slim = _slim(tech)
    assert slim["technique_id"] == "T1059"
    assert slim["tactic"] == "Execution"
    assert "keywords" not in slim
