"""tests/test_threat_actor_engine.py — Unit tests for intelligence/threat_actor_engine.py.

All I/O is isolated via a tmp-path fixture so tests never touch the real
data/threat_actors.json unless explicitly testing its contents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intelligence.threat_actor_engine import (
    actor_campaign_count,
    actor_statistics,
    get_actor,
    load_actor_database,
    map_incident_to_actor,
    search_actor,
)

# ---------------------------------------------------------------------------
# Minimal actor fixtures
# ---------------------------------------------------------------------------

_ACTOR_LOCKBIT = {
    "name": "LockBit",
    "aliases": ["LockBit 4.0", "LockBit RaaS", "ABCD Ransomware"],
    "country": "Russia",
    "type": "Criminal",
    "motivation": ["Financial", "Ransomware-as-a-Service"],
    "sophistication": "advanced",
    "description": "Most prolific RaaS operation with cross-platform encryption.",
    "known_campaigns": ["LockBit 3.0 Global", "Hospital Network 2026"],
    "mitre_techniques": ["T1486", "T1490", "T1078", "T1059.001"],
    "severity": "CRITICAL",
    "attribution_confidence": 0.94,
}

_ACTOR_APT29 = {
    "name": "APT29",
    "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM"],
    "country": "Russia",
    "type": "Nation-State",
    "motivation": ["Espionage"],
    "sophistication": "nation-state",
    "description": "Russian SVR threat actor known for SolarWinds supply-chain attack.",
    "known_campaigns": ["Operation SolarWinds", "OAuth Phishing 2024"],
    "mitre_techniques": ["T1566.002", "T1528", "T1539", "T1078"],
    "severity": "CRITICAL",
    "attribution_confidence": 0.95,
}

_ACTOR_FIN7 = {
    "name": "FIN7",
    "aliases": ["Carbon Spider", "Carbanak Group"],
    "country": "Russia",
    "type": "Criminal",
    "motivation": ["Financial", "Payment Card Theft"],
    "sophistication": "advanced",
    "description": "Banking malware group behind Carbanak framework.",
    "known_campaigns": ["Operation Carbanak", "Banking Phishing Wave 2026"],
    "mitre_techniques": ["T1059.001", "T1059.005", "T1071.001", "T1056.001"],
    "severity": "CRITICAL",
    "attribution_confidence": 0.89,
}

_ACTOR_LAZARUS = {
    "name": "Lazarus",
    "aliases": ["HIDDEN COBRA", "TraderTraitor", "ZINC"],
    "country": "North Korea",
    "type": "Nation-State",
    "motivation": ["Financial", "Cryptocurrency Theft"],
    "sophistication": "nation-state",
    "description": "DPRK state actor responsible for WannaCry and $3B+ crypto theft.",
    "known_campaigns": ["WannaCry 2017", "TraderTraitor npm 2026"],
    "mitre_techniques": ["T1195.002", "T1059.001", "T1486", "T1552"],
    "severity": "CRITICAL",
    "attribution_confidence": 0.91,
}

_ACTOR_TA505 = {
    "name": "TA505",
    "aliases": ["Cl0p Operators", "Hive0065"],
    "country": "Russia",
    "type": "Criminal",
    "motivation": ["Financial", "Ransomware"],
    "sophistication": "advanced",
    "description": "Cl0p ransomware operators exploiting MFT zero-days.",
    "known_campaigns": ["MOVEit Zero-Day 2023", "Cl0p MFT Campaign 2026"],
    "mitre_techniques": ["T1190", "T1041", "T1074", "T1560", "T1567", "T1486"],
    "severity": "CRITICAL",
    "attribution_confidence": 0.92,
}

_ACTORS_5 = [_ACTOR_LOCKBIT, _ACTOR_APT29, _ACTOR_FIN7, _ACTOR_LAZARUS, _ACTOR_TA505]


@pytest.fixture()
def actor_db(tmp_path: Path) -> Path:
    """Write a 5-actor database to a temp file and return its path."""
    p = tmp_path / "threat_actors.json"
    p.write_text(json.dumps(_ACTORS_5), encoding="utf-8")
    return p


@pytest.fixture()
def single_actor_db(tmp_path: Path) -> Path:
    """Database with only LockBit."""
    p = tmp_path / "threat_actors_single.json"
    p.write_text(json.dumps([_ACTOR_LOCKBIT]), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# load_actor_database
# ---------------------------------------------------------------------------


def test_load_returns_list(actor_db):
    result = load_actor_database(actor_db)
    assert isinstance(result, list)


def test_load_correct_count(actor_db):
    result = load_actor_database(actor_db)
    assert len(result) == 5


def test_load_each_actor_is_dict(actor_db):
    for actor in load_actor_database(actor_db):
        assert isinstance(actor, dict)


def test_load_preserves_name(actor_db):
    names = {a["name"] for a in load_actor_database(actor_db)}
    assert "LockBit" in names
    assert "APT29" in names


def test_load_preserves_fields(actor_db):
    actors = load_actor_database(actor_db)
    lb = next(a for a in actors if a["name"] == "LockBit")
    assert lb["country"] == "Russia"
    assert lb["attribution_confidence"] == pytest.approx(0.94)


def test_load_real_database_has_10_actors():
    """The real threat_actors.json must contain exactly 10 actors."""
    actors = load_actor_database()
    assert len(actors) == 10


def test_load_real_database_required_fields():
    required = {"name", "aliases", "country", "type", "description",
                "known_campaigns", "mitre_techniques"}
    for actor in load_actor_database():
        missing = required - set(actor.keys())
        assert not missing, f"{actor.get('name')} missing fields: {missing}"


# ---------------------------------------------------------------------------
# get_actor — by name
# ---------------------------------------------------------------------------


def test_get_actor_by_exact_name(actor_db):
    result = get_actor("LockBit", actor_db)
    assert result is not None
    assert result["name"] == "LockBit"


def test_get_actor_by_name_case_insensitive(actor_db):
    assert get_actor("lockbit", actor_db) is not None
    assert get_actor("LOCKBIT", actor_db) is not None


def test_get_actor_by_alias(actor_db):
    result = get_actor("Cozy Bear", actor_db)
    assert result is not None
    assert result["name"] == "APT29"


def test_get_actor_by_alias_case_insensitive(actor_db):
    result = get_actor("midnight blizzard", actor_db)
    assert result is not None
    assert result["name"] == "APT29"


def test_get_actor_returns_none_for_unknown(actor_db):
    assert get_actor("NonExistentGroup", actor_db) is None


def test_get_actor_returns_dict(actor_db):
    result = get_actor("FIN7", actor_db)
    assert isinstance(result, dict)


def test_get_actor_by_alias_lazarus(actor_db):
    result = get_actor("TraderTraitor", actor_db)
    assert result is not None
    assert result["name"] == "Lazarus"


def test_get_actor_returns_all_fields(actor_db):
    actor = get_actor("TA505", actor_db)
    assert actor is not None
    assert "mitre_techniques" in actor
    assert "known_campaigns" in actor
    assert "attribution_confidence" in actor


# ---------------------------------------------------------------------------
# search_actor
# ---------------------------------------------------------------------------


def test_search_by_name(actor_db):
    results = search_actor("LockBit", actor_db)
    assert any(a["name"] == "LockBit" for a in results)


def test_search_by_country(actor_db):
    results = search_actor("North Korea", actor_db)
    assert any(a["name"] == "Lazarus" for a in results)


def test_search_by_description_keyword(actor_db):
    results = search_actor("SolarWinds", actor_db)
    assert any(a["name"] == "APT29" for a in results)


def test_search_by_type(actor_db):
    results = search_actor("Nation-State", actor_db)
    names = {a["name"] for a in results}
    assert "APT29"   in names
    assert "Lazarus" in names


def test_search_by_technique(actor_db):
    results = search_actor("T1190", actor_db)
    assert any(a["name"] == "TA505" for a in results)


def test_search_by_alias(actor_db):
    results = search_actor("Carbon Spider", actor_db)
    assert any(a["name"] == "FIN7" for a in results)


def test_search_by_campaign_name(actor_db):
    results = search_actor("MOVEit", actor_db)
    assert any(a["name"] == "TA505" for a in results)


def test_search_empty_query_returns_empty(actor_db):
    assert search_actor("", actor_db) == []


def test_search_whitespace_only_returns_empty(actor_db):
    assert search_actor("   ", actor_db) == []


def test_search_no_match_returns_empty(actor_db):
    assert search_actor("xyzzy_not_real_actor", actor_db) == []


def test_search_returns_list(actor_db):
    results = search_actor("Russia", actor_db)
    assert isinstance(results, list)


def test_search_results_sorted_by_name(actor_db):
    results = search_actor("Russia", actor_db)
    names = [r["name"] for r in results]
    assert names == sorted(names)


# ---------------------------------------------------------------------------
# actor_statistics
# ---------------------------------------------------------------------------


def test_actor_statistics_keys(actor_db):
    stats = actor_statistics(actor_db)
    required = {
        "total_actors", "by_country", "by_type", "by_sophistication",
        "total_campaigns", "total_techniques", "unique_techniques",
        "countries_represented", "avg_attribution_conf", "high_confidence_actors",
    }
    assert required.issubset(set(stats.keys()))


def test_actor_statistics_total_count(actor_db):
    stats = actor_statistics(actor_db)
    assert stats["total_actors"] == 5


def test_actor_statistics_by_country(actor_db):
    stats = actor_statistics(actor_db)
    assert stats["by_country"]["Russia"] == 4   # LockBit, APT29, FIN7, TA505
    assert stats["by_country"]["North Korea"] == 1


def test_actor_statistics_by_type(actor_db):
    stats = actor_statistics(actor_db)
    assert stats["by_type"]["Criminal"]     == 3   # LockBit, FIN7, TA505
    assert stats["by_type"]["Nation-State"] == 2   # APT29, Lazarus


def test_actor_statistics_countries_represented(actor_db):
    stats = actor_statistics(actor_db)
    assert stats["countries_represented"] == 2


def test_actor_statistics_total_campaigns(actor_db):
    stats = actor_statistics(actor_db)
    # LockBit=2, APT29=2, FIN7=2, Lazarus=2, TA505=2 = 10
    assert stats["total_campaigns"] == 10


def test_actor_statistics_avg_conf_in_range(actor_db):
    stats = actor_statistics(actor_db)
    assert 0.0 <= stats["avg_attribution_conf"] <= 1.0


def test_actor_statistics_high_confidence(actor_db):
    stats = actor_statistics(actor_db)
    # actors with conf >= 0.90: APT29(0.95), Lazarus(0.91), TA505(0.92), LockBit(0.94) = 4
    assert stats["high_confidence_actors"] == 4


def test_actor_statistics_technique_counts(actor_db):
    stats = actor_statistics(actor_db)
    assert stats["total_techniques"] >= 5
    assert stats["unique_techniques"] >= 1
    assert stats["unique_techniques"] <= stats["total_techniques"]


# ---------------------------------------------------------------------------
# actor_campaign_count
# ---------------------------------------------------------------------------


def test_campaign_count_keys(actor_db):
    result = actor_campaign_count(actor_db)
    names = set(result.keys())
    assert "LockBit"  in names
    assert "APT29"    in names
    assert "FIN7"     in names
    assert "Lazarus"  in names
    assert "TA505"    in names


def test_campaign_count_values(actor_db):
    result = actor_campaign_count(actor_db)
    # Each actor has 2 known_campaigns in our fixture
    assert result["LockBit"] == 2
    assert result["APT29"]   == 2


def test_campaign_count_returns_dict(actor_db):
    assert isinstance(actor_campaign_count(actor_db), dict)


def test_campaign_count_no_negative(actor_db):
    for count in actor_campaign_count(actor_db).values():
        assert count >= 0


# ---------------------------------------------------------------------------
# map_incident_to_actor
# ---------------------------------------------------------------------------


def _inc(threat_name="UNKNOWN", category="", actor="UNKNOWN", techniques=None):
    return {
        "incident_id":     "INC-2026-001",
        "threat_name":     threat_name,
        "suspected_actor": actor,
        "threat_category": category,
        "attack_techniques": [
            {"technique_id": t, "technique_name": "Test"}
            for t in (techniques or [])
        ],
    }


def test_map_ransomware_to_lockbit(actor_db):
    inc = _inc(threat_name="LOCKBIT4-RANSOMWARE")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "LockBit"


def test_map_powershell_to_fin7(actor_db):
    inc = _inc(category="PowerShell Abuse")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "FIN7"


def test_map_c2_to_ta505(actor_db):
    inc = _inc(category="Command and Control")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "TA505"


def test_map_lateral_movement_to_blackcat(actor_db):
    # BlackCat not in 5-actor DB, so should return None
    inc = _inc(category="Lateral Movement")
    result = map_incident_to_actor(inc, actor_db)
    assert result is None   # BlackCat not in fixture


def test_map_credential_harvesting_to_apt29(actor_db):
    inc = _inc(category="Credential Harvesting")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "APT29"


def test_map_explicit_suspected_actor_wins(actor_db):
    inc = _inc(threat_name="LOCKBIT4-RANSOMWARE", actor="APT29")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "APT29"


def test_map_technique_t1486_to_lockbit(actor_db):
    inc = _inc(techniques=["T1486"])
    result = map_incident_to_actor(inc, actor_db)
    assert result == "LockBit"


def test_map_technique_t1190_to_ta505(actor_db):
    inc = _inc(techniques=["T1190"])
    result = map_incident_to_actor(inc, actor_db)
    assert result == "TA505"


def test_map_unknown_returns_none(actor_db):
    inc = _inc(threat_name="UNKNOWN-MALWARE", category="", actor="UNKNOWN")
    result = map_incident_to_actor(inc, actor_db)
    assert result is None


def test_map_returns_string_or_none(actor_db):
    inc = _inc(threat_name="LOCKBIT4-RANSOMWARE")
    result = map_incident_to_actor(inc, actor_db)
    assert result is None or isinstance(result, str)


def test_map_clop_keyword_to_ta505(actor_db):
    inc = _inc(threat_name="CLOP-MOVEIT-EXPLOIT")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "TA505"


def test_map_midnight_blizzard_to_apt29(actor_db):
    inc = _inc(threat_name="MIDNIGHT-BLIZZARD-OAUTH")
    result = map_incident_to_actor(inc, actor_db)
    assert result == "APT29"
