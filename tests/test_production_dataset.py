"""tests/test_production_dataset.py — Dataset integrity tests for Phase 7.1.

Validates the enriched sample_incidents.json, campaigns.json, and analysts.json
to ensure they meet the SOC platform's data quality requirements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_INCIDENTS_FILE = _ROOT / "data" / "sample_incidents.json"
_CAMPAIGNS_FILE = _ROOT / "data" / "campaigns.json"
_ANALYSTS_FILE  = _ROOT / "data" / "analysts.json"

_VALID_SEVERITIES   = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_INC_STATUSES = {"DETECTED", "INVESTIGATING", "CONTAINED", "MITIGATED", "RESOLVED"}
_VALID_ANALYST_TIERS = {"Tier 1", "Tier 2", "Tier 3"}
_REQUIRED_INCIDENT_FIELDS = {
    "incident_id", "threat_name", "severity", "status", "campaign_id",
    "created_at", "updated_at", "indicators", "confidence_score",
    "risk_score", "attribution_confidence", "suspected_actor",
    "attack_techniques", "description", "assigned_analyst",
}
_REQUIRED_ANALYST_FIELDS = {
    "analyst_id", "name", "email", "tier", "specializations",
    "certifications", "years_experience", "active_cases",
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def incidents() -> list[dict]:
    return json.loads(_INCIDENTS_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def campaigns() -> list[dict]:
    return json.loads(_CAMPAIGNS_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def analysts() -> list[dict]:
    return json.loads(_ANALYSTS_FILE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


def test_incidents_file_exists():
    assert _INCIDENTS_FILE.exists(), "sample_incidents.json not found"


def test_campaigns_file_exists():
    assert _CAMPAIGNS_FILE.exists(), "campaigns.json not found"


def test_analysts_file_exists():
    assert _ANALYSTS_FILE.exists(), "analysts.json not found"


# ---------------------------------------------------------------------------
# Incident count and structure
# ---------------------------------------------------------------------------


def test_incidents_count(incidents):
    assert len(incidents) == 50, f"Expected 50 incidents, got {len(incidents)}"


def test_incidents_required_fields(incidents):
    for inc in incidents:
        missing = _REQUIRED_INCIDENT_FIELDS - set(inc.keys())
        assert not missing, f"{inc['incident_id']} missing fields: {missing}"


def test_incidents_unique_ids(incidents):
    ids = [i["incident_id"] for i in incidents]
    assert len(ids) == len(set(ids)), "Duplicate incident_id values found"


def test_incidents_id_format(incidents):
    import re
    pattern = re.compile(r"^INC-\d{4}-\d{3,6}$")
    for inc in incidents:
        assert pattern.match(inc["incident_id"]), (
            f"Bad incident_id format: {inc['incident_id']}"
        )


def test_incidents_severity_distribution(incidents):
    from collections import Counter
    dist = Counter(i["severity"] for i in incidents)
    # Require at least one of each major severity
    assert dist["CRITICAL"] >= 1
    assert dist["HIGH"]     >= 1
    assert dist["MEDIUM"]   >= 1
    # All severities valid
    assert set(dist.keys()).issubset(_VALID_SEVERITIES)


def test_incidents_status_distribution(incidents):
    from collections import Counter
    dist = Counter(i["status"] for i in incidents)
    assert set(dist.keys()).issubset(_VALID_INC_STATUSES)
    # Should have both active and resolved incidents
    active   = dist["INVESTIGATING"] + dist["CONTAINED"] + dist["DETECTED"]
    resolved = dist["RESOLVED"] + dist["MITIGATED"]
    assert active   >= 5, "Expected at least 5 active incidents"
    assert resolved >= 5, "Expected at least 5 resolved/mitigated incidents"


def test_incidents_confidence_scores_in_range(incidents):
    for inc in incidents:
        conf = inc.get("confidence_score", 0)
        assert 0.0 <= conf <= 1.0, (
            f"{inc['incident_id']} confidence_score {conf} out of range"
        )


def test_incidents_risk_scores_in_range(incidents):
    for inc in incidents:
        risk = inc.get("risk_score", 0)
        assert 0.0 <= risk <= 1.0, (
            f"{inc['incident_id']} risk_score {risk} out of range"
        )


def test_incidents_attribution_confidence_in_range(incidents):
    for inc in incidents:
        attr = inc.get("attribution_confidence", 0)
        assert 0.0 <= attr <= 1.0, (
            f"{inc['incident_id']} attribution_confidence {attr} out of range"
        )


def test_incidents_all_have_indicators(incidents):
    for inc in incidents:
        assert isinstance(inc["indicators"], list), (
            f"{inc['incident_id']} indicators must be a list"
        )
        assert len(inc["indicators"]) > 0, (
            f"{inc['incident_id']} has no indicators"
        )


def test_incidents_all_have_attack_techniques(incidents):
    for inc in incidents:
        assert isinstance(inc["attack_techniques"], list), (
            f"{inc['incident_id']} attack_techniques must be a list"
        )
        assert len(inc["attack_techniques"]) >= 1, (
            f"{inc['incident_id']} has no attack_techniques"
        )


def test_incidents_attack_technique_structure(incidents):
    required_tech_fields = {"technique_id", "technique_name", "tactic"}
    for inc in incidents:
        for tech in inc.get("attack_techniques", []):
            missing = required_tech_fields - set(tech.keys())
            assert not missing, (
                f"{inc['incident_id']} technique missing fields: {missing}"
            )


def test_incidents_all_have_description(incidents):
    for inc in incidents:
        desc = inc.get("description", "")
        assert isinstance(desc, str) and len(desc) > 10, (
            f"{inc['incident_id']} has empty or short description"
        )


def test_incidents_all_have_assigned_analyst(incidents):
    for inc in incidents:
        analyst = inc.get("assigned_analyst", "")
        assert analyst, f"{inc['incident_id']} has no assigned_analyst"


def test_incidents_analysts_are_known(incidents, analysts):
    known_names = {a["name"] for a in analysts}
    for inc in incidents:
        analyst = inc.get("assigned_analyst", "")
        assert analyst in known_names, (
            f"{inc['incident_id']} assigned to unknown analyst: '{analyst}'"
        )


def test_incidents_created_at_parseable(incidents):
    from datetime import datetime
    for inc in incidents:
        ts_raw = inc.get("created_at", "")
        try:
            datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pytest.fail(f"{inc['incident_id']} invalid created_at: '{ts_raw}'")


def test_incidents_updated_at_parseable(incidents):
    from datetime import datetime
    for inc in incidents:
        ts_raw = inc.get("updated_at", "")
        try:
            datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pytest.fail(f"{inc['incident_id']} invalid updated_at: '{ts_raw}'")


def test_incidents_updated_not_before_created(incidents):
    from datetime import datetime
    for inc in incidents:
        c = datetime.fromisoformat(inc["created_at"].replace("Z", "+00:00"))
        u = datetime.fromisoformat(inc["updated_at"].replace("Z", "+00:00"))
        assert u >= c, (
            f"{inc['incident_id']}: updated_at {u} before created_at {c}"
        )


def test_incidents_all_have_campaign_id(incidents):
    for inc in incidents:
        assert inc.get("campaign_id"), f"{inc['incident_id']} has no campaign_id"


def test_incidents_mitre_technique_ids_format(incidents):
    import re
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for inc in incidents:
        for tech in inc.get("attack_techniques", []):
            tid = tech.get("technique_id", "")
            assert pattern.match(tid), (
                f"{inc['incident_id']}: bad technique_id format '{tid}'"
            )


def test_incidents_critical_high_majority(incidents):
    crit_high = sum(1 for i in incidents if i["severity"] in ("CRITICAL", "HIGH"))
    assert crit_high >= 25, (
        f"Expected >=25 CRITICAL+HIGH incidents (enterprise SOC bias), got {crit_high}"
    )


# ---------------------------------------------------------------------------
# Campaign tests
# ---------------------------------------------------------------------------


def test_campaigns_count(campaigns):
    assert len(campaigns) >= 20, f"Expected at least 20 campaigns, got {len(campaigns)}"


def test_campaigns_unique_ids(campaigns):
    ids = [c["campaign_id"] for c in campaigns]
    assert len(ids) == len(set(ids)), "Duplicate campaign_id values found"


def test_campaigns_required_fields(campaigns):
    required = {"campaign_id", "name", "threat_actor", "ttps", "status"}
    for camp in campaigns:
        missing = required - set(camp.keys())
        assert not missing, f"{camp['campaign_id']} missing: {missing}"


def test_campaigns_ttps_are_lists(campaigns):
    for camp in campaigns:
        assert isinstance(camp.get("ttps"), list), (
            f"{camp['campaign_id']} ttps must be a list"
        )


def test_campaigns_estimated_victims_non_negative(campaigns):
    for camp in campaigns:
        victims = camp.get("estimated_victims")
        if victims is not None:
            assert int(victims) >= 0, (
                f"{camp['campaign_id']} estimated_victims must be non-negative"
            )


def test_campaigns_cover_multiple_threat_actors(campaigns):
    actors = {c["threat_actor"] for c in campaigns}
    assert len(actors) >= 5, (
        f"Expected coverage of at least 5 distinct threat actors, got {len(actors)}"
    )


# ---------------------------------------------------------------------------
# Analyst tests
# ---------------------------------------------------------------------------


def test_analysts_count(analysts):
    assert len(analysts) == 10, f"Expected 10 analysts, got {len(analysts)}"


def test_analysts_required_fields(analysts):
    for a in analysts:
        missing = _REQUIRED_ANALYST_FIELDS - set(a.keys())
        assert not missing, f"{a.get('analyst_id')} missing: {missing}"


def test_analysts_unique_ids(analysts):
    ids = [a["analyst_id"] for a in analysts]
    assert len(ids) == len(set(ids)), "Duplicate analyst_id found"


def test_analysts_unique_names(analysts):
    names = [a["name"] for a in analysts]
    assert len(names) == len(set(names)), "Duplicate analyst name found"


def test_analysts_valid_tiers(analysts):
    for a in analysts:
        assert a["tier"] in _VALID_ANALYST_TIERS, (
            f"{a['name']} has invalid tier: {a['tier']}"
        )


def test_analysts_all_have_email(analysts):
    import re
    pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    for a in analysts:
        assert pattern.match(a.get("email", "")), (
            f"{a['name']} has invalid email: {a.get('email')}"
        )


def test_analysts_positive_experience(analysts):
    for a in analysts:
        assert a.get("years_experience", 0) >= 0


def test_analysts_have_specializations(analysts):
    for a in analysts:
        specs = a.get("specializations", [])
        assert isinstance(specs, list) and len(specs) >= 1, (
            f"{a['name']} must have at least one specialization"
        )


def test_analysts_have_certifications(analysts):
    for a in analysts:
        certs = a.get("certifications", [])
        assert isinstance(certs, list) and len(certs) >= 1, (
            f"{a['name']} must have at least one certification"
        )


def test_analysts_tier_distribution(analysts):
    from collections import Counter
    dist = Counter(a["tier"] for a in analysts)
    # Realistic SOC: should have both T1 entry-level and T2/T3 senior
    assert dist.get("Tier 1", 0) >= 1, "Expected at least 1 Tier 1 analyst"
    assert dist.get("Tier 2", 0) >= 1, "Expected at least 1 Tier 2 analyst"
    assert dist.get("Tier 3", 0) >= 1, "Expected at least 1 Tier 3 analyst"


# ---------------------------------------------------------------------------
# Cross-dataset consistency
# ---------------------------------------------------------------------------


def test_incidents_campaign_ids_exist_in_campaigns(incidents, campaigns):
    campaign_ids = {c["campaign_id"] for c in campaigns}
    for inc in incidents:
        cid = inc.get("campaign_id", "")
        assert cid in campaign_ids, (
            f"{inc['incident_id']} references unknown campaign: {cid}"
        )


def test_incidents_analyst_count_matches_roster(incidents, analysts):
    """All analysts assigned in incidents should appear in analysts.json."""
    analyst_names = {a["name"] for a in analysts}
    inc_analysts  = {i["assigned_analyst"] for i in incidents if i.get("assigned_analyst")}
    unknown = inc_analysts - analyst_names
    assert not unknown, f"Incidents reference unknown analysts: {unknown}"
