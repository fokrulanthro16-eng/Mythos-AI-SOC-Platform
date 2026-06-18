"""tests/test_validators.py — Unit tests for dashboard/validators.py.

Tests every validator and the dataset-level validate_dataset helper.
"""

from __future__ import annotations

import pytest

from dashboard.validators import (
    validate_analyst,
    validate_campaign,
    validate_case,
    validate_dataset,
    validate_incident,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(validator, record: dict) -> None:
    valid, errors = validator(record)
    assert valid, f"Expected valid, got errors: {errors}"


def _err(validator, record: dict, fragment: str) -> None:
    valid, errors = validator(record)
    assert not valid, "Expected invalid, but was valid"
    assert any(fragment.lower() in e.lower() for e in errors), (
        f"Expected error containing '{fragment}', got: {errors}"
    )


def _minimal_incident(**overrides) -> dict:
    base = {
        "incident_id": "INC-2026-001",
        "threat_name": "LOCKBIT4-RANSOMWARE",
        "severity":    "CRITICAL",
        "status":      "INVESTIGATING",
        "created_at":  "2026-05-18T02:14:33Z",
    }
    base.update(overrides)
    return base


def _minimal_campaign(**overrides) -> dict:
    base = {
        "campaign_id":  "CAMP-LOCKBIT4-2026",
        "name":         "LockBit 4.0 Global Campaign",
        "threat_actor": "LOCKBIT4",
        "status":       "ACTIVE",
        "first_seen":   "2026-01-08",
        "last_seen":    "2026-06-15",
    }
    base.update(overrides)
    return base


def _minimal_case(**overrides) -> dict:
    base = {
        "id":         "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "title":      "LockBit — Hospital Network Encryption",
        "status":     "OPEN",
        "priority":   "P1",
        "created_at": "2026-05-18T03:00:00Z",
    }
    base.update(overrides)
    return base


def _minimal_analyst(**overrides) -> dict:
    base = {
        "analyst_id": "ANA-001",
        "name":       "Sarah Kim",
        "email":      "s.kim@soc.mythos",
        "tier":       "Tier 2",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# validate_incident — valid cases
# ---------------------------------------------------------------------------


def test_incident_valid_minimal():
    _ok(validate_incident, _minimal_incident())


def test_incident_valid_all_fields():
    _ok(validate_incident, _minimal_incident(
        updated_at="2026-05-19T10:00:00Z",
        confidence_score=0.91,
        risk_score=0.87,
        attribution_confidence=0.85,
        indicators=["hash:abc123"],
        attack_techniques=[{"technique_id": "T1486", "technique_name": "Data Encrypted"}],
    ))


def test_incident_valid_all_statuses():
    for status in ("DETECTED", "INVESTIGATING", "CONTAINED", "MITIGATED", "RESOLVED"):
        _ok(validate_incident, _minimal_incident(status=status))


def test_incident_valid_all_severities():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        _ok(validate_incident, _minimal_incident(severity=sev))


def test_incident_valid_confidence_at_boundaries():
    _ok(validate_incident, _minimal_incident(confidence_score=0.0))
    _ok(validate_incident, _minimal_incident(confidence_score=1.0))


def test_incident_valid_empty_indicators():
    _ok(validate_incident, _minimal_incident(indicators=[]))


def test_incident_valid_updated_after_created():
    _ok(validate_incident, _minimal_incident(
        created_at="2026-05-18T00:00:00Z",
        updated_at="2026-05-19T00:00:00Z",
    ))


# ---------------------------------------------------------------------------
# validate_incident — invalid cases
# ---------------------------------------------------------------------------


def test_incident_invalid_missing_id():
    _err(validate_incident, _minimal_incident(incident_id=""), "incident_id")


def test_incident_invalid_id_format():
    _err(validate_incident, _minimal_incident(incident_id="BAD-ID"), "incident_id")


def test_incident_invalid_severity():
    _err(validate_incident, _minimal_incident(severity="EXTREME"), "severity")


def test_incident_invalid_status():
    _err(validate_incident, _minimal_incident(status="PENDING"), "status")


def test_incident_invalid_missing_threat_name():
    _err(validate_incident, _minimal_incident(threat_name=""), "threat_name")


def test_incident_invalid_created_at_format():
    _err(validate_incident, _minimal_incident(created_at="not-a-date"), "created_at")


def test_incident_invalid_updated_before_created():
    _err(validate_incident, _minimal_incident(
        created_at="2026-05-18T10:00:00Z",
        updated_at="2026-05-17T10:00:00Z",
    ), "updated_at")


def test_incident_invalid_confidence_above_1():
    _err(validate_incident, _minimal_incident(confidence_score=1.5), "confidence_score")


def test_incident_invalid_confidence_below_0():
    _err(validate_incident, _minimal_incident(confidence_score=-0.1), "confidence_score")


def test_incident_invalid_risk_score_not_numeric():
    _err(validate_incident, _minimal_incident(risk_score="high"), "risk_score")


def test_incident_invalid_attribution_above_1():
    _err(validate_incident, _minimal_incident(attribution_confidence=1.1), "attribution_confidence")


def test_incident_invalid_indicators_not_list():
    _err(validate_incident, _minimal_incident(indicators="hash:abc"), "indicators")


def test_incident_invalid_attack_techniques_not_list():
    _err(validate_incident, _minimal_incident(attack_techniques="T1486"), "attack_techniques")


def test_incident_invalid_technique_missing_id():
    _err(validate_incident, _minimal_incident(
        attack_techniques=[{"technique_name": "Data Encrypted"}]
    ), "technique_id")


# ---------------------------------------------------------------------------
# validate_campaign — valid cases
# ---------------------------------------------------------------------------


def test_campaign_valid_minimal():
    _ok(validate_campaign, _minimal_campaign())


def test_campaign_valid_full():
    _ok(validate_campaign, _minimal_campaign(
        sophistication="advanced",
        ttps=["T1486", "T1490"],
        estimated_victims=38,
        known_ransom_demands_usd=2500000,
    ))


def test_campaign_valid_all_statuses():
    for status in ("ACTIVE", "INACTIVE", "DISRUPTED", "MONITORING"):
        _ok(validate_campaign, _minimal_campaign(status=status))


def test_campaign_valid_all_sophistication():
    for soph in ("basic", "intermediate", "advanced", "nation-state"):
        _ok(validate_campaign, _minimal_campaign(sophistication=soph))


def test_campaign_valid_zero_victims():
    _ok(validate_campaign, _minimal_campaign(estimated_victims=0))


# ---------------------------------------------------------------------------
# validate_campaign — invalid cases
# ---------------------------------------------------------------------------


def test_campaign_invalid_missing_id():
    _err(validate_campaign, _minimal_campaign(campaign_id=""), "campaign_id")


def test_campaign_invalid_id_format():
    _err(validate_campaign, _minimal_campaign(campaign_id="CAMP"), "campaign_id")


def test_campaign_invalid_missing_name():
    _err(validate_campaign, _minimal_campaign(name=""), "name")


def test_campaign_invalid_missing_threat_actor():
    _err(validate_campaign, _minimal_campaign(threat_actor=""), "threat_actor")


def test_campaign_invalid_status():
    _err(validate_campaign, _minimal_campaign(status="TERMINATED"), "status")


def test_campaign_invalid_sophistication():
    _err(validate_campaign, _minimal_campaign(sophistication="ultra"), "sophistication")


def test_campaign_invalid_date_order():
    _err(validate_campaign, _minimal_campaign(first_seen="2026-06-01", last_seen="2026-01-01"),
         "last_seen")


def test_campaign_invalid_ttps_not_list():
    _err(validate_campaign, _minimal_campaign(ttps="T1486"), "ttps")


def test_campaign_invalid_victims_negative():
    _err(validate_campaign, _minimal_campaign(estimated_victims=-5), "estimated_victims")


# ---------------------------------------------------------------------------
# validate_case — valid cases
# ---------------------------------------------------------------------------


def test_case_valid_minimal():
    _ok(validate_case, _minimal_case())


def test_case_valid_resolved_with_timestamp():
    _ok(validate_case, _minimal_case(
        status="RESOLVED",
        resolved_at="2026-05-19T12:00:00Z",
    ))


def test_case_valid_all_statuses():
    # RESOLVED and CLOSED require resolved_at
    for status in ("OPEN", "INVESTIGATING", "CONTAINED"):
        _ok(validate_case, _minimal_case(status=status))


def test_case_valid_all_priorities():
    for p in ("P1", "P2", "P3", "P4"):
        _ok(validate_case, _minimal_case(priority=p))


def test_case_valid_with_notes_and_history():
    _ok(validate_case, _minimal_case(
        notes=[{"author": "Alice", "content": "Note", "timestamp": "T1"}],
        history=[{"action": "CREATED", "content": "Created", "timestamp": "T1"}],
    ))


# ---------------------------------------------------------------------------
# validate_case — invalid cases
# ---------------------------------------------------------------------------


def test_case_invalid_no_id():
    rec = _minimal_case()
    rec.pop("id")
    _err(validate_case, rec, "case requires")


def test_case_invalid_missing_title():
    _err(validate_case, _minimal_case(title=""), "title")


def test_case_invalid_status():
    _err(validate_case, _minimal_case(status="PENDING"), "status")


def test_case_invalid_priority():
    _err(validate_case, _minimal_case(priority="URGENT"), "priority")


def test_case_invalid_created_at():
    _err(validate_case, _minimal_case(created_at="tomorrow"), "created_at")


def test_case_invalid_resolved_before_created():
    _err(validate_case, _minimal_case(
        created_at="2026-05-20T12:00:00Z",
        resolved_at="2026-05-19T12:00:00Z",
        status="RESOLVED",
    ), "resolved_at")


def test_case_invalid_resolved_status_without_timestamp():
    _err(validate_case, _minimal_case(status="RESOLVED"), "resolved_at")


def test_case_invalid_closed_status_without_timestamp():
    _err(validate_case, _minimal_case(status="CLOSED"), "resolved_at")


def test_case_invalid_notes_not_list():
    _err(validate_case, _minimal_case(notes="see ticket"), "notes")


# ---------------------------------------------------------------------------
# validate_analyst — valid cases
# ---------------------------------------------------------------------------


def test_analyst_valid_minimal():
    _ok(validate_analyst, _minimal_analyst())


def test_analyst_valid_full():
    _ok(validate_analyst, _minimal_analyst(
        tier="Tier 3",
        years_experience=8,
        active_cases=3,
        certifications=["GCFE", "CISSP"],
        specializations=["Ransomware", "Forensics"],
    ))


def test_analyst_valid_all_tiers():
    for tier in ("Tier 1", "Tier 2", "Tier 3"):
        _ok(validate_analyst, _minimal_analyst(tier=tier))


def test_analyst_valid_zero_experience():
    _ok(validate_analyst, _minimal_analyst(years_experience=0))


def test_analyst_valid_empty_certs():
    _ok(validate_analyst, _minimal_analyst(certifications=[]))


# ---------------------------------------------------------------------------
# validate_analyst — invalid cases
# ---------------------------------------------------------------------------


def test_analyst_invalid_missing_id():
    _err(validate_analyst, _minimal_analyst(analyst_id=""), "analyst_id")


def test_analyst_invalid_missing_name():
    _err(validate_analyst, _minimal_analyst(name=""), "name")


def test_analyst_invalid_email():
    _err(validate_analyst, _minimal_analyst(email="not-an-email"), "email")


def test_analyst_invalid_tier():
    _err(validate_analyst, _minimal_analyst(tier="Tier 4"), "tier")


def test_analyst_invalid_active_cases_negative():
    _err(validate_analyst, _minimal_analyst(active_cases=-1), "active_cases")


def test_analyst_invalid_experience_negative():
    _err(validate_analyst, _minimal_analyst(years_experience=-3), "years_experience")


def test_analyst_invalid_certifications_not_list():
    _err(validate_analyst, _minimal_analyst(certifications="GCFE"), "certifications")


def test_analyst_invalid_specializations_not_list():
    _err(validate_analyst, _minimal_analyst(specializations="Ransomware"), "specializations")


# ---------------------------------------------------------------------------
# validate_dataset
# ---------------------------------------------------------------------------


def test_validate_dataset_all_valid():
    records = [_minimal_incident(), _minimal_incident(incident_id="INC-2026-002", threat_name="X")]
    result  = validate_dataset(records, validate_incident, id_field="incident_id")
    assert result["total"]   == 2
    assert result["valid"]   == 2
    assert result["invalid"] == 0
    assert result["errors"]  == []


def test_validate_dataset_one_invalid():
    records = [_minimal_incident(), _minimal_incident(severity="EXTREME")]
    result  = validate_dataset(records, validate_incident, id_field="incident_id")
    assert result["invalid"] == 1
    assert len(result["errors"]) == 1


def test_validate_dataset_empty():
    result = validate_dataset([], validate_incident, id_field="incident_id")
    assert result["total"]   == 0
    assert result["valid"]   == 0
    assert result["invalid"] == 0


def test_validate_dataset_duplicate_ids():
    records = [_minimal_incident(), _minimal_incident()]  # same incident_id
    result  = validate_dataset(records, validate_incident, id_field="incident_id")
    assert result["invalid"] >= 1
    assert any("duplicate" in e["errors"][0].lower() for e in result["errors"])


def test_validate_dataset_analysts():
    records = [_minimal_analyst(), _minimal_analyst(analyst_id="ANA-002", name="Bob")]
    result  = validate_dataset(records, validate_analyst, id_field="analyst_id")
    assert result["total"]   == 2
    assert result["valid"]   == 2


def test_validate_dataset_campaigns():
    records = [_minimal_campaign(), _minimal_campaign(campaign_id="CAMP-AKIRA-2026", name="Akira")]
    result  = validate_dataset(records, validate_campaign, id_field="campaign_id")
    assert result["total"]   == 2
    assert result["valid"]   == 2


def test_validate_dataset_returns_error_details():
    records = [_minimal_incident(severity="BAD")]
    result  = validate_dataset(records, validate_incident, id_field="incident_id")
    assert result["errors"][0]["record_id"] == "INC-2026-001"
    assert len(result["errors"][0]["errors"]) >= 1
