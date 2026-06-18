"""tests/test_state.py — Unit tests for core/state.py"""

from __future__ import annotations

import pytest

from core.state import IncidentStatus, StateObject, ThreatSeverity


def test_default_state_object():
    state = StateObject()
    assert state.status == IncidentStatus.DETECTED
    assert state.confidence_score == 0.0
    assert state.risk_score == 0.0
    assert state.indicators == []
    assert state.mitigation_actions == []
    assert state.incident_id  # non-empty UUID string


def test_custom_fields_are_preserved():
    state = StateObject(
        incident_id="INC-TEST-001",
        threat_name="APT-TEST",
        severity=ThreatSeverity.HIGH,
    )
    assert state.incident_id == "INC-TEST-001"
    assert state.threat_name == "APT-TEST"
    assert state.severity == ThreatSeverity.HIGH


def test_incident_status_enum_values():
    assert IncidentStatus.DETECTED.value == "DETECTED"
    assert IncidentStatus.ANALYZED.value == "ANALYZED"
    assert IncidentStatus.ATTRIBUTED.value == "ATTRIBUTED"
    assert IncidentStatus.MITIGATED.value == "MITIGATED"


def test_threat_severity_enum_values():
    assert ThreatSeverity.LOW.value == "LOW"
    assert ThreatSeverity.MEDIUM.value == "MEDIUM"
    assert ThreatSeverity.HIGH.value == "HIGH"
    assert ThreatSeverity.CRITICAL.value == "CRITICAL"


def test_touch_updates_updated_at():
    state = StateObject()
    original = state.updated_at
    state.touch()
    assert state.updated_at >= original


def test_to_log_dict_contains_required_keys():
    state = StateObject(
        indicators=["ip:1.2.3.4", "hash:abc"],
        mitigation_actions=["block ip"],
    )
    d = state.to_log_dict()
    for key in ("incident_id", "status", "severity", "risk_score", "indicators", "mitigation_actions"):
        assert key in d, f"Missing key: {key}"


def test_to_log_dict_joins_list_fields():
    state = StateObject(
        indicators=["ip:1.2.3.4", "hash:abc"],
        mitigation_actions=["block ip", "rotate creds"],
    )
    d = state.to_log_dict()
    assert d["indicators"] == "ip:1.2.3.4|hash:abc"
    assert d["mitigation_actions"] == "block ip|rotate creds"


def test_confidence_score_upper_bound():
    with pytest.raises(Exception):
        StateObject(confidence_score=1.5)


def test_confidence_score_lower_bound():
    with pytest.raises(Exception):
        StateObject(confidence_score=-0.1)


def test_severity_from_string():
    state = StateObject(severity=ThreatSeverity("CRITICAL"))
    assert state.severity == ThreatSeverity.CRITICAL


def test_empty_lists_produce_empty_pipe_strings():
    state = StateObject()
    d = state.to_log_dict()
    assert d["indicators"] == ""
    assert d["mitigation_actions"] == ""
