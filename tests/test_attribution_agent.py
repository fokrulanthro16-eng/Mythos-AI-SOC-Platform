"""tests/test_attribution_agent.py — Unit tests for AttributionAgent."""

from __future__ import annotations

import re

import pytest

from core.logger import setup_logging
from core.state import IncidentStatus, StateObject, ThreatSeverity
from agents.planner_agent import PlannerAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.attribution_agent import AttributionAgent, cluster_campaign, _count_ioc_matches

setup_logging()


def _enriched(
    threat: str = "APT-SHADOW-VIPER",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
) -> StateObject:
    state = StateObject(
        incident_id="TEST-ATTR-001",
        threat_name=threat,
        severity=severity,
    )
    state = PlannerAgent().run(state)
    return IntelligenceAgent().run(state)


# ---------------------------------------------------------------------------
# Status transition
# ---------------------------------------------------------------------------


def test_transitions_to_attributed():
    result = AttributionAgent().run(_enriched())
    assert result.status == IncidentStatus.ATTRIBUTED


def test_does_not_skip_to_mitigated():
    result = AttributionAgent().run(_enriched())
    assert result.status != IncidentStatus.MITIGATED


# ---------------------------------------------------------------------------
# Suspected actor
# ---------------------------------------------------------------------------


def test_sets_suspected_actor_nonempty():
    result = AttributionAgent().run(_enriched())
    assert result.suspected_actor != ""


def test_known_threat_maps_correct_actor():
    result = AttributionAgent().run(_enriched(threat="APT-SHADOW-VIPER"))
    assert result.suspected_actor == "TA505"


def test_lockbit_maps_correct_actor():
    result = AttributionAgent().run(_enriched(threat="RANSOMWARE-LOCKBIT3", severity=ThreatSeverity.HIGH))
    assert result.suspected_actor == "LOCKBIT4"


def test_fin7_maps_correct_actor():
    result = AttributionAgent().run(_enriched(threat="PHISH-CREDENTIAL-HARVEST", severity=ThreatSeverity.MEDIUM))
    assert result.suspected_actor == "FIN7-SPINOFF"


def test_unknown_threat_gets_unattributed():
    result = AttributionAgent().run(_enriched(threat="UNKNOWN-MALWARE-XYZ"))
    assert result.suspected_actor == "UNATTRIBUTED"


# ---------------------------------------------------------------------------
# Attribution confidence
# ---------------------------------------------------------------------------


def test_attribution_confidence_is_set():
    result = AttributionAgent().run(_enriched())
    assert result.attribution_confidence > 0.0


def test_attribution_confidence_in_bounds():
    result = AttributionAgent().run(_enriched())
    assert 0.0 <= result.attribution_confidence <= 1.0


def test_known_actor_confidence_exceeds_unknown():
    known = AttributionAgent().run(_enriched(threat="APT-SHADOW-VIPER"))
    unknown = AttributionAgent().run(_enriched(threat="UNKNOWN-MALWARE-XYZ"))
    assert known.attribution_confidence > unknown.attribution_confidence


@pytest.mark.parametrize("threat,severity", [
    ("APT-SHADOW-VIPER",         ThreatSeverity.CRITICAL),
    ("RANSOMWARE-LOCKBIT3",      ThreatSeverity.HIGH),
    ("PHISH-CREDENTIAL-HARVEST", ThreatSeverity.MEDIUM),
    ("ADWARE-BUNDLER",           ThreatSeverity.LOW),
])
def test_attribution_confidence_set_for_all_threats(threat, severity):
    result = AttributionAgent().run(_enriched(threat=threat, severity=severity))
    assert 0.0 <= result.attribution_confidence <= 1.0


# ---------------------------------------------------------------------------
# Campaign clustering
# ---------------------------------------------------------------------------


def test_campaign_id_is_set():
    result = AttributionAgent().run(_enriched())
    assert result.campaign_id != ""


def test_campaign_id_format():
    result = AttributionAgent().run(_enriched())
    # Expected: CAMP-{4CHAR}-{YEAR}-{6HEX}  e.g. CAMP-TA50-2026-3FA1C2
    assert re.match(r"^CAMP-[A-Z0-9]{1,8}-\d{4}-[A-F0-9]{6}$", result.campaign_id), \
        f"Unexpected format: {result.campaign_id}"


def test_campaign_id_contains_year():
    result = AttributionAgent().run(_enriched())
    assert "2026" in result.campaign_id or "2025" in result.campaign_id


def test_campaign_id_deterministic_for_same_state():
    state_a = _enriched()
    state_b = _enriched()
    # Same threat/indicators -> same IOC fingerprint -> same hash suffix
    camp_a = AttributionAgent().run(state_a).campaign_id
    camp_b = AttributionAgent().run(state_b).campaign_id
    # Strip incident-specific parts — just compare hash suffix
    assert camp_a.split("-")[-1] == camp_b.split("-")[-1]


# ---------------------------------------------------------------------------
# cluster_campaign helper
# ---------------------------------------------------------------------------


def test_cluster_campaign_output_keys():
    state = _enriched()
    state.suspected_actor = "TA505"
    state.attribution_confidence = 0.77
    cluster = cluster_campaign(state)
    assert "campaign_id" in cluster
    assert "threat_actor" in cluster
    assert "confidence" in cluster
    assert "related_incidents" in cluster


def test_cluster_campaign_related_incidents_contains_incident_id():
    state = _enriched()
    state.suspected_actor = "TA505"
    cluster = cluster_campaign(state)
    assert state.incident_id in cluster["related_incidents"]


# ---------------------------------------------------------------------------
# _count_ioc_matches helper
# ---------------------------------------------------------------------------


def test_count_ioc_matches_known_pattern():
    profile = {"known_ioc_patterns": ["185.220.", "shadow-net"]}
    indicators = ["C2:185.220.101.47", "domain:exfil-drop.shadow-net.io", "hash:abc"]
    assert _count_ioc_matches(indicators, profile) == 2


def test_count_ioc_matches_no_match():
    profile = {"known_ioc_patterns": ["apt28", "fancy-bear"]}
    indicators = ["C2:185.220.101.47", "hash:abc"]
    assert _count_ioc_matches(indicators, profile) == 0


def test_count_ioc_matches_empty_profile():
    assert _count_ioc_matches(["C2:1.2.3.4"], {}) == 0
