"""tests/test_intelligence_agent.py — Unit tests for IntelligenceAgent."""

from __future__ import annotations

from core.logger import setup_logging
from core.state import IncidentStatus, StateObject, ThreatSeverity
from agents.planner_agent import PlannerAgent
from agents.intelligence_agent import IntelligenceAgent

setup_logging()


def _analyzed(
    threat: str = "APT-SHADOW-VIPER",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
    indicators: list[str] | None = None,
) -> StateObject:
    state = StateObject(
        incident_id="TEST-INTEL-001",
        threat_name=threat,
        severity=severity,
        indicators=indicators or [],
    )
    return PlannerAgent().run(state)


# ---------------------------------------------------------------------------
# Status transition
# ---------------------------------------------------------------------------


def test_transitions_to_enriched():
    result = IntelligenceAgent().run(_analyzed())
    assert result.status == IncidentStatus.ENRICHED


def test_does_not_advance_past_enriched():
    result = IntelligenceAgent().run(_analyzed())
    assert result.status != IncidentStatus.ATTRIBUTED


# ---------------------------------------------------------------------------
# Threat summary
# ---------------------------------------------------------------------------


def test_threat_summary_is_nonempty_string():
    result = IntelligenceAgent().run(_analyzed())
    assert isinstance(result.threat_summary, str)
    assert len(result.threat_summary) > 0


def test_threat_summary_for_unknown_threat_is_generic():
    result = IntelligenceAgent().run(_analyzed(threat="TOTALLY-UNKNOWN-XYZ"))
    assert "TOTALLY-UNKNOWN-XYZ" in result.threat_summary


# ---------------------------------------------------------------------------
# IOC enrichment
# ---------------------------------------------------------------------------


def test_ioc_enrichments_populated():
    result = IntelligenceAgent().run(_analyzed())
    assert len(result.ioc_enrichments) > 0


def test_ioc_enrichments_count_matches_indicator_count():
    state = _analyzed(indicators=["C2:1.2.3.4", "hash:abc", "domain:evil.io"])
    result = IntelligenceAgent().run(state)
    assert len(result.ioc_enrichments) == 3


def test_ioc_enrichments_contain_original_ioc():
    state = _analyzed(indicators=["C2:185.220.101.47"])
    result = IntelligenceAgent().run(state)
    assert any("185.220.101.47" in e for e in result.ioc_enrichments)


def test_ioc_enrichments_contain_type_annotation():
    state = _analyzed(indicators=["hash:deadbeef"])
    result = IntelligenceAgent().run(state)
    assert any("type=" in e for e in result.ioc_enrichments)


def test_handles_empty_indicators_gracefully():
    state = StateObject(incident_id="EMPTY-001", threat_name="APT-SHADOW-VIPER")
    state.status = IncidentStatus.ANALYZED
    result = IntelligenceAgent().run(state)
    assert result.status == IncidentStatus.ENRICHED
    assert result.ioc_enrichments == []


# ---------------------------------------------------------------------------
# Enrichment data
# ---------------------------------------------------------------------------


def test_enrichment_data_is_dict():
    result = IntelligenceAgent().run(_analyzed())
    assert isinstance(result.enrichment_data, dict)


def test_known_threat_has_profile_match_true():
    result = IntelligenceAgent().run(_analyzed(threat="APT-SHADOW-VIPER"))
    assert result.enrichment_data.get("profile_match") is True


def test_unknown_threat_has_profile_match_false():
    result = IntelligenceAgent().run(_analyzed(threat="TOTALLY-UNKNOWN-XYZ"))
    assert result.enrichment_data.get("profile_match") is False


def test_known_threat_enrichment_has_ttps():
    result = IntelligenceAgent().run(_analyzed(threat="APT-SHADOW-VIPER"))
    ttps = result.enrichment_data.get("ttps", [])
    assert isinstance(ttps, list) and len(ttps) > 0


def test_known_threat_enrichment_has_origin():
    result = IntelligenceAgent().run(_analyzed(threat="APT-SHADOW-VIPER"))
    assert result.enrichment_data.get("origin") == "Russia"


def test_known_threat_enrichment_has_known_tools():
    result = IntelligenceAgent().run(_analyzed(threat="RANSOMWARE-LOCKBIT3"))
    tools = result.enrichment_data.get("known_tools", [])
    assert isinstance(tools, list) and len(tools) > 0


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------


def test_updated_at_refreshed():
    state = _analyzed()
    original_updated = state.updated_at
    result = IntelligenceAgent().run(state)
    assert result.updated_at >= original_updated
