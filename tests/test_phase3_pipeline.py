"""tests/test_phase3_pipeline.py — Phase 3 end-to-end integration tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.logger import setup_logging
from core.orchestrator import MythosOrchestrator, load_sample_incidents
from core.state import IncidentStatus, StateObject, ThreatSeverity
from agents.planner_agent import PlannerAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.attribution_agent import AttributionAgent
from agents.compliance_agent import ComplianceAgent

setup_logging()


def _state(
    threat: str = "APT-SHADOW-VIPER",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
    incident_id: str = "PHASE3-001",
) -> StateObject:
    return StateObject(incident_id=incident_id, threat_name=threat, severity=severity)


# ---------------------------------------------------------------------------
# ENRICHED status exists in the enum
# ---------------------------------------------------------------------------


def test_enriched_status_in_enum():
    assert IncidentStatus.ENRICHED.value == "ENRICHED"


# ---------------------------------------------------------------------------
# Manual stage-by-stage traversal
# ---------------------------------------------------------------------------


def test_enriched_status_reached_after_intelligence_agent():
    state = PlannerAgent().run(_state())
    state = IntelligenceAgent().run(state)
    assert state.status == IncidentStatus.ENRICHED


def test_attribution_confidence_nonzero_after_attribution_agent():
    state = PlannerAgent().run(_state())
    state = IntelligenceAgent().run(state)
    state = AttributionAgent().run(state)
    assert state.attribution_confidence > 0.0


def test_campaign_id_set_after_attribution_agent():
    state = PlannerAgent().run(_state())
    state = IntelligenceAgent().run(state)
    state = AttributionAgent().run(state)
    assert state.campaign_id.startswith("CAMP-")


def test_threat_summary_nonempty_after_intelligence_agent():
    state = PlannerAgent().run(_state())
    state = IntelligenceAgent().run(state)
    assert len(state.threat_summary) > 0


# ---------------------------------------------------------------------------
# Full orchestrator pipeline
# ---------------------------------------------------------------------------


def test_orchestrator_full_pipeline_reaches_mitigated():
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(_state())
    assert result.status == IncidentStatus.MITIGATED


def test_orchestrator_pipeline_sets_campaign_id():
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(_state())
    assert result.campaign_id != ""


def test_orchestrator_pipeline_sets_threat_summary():
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(_state())
    assert len(result.threat_summary) > 0


def test_orchestrator_pipeline_sets_attribution_confidence():
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(_state())
    assert 0.0 <= result.attribution_confidence <= 1.0


def test_orchestrator_pipeline_sets_ioc_enrichments():
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(_state())
    assert len(result.ioc_enrichments) > 0


# ---------------------------------------------------------------------------
# Batch over all four sample severity tiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("threat,severity", [
    ("APT-SHADOW-VIPER",         ThreatSeverity.CRITICAL),
    ("RANSOMWARE-LOCKBIT3",      ThreatSeverity.HIGH),
    ("PHISH-CREDENTIAL-HARVEST", ThreatSeverity.MEDIUM),
    ("ADWARE-BUNDLER",           ThreatSeverity.LOW),
])
def test_all_sample_threats_complete_phase3_pipeline(threat, severity):
    orc = MythosOrchestrator()
    with patch("core.orchestrator.persist"):
        result = orc.run_incident(
            StateObject(threat_name=threat, severity=severity)
        )
    assert result.status == IncidentStatus.MITIGATED
    assert len(result.mitigation_actions) > 0


# ---------------------------------------------------------------------------
# Batch run
# ---------------------------------------------------------------------------


def test_batch_run_processes_all_incidents():
    orc = MythosOrchestrator()
    incidents = [_state(incident_id=f"ID-{i}") for i in range(3)]
    with patch("core.orchestrator.persist"):
        results = orc.run_batch(incidents)
    assert len(results) == 3
    assert all(r.status == IncidentStatus.MITIGATED for r in results)


def test_batch_run_each_incident_has_unique_campaign_id():
    orc = MythosOrchestrator()
    incidents = [
        StateObject(threat_name="APT-SHADOW-VIPER",         severity=ThreatSeverity.CRITICAL),
        StateObject(threat_name="RANSOMWARE-LOCKBIT3",      severity=ThreatSeverity.HIGH),
        StateObject(threat_name="PHISH-CREDENTIAL-HARVEST", severity=ThreatSeverity.MEDIUM),
    ]
    with patch("core.orchestrator.persist"):
        results = orc.run_batch(incidents)
    camp_ids = [r.campaign_id for r in results]
    assert len(set(camp_ids)) == 3  # all different actors -> all different campaign IDs


# ---------------------------------------------------------------------------
# load_sample_incidents compatibility
# ---------------------------------------------------------------------------


def test_load_sample_incidents_returns_enrichable_states():
    incidents = load_sample_incidents()
    assert len(incidents) > 0
    assert all(i.status == IncidentStatus.DETECTED for i in incidents)
    assert all(i.severity in list(ThreatSeverity) for i in incidents)
