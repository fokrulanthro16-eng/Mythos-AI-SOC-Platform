"""tests/test_agents.py — Unit tests for each agent module."""

from __future__ import annotations

from core.logger import setup_logging
from core.state import IncidentStatus, StateObject, ThreatSeverity
from agents.planner_agent import PlannerAgent
from agents.forensics_agent import ForensicsAgent
from agents.compliance_agent import ComplianceAgent

setup_logging()


def _state(
    threat: str = "APT-SHADOW-VIPER",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
) -> StateObject:
    return StateObject(
        incident_id="TEST-AGENT-001",
        threat_name=threat,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# PlannerAgent
# ---------------------------------------------------------------------------


class TestPlannerAgent:
    def test_transitions_to_analyzed(self):
        result = PlannerAgent().run(_state())
        assert result.status == IncidentStatus.ANALYZED

    def test_sets_nonzero_confidence(self):
        result = PlannerAgent().run(_state())
        assert result.confidence_score > 0.0

    def test_sets_nonzero_risk_score(self):
        result = PlannerAgent().run(_state())
        assert result.risk_score > 0.0

    def test_populates_default_indicators_when_empty(self):
        state = _state()
        assert state.indicators == []
        result = PlannerAgent().run(state)
        assert len(result.indicators) > 0

    def test_preserves_existing_indicators(self):
        state = _state()
        state.indicators = ["ip:9.9.9.9"]
        result = PlannerAgent().run(state)
        assert "ip:9.9.9.9" in result.indicators

    def test_risk_score_in_bounds(self):
        result = PlannerAgent().run(_state())
        assert 0.0 <= result.risk_score <= 1.0

    def test_unknown_threat_gets_default_confidence(self):
        result = PlannerAgent().run(_state(threat="UNKNOWN-XYZ"))
        assert result.confidence_score == 0.50


# ---------------------------------------------------------------------------
# ForensicsAgent
# ---------------------------------------------------------------------------


class TestForensicsAgent:
    def _analyzed(self, **kwargs) -> StateObject:
        return PlannerAgent().run(_state(**kwargs))

    def test_transitions_to_attributed(self):
        result = ForensicsAgent().run(self._analyzed())
        assert result.status == IncidentStatus.ATTRIBUTED

    def test_sets_suspected_actor(self):
        result = ForensicsAgent().run(self._analyzed())
        assert result.suspected_actor != ""

    def test_known_threat_maps_correct_actor(self):
        result = ForensicsAgent().run(self._analyzed(threat="RANSOMWARE-LOCKBIT3"))
        assert result.suspected_actor == "LOCKBIT-GRP"

    def test_unknown_threat_gets_default_actor(self):
        result = ForensicsAgent().run(self._analyzed(threat="UNKNOWN-XYZ"))
        assert result.suspected_actor == "UNATTRIBUTED"

    def test_updates_confidence_score(self):
        state = self._analyzed()
        initial_confidence = state.confidence_score
        result = ForensicsAgent().run(state)
        # forensics raises or sets confidence based on intel
        assert result.confidence_score > 0.0
        assert result.confidence_score != initial_confidence

    def test_risk_score_recalculated(self):
        state = self._analyzed()
        result = ForensicsAgent().run(state)
        assert result.risk_score > 0.0


# ---------------------------------------------------------------------------
# ComplianceAgent
# ---------------------------------------------------------------------------


class TestComplianceAgent:
    def _attributed(self, **kwargs) -> StateObject:
        state = PlannerAgent().run(_state(**kwargs))
        return ForensicsAgent().run(state)

    def test_transitions_to_mitigated(self):
        result = ComplianceAgent().run(self._attributed())
        assert result.status == IncidentStatus.MITIGATED

    def test_generates_mitigation_actions(self):
        result = ComplianceAgent().run(self._attributed())
        assert len(result.mitigation_actions) > 0

    def test_known_threat_uses_specific_playbook(self):
        result = ComplianceAgent().run(self._attributed(threat="APT-SHADOW-VIPER"))
        assert any("185.220.101.47" in a for a in result.mitigation_actions)

    def test_unknown_threat_uses_default_playbook(self):
        result = ComplianceAgent().run(self._attributed(threat="UNKNOWN-THREAT-XYZ"))
        assert len(result.mitigation_actions) > 0

    def test_all_severities_produce_actions(self):
        for sev in ThreatSeverity:
            result = ComplianceAgent().run(self._attributed(severity=sev))
            assert len(result.mitigation_actions) > 0
