"""tests/test_orchestrator.py — Integration tests for MythosOrchestrator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from core.logger import setup_logging
from core.state import IncidentStatus, StateObject, ThreatSeverity
from core.orchestrator import MythosOrchestrator, load_sample_incidents

setup_logging()


def _state(
    incident_id: str = "TEST-ORCH-001",
    threat: str = "APT-SHADOW-VIPER",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
) -> StateObject:
    return StateObject(
        incident_id=incident_id,
        threat_name=threat,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# MythosOrchestrator
# ---------------------------------------------------------------------------


class TestMythosOrchestrator:
    def test_pipeline_reaches_mitigated(self):
        orc = MythosOrchestrator()
        with patch("core.orchestrator.persist"):
            result = orc.run_incident(_state())
        assert result.status == IncidentStatus.MITIGATED

    def test_pipeline_sets_risk_score(self):
        orc = MythosOrchestrator()
        with patch("core.orchestrator.persist"):
            result = orc.run_incident(_state())
        assert result.risk_score > 0.0

    def test_pipeline_sets_suspected_actor(self):
        orc = MythosOrchestrator()
        with patch("core.orchestrator.persist"):
            result = orc.run_incident(_state())
        assert result.suspected_actor != ""

    def test_pipeline_sets_mitigation_actions(self):
        orc = MythosOrchestrator()
        with patch("core.orchestrator.persist"):
            result = orc.run_incident(_state())
        assert len(result.mitigation_actions) > 0

    def test_batch_processes_all_incidents(self):
        orc = MythosOrchestrator()
        incidents = [_state("ID-1"), _state("ID-2"), _state("ID-3")]
        with patch("core.orchestrator.persist"):
            results = orc.run_batch(incidents)
        assert len(results) == 3
        assert all(r.status == IncidentStatus.MITIGATED for r in results)

    def test_batch_preserves_incident_ids(self):
        orc = MythosOrchestrator()
        ids = ["ID-A", "ID-B"]
        incidents = [_state(i) for i in ids]
        with patch("core.orchestrator.persist"):
            results = orc.run_batch(incidents)
        assert [r.incident_id for r in results] == ids

    @pytest.mark.parametrize("severity", list(ThreatSeverity))
    def test_all_severities_complete_pipeline(self, severity: ThreatSeverity):
        orc = MythosOrchestrator()
        with patch("core.orchestrator.persist"):
            result = orc.run_incident(_state(severity=severity))
        assert result.status == IncidentStatus.MITIGATED


# ---------------------------------------------------------------------------
# load_sample_incidents
# ---------------------------------------------------------------------------


class TestLoadSampleIncidents:
    def test_loads_all_incidents_from_valid_json(self):
        sample = [
            {"incident_id": "T-001", "threat_name": "APT-SHADOW-VIPER", "severity": "CRITICAL", "indicators": []},
            {"incident_id": "T-002", "threat_name": "ADWARE-BUNDLER", "severity": "LOW", "indicators": []},
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(sample, fh)
            tmp_path = fh.name

        with patch("core.orchestrator.config") as mock_cfg:
            mock_cfg.INCIDENT_DATA_PATH = tmp_path
            incidents = load_sample_incidents()

        Path(tmp_path).unlink(missing_ok=True)
        assert len(incidents) == 2
        assert incidents[0].incident_id == "T-001"
        assert incidents[0].severity == ThreatSeverity.CRITICAL

    def test_missing_file_returns_single_default_incident(self):
        with patch("core.orchestrator.config") as mock_cfg:
            mock_cfg.INCIDENT_DATA_PATH = "/nonexistent/path/file.json"
            incidents = load_sample_incidents()
        assert len(incidents) == 1
        assert isinstance(incidents[0], StateObject)

    def test_loaded_incidents_start_as_detected(self):
        sample = [{"incident_id": "T-001", "threat_name": "APT-SHADOW-VIPER", "severity": "HIGH"}]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(sample, fh)
            tmp_path = fh.name

        with patch("core.orchestrator.config") as mock_cfg:
            mock_cfg.INCIDENT_DATA_PATH = tmp_path
            incidents = load_sample_incidents()

        Path(tmp_path).unlink(missing_ok=True)
        assert incidents[0].status == IncidentStatus.DETECTED
