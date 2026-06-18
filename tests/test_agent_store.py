"""tests/test_agent_store.py — Unit tests for agent_store and orchestrator timing."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    """Redirect agent_runs log to a temp file for every test."""
    log_path = tmp_path / "agent_runs.jsonl"
    import dashboard.agent_store as ag
    monkeypatch.setattr(ag, "_RUNS_LOG", log_path)
    yield log_path


def _write_runs(log_path: Path, runs: list[dict]) -> None:
    log_path.write_text(
        "\n".join(json.dumps(r) for r in runs) + "\n", encoding="utf-8"
    )


def _make_run(
    threat: str = "RANSOMWARE-TEST",
    severity: str = "HIGH",
    status: str = "MITIGATED",
    agent_durations: list[float] | None = None,
) -> dict:
    durations = agent_durations or [60.0, 120.0, 80.0, 40.0]
    agent_names = ["PlannerAgent", "IntelligenceAgent", "AttributionAgent", "ComplianceAgent"]
    from datetime import timedelta
    t0 = datetime.now(timezone.utc)
    agents = []
    total = 0.0
    ct = t0
    for name, ms in zip(agent_names, durations):
        end = ct + timedelta(milliseconds=ms)
        agents.append({
            "agent_name": name,
            "status": "COMPLETED",
            "started_at": ct.isoformat(),
            "ended_at": end.isoformat(),
            "duration_ms": ms,
            "output_status": status,
            "output_summary": f"confidence=0.75 risk=0.50",
            "confidence": 0.75,
            "risk_score": 0.50,
            "campaign_id": "CAMP-TEST-001",
        })
        ct = end
        total += ms
    return {
        "run_id": str(uuid.uuid4()),
        "incident_id": f"INC-{uuid.uuid4().hex[:6].upper()}",
        "threat_name": threat,
        "severity": severity,
        "started_at": t0.isoformat(),
        "completed_at": ct.isoformat(),
        "duration_ms": round(total, 2),
        "final_status": status,
        "campaign_id": "CAMP-TEST-001",
        "suspected_actor": "LOCKBIT-GRP",
        "agents": agents,
    }


# ---------------------------------------------------------------------------
# Import after monkeypatch
# ---------------------------------------------------------------------------

from dashboard.agent_store import (
    _AGENT_NAMES,
    get_agent_stats,
    get_latest_agent_states,
    get_processing_metrics,
    load_runs,
    seed_sample_runs,
    get_run,
)


# ---------------------------------------------------------------------------
# load_runs
# ---------------------------------------------------------------------------


def test_load_runs_empty_when_no_file():
    assert load_runs() == []


def test_load_runs_empty_when_file_is_empty(isolated_log):
    isolated_log.write_text("", encoding="utf-8")
    assert load_runs() == []


def test_load_runs_returns_single_run(isolated_log):
    run = _make_run()
    _write_runs(isolated_log, [run])
    runs = load_runs()
    assert len(runs) == 1


def test_load_runs_most_recent_first(isolated_log):
    run1 = _make_run(threat="THREAT-A")
    run2 = _make_run(threat="THREAT-B")
    _write_runs(isolated_log, [run1, run2])
    runs = load_runs()
    # Most recent (last in file) should be first in result
    assert runs[0]["threat_name"] == "THREAT-B"


def test_load_runs_limit_respected(isolated_log):
    _write_runs(isolated_log, [_make_run() for _ in range(10)])
    assert len(load_runs(limit=5)) == 5


def test_load_runs_handles_corrupt_lines(isolated_log):
    good = json.dumps(_make_run())
    isolated_log.write_text(f"{good}\nnot-valid-json\n{good}\n", encoding="utf-8")
    runs = load_runs()
    assert len(runs) == 2


# ---------------------------------------------------------------------------
# get_run
# ---------------------------------------------------------------------------


def test_get_run_returns_matching(isolated_log):
    run = _make_run()
    _write_runs(isolated_log, [run])
    found = get_run(run["run_id"])
    assert found is not None
    assert found["run_id"] == run["run_id"]


def test_get_run_returns_none_for_unknown(isolated_log):
    _write_runs(isolated_log, [_make_run()])
    assert get_run("no-such-run-id") is None


# ---------------------------------------------------------------------------
# get_agent_stats
# ---------------------------------------------------------------------------


def test_get_agent_stats_all_four_agents():
    stats = get_agent_stats()
    for name in _AGENT_NAMES:
        assert name in stats


def test_get_agent_stats_zeros_when_empty():
    stats = get_agent_stats()
    for name in _AGENT_NAMES:
        assert stats[name]["runs"] == 0
        assert stats[name]["avg_ms"] == 0.0


def test_get_agent_stats_counts_runs(isolated_log):
    _write_runs(isolated_log, [_make_run(), _make_run()])
    stats = get_agent_stats()
    for name in _AGENT_NAMES:
        assert stats[name]["runs"] == 2


def test_get_agent_stats_avg_ms(isolated_log):
    run1 = _make_run(agent_durations=[100.0, 200.0, 150.0, 50.0])
    run2 = _make_run(agent_durations=[200.0, 400.0, 100.0, 50.0])
    _write_runs(isolated_log, [run1, run2])
    stats = get_agent_stats()
    assert stats["PlannerAgent"]["avg_ms"] == 150.0
    assert stats["IntelligenceAgent"]["avg_ms"] == 300.0


def test_get_agent_stats_min_max(isolated_log):
    run1 = _make_run(agent_durations=[50.0, 100.0, 75.0, 25.0])
    run2 = _make_run(agent_durations=[150.0, 300.0, 200.0, 100.0])
    _write_runs(isolated_log, [run1, run2])
    stats = get_agent_stats()
    assert stats["PlannerAgent"]["min_ms"] == 50.0
    assert stats["PlannerAgent"]["max_ms"] == 150.0


def test_get_agent_stats_success_rate_100(isolated_log):
    _write_runs(isolated_log, [_make_run()])
    stats = get_agent_stats()
    for name in _AGENT_NAMES:
        assert stats[name]["success_rate"] == 100.0


# ---------------------------------------------------------------------------
# get_latest_agent_states
# ---------------------------------------------------------------------------


def test_get_latest_agent_states_all_four_agents():
    run = _make_run()
    states = get_latest_agent_states(run)
    assert len(states) == 4
    names = [s["agent_name"] for s in states]
    assert names == _AGENT_NAMES


def test_get_latest_agent_states_pending_for_missing():
    # Run with only 2 agents completed
    partial_run = {"agents": [
        {"agent_name": "PlannerAgent", "status": "COMPLETED", "duration_ms": 100,
         "started_at": datetime.now(timezone.utc).isoformat(),
         "ended_at": datetime.now(timezone.utc).isoformat(),
         "output_summary": "", "confidence": 0.5, "risk_score": 0.3},
    ]}
    states = get_latest_agent_states(partial_run)
    assert states[0]["status"] == "COMPLETED"
    assert states[1]["status"] == "PENDING"
    assert states[2]["status"] == "PENDING"
    assert states[3]["status"] == "PENDING"


def test_get_latest_agent_states_duration_preserved():
    run = _make_run(agent_durations=[111.0, 222.0, 333.0, 444.0])
    states = get_latest_agent_states(run)
    assert states[0]["duration_ms"] == 111.0
    assert states[3]["duration_ms"] == 444.0


# ---------------------------------------------------------------------------
# get_processing_metrics
# ---------------------------------------------------------------------------


def test_get_processing_metrics_empty():
    m = get_processing_metrics()
    assert m["total_runs"] == 0
    assert m["avg_pipeline_ms"] == 0.0


def test_get_processing_metrics_total_runs(isolated_log):
    _write_runs(isolated_log, [_make_run(), _make_run(), _make_run()])
    m = get_processing_metrics()
    assert m["total_runs"] == 3


def test_get_processing_metrics_avg_ms(isolated_log):
    r1 = _make_run(agent_durations=[100.0, 100.0, 100.0, 100.0])  # total 400ms
    r2 = _make_run(agent_durations=[200.0, 200.0, 200.0, 200.0])  # total 800ms
    _write_runs(isolated_log, [r1, r2])
    m = get_processing_metrics()
    assert m["avg_pipeline_ms"] == 600.0


def test_get_processing_metrics_by_severity(isolated_log):
    _write_runs(isolated_log, [
        _make_run(severity="CRITICAL"),
        _make_run(severity="HIGH"),
        _make_run(severity="CRITICAL"),
    ])
    m = get_processing_metrics()
    assert m["by_severity"]["CRITICAL"] == 2
    assert m["by_severity"]["HIGH"] == 1


def test_get_processing_metrics_by_status(isolated_log):
    _write_runs(isolated_log, [
        _make_run(status="MITIGATED"),
        _make_run(status="MITIGATED"),
    ])
    m = get_processing_metrics()
    assert m["by_status"]["MITIGATED"] == 2


def test_get_processing_metrics_min_max(isolated_log):
    r1 = _make_run(agent_durations=[10.0, 10.0, 10.0, 10.0])   # 40ms
    r2 = _make_run(agent_durations=[100.0, 100.0, 100.0, 100.0])  # 400ms
    _write_runs(isolated_log, [r1, r2])
    m = get_processing_metrics()
    assert m["min_pipeline_ms"] == 40.0
    assert m["max_pipeline_ms"] == 400.0


# ---------------------------------------------------------------------------
# seed_sample_runs
# ---------------------------------------------------------------------------


def test_seed_sample_runs_creates_runs(isolated_log):
    seed_sample_runs(n=5)
    runs = load_runs()
    assert len(runs) == 5


def test_seed_sample_runs_is_idempotent(isolated_log):
    seed_sample_runs(n=5)
    seed_sample_runs(n=5)
    runs = load_runs()
    assert len(runs) == 5  # must not double


def test_seed_sample_runs_all_four_agents_per_run(isolated_log):
    seed_sample_runs(n=3)
    runs = load_runs()
    for run in runs:
        names = [a["agent_name"] for a in run.get("agents", [])]
        for expected in _AGENT_NAMES:
            assert expected in names, f"{expected} missing from seeded run"


def test_seed_sample_runs_valid_json_lines(isolated_log):
    seed_sample_runs(n=4)
    for line in isolated_log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            data = json.loads(line)
            assert "run_id" in data
            assert "agents" in data


# ---------------------------------------------------------------------------
# Orchestrator integration — timing is logged
# ---------------------------------------------------------------------------


def test_orchestrator_writes_to_agent_runs_log(tmp_path, monkeypatch):
    """Verify MythosOrchestrator appends to agent_runs.jsonl after run_incident."""
    import core.orchestrator as orch_mod

    log_path = tmp_path / "agent_runs.jsonl"
    monkeypatch.setattr(orch_mod, "_AGENT_RUNS_LOG", log_path)

    from core.orchestrator import MythosOrchestrator
    from core.state import StateObject, ThreatSeverity, IncidentStatus

    state = StateObject(
        incident_id="TEST-ORCH-001",
        threat_name="RANSOMWARE-LOCKBIT3",
        severity=ThreatSeverity.HIGH,
    )
    MythosOrchestrator().run_incident(state)

    assert log_path.exists()
    lines = [l for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["incident_id"] == "TEST-ORCH-001"
    assert len(record["agents"]) == 4


def test_orchestrator_agent_record_has_timing(tmp_path, monkeypatch):
    """Each agent record must have duration_ms, started_at, ended_at."""
    import core.orchestrator as orch_mod
    log_path = tmp_path / "agent_runs.jsonl"
    monkeypatch.setattr(orch_mod, "_AGENT_RUNS_LOG", log_path)

    from core.orchestrator import MythosOrchestrator
    from core.state import StateObject, ThreatSeverity

    MythosOrchestrator().run_incident(StateObject(threat_name="APT-SHADOW-VIPER", severity=ThreatSeverity.HIGH))

    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    for ag in record["agents"]:
        assert "duration_ms" in ag
        assert ag["duration_ms"] >= 0
        assert "started_at" in ag
        assert "ended_at" in ag


def test_orchestrator_all_four_agents_logged(tmp_path, monkeypatch):
    import core.orchestrator as orch_mod
    log_path = tmp_path / "agent_runs.jsonl"
    monkeypatch.setattr(orch_mod, "_AGENT_RUNS_LOG", log_path)

    from core.orchestrator import MythosOrchestrator
    from core.state import StateObject, ThreatSeverity

    MythosOrchestrator().run_incident(StateObject(severity=ThreatSeverity.MEDIUM))

    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    logged_names = [a["agent_name"] for a in record["agents"]]
    for expected in _AGENT_NAMES:
        assert expected in logged_names
