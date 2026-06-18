"""
core/orchestrator.py — MythosOrchestrator: Phase 3 five-stage pipeline.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is resolvable when executed directly as `python core/orchestrator.py`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agents.attribution_agent import AttributionAgent
from agents.compliance_agent import ComplianceAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.planner_agent import PlannerAgent
from core.logger import CSV_LOG, JSONL_LOG, get_logger, persist, setup_logging
from core.state import IncidentStatus, StateObject, ThreatSeverity
from utils.config import config
from utils.helpers import format_summary

setup_logging(config.LOG_LEVEL)
logger = get_logger("orchestrator")

_AGENT_RUNS_LOG = _PROJECT_ROOT / "logs" / "agent_runs.jsonl"


def _log_run(record: dict) -> None:
    """Append a pipeline run record to agent_runs.jsonl (best-effort)."""
    try:
        _AGENT_RUNS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _AGENT_RUNS_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


class MythosOrchestrator:
    """
    Drives each incident through the full Phase 3 lifecycle:
        DETECTED -> ANALYZED -> ENRICHED -> ATTRIBUTED -> MITIGATED

    Every state transition is persisted to JSONL and CSV logs.
    """

    _PIPELINE = [PlannerAgent, IntelligenceAgent, AttributionAgent, ComplianceAgent]

    def __init__(self) -> None:
        self.agents = [cls() for cls in self._PIPELINE]

    def run_incident(self, state: StateObject) -> StateObject:
        logger.info("=" * 68)
        logger.info(
            "Incident %s | START | severity=%s threat=%s",
            state.incident_id,
            state.severity.value,
            state.threat_name or "UNKNOWN",
        )
        logger.info("=" * 68)

        persist(state)

        run_id = str(uuid.uuid4())
        pipeline_start = datetime.now(timezone.utc)
        agent_records: list[dict] = []

        for agent in self.agents:
            t0 = time.perf_counter()
            agent_start = datetime.now(timezone.utc)
            state = agent.run(state)
            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            persist(state)
            agent_records.append({
                "agent_name": agent.name,
                "status": "COMPLETED",
                "started_at": agent_start.isoformat(),
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": duration_ms,
                "output_status": state.status.value,
                "output_summary": (
                    f"actor={state.suspected_actor} "
                    f"confidence={state.confidence_score:.2f} "
                    f"risk={state.risk_score:.4f}"
                ),
                "confidence": state.confidence_score,
                "risk_score": state.risk_score,
                "campaign_id": state.campaign_id,
            })

        completed_at = datetime.now(timezone.utc)
        _log_run({
            "run_id": run_id,
            "incident_id": state.incident_id,
            "threat_name": state.threat_name,
            "severity": state.severity.value,
            "started_at": pipeline_start.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_ms": round((completed_at - pipeline_start).total_seconds() * 1000, 2),
            "final_status": state.status.value,
            "campaign_id": state.campaign_id,
            "suspected_actor": state.suspected_actor,
            "agents": agent_records,
        })

        logger.info("=" * 68)
        logger.info(
            "Incident %s | COMPLETE | status=%s campaign=%s",
            state.incident_id,
            state.status.value,
            state.campaign_id or "NONE",
        )
        logger.info("=" * 68)
        return state

    def run_batch(self, incidents: list[StateObject]) -> list[StateObject]:
        return [self.run_incident(inc) for inc in incidents]


# ---------------------------------------------------------------------------
# Sample incident loader
# ---------------------------------------------------------------------------


def load_sample_incidents() -> list[StateObject]:
    data_path = Path(config.INCIDENT_DATA_PATH)
    if not data_path.exists():
        logger.warning("Sample data not found at %s — using blank default", data_path)
        return [StateObject()]

    with data_path.open(encoding="utf-8") as fh:
        raw: list[dict] = json.load(fh)

    incidents: list[StateObject] = []
    for item in raw:
        state = StateObject(
            incident_id=item.get("incident_id", str(uuid.uuid4())),
            threat_name=item.get("threat_name", ""),
            severity=ThreatSeverity(item.get("severity", "MEDIUM")),
            indicators=item.get("indicators", []),
            status=IncidentStatus.DETECTED,
        )
        incidents.append(state)
    return incidents


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    orchestrator = MythosOrchestrator()
    incidents = load_sample_incidents()

    logger.info("Loaded %d incident(s) — starting Phase 3 batch run", len(incidents))
    results = orchestrator.run_batch(incidents)

    print("\n" + "=" * 100)
    print(f"  {config.PROJECT_NAME.upper()} — PHASE 3 INTELLIGENCE SUMMARY REPORT")
    print("=" * 100)
    for state in results:
        print(format_summary(state))
    print("=" * 100)

    print(f"\nLogs written to:")
    print(f"  {JSONL_LOG}")
    print(f"  {CSV_LOG}")
    print("\nPHASE 3 COMPLETED")


if __name__ == "__main__":
    main()
