"""dashboard/agent_store.py — Pipeline run reader + agent collaboration metrics.

Reads from logs/agent_runs.jsonl which MythosOrchestrator writes during every pipeline run.
Provides per-agent stats, processing metrics, and seeded demo data when the log is empty.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_RUNS_LOG = Path(__file__).parent.parent / "logs" / "agent_runs.jsonl"

_AGENT_NAMES = ["PlannerAgent", "IntelligenceAgent", "AttributionAgent", "ComplianceAgent"]

_STATUS_ICON = {
    "COMPLETED": "✅",
    "RUNNING":   "🔄",
    "FAILED":    "❌",
    "PENDING":   "⏳",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Raw log reader
# ---------------------------------------------------------------------------


def load_runs(limit: int = 200) -> list[dict]:
    """Load pipeline runs from JSONL log, most-recent first."""
    if not _RUNS_LOG.exists():
        return []
    runs: list[dict] = []
    try:
        lines = _RUNS_LOG.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(runs) >= limit:
                break
    except Exception:
        return []
    return runs


def get_run(run_id: str) -> dict | None:
    for run in load_runs(limit=500):
        if run.get("run_id") == run_id:
            return run
    return None


# ---------------------------------------------------------------------------
# Agent-level stats
# ---------------------------------------------------------------------------


def get_agent_stats() -> dict[str, dict]:
    """Return per-agent aggregated stats across all pipeline runs."""
    runs = load_runs()
    stats: dict[str, dict] = {
        name: {"runs": 0, "total_ms": 0.0, "min_ms": None, "max_ms": None, "errors": 0}
        for name in _AGENT_NAMES
    }

    for run in runs:
        for agent_rec in run.get("agents", []):
            name = agent_rec.get("agent_name", "")
            if name not in stats:
                continue
            s = stats[name]
            s["runs"] += 1
            ms = agent_rec.get("duration_ms", 0)
            s["total_ms"] += ms
            if s["min_ms"] is None or ms < s["min_ms"]:
                s["min_ms"] = ms
            if s["max_ms"] is None or ms > s["max_ms"]:
                s["max_ms"] = ms
            if agent_rec.get("status") == "FAILED":
                s["errors"] += 1

    for name, s in stats.items():
        s["avg_ms"] = round(s["total_ms"] / s["runs"], 2) if s["runs"] else 0.0
        s["success_rate"] = (
            round((s["runs"] - s["errors"]) / s["runs"] * 100, 1) if s["runs"] else 0.0
        )

    return stats


def get_latest_agent_states(run: dict) -> list[dict]:
    """Return the per-agent state records from a given run, padded with PENDING for missing."""
    agent_map: dict[str, dict] = {a["agent_name"]: a for a in run.get("agents", [])}
    result = []
    for name in _AGENT_NAMES:
        if name in agent_map:
            rec = agent_map[name]
        else:
            rec = {
                "agent_name": name,
                "status": "PENDING",
                "started_at": None,
                "ended_at": None,
                "duration_ms": None,
                "output_summary": "",
                "confidence": 0.0,
                "risk_score": 0.0,
            }
        result.append(rec)
    return result


# ---------------------------------------------------------------------------
# Processing metrics
# ---------------------------------------------------------------------------


def get_processing_metrics() -> dict:
    """Return overall pipeline throughput and timing metrics."""
    runs = load_runs()
    if not runs:
        return {
            "total_runs": 0,
            "avg_pipeline_ms": 0.0,
            "min_pipeline_ms": None,
            "max_pipeline_ms": None,
            "by_severity": {},
            "by_status": {},
            "throughput_per_hour": 0.0,
        }

    total_ms = sum(r.get("duration_ms", 0) for r in runs)
    durations = [r.get("duration_ms", 0) for r in runs if r.get("duration_ms")]

    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for r in runs:
        sev = r.get("severity", "UNKNOWN")
        st = r.get("final_status", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_status[st] = by_status.get(st, 0) + 1

    # Approximate throughput using first/last run timestamps
    throughput = 0.0
    if len(runs) >= 2:
        try:
            last_ts = datetime.fromisoformat(runs[0].get("completed_at", ""))
            first_ts = datetime.fromisoformat(runs[-1].get("started_at", ""))
            span_hours = max((last_ts - first_ts).total_seconds() / 3600, 0.001)
            throughput = round(len(runs) / span_hours, 2)
        except (ValueError, TypeError):
            pass

    return {
        "total_runs": len(runs),
        "avg_pipeline_ms": round(total_ms / len(runs), 2) if runs else 0.0,
        "min_pipeline_ms": min(durations) if durations else None,
        "max_pipeline_ms": max(durations) if durations else None,
        "by_severity": by_severity,
        "by_status": by_status,
        "throughput_per_hour": throughput,
    }


# ---------------------------------------------------------------------------
# Seed sample data
# ---------------------------------------------------------------------------


def seed_sample_runs(n: int = 8) -> None:
    """Write n demo pipeline run records to agent_runs.jsonl if the log is empty."""
    if _RUNS_LOG.exists() and _RUNS_LOG.stat().st_size > 0:
        return

    import random
    threats = [
        ("LOCKBIT4-RANSOMWARE",            "CRITICAL"),
        ("BLACKCAT-ALPHV-RANSOMWARE",      "CRITICAL"),
        ("AKIRA-RANSOMWARE",               "HIGH"),
        ("PLAY-RANSOMWARE",                "HIGH"),
        ("RHYSIDA-RANSOMWARE",             "CRITICAL"),
        ("CLOP-MOVEIT-STYLE-SQLI",         "CRITICAL"),
        ("SCATTERED-SPIDER-BEC",           "HIGH"),
        ("VOLT-TYPHOON-LOTL",              "HIGH"),
        ("APT28-SPEARPHISH",               "HIGH"),
        ("LAZARUS-C2-CRYPTO",              "CRITICAL"),
        ("DARKGATE-MALSPAM",               "MEDIUM"),
        ("QAKBOT-REVIVAL-PHISH",           "MEDIUM"),
        ("EMOTET-WAVE-2026",               "MEDIUM"),
        ("BUMBLEBEE-LOADER-EMAIL",         "MEDIUM"),
        ("MIDNIGHT-BLIZZARD-OAUTH",        "CRITICAL"),
        ("CITRIX-BLEED-CVE-2023-4966",     "CRITICAL"),
        ("STORM0558-EXCHANGE-TOKEN",       "CRITICAL"),
        ("CARBANAK-BANKING-PHISH",         "HIGH"),
        ("ICEDID-BANKING-MALWARE",         "MEDIUM"),
        ("REVIL-REVIVAL-RANSOMWARE",       "CRITICAL"),
        ("COBALTSTRIKE-BEACON-ENTERPRISE", "HIGH"),
        ("BRUTERATEL-C4-IMPLANT",          "HIGH"),
        ("SLIVER-C2-FRAMEWORK",            "MEDIUM"),
        ("LAZARUS-CRYPTO-DRAIN",           "CRITICAL"),
        ("RHYSIDA-EXFIL-PRE-ENCRYPT",      "HIGH"),
        ("MIMIKATZ-PASS-THE-HASH",         "HIGH"),
        ("KERBEROASTING-ATTACK",           "MEDIUM"),
        ("LOTL-GOVERNMENT-NETWORK",        "HIGH"),
        ("SUPPLY-CHAIN-NPM-PACKAGE",       "HIGH"),
        ("PAPERCUT-CVE-2023-27350",        "HIGH"),
    ][:n]

    agent_seq = [
        ("PlannerAgent",       ("DETECTED",   "ANALYZED"),   40, 120),
        ("IntelligenceAgent",  ("ANALYZED",   "ENRICHED"),   80, 300),
        ("AttributionAgent",   ("ENRICHED",   "ATTRIBUTED"), 50, 180),
        ("ComplianceAgent",    ("ATTRIBUTED", "MITIGATED"),  30, 100),
    ]

    _RUNS_LOG.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for i, (threat, sev) in enumerate(threats):
        started_at = datetime.now(timezone.utc)
        agents = []
        current_dt = started_at
        total_ms = 0.0
        for agent_name, (in_status, out_status), lo, hi in agent_seq:
            ms = round(random.uniform(lo, hi), 2)
            a_start = current_dt
            from datetime import timedelta
            a_end = a_start + timedelta(milliseconds=ms)
            agents.append({
                "agent_name": agent_name,
                "status": "COMPLETED",
                "started_at": a_start.isoformat(),
                "ended_at": a_end.isoformat(),
                "duration_ms": ms,
                "output_status": out_status,
                "output_summary": (
                    f"actor=UNATTRIBUTED confidence={random.uniform(0.4,0.9):.2f} "
                    f"risk={random.uniform(0.1,0.9):.4f}"
                ),
                "confidence": round(random.uniform(0.4, 0.9), 3),
                "risk_score": round(random.uniform(0.1, 0.9), 4),
                "campaign_id": f"CAMP-{threat[:4].upper()}-2026-{uuid.uuid4().hex[:6].upper()}",
            })
            current_dt = a_end
            total_ms += ms

        record = {
            "run_id": str(uuid.uuid4()),
            "incident_id": f"INC-2026-{i+1:03d}",
            "threat_name": threat,
            "severity": sev,
            "started_at": started_at.isoformat(),
            "completed_at": current_dt.isoformat(),
            "duration_ms": round(total_ms, 2),
            "final_status": "MITIGATED",
            "campaign_id": agents[-1]["campaign_id"],
            "suspected_actor": "UNATTRIBUTED",
            "agents": agents,
        }
        lines.append(json.dumps(record))

    _RUNS_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
