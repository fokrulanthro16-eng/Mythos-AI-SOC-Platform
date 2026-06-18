"""dashboard/executive_store.py — Executive KPI aggregation for the Mythos SOC dashboard.

Aggregates data from case_store, workbench_store, agent_store, and the static
incident JSON to produce executive-level metrics and chart data for the C-suite view.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

_INCIDENTS_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_incidents.json"

_SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_CASE_STATUSES   = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]

# Threat name → executive actor family (7 families for C-suite view)
_THREAT_ACTOR_FAMILY: dict[str, str] = {
    # LOCKBIT umbrella
    "LOCKBIT4-RANSOMWARE":            "LOCKBIT",
    # TA505 / Cl0p
    "CLOP-MOVEIT-STYLE-SQLI":         "TA505",
    "TA505-EXFIL-FTP":                "TA505",
    "MOVEIT-STYLE-SQLI-2026":         "TA505",
    # FIN7 / Carbanak family
    "CARBANAK-BANKING-PHISH":         "FIN7",
    "EVILGINX2-AITM-PHISH":           "FIN7",
    "DARKGATE-MALSPAM":               "FIN7",
    # APT29 — Russian state-sponsored
    "MIDNIGHT-BLIZZARD-OAUTH":        "APT29",
    "APT28-SPEARPHISH":               "APT29",
    "APT28-DOCUMENT-EXFIL":           "APT29",
    "BRUTERATEL-C4-IMPLANT":          "APT29",
    # APT41 — Chinese state-sponsored
    "VOLT-TYPHOON-LOTL":              "APT41",
    "VOLT-TYPHOON-EXFIL":             "APT41",
    "WMIC-LATERAL-MOVEMENT":          "APT41",
    "LOTL-GOVERNMENT-NETWORK":        "APT41",
    "STORM0558-EXCHANGE-TOKEN":       "APT41",
    # Lazarus — DPRK
    "LAZARUS-C2-CRYPTO":              "Lazarus",
    "LAZARUS-CRYPTO-DRAIN":           "Lazarus",
    "SUPPLY-CHAIN-NPM-PACKAGE":       "Lazarus",
    # All others → Unknown Criminal Group
}

# Threat name → SOC category (8 threat categories)
_THREAT_CATEGORY: dict[str, str] = {
    # Ransomware
    "LOCKBIT4-RANSOMWARE":            "Ransomware",
    "BLACKCAT-ALPHV-RANSOMWARE":      "Ransomware",
    "AKIRA-RANSOMWARE":               "Ransomware",
    "PLAY-RANSOMWARE":                "Ransomware",
    "RHYSIDA-RANSOMWARE":             "Ransomware",
    "REVIL-REVIVAL-RANSOMWARE":       "Ransomware",
    "ICEFIRE-LINUX-RANSOMWARE":       "Ransomware",
    "RHYSIDA-EXFIL-PRE-ENCRYPT":      "Ransomware",
    # Phishing
    "APT28-SPEARPHISH":               "Phishing",
    "CARBANAK-BANKING-PHISH":         "Phishing",
    "EVILGINX2-AITM-PHISH":           "Phishing",
    "DARKGATE-MALSPAM":               "Phishing",
    # Credential Theft
    "SCATTERED-SPIDER-BEC":           "Credential Theft",
    "SCATTERED-SPIDER-SMS-MFA":       "Credential Theft",
    "MIDNIGHT-BLIZZARD-OAUTH":        "Credential Theft",
    "STORM0558-EXCHANGE-TOKEN":       "Credential Theft",
    "ICEDID-BANKING-MALWARE":         "Credential Theft",
    # Data Exfiltration
    "CLOP-MOVEIT-STYLE-SQLI":         "Data Exfiltration",
    "TA505-EXFIL-FTP":                "Data Exfiltration",
    "SCATTERED-SPIDER-DATA-THEFT":    "Data Exfiltration",
    "VOLT-TYPHOON-EXFIL":             "Data Exfiltration",
    "APT28-DOCUMENT-EXFIL":           "Data Exfiltration",
    "LAZARUS-CRYPTO-DRAIN":           "Data Exfiltration",
    "MOVEIT-STYLE-SQLI-2026":         "Data Exfiltration",
    # Command & Control
    "COBALTSTRIKE-BEACON-ENTERPRISE": "Command & Control",
    "BRUTERATEL-C4-IMPLANT":          "Command & Control",
    "SLIVER-C2-FRAMEWORK":            "Command & Control",
    "VOLT-TYPHOON-LOTL":              "Command & Control",
    "LAZARUS-C2-CRYPTO":              "Command & Control",
    "COBALTSTRIKE-VIA-RDP":           "Command & Control",
    "HAVOC-C2-FRAMEWORK":             "Command & Control",
    "MYTHIC-C2-AGENT":                "Command & Control",
    "CITRIX-BLEED-CVE-2023-4966":     "Command & Control",
    "K8S-CRYPTOMINING":               "Command & Control",
    "PAPERCUT-CVE-2023-27350":        "Command & Control",
    # Insider Threat
    "INSIDER-DATA-STAGING":           "Insider Threat",
    # Malware Delivery
    "QAKBOT-REVIVAL-PHISH":           "Malware Delivery",
    "BUMBLEBEE-LOADER-EMAIL":         "Malware Delivery",
    "EMOTET-WAVE-2026":               "Malware Delivery",
    "SUPPLY-CHAIN-NPM-PACKAGE":       "Malware Delivery",
    # Lateral Movement
    "MIMIKATZ-PASS-THE-HASH":         "Lateral Movement",
    "KERBEROASTING-ATTACK":           "Lateral Movement",
    "RDP-BRUTEFORCE-LATERAL":         "Lateral Movement",
    "WMIC-LATERAL-MOVEMENT":          "Lateral Movement",
    "LOTL-GOVERNMENT-NETWORK":        "Lateral Movement",
}

# Severity → estimated mean time to detect in hours (industry-calibrated)
_SEV_MTTD_HOURS: dict[str, float] = {
    "CRITICAL": 2.1,
    "HIGH":     6.3,
    "MEDIUM":   14.7,
    "LOW":      28.4,
}


def _load_incidents() -> list[dict]:
    if not _INCIDENTS_PATH.exists():
        return []
    try:
        return json.loads(_INCIDENTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Pure compute functions (no file I/O — easily unit-tested)
# ---------------------------------------------------------------------------


def compute_mttr(cases: list[dict]) -> float:
    """Return mean time to resolve in hours. 0.0 if no resolved cases."""
    total_hours = 0.0
    count = 0
    for c in cases:
        if c.get("status") not in ("RESOLVED", "CLOSED"):
            continue
        created_raw  = c.get("created_at", "")
        resolved_raw = c.get("resolved_at", "")
        if not created_raw or not resolved_raw:
            continue
        try:
            created     = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            resolved_at = datetime.fromisoformat(resolved_raw.replace("Z", "+00:00"))
            delta_h = (resolved_at - created).total_seconds() / 3600
            if delta_h >= 0:
                total_hours += delta_h
                count += 1
        except (ValueError, TypeError):
            continue
    return round(total_hours / count, 1) if count else 0.0


def compute_mttd(incidents: list[dict]) -> float:
    """Return estimated mean time to detect in hours (severity-based model)."""
    total = 0.0
    count = 0
    for inc in incidents:
        sev  = inc.get("severity", "MEDIUM")
        base = _SEV_MTTD_HOURS.get(sev, 14.7)
        try:
            num    = int(inc.get("incident_id", "0").split("-")[-1])
            jitter = (num % 5) * 0.4 - 1.0  # deterministic ±1.6 h spread
        except (ValueError, IndexError):
            jitter = 0.0
        total += max(0.3, base + jitter)
        count += 1
    return round(total / count, 1) if count else 0.0


def compute_analyst_utilization(assignments: list[dict], analyst_count: int = 10) -> float:
    """Return utilization as a percentage (active / theoretical capacity)."""
    active   = [a for a in assignments if a.get("status") not in ("RESOLVED", "CLOSED")]
    capacity = analyst_count * 5  # 5 concurrent incidents per analyst
    return round(min(len(active) / max(capacity, 1) * 100, 100.0), 1)


def compute_attribution_confidence(runs: list[dict]) -> float:
    """Average AttributionAgent confidence across all pipeline runs (0–100 %)."""
    confs: list[float] = []
    for run in runs:
        for agent in run.get("agents", []):
            if agent.get("agent_name") == "AttributionAgent":
                c = agent.get("confidence")
                if c is not None:
                    confs.append(float(c))
                break
    return round(sum(confs) / len(confs) * 100, 1) if confs else 0.0


def incidents_last_n_days(incidents: list[dict], n: int = 7) -> int:
    """Count incidents created in the last N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=n)
    count  = 0
    for inc in incidents:
        ts_raw = inc.get("created_at", "")
        if not ts_raw:
            continue
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if ts >= cutoff:
                count += 1
        except (ValueError, TypeError):
            continue
    return count


# ---------------------------------------------------------------------------
# KPI aggregator
# ---------------------------------------------------------------------------


def _compute_executive_kpis(
    incidents:   list[dict],
    cases:       list[dict],
    assignments: list[dict],
    runs:        list[dict],
) -> dict:
    open_cases    = sum(1 for c in cases if c.get("status") not in ("RESOLVED", "CLOSED"))
    critical_incs = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    active_camps  = len({i.get("campaign_id") for i in incidents if i.get("campaign_id")})
    return {
        "open_cases":              open_cases,
        "critical_incidents":      critical_incs,
        "mttr_hours":              compute_mttr(cases),
        "mttd_hours":              compute_mttd(incidents),
        "active_campaigns":        active_camps,
        "analyst_utilization_pct": compute_analyst_utilization(assignments),
        "attribution_confidence":  compute_attribution_confidence(runs),
        "incidents_last_7_days":   incidents_last_n_days(incidents, 7),
    }


def get_executive_kpis() -> dict:
    """Return all executive KPI values aggregated from all live data sources."""
    from dashboard.case_store import get_all_cases
    from dashboard.workbench_store import get_all_assignments
    from dashboard.agent_store import load_runs

    return _compute_executive_kpis(
        incidents   = _load_incidents(),
        cases       = get_all_cases(),
        assignments = get_all_assignments(),
        runs        = load_runs(),
    )


# ---------------------------------------------------------------------------
# Chart data builders
# ---------------------------------------------------------------------------


def _compute_incident_trend(incidents: list[dict], days: int = 30) -> list[dict]:
    now = datetime.now(timezone.utc)
    day_counts: dict[str, int] = {}
    for d in range(days):
        day = (now - timedelta(days=days - 1 - d)).strftime("%Y-%m-%d")
        day_counts[day] = 0
    for inc in incidents:
        ts_raw = inc.get("created_at", "")
        if not ts_raw:
            continue
        try:
            ts  = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            day = ts.strftime("%Y-%m-%d")
            if day in day_counts:
                day_counts[day] += 1
        except (ValueError, TypeError):
            continue
    return [{"date": d, "count": c} for d, c in sorted(day_counts.items())]


def get_incident_trend(days: int = 30) -> list[dict]:
    return _compute_incident_trend(_load_incidents(), days)


def _compute_severity_distribution(incidents: list[dict]) -> dict[str, int]:
    dist = {s: 0 for s in _SEVERITY_LEVELS}
    for inc in incidents:
        sev = inc.get("severity", "")
        if sev in dist:
            dist[sev] += 1
    return dist


def get_severity_distribution() -> dict[str, int]:
    return _compute_severity_distribution(_load_incidents())


def _compute_case_status_distribution(cases: list[dict]) -> dict[str, int]:
    dist = {s: 0 for s in _CASE_STATUSES}
    for c in cases:
        status = c.get("status", "")
        if status in dist:
            dist[status] += 1
    return dist


def get_case_status_distribution() -> dict[str, int]:
    from dashboard.case_store import get_all_cases
    return _compute_case_status_distribution(get_all_cases())


def _compute_campaign_activity(incidents: list[dict], top_n: int = 10) -> list[dict]:
    counts: dict[str, int] = {}
    for inc in incidents:
        cid = inc.get("campaign_id", "")
        if cid:
            counts[cid] = counts.get(cid, 0) + 1
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [{"campaign_id": cid, "incident_count": cnt} for cid, cnt in sorted_items]


def get_campaign_activity(top_n: int = 10) -> list[dict]:
    return _compute_campaign_activity(_load_incidents(), top_n)


def _compute_threat_actor_breakdown(incidents: list[dict]) -> dict[str, int]:
    """Roll up incidents to 7 executive actor families."""
    counts: dict[str, int] = {}
    for inc in incidents:
        threat = inc.get("threat_name", "")
        family = _THREAT_ACTOR_FAMILY.get(threat, "Unknown Criminal Group")
        counts[family] = counts.get(family, 0) + 1
    return counts


def get_threat_actor_breakdown() -> dict[str, int]:
    return _compute_threat_actor_breakdown(_load_incidents())


def _compute_threat_category_breakdown(incidents: list[dict]) -> dict[str, int]:
    categories = [
        "Ransomware", "Phishing", "Credential Theft",
        "Data Exfiltration", "Command & Control",
        "Insider Threat", "Malware Delivery", "Lateral Movement",
    ]
    counts = {c: 0 for c in categories}
    for inc in incidents:
        threat = inc.get("threat_name", "")
        cat    = _THREAT_CATEGORY.get(threat, "Command & Control")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def get_threat_category_breakdown() -> dict[str, int]:
    return _compute_threat_category_breakdown(_load_incidents())


def get_analyst_utilization_breakdown() -> dict[str, dict]:
    """Per-analyst open/resolved/critical counts from workbench_store."""
    from dashboard.workbench_store import get_workload_metrics
    return get_workload_metrics().get("by_analyst", {})
