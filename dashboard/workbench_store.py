"""dashboard/workbench_store.py — Analyst workbench file-backed store.

Tracks: incident assignments, analyst activity feed, priority escalations.
Delegates actual case data to case_store.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

_STORE_PATH = Path(__file__).parent.parent / "logs" / "workbench_store.json"

_PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
_ANALYSTS = [
    "Sarah Kim",
    "Marcus Webb",
    "Priya Nair",
    "James Okafor",
    "Elena Vasquez",
    "Tom Brandt",
    "Nia Thompson",
    "Carlos Mendez",
    "Aisha Patel",
    "Ryan O'Brien",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if _STORE_PATH.exists():
        try:
            return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"assignments": [], "activity_feed": [], "escalations": []}


def _save(data: dict) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------


def get_all_assignments() -> list[dict]:
    return _load()["assignments"]


def get_assignment(incident_id: str) -> dict | None:
    return next(
        (a for a in get_all_assignments() if a["incident_id"] == incident_id), None
    )


def assign_incident(
    incident_id: str,
    analyst: str,
    *,
    assigned_by: str = "System",
    title: str = "",
    severity: str = "MEDIUM",
    priority: str = "P3",
    case_id: str = "",
) -> dict:
    """Assign or re-assign an incident to an analyst. Returns the assignment record."""
    store = _load()
    ts = _now()
    existing = next(
        (a for a in store["assignments"] if a["incident_id"] == incident_id), None
    )
    if existing:
        old_analyst = existing.get("analyst", "")
        existing["analyst"] = analyst
        existing["assigned_by"] = assigned_by
        existing["updated_at"] = ts
        if old_analyst != analyst:
            store["activity_feed"].append({
                "id": str(uuid.uuid4()),
                "user": assigned_by,
                "action": "REASSIGNED",
                "target": incident_id,
                "detail": f"Reassigned from {old_analyst} to {analyst}",
                "timestamp": ts,
            })
        _save(store)
        return existing

    assignment: dict = {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "case_id": case_id,
        "analyst": analyst,
        "assigned_by": assigned_by,
        "title": title,
        "severity": severity,
        "priority": priority,
        "status": "OPEN",
        "assigned_at": ts,
        "updated_at": ts,
        "notes": [],
    }
    store["assignments"].append(assignment)
    store["activity_feed"].append({
        "id": str(uuid.uuid4()),
        "user": assigned_by,
        "action": "ASSIGNED",
        "target": incident_id,
        "detail": f"Assigned to {analyst}",
        "timestamp": ts,
    })
    _save(store)
    return assignment


def unassign_incident(incident_id: str, user: str = "System") -> bool:
    store = _load()
    store["assignments"] = [
        a for a in store["assignments"] if a["incident_id"] != incident_id
    ]
    store["activity_feed"].append({
        "id": str(uuid.uuid4()),
        "user": user,
        "action": "UNASSIGNED",
        "target": incident_id,
        "detail": "Assignment removed",
        "timestamp": _now(),
    })
    _save(store)
    return True


def get_analyst_assignments(analyst: str) -> list[dict]:
    return [a for a in get_all_assignments() if a.get("analyst") == analyst]


def update_assignment_status(incident_id: str, status: str, user: str = "Analyst") -> dict | None:
    store = _load()
    for a in store["assignments"]:
        if a["incident_id"] != incident_id:
            continue
        old = a.get("status", "")
        a["status"] = status
        a["updated_at"] = _now()
        store["activity_feed"].append({
            "id": str(uuid.uuid4()),
            "user": user,
            "action": "STATUS_CHANGED",
            "target": incident_id,
            "detail": f"Status: {old} → {status}",
            "timestamp": _now(),
        })
        if status in ("RESOLVED", "CLOSED") and not a.get("closed_at"):
            a["closed_at"] = _now()
        _save(store)
        return a
    return None


def add_workbench_note(incident_id: str, content: str, author: str = "Analyst") -> dict | None:
    store = _load()
    ts = _now()
    for a in store["assignments"]:
        if a["incident_id"] != incident_id:
            continue
        note = {"id": str(uuid.uuid4()), "author": author, "content": content, "timestamp": ts}
        a.setdefault("notes", []).append(note)
        a["updated_at"] = ts
        store["activity_feed"].append({
            "id": str(uuid.uuid4()),
            "user": author,
            "action": "NOTE_ADDED",
            "target": incident_id,
            "detail": content[:100] + ("…" if len(content) > 100 else ""),
            "timestamp": ts,
        })
        _save(store)
        return note
    return None


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------


def record_escalation(
    incident_id: str,
    from_priority: str,
    to_priority: str,
    analyst: str,
    reason: str = "",
) -> dict:
    store = _load()
    ts = _now()
    esc = {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "from_priority": from_priority,
        "to_priority": to_priority,
        "analyst": analyst,
        "reason": reason,
        "timestamp": ts,
    }
    store["escalations"].append(esc)
    store["activity_feed"].append({
        "id": str(uuid.uuid4()),
        "user": analyst,
        "action": "ESCALATED",
        "target": incident_id,
        "detail": f"Priority: {from_priority} → {to_priority}. {reason}",
        "timestamp": ts,
    })
    # Also update assignment priority if it exists
    for a in store["assignments"]:
        if a["incident_id"] == incident_id:
            a["priority"] = to_priority
            a["updated_at"] = ts
            break
    _save(store)
    return esc


def get_escalations(incident_id: str | None = None) -> list[dict]:
    store = _load()
    escs = store["escalations"]
    if incident_id:
        escs = [e for e in escs if e["incident_id"] == incident_id]
    return sorted(escs, key=lambda x: x["timestamp"], reverse=True)


# ---------------------------------------------------------------------------
# Activity feed
# ---------------------------------------------------------------------------


def log_activity(
    user: str,
    action: str,
    target: str,
    detail: str = "",
) -> dict:
    store = _load()
    entry = {
        "id": str(uuid.uuid4()),
        "user": user,
        "action": action,
        "target": target,
        "detail": detail,
        "timestamp": _now(),
    }
    store["activity_feed"].append(entry)
    _save(store)
    return entry


def get_activity_feed(limit: int = 50, analyst: str | None = None) -> list[dict]:
    feed = _load()["activity_feed"]
    if analyst:
        feed = [e for e in feed if e.get("user") == analyst]
    return sorted(feed, key=lambda x: x["timestamp"], reverse=True)[:limit]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def get_workload_metrics() -> dict:
    """Return per-analyst assignment counts and case ownership stats."""
    assignments = get_all_assignments()
    by_analyst: dict[str, dict] = {}

    for a in assignments:
        name = a.get("analyst") or "Unassigned"
        if name not in by_analyst:
            by_analyst[name] = {"total": 0, "open": 0, "resolved": 0, "critical": 0}
        by_analyst[name]["total"] += 1
        status = a.get("status", "OPEN")
        if status in ("OPEN", "INVESTIGATING", "CONTAINED"):
            by_analyst[name]["open"] += 1
        elif status in ("RESOLVED", "CLOSED"):
            by_analyst[name]["resolved"] += 1
        if a.get("priority") == "P1" or a.get("severity") == "CRITICAL":
            by_analyst[name]["critical"] += 1

    active = [a for a in assignments if a.get("status") not in ("RESOLVED", "CLOSED")]
    return {
        "total_assigned": len(assignments),
        "active": len(active),
        "resolved": len(assignments) - len(active),
        "unassigned_count": 0,
        "by_analyst": by_analyst,
        "escalations_today": len([
            e for e in get_escalations()
            if e["timestamp"][:10] == datetime.now(timezone.utc).strftime("%Y-%m-%d")
        ]),
    }


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------


def _wb_ts(inc_id: str, offset_hours: float = 0.0) -> str:
    """Deterministic ISO timestamp for workbench records based on incident number."""
    base = datetime(2026, 5, 18, tzinfo=timezone.utc)
    try:
        num = int(inc_id.split("-")[-1])
    except (ValueError, IndexError):
        num = 1
    day_frac = (num - 1) * 30.0 / 49.0
    return (base + timedelta(days=day_frac, hours=offset_hours)).isoformat()


_WB_RES_HOURS = {"P1": 36, "P2": 72, "P3": 120, "P4": 48}


def seed_sample_data() -> None:
    """Seed realistic 2026 threat incident assignments for 10 analysts."""
    if get_all_assignments():
        return
    # (incident_id, analyst, title, severity, priority, status, campaign_id)
    samples = [
        ("INC-2026-001", "Sarah Kim",     "LockBit 4.0 — Hospital Network Encryption",         "CRITICAL", "P1", "INVESTIGATING", "CAMP-LOCKBIT4-2026"),
        ("INC-2026-002", "James Okafor",  "BlackCat/ALPHV — Energy Sector Ransomware",          "CRITICAL", "P1", "INVESTIGATING", "CAMP-BLACKCAT-2026"),
        ("INC-2026-003", "Marcus Webb",   "Akira — Cisco VPN Initial Access",                   "HIGH",     "P2", "INVESTIGATING", "CAMP-AKIRA-2026"),
        ("INC-2026-004", "Aisha Patel",   "PLAY Ransomware — Municipal Government",             "HIGH",     "P2", "CONTAINED",    "CAMP-PLAY-2026"),
        ("INC-2026-005", "Aisha Patel",   "Rhysida — University Double-Extortion",              "CRITICAL", "P1", "CONTAINED",    "CAMP-RHYSIDA-2026"),
        ("INC-2026-006", "Tom Brandt",    "LockBit 4.0 — Logistics Company Encryption",        "HIGH",     "P2", "INVESTIGATING", "CAMP-LOCKBIT4-2026"),
        ("INC-2026-007", "James Okafor",  "BlackCat/ALPHV — Energy Sector Wave 2",              "CRITICAL", "P1", "INVESTIGATING", "CAMP-BLACKCAT-2026"),
        ("INC-2026-008", "Marcus Webb",   "Akira — Architecture Firm Encryption",               "HIGH",     "P2", "RESOLVED",     "CAMP-AKIRA-2026"),
        ("INC-2026-009", "Carlos Mendez", "REvil 3.0 — Retail Chain Ransomware",                "CRITICAL", "P1", "INVESTIGATING", "CAMP-REVIL-2026"),
        ("INC-2026-010", "Tom Brandt",    "PLAY Ransomware — Financial Services",               "HIGH",     "P2", "RESOLVED",     "CAMP-PLAY-2026"),
        ("INC-2026-011", "Aisha Patel",   "Rhysida — Defence Contractor Threat",                "HIGH",     "P2", "INVESTIGATING", "CAMP-RHYSIDA-2026"),
        ("INC-2026-012", "Tom Brandt",    "IceFire Linux — Media Company",                     "MEDIUM",   "P3", "RESOLVED",     "CAMP-ICEFIRE-2026"),
        ("INC-2026-013", "Elena Vasquez", "Scattered Spider — BEC Identity Compromise",         "HIGH",     "P1", "CONTAINED",    "CAMP-SCATTERED-2026"),
        ("INC-2026-014", "Priya Nair",    "APT28 — Spear-Phishing NATO Officials",             "HIGH",     "P2", "INVESTIGATING", "CAMP-FANCY-BEAR-2026"),
        ("INC-2026-015", "Priya Nair",    "Midnight Blizzard — OAuth Token Theft M365",         "CRITICAL", "P1", "INVESTIGATING", "CAMP-MIDNIGHT-BLIZZARD-2026"),
        ("INC-2026-016", "Carlos Mendez", "Carbanak — Banking Phishing Campaign",               "HIGH",     "P2", "CONTAINED",    "CAMP-CARBANAK-2026"),
        ("INC-2026-017", "Tom Brandt",    "DarkGate — Malspam Healthcare Admin",                "MEDIUM",   "P3", "RESOLVED",     "CAMP-DARKGATE-2026"),
        ("INC-2026-018", "Tom Brandt",    "QakBot Revival — Law Firm Infection",                "MEDIUM",   "P3", "RESOLVED",     "CAMP-QAKBOT-2026"),
        ("INC-2026-019", "Marcus Webb",   "BumbleBee Loader — Manufacturing Phishing",          "MEDIUM",   "P3", "RESOLVED",     "CAMP-BUMBLEBEE-2026"),
        ("INC-2026-020", "Tom Brandt",    "Emotet Wave 12 — Multi-Org Outbreak",               "MEDIUM",   "P3", "CONTAINED",    "CAMP-EMOTET-2026"),
        ("INC-2026-021", "Elena Vasquez", "Scattered Spider — SMS MFA SaaS Breach",             "HIGH",     "P2", "INVESTIGATING", "CAMP-SCATTERED-2026"),
        ("INC-2026-022", "Aisha Patel",   "IcedID — Insurance Sector Banking Malware",         "MEDIUM",   "P3", "RESOLVED",     "CAMP-ICEDID-2026"),
        ("INC-2026-023", "Elena Vasquez", "Evilginx2 — Adversary-in-the-Middle Phishing",      "HIGH",     "P2", "CONTAINED",    "CAMP-SCATTERED-2026"),
        ("INC-2026-024", "Ryan O'Brien",  "Storm-0558 — Exchange Online Token Forgery",         "CRITICAL", "P1", "INVESTIGATING", "CAMP-STORM0558-2026"),
        ("INC-2026-025", "Marcus Webb",   "Cobalt Strike Beacon — Enterprise Manufacturing",    "HIGH",     "P2", "CONTAINED",    "CAMP-LOCKBIT4-2026"),
        ("INC-2026-026", "Priya Nair",    "Brute Ratel C4 — Defence Contractor Implant",       "HIGH",     "P2", "INVESTIGATING", "CAMP-FANCY-BEAR-2026"),
        ("INC-2026-027", "Elena Vasquez", "Sliver C2 — Retail Sector Framework",               "MEDIUM",   "P3", "RESOLVED",     "CAMP-SCATTERED-2026"),
        ("INC-2026-028", "Ryan O'Brien",  "Volt Typhoon — LOTL in Utilities Network",           "HIGH",     "P2", "INVESTIGATING", "CAMP-VOLT-TYPHOON-2026"),
        ("INC-2026-029", "Nia Thompson",  "Lazarus — C2 Infrastructure Crypto Exchange",        "CRITICAL", "P1", "INVESTIGATING", "CAMP-LAZARUS-2026"),
        ("INC-2026-030", "Marcus Webb",   "Cobalt Strike — RDP Pivot Insurance Sector",         "HIGH",     "P2", "RESOLVED",     "CAMP-AKIRA-2026"),
        ("INC-2026-031", "Tom Brandt",    "Havoc C2 — Tech Firm Intrusion",                    "MEDIUM",   "P3", "RESOLVED",     "CAMP-DARKGATE-2026"),
        ("INC-2026-032", "Elena Vasquez", "Mythic C2 — macOS Agent Healthcare",                "MEDIUM",   "P3", "RESOLVED",     "CAMP-SCATTERED-2026"),
        ("INC-2026-033", "Carlos Mendez", "Cl0p — MFT Zero-Day Mass Exfiltration",             "CRITICAL", "P1", "RESOLVED",     "CAMP-CLOP-2026"),
        ("INC-2026-034", "Carlos Mendez", "TA505 — FTP Exfiltration Financial Data",           "HIGH",     "P2", "RESOLVED",     "CAMP-CLOP-2026"),
        ("INC-2026-035", "Elena Vasquez", "Scattered Spider — SharePoint Mass Download",        "HIGH",     "P2", "CONTAINED",    "CAMP-SCATTERED-2026"),
        ("INC-2026-036", "Sarah Kim",     "Insider Threat — Financial Report Staging",          "HIGH",     "P2", "INVESTIGATING", "CAMP-CLOP-2026"),
        ("INC-2026-037", "Ryan O'Brien",  "Volt Typhoon — Telecoms Exfiltration",              "HIGH",     "P2", "INVESTIGATING", "CAMP-VOLT-TYPHOON-2026"),
        ("INC-2026-038", "Priya Nair",    "APT28 — NATO Document Exfiltration",                "HIGH",     "P2", "CONTAINED",    "CAMP-FANCY-BEAR-2026"),
        ("INC-2026-039", "Nia Thompson",  "Lazarus — Crypto Exchange $14.2M Drain",            "CRITICAL", "P1", "INVESTIGATING", "CAMP-LAZARUS-2026"),
        ("INC-2026-040", "Aisha Patel",   "Rhysida — University Pre-Encryption Staging",       "HIGH",     "P2", "RESOLVED",     "CAMP-RHYSIDA-2026"),
        ("INC-2026-041", "Sarah Kim",     "Mimikatz Pass-the-Hash — Enterprise AD",            "HIGH",     "P2", "CONTAINED",    "CAMP-LOCKBIT4-2026"),
        ("INC-2026-042", "Marcus Webb",   "Kerberoasting — Financial Sector AD Attack",         "MEDIUM",   "P3", "RESOLVED",     "CAMP-AKIRA-2026"),
        ("INC-2026-043", "Tom Brandt",    "RDP Brute Force — Healthcare Lateral Movement",     "MEDIUM",   "P3", "CONTAINED",    "CAMP-PLAY-2026"),
        ("INC-2026-044", "Ryan O'Brien",  "WMIC Lateral Movement — Manufacturing",             "MEDIUM",   "P3", "RESOLVED",     "CAMP-VOLT-TYPHOON-2026"),
        ("INC-2026-045", "Ryan O'Brien",  "LOTL — Government Network Pre-Positioning",         "HIGH",     "P2", "INVESTIGATING", "CAMP-VOLT-TYPHOON-2026"),
        ("INC-2026-046", "Carlos Mendez", "Citrix Bleed CVE-2023-4966 — Session Hijack",      "CRITICAL", "P2", "RESOLVED",     "CAMP-CITRIX-BLEED-2026"),
        ("INC-2026-047", "Carlos Mendez", "MOVEit-Style SQLi — File Transfer Platform",        "HIGH",     "P2", "RESOLVED",     "CAMP-CLOP-2026"),
        ("INC-2026-048", "Nia Thompson",  "npm Supply Chain — Lazarus Backdoor",               "HIGH",     "P2", "RESOLVED",     "CAMP-LAZARUS-2026"),
        ("INC-2026-049", "Tom Brandt",    "K8s Cryptomining — Cloud Cluster Abuse",            "LOW",      "P4", "CLOSED",       "CAMP-SCATTERED-2026"),
        ("INC-2026-050", "Carlos Mendez", "PaperCut CVE-2023-27350 — Print Server RCE",        "HIGH",     "P2", "RESOLVED",     "CAMP-CLOP-2026"),
    ]
    store = _load()
    escalated_incidents = {
        "INC-2026-001": ("P2", "P1", "Sarah Kim",     "Confirmed encryption spreading to backup systems."),
        "INC-2026-002": ("P2", "P1", "James Okafor",  "OT network proximity — potential ICS impact."),
        "INC-2026-009": ("P2", "P1", "Carlos Mendez", "ESXi infrastructure targeted — full virtualisation stack at risk."),
        "INC-2026-015": ("P2", "P1", "Priya Nair",    "OAuth tokens active across 3 tenants — escalating blast radius."),
        "INC-2026-029": ("P2", "P1", "Nia Thompson",  "Live crypto drain confirmed — $14.2M moved to mixer."),
        "INC-2026-033": ("P2", "P1", "Carlos Mendez", "152 GB patient data confirmed exfiltrated — HIPAA breach."),
        "INC-2026-024": ("P2", "P1", "Ryan O'Brien",  "Executive mailbox access confirmed — 8-week dwell time."),
        "INC-2026-039": ("P2", "P1", "Nia Thompson",  "Ethereum bridge exploit — funds moved to DPRK mixer."),
    }
    for (inc_id, analyst, title, severity, priority, status, campaign_id) in samples:
        assigned_ts = _wb_ts(inc_id)
        updated_ts  = _wb_ts(inc_id, offset_hours=2)
        notes = [
            {
                "id": str(uuid.uuid4()),
                "author": analyst,
                "content": "Initial triage complete. Severity confirmed. Evidence preservation started.",
                "timestamp": _wb_ts(inc_id, offset_hours=1),
            }
        ]
        if status not in ("OPEN",):
            notes.append({
                "id": str(uuid.uuid4()),
                "author": analyst,
                "content": "Containment actions initiated. Affected systems isolated from network.",
                "timestamp": _wb_ts(inc_id, offset_hours=4),
            })
        if status in ("RESOLVED", "CLOSED"):
            res_h = _WB_RES_HOURS.get(priority, 72)
            notes.append({
                "id": str(uuid.uuid4()),
                "author": analyst,
                "content": "Remediation complete. IOCs blocked at perimeter. Post-incident review scheduled.",
                "timestamp": _wb_ts(inc_id, offset_hours=res_h),
            })
        a = {
            "id": str(uuid.uuid4()),
            "incident_id": inc_id,
            "case_id": "",
            "analyst": analyst,
            "assigned_by": "SOC Lead",
            "title": title,
            "severity": severity,
            "priority": priority,
            "campaign_id": campaign_id,
            "status": status,
            "assigned_at": assigned_ts,
            "updated_at": updated_ts,
            "notes": notes,
        }
        if status in ("RESOLVED", "CLOSED"):
            res_h = _WB_RES_HOURS.get(priority, 72)
            a["closed_at"] = _wb_ts(inc_id, offset_hours=res_h)
        store["assignments"].append(a)
        store["activity_feed"].append({
            "id": str(uuid.uuid4()),
            "user": "SOC Lead",
            "action": "ASSIGNED",
            "target": inc_id,
            "detail": f"Assigned to {analyst} — {title}",
            "timestamp": assigned_ts,
        })

    # Add escalations
    for inc_id, (old_p, new_p, analyst, reason) in escalated_incidents.items():
        esc_ts = _wb_ts(inc_id, offset_hours=3)
        store["escalations"].append({
            "id": str(uuid.uuid4()),
            "incident_id": inc_id,
            "from_priority": old_p,
            "to_priority": new_p,
            "analyst": analyst,
            "reason": reason,
            "timestamp": esc_ts,
        })
        store["activity_feed"].append({
            "id": str(uuid.uuid4()),
            "user": analyst,
            "action": "ESCALATED",
            "target": inc_id,
            "detail": f"Priority {old_p} → {new_p}: {reason}",
            "timestamp": esc_ts,
        })
    _save(store)
