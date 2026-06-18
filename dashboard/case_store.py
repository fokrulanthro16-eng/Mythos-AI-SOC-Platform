"""dashboard/case_store.py — File-backed case store for the standalone dashboard."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

_STORE_PATH = Path(__file__).parent.parent / "logs" / "case_store.json"

_STATUS_FLOW = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
_PRIORITY_LABELS = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if _STORE_PATH.exists():
        try:
            return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"cases": []}


def _save(data: dict) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def get_all_cases() -> list[dict]:
    return _load()["cases"]


def get_case(case_id: str) -> dict | None:
    return next((c for c in get_all_cases() if c["id"] == case_id), None)


def create_case(
    title: str,
    priority: str = "P3",
    description: str = "",
    assigned_analyst: str | None = None,
    incident_id: str = "",
    threat_name: str = "",
) -> dict:
    store = _load()
    year = datetime.now(timezone.utc).strftime("%Y")
    num = len(store["cases"]) + 1
    case: dict = {
        "id": str(uuid.uuid4()),
        "case_number": f"CASE-{year}-{num:04d}",
        "incident_id": incident_id,
        "threat_name": threat_name,
        "title": title,
        "description": description,
        "status": "OPEN",
        "priority": priority,
        "assigned_analyst": assigned_analyst,
        "notes": [],
        "history": [
            {
                "action": "CREATED",
                "content": f"Case created: {title}",
                "user": "System",
                "timestamp": _now(),
            }
        ],
        "created_at": _now(),
        "updated_at": _now(),
    }
    store["cases"].append(case)
    _save(store)
    return case


def update_case(case_id: str, updates: dict, user: str = "Analyst") -> dict | None:
    store = _load()
    for case in store["cases"]:
        if case["id"] != case_id:
            continue
        for field, new_val in updates.items():
            old_val = case.get(field)
            if old_val == new_val:
                continue
            action = (
                "STATUS_CHANGE"   if field == "status"          else
                "ASSIGNMENT"      if field == "assigned_analyst" else
                "PRIORITY_CHANGE" if field == "priority"         else
                f"{field.upper()}_CHANGED"
            )
            case.setdefault("history", []).append(
                {
                    "action": action,
                    "content": f"{field.replace('_', ' ').title()} changed: {old_val} → {new_val}",
                    "old_value": str(old_val) if old_val is not None else "",
                    "new_value": str(new_val),
                    "user": user,
                    "timestamp": _now(),
                }
            )
            case[field] = new_val
            if field == "status" and new_val == "RESOLVED" and not case.get("resolved_at"):
                case["resolved_at"] = _now()
        case["updated_at"] = _now()
        _save(store)
        return case
    return None


def add_note(case_id: str, content: str, author: str = "Analyst") -> dict | None:
    store = _load()
    for case in store["cases"]:
        if case["id"] != case_id:
            continue
        ts = _now()
        note = {"author": author, "content": content, "timestamp": ts}
        case.setdefault("notes", []).append(note)
        case.setdefault("history", []).append(
            {
                "action": "NOTE_ADDED",
                "content": content[:120] + ("…" if len(content) > 120 else ""),
                "user": author,
                "timestamp": ts,
            }
        )
        case["updated_at"] = ts
        _save(store)
        return note
    return None


def get_stats() -> dict:
    cases = get_all_cases()
    by_status: dict[str, int] = {s: 0 for s in _STATUS_FLOW}
    by_priority: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for c in cases:
        s = c.get("status", "OPEN")
        p = c.get("priority", "P3")
        by_status[s] = by_status.get(s, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1
    return {
        "total": len(cases),
        "by_status": by_status,
        "by_priority": by_priority,
        "open": by_status.get("OPEN", 0),
        "investigating": by_status.get("INVESTIGATING", 0),
        "contained": by_status.get("CONTAINED", 0),
        "resolved": by_status.get("RESOLVED", 0),
        "closed": by_status.get("CLOSED", 0),
    }


def _ts_for_inc(inc_id: str, offset_hours: float = 0.0) -> str:
    """Deterministic ISO timestamp based on incident number + optional hour offset."""
    base = datetime(2026, 5, 18, tzinfo=timezone.utc)
    try:
        num = int(inc_id.split("-")[-1])  # 1-50
    except (ValueError, IndexError):
        num = 1
    day_frac = (num - 1) * 30.0 / 49.0  # spread across 30 days
    return (base + timedelta(days=day_frac, hours=offset_hours)).isoformat()


# Resolution hours by priority (used to compute realistic MTTR)
_RES_HOURS = {"P1": 36, "P2": 72, "P3": 120, "P4": 48}


def seed_sample_cases() -> None:
    """Seed 15 realistic 2026 threat cases if the store is empty."""
    if get_all_cases():
        return
    # (title, priority, status, analyst, incident_id, campaign_id, description)
    samples = [
        (
            "LockBit 4.0 — Hospital Network Encryption",
            "P1", "INVESTIGATING", "Sarah Kim",
            "INC-2026-001", "CAMP-LOCKBIT4-2026",
            "LockBit 4.0 ransomware detected across 47 endpoints in hospital network. "
            "Encryption in progress on file shares. C2 callback to cdn-update-check.systems. "
            "Estimated patient data at risk. Backup systems reportedly compromised.",
        ),
        (
            "BlackCat/ALPHV — Energy Sector Ransomware",
            "P1", "INVESTIGATING", "James Okafor",
            "INC-2026-002", "CAMP-BLACKCAT-2026",
            "ALPHV Rust-based ransomware deployed across energy operator OT-adjacent systems. "
            "Double-extortion: 2.4 TB data staged for exfiltration. ExMatter tool detected. "
            "Incident may affect grid management software.",
        ),
        (
            "Scattered Spider — BEC & Identity Compromise",
            "P1", "CONTAINED", "Elena Vasquez",
            "INC-2026-013", "CAMP-SCATTERED-2026",
            "Scattered Spider conducted SMS phishing + MFA fatigue targeting Okta admin accounts. "
            "Three privileged accounts compromised. Attacker accessed SharePoint and exfiltrated source "
            "code repositories. Azure AD federation rules modified.",
        ),
        (
            "Midnight Blizzard — OAuth Token Theft M365",
            "P1", "INVESTIGATING", "Priya Nair",
            "INC-2026-015", "CAMP-MIDNIGHT-BLIZZARD-2026",
            "APT29/Midnight Blizzard device-code phishing campaign targeting Microsoft 365. "
            "OAuth refresh tokens captured, granting persistent access to mailboxes. "
            "Executive communications accessed. Three tenants affected.",
        ),
        (
            "Lazarus Group — Crypto Exchange Drain",
            "P1", "INVESTIGATING", "Nia Thompson",
            "INC-2026-039", "CAMP-LAZARUS-2026",
            "Lazarus TraderTraitor malware in developer npm package led to $14.2M cryptocurrency "
            "drain from exchange hot wallet. Smart contract exploit used. Ethereum blockchain "
            "trace to DPRK-linked mixer identified.",
        ),
        (
            "Cl0p — MFT Zero-Day SQL Injection",
            "P1", "RESOLVED", "Carlos Mendez",
            "INC-2026-033", "CAMP-CLOP-2026",
            "Cl0p exploited CVE-2024-5806 (MOVEit-style SQLi) in managed file transfer platform. "
            "152 GB of patient records exfiltrated to MEGA.nz. Cl0p leak site publication "
            "confirmed. HIPAA breach notification required for 48,000 records.",
        ),
        (
            "Akira — Cisco VPN Initial Access + Lateral Movement",
            "P2", "INVESTIGATING", "Marcus Webb",
            "INC-2026-003", "CAMP-AKIRA-2026",
            "Akira ransomware gang gained access via Cisco SSL VPN credential abuse. "
            "Deployed Cobalt Strike, conducted Kerberoasting, and moved laterally to backup "
            "infrastructure. Ransomware staged but not yet detonated — containment active.",
        ),
        (
            "APT28 — Spear-Phishing NATO Officials",
            "P2", "INVESTIGATING", "Priya Nair",
            "INC-2026-014", "CAMP-FANCY-BEAR-2026",
            "APT28 spear-phishing campaign targeting defence contractor senior staff with "
            "malicious DOCM exploiting CVE-2022-30190. Brute Ratel C4 implant installed. "
            "Classified document repository access detected.",
        ),
        (
            "Volt Typhoon — Critical Infrastructure Pre-Positioning",
            "P2", "INVESTIGATING", "Ryan O'Brien",
            "INC-2026-028", "CAMP-VOLT-TYPHOON-2026",
            "Volt Typhoon LOTL activity detected in utilities OT network. Netsh port-forwarding "
            "tunnels established, wmic.exe used for lateral reconnaisance. No malware deployed — "
            "purely living-off-the-land. Dwell time estimated at 4+ months.",
        ),
        (
            "Rhysida — University Data Double-Extortion",
            "P2", "CONTAINED", "Aisha Patel",
            "INC-2026-005", "CAMP-RHYSIDA-2026",
            "Rhysida ransomware deployed across university research systems. 890 GB of student "
            "records and research data staged via WinSCP for exfiltration. Ransom demand "
            "of £3.2M. Backup restoration underway. Ransom not paid.",
        ),
        (
            "QakBot Revival — Law Firm Infection Chain",
            "P3", "RESOLVED", "Tom Brandt",
            "INC-2026-018", "CAMP-QAKBOT-2026",
            "QakBot delivered via OneNote attachment in thread-hijacking email. Wermgr.exe "
            "process hollowing detected. Cobalt Strike beacon established. No ransomware "
            "deployed — contained at C2 stage. 6 endpoints remediated.",
        ),
        (
            "Citrix Bleed CVE-2023-4966 — Session Hijack",
            "P2", "RESOLVED", "Carlos Mendez",
            "INC-2026-046", "CAMP-CITRIX-BLEED-2026",
            "Citrix ADC appliance exploited via CVE-2023-4966. Session tokens for 19 active "
            "admin sessions hijacked without authentication. Attacker pivoted to internal "
            "VPN resources before detection. Patch applied, sessions revoked.",
        ),
        (
            "Cobalt Strike Beacon — Pass-the-Hash Lateral Movement",
            "P2", "CONTAINED", "Marcus Webb",
            "INC-2026-041", "CAMP-LOCKBIT4-2026",
            "Mimikatz executed from memory to harvest NTLM hashes. Pass-the-hash used to "
            "authenticate to domain controller. LockBit pre-ransomware recon activity "
            "suspected. Active Directory backup taken as precaution.",
        ),
        (
            "Storm-0558 — Exchange Online Token Forgery",
            "P1", "INVESTIGATING", "Ryan O'Brien",
            "INC-2026-024", "CAMP-STORM0558-2026",
            "Storm-0558 forged MSA authentication token to access Exchange Online OWA. "
            "Senior official email inboxes accessed for 8 weeks. Microsoft investigation "
            "ongoing. M365 unified audit logs confirmed access pattern.",
        ),
        (
            "npm Supply Chain — Lazarus Backdoored Package",
            "P2", "RESOLVED", "Nia Thompson",
            "INC-2026-048", "CAMP-LAZARUS-2026",
            "Malicious npm package 'axios-http-client@3.1.7' published by Lazarus Group "
            "containing postInstall exfiltration backdoor. Package downloaded 8,400 times "
            "before removal. Internal CI/CD pipelines scanned — 3 affected repositories identified.",
        ),
    ]
    store = _load()
    for i, (title, priority, status, analyst, inc_id, campaign_id, desc) in enumerate(samples, 1):
        case_ts     = _ts_for_inc(inc_id)
        assign_ts   = _ts_for_inc(inc_id, offset_hours=1)
        status_ts   = _ts_for_inc(inc_id, offset_hours=2)
        note1_ts    = _ts_for_inc(inc_id, offset_hours=3)
        note2_ts    = _ts_for_inc(inc_id, offset_hours=6)
        res_hours   = _RES_HOURS.get(priority, 72)
        resolved_ts = _ts_for_inc(inc_id, offset_hours=res_hours) if status in ("RESOLVED", "CLOSED") else None

        year = datetime(2026, 5, 18, tzinfo=timezone.utc).strftime("%Y")
        case: dict = {
            "id": str(uuid.uuid4()),
            "case_number": f"CASE-{year}-{i:04d}",
            "incident_id": inc_id,
            "campaign_id": campaign_id,
            "threat_name": title,
            "title": title,
            "description": desc,
            "status": status,
            "priority": priority,
            "assigned_analyst": analyst,
            "notes": [
                {
                    "author": analyst,
                    "content": "Initial triage complete. Evidence collection in progress.",
                    "timestamp": note1_ts,
                },
                {
                    "author": analyst,
                    "content": "Containment actions initiated. Affected systems isolated.",
                    "timestamp": note2_ts,
                },
            ],
            "history": [
                {
                    "action": "CREATED",
                    "content": f"Case auto-created for incident {inc_id}",
                    "user": "System",
                    "timestamp": case_ts,
                },
                {
                    "action": "ASSIGNMENT",
                    "content": f"Assigned to {analyst}",
                    "old_value": "",
                    "new_value": analyst,
                    "user": "SOC Lead",
                    "timestamp": assign_ts,
                },
                {
                    "action": "STATUS_CHANGE",
                    "content": f"Status: OPEN → {status}",
                    "old_value": "OPEN",
                    "new_value": status,
                    "user": analyst,
                    "timestamp": status_ts,
                },
            ],
            "created_at": case_ts,
            "updated_at": resolved_ts or status_ts,
        }
        if resolved_ts:
            case["resolved_at"] = resolved_ts
        store["cases"].append(case)
    _save(store)
