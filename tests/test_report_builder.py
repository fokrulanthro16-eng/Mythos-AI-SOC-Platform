"""tests/test_report_builder.py — Unit tests for the Mythos SOC PDF report generator.

Tests are split into:
  - Pure-logic tests (get_recommendations, assemble_report_data)
  - PDF generation smoke tests (build_incident_report)
  - Section-level edge-case tests (empty data, None values, malformed input)

Requires: pip install reportlab
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from reporting.report_builder import (
    _CATEGORY_MAP,
    _DEFAULT_RECS,
    _RECS,
    assemble_report_data,
    build_incident_report,
    get_recommendations,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_data(**overrides) -> dict:
    """Return the smallest valid report data dict."""
    base = {
        "incident_id": "INC-2026-001",
        "threat_name": "LOCKBIT4-RANSOMWARE",
        "severity": "CRITICAL",
        "status": "INVESTIGATING",
        "campaign_id": "CAMP-LOCKBIT4-2026",
        "created_at": "2026-05-18T02:14:33",
        "generated_at": "2026-06-17T10:00:00",
        "generated_by": "Sarah Kim",
        "classification": "CONFIDENTIAL",
    }
    base.update(overrides)
    return base


def _full_data() -> dict:
    return {
        "incident_id": "INC-2026-001",
        "threat_name": "LOCKBIT4-RANSOMWARE",
        "severity": "CRITICAL",
        "status": "INVESTIGATING",
        "campaign_id": "CAMP-LOCKBIT4-2026",
        "created_at": "2026-05-18T02:14:33",
        "confidence_score": 0.91,
        "risk_score": 0.87,
        "attribution_confidence": 0.88,
        "suspected_actor": "LOCKBIT4",
        "description": "LockBit 4.0 ransomware detected across 47 hospital endpoints.",
        "indicators": [
            "hash:a3f8e2b1c94d7f60",
            "domain:cdn-update-check.systems",
            "ip:91.234.99.107",
        ],
        "attack_techniques": [
            {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "impact",
                "tactic_id": "impact",
                "url": "https://attack.mitre.org/techniques/T1486",
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "execution",
                "tactic_id": "execution",
                "url": "https://attack.mitre.org/techniques/T1059",
            },
        ],
        "threat_actor_profile": {
            "aliases": ["LockBit", "ABCD"],
            "origin": "Russia",
            "motivation": "Financial",
            "target_sectors": ["Healthcare", "Finance"],
            "ttps": ["T1486", "T1059", "T1027"],
            "tools": ["LockBit 4.0", "Cobalt Strike"],
        },
        "notes": [
            {
                "author": "Sarah Kim",
                "content": "Initial triage complete. 47 endpoints encrypted.",
                "timestamp": "2026-05-18T04:00:00",
            },
            {
                "author": "Marcus Webb",
                "content": "C2 domain blocked at perimeter.",
                "timestamp": "2026-05-18T06:00:00",
            },
        ],
        "case": {
            "case_number": "CASE-2026-0001",
            "status": "INVESTIGATING",
            "priority": "P1",
            "assigned_analyst": "Sarah Kim",
            "description": "LockBit 4.0 hospital network encryption.",
            "created_at": "2026-05-18T03:00:00",
            "updated_at": "2026-05-18T06:00:00",
            "resolved_at": None,
            "notes": [],
            "history": [
                {
                    "action": "CREATED",
                    "content": "Case auto-created for incident INC-2026-001",
                    "user": "System",
                    "timestamp": "2026-05-18T03:00:00",
                },
                {
                    "action": "ASSIGNMENT",
                    "content": "Assigned to Sarah Kim",
                    "user": "SOC Lead",
                    "timestamp": "2026-05-18T03:15:00",
                },
            ],
        },
        "timeline": [
            {"timestamp": "2026-05-18T02:14:33", "event": "Incident detected", "actor": "System"},
            {"timestamp": "2026-05-18T04:00:00", "event": "Triage started", "actor": "Sarah Kim"},
        ],
        "generated_at": "2026-06-17T10:00:00",
        "generated_by": "Sarah Kim",
        "classification": "CONFIDENTIAL",
    }


# ---------------------------------------------------------------------------
# get_recommendations
# ---------------------------------------------------------------------------


def test_get_recommendations_by_category_name():
    recs = get_recommendations("Ransomware")
    assert isinstance(recs, list)
    assert len(recs) > 0
    assert all(isinstance(r, str) for r in recs)


def test_get_recommendations_by_threat_name():
    recs = get_recommendations("LOCKBIT4-RANSOMWARE")
    assert recs == get_recommendations("Ransomware")


def test_get_recommendations_all_8_categories():
    categories = [
        "Ransomware", "Phishing", "Credential Theft", "Data Exfiltration",
        "Command & Control", "Insider Threat", "Malware Delivery", "Lateral Movement",
    ]
    for cat in categories:
        recs = get_recommendations(cat)
        assert len(recs) >= 4, f"{cat} has fewer than 4 recommendations"


def test_get_recommendations_unknown_returns_defaults():
    recs = get_recommendations("SOME-UNKNOWN-THREAT-XYZ")
    assert recs == _DEFAULT_RECS


def test_get_recommendations_empty_string_returns_defaults():
    assert get_recommendations("") == _DEFAULT_RECS


def test_get_recommendations_attack_techniques_enrich():
    base = get_recommendations("Ransomware")
    techs = [{"tactic_id": "persistence"}]
    enriched = get_recommendations("Ransomware", attack_techniques=techs)
    assert len(enriched) >= len(base)


def test_get_recommendations_no_duplicate_from_attack():
    techs = [{"tactic_id": "impact"}]
    recs = get_recommendations("Ransomware", attack_techniques=techs)
    assert len(recs) == len(set(recs)), "Duplicate recommendations should not occur"


def test_get_recommendations_returns_new_list():
    r1 = get_recommendations("Phishing")
    r2 = get_recommendations("Phishing")
    r1.append("extra item")
    assert "extra item" not in r2, "get_recommendations should return independent lists"


def test_get_recommendations_credential_theft_by_threat_name():
    recs = get_recommendations("MIDNIGHT-BLIZZARD-OAUTH")
    assert recs == get_recommendations("Credential Theft")


def test_get_recommendations_lateral_movement_by_threat_name():
    recs = get_recommendations("MIMIKATZ-PASS-THE-HASH")
    assert recs == get_recommendations("Lateral Movement")


# ---------------------------------------------------------------------------
# assemble_report_data
# ---------------------------------------------------------------------------


def test_assemble_required_keys():
    data = assemble_report_data("INC-2026-001")
    required = {
        "incident_id", "threat_name", "severity", "status", "campaign_id",
        "created_at", "confidence_score", "risk_score", "attribution_confidence",
        "suspected_actor", "indicators", "attack_techniques", "threat_actor_profile",
        "description", "notes", "case", "timeline", "generated_at",
        "generated_by", "classification",
    }
    assert required.issubset(data.keys())


def test_assemble_incident_id_preserved():
    data = assemble_report_data("INC-2026-TEST")
    assert data["incident_id"] == "INC-2026-TEST"


def test_assemble_generated_by_passed_through():
    data = assemble_report_data("INC-X", generated_by="Alice Chen")
    assert data["generated_by"] == "Alice Chen"


def test_assemble_classification_passed_through():
    data = assemble_report_data("INC-X", classification="RESTRICTED")
    assert data["classification"] == "RESTRICTED"


def test_assemble_from_incident_record():
    inc = {
        "incident_id": "INC-2026-001",
        "threat_name": "LOCKBIT4-RANSOMWARE",
        "severity": "CRITICAL",
        "status": "INVESTIGATING",
        "campaign_id": "CAMP-X",
        "created_at": "2026-05-18T02:00:00",
        "indicators": ["hash:abc123", "domain:evil.example"],
        "confidence_score": 0.91,
    }
    data = assemble_report_data("INC-2026-001", incident_record=inc)
    assert data["threat_name"]  == "LOCKBIT4-RANSOMWARE"
    assert data["severity"]     == "CRITICAL"
    assert data["indicators"]   == ["hash:abc123", "domain:evil.example"]
    assert data["confidence_score"] == pytest.approx(0.91)


def test_assemble_notes_merged_from_case_and_assignment():
    case = {"notes": [{"author": "Alice", "content": "Case note", "timestamp": "T1"}]}
    asgn = {"notes": [{"author": "Bob",   "content": "WB note",   "timestamp": "T2"}]}
    data = assemble_report_data("INC-X", case_record=case, assignment_record=asgn)
    authors = {n["author"] for n in data["notes"]}
    assert "Alice" in authors
    assert "Bob"   in authors


def test_assemble_timeline_includes_created_at():
    inc = {"created_at": "2026-05-20T00:00:00", "threat_name": "TEST"}
    data = assemble_report_data("INC-Y", incident_record=inc)
    assert len(data["timeline"]) >= 1
    assert any("INC-Y" in ev["event"] for ev in data["timeline"])


def test_assemble_timeline_sorted():
    case = {
        "history": [
            {"timestamp": "2026-05-20T10:00:00", "content": "Later event",   "user": "Bob"},
            {"timestamp": "2026-05-20T08:00:00", "content": "Earlier event", "user": "Alice"},
        ]
    }
    data = assemble_report_data("INC-Z", case_record=case)
    ts   = [ev["timestamp"] for ev in data["timeline"] if ev["timestamp"]]
    assert ts == sorted(ts)


def test_assemble_indicators_non_list_becomes_empty():
    inc = {"indicators": "not-a-list"}
    data = assemble_report_data("INC-X", incident_record=inc)
    assert data["indicators"] == []


def test_assemble_attack_techniques_non_list_becomes_empty():
    inc = {"attack_techniques": 42}
    data = assemble_report_data("INC-X", incident_record=inc)
    assert data["attack_techniques"] == []


def test_assemble_confidence_defaults_to_zero():
    data = assemble_report_data("INC-X")
    assert data["confidence_score"] == 0.0
    assert data["risk_score"]       == 0.0


# ---------------------------------------------------------------------------
# build_incident_report — smoke tests
# ---------------------------------------------------------------------------


def test_build_returns_bytes():
    pdf = build_incident_report({})
    assert isinstance(pdf, bytes)


def test_build_starts_with_pdf_header():
    pdf = build_incident_report({})
    assert pdf[:4] == b"%PDF"


def test_build_minimal_data_no_crash():
    pdf = build_incident_report(_minimal_data())
    assert len(pdf) > 1000


def test_build_full_data_no_crash():
    pdf = build_incident_report(_full_data())
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 5000


def test_build_empty_dict_produces_pdf():
    pdf = build_incident_report({})
    assert pdf[:4] == b"%PDF"


def test_build_all_severities():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        pdf = build_incident_report(_minimal_data(severity=sev))
        assert pdf[:4] == b"%PDF"


def test_build_with_attack_techniques():
    data = _minimal_data(attack_techniques=[
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact",
         "tactic": "impact", "tactic_id": "impact", "url": "https://attack.mitre.org/T1486"},
    ])
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_empty_attack_techniques():
    pdf = build_incident_report(_minimal_data(attack_techniques=[]))
    assert pdf[:4] == b"%PDF"


def test_build_with_indicators():
    data = _minimal_data(indicators=["hash:deadbeef", "domain:evil.example", "ip:1.2.3.4"])
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_notes():
    data = _minimal_data(notes=[
        {"author": "Alice", "content": "Initial triage complete.", "timestamp": "2026-05-18T04:00:00"},
    ])
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_none_notes():
    data = _minimal_data(notes=None)
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_case_record():
    data = _minimal_data(case={
        "case_number": "CASE-2026-0001",
        "status": "INVESTIGATING",
        "priority": "P1",
        "assigned_analyst": "Sarah Kim",
        "created_at": "2026-05-18T03:00:00",
        "updated_at": "2026-05-18T06:00:00",
        "history": [
            {"action": "CREATED", "content": "Case opened", "user": "System", "timestamp": "2026-05-18T03:00:00"},
        ],
        "notes": [],
    })
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_no_case():
    pdf = build_incident_report(_minimal_data(case=None))
    assert pdf[:4] == b"%PDF"


def test_build_with_threat_actor_profile():
    data = _minimal_data(threat_actor_profile={
        "aliases": ["LockBit", "ABCD"],
        "origin": "Russia",
        "motivation": "Financial",
        "target_sectors": ["Healthcare"],
        "ttps": ["T1486", "T1059"],
        "tools": ["LockBit 4.0"],
    })
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_timeline():
    data = _minimal_data(timeline=[
        {"timestamp": "2026-05-18T02:14:33", "event": "Incident detected", "actor": "System"},
        {"timestamp": "2026-05-18T04:00:00", "event": "Triage started", "actor": "Sarah Kim"},
    ])
    pdf = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_classification_confidential():
    pdf = build_incident_report(_minimal_data(classification="CONFIDENTIAL"))
    assert pdf[:4] == b"%PDF"


def test_build_classification_restricted():
    pdf = build_incident_report(_minimal_data(classification="RESTRICTED"))
    assert pdf[:4] == b"%PDF"


def test_build_pdf_size_reasonable():
    """Full report should be at least 5 KB and less than 2 MB."""
    pdf = build_incident_report(_full_data())
    assert 5_000 < len(pdf) < 2_000_000


def test_assemble_then_build_round_trip():
    """assemble_report_data output must be accepted by build_incident_report."""
    inc = {
        "incident_id": "INC-2026-001",
        "threat_name": "CLOP-MOVEIT-STYLE-SQLI",
        "severity": "CRITICAL",
        "status": "RESOLVED",
        "campaign_id": "CAMP-CLOP-2026",
        "created_at": "2026-06-01T10:00:00",
        "confidence_score": 0.96,
        "risk_score": 0.94,
        "indicators": ["domain:cl0p-exfil.onion.ws", "ip:45.155.37.42"],
        "attack_techniques": [
            {"technique_id": "T1041", "technique_name": "Exfiltration over C2", "tactic": "exfiltration", "tactic_id": "exfiltration", "url": ""},
        ],
    }
    data = assemble_report_data("INC-2026-001", incident_record=inc, generated_by="Carlos Mendez")
    pdf  = build_incident_report(data)
    assert pdf[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# Category map completeness
# ---------------------------------------------------------------------------


def test_category_map_covers_all_8_categories():
    covered = set(_CATEGORY_MAP.values())
    required = {
        "Ransomware", "Phishing", "Credential Theft", "Data Exfiltration",
        "Command & Control", "Insider Threat", "Malware Delivery", "Lateral Movement",
    }
    assert required == covered


def test_all_categories_have_recommendations():
    for cat in _RECS:
        assert len(_RECS[cat]) >= 4, f"{cat} needs at least 4 recommendations"
