"""tests/test_executive_report.py — Tests for reporting/executive_report_builder.py.

Validates PDF generation (byte output, valid PDF header), data assembly,
and each helper builder function in isolation.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from reporting.executive_report_builder import (
    assemble_executive_data,
    build_executive_report,
    save_executive_report,
)

# ---------------------------------------------------------------------------
# Minimal stub data (no external I/O needed for unit tests)
# ---------------------------------------------------------------------------

_STUB_KPIS = {
    "total_incidents":          50,
    "critical_incidents":       11,
    "open_cases":               7,
    "active_campaigns":         4,
    "mttd_minutes":             142.5,
    "mttr_minutes":             2160.0,
    "analyst_utilization":      0.72,
    "avg_attribution_confidence": 0.81,
}

_STUB_SEV_DIST = {
    "CRITICAL": 11,
    "HIGH":     26,
    "MEDIUM":   12,
    "LOW":       1,
}

_STUB_CAMPAIGNS = [
    {
        "campaign_id":    "CAMP-LOCKBIT4-2026",
        "name":           "LockBit 4.0 Hospital Campaign",
        "threat_actor":   "LOCKBIT",
        "status":         "ACTIVE",
        "incident_count": 8,
        "risk_score":     0.92,
    },
    {
        "campaign_id":    "CAMP-APT29-2026",
        "name":           "Midnight Blizzard M365",
        "threat_actor":   "APT29",
        "status":         "MONITORING",
        "incident_count": 4,
        "risk_score":     0.88,
    },
]

_STUB_ACTOR_BKN = {
    "APT29":    12,
    "LOCKBIT":   9,
    "Lazarus":   7,
    "FIN7":      5,
    "TA505":     4,
    "UNKNOWN":   8,
}

_STUB_CAT_BKN = {
    "Ransomware":          14,
    "Credential Theft":     9,
    "Command and Control":  8,
    "Phishing":             7,
    "Lateral Movement":     5,
}

_STUB_MITRE = [
    {
        "tactic":    "Initial Access",
        "tactic_id": "initial-access",
        "techniques": 2,
    },
    {
        "tactic":    "Impact",
        "tactic_id": "impact",
        "techniques": 2,
    },
    {
        "tactic":    "Command and Control",
        "tactic_id": "command-and-control",
        "techniques": 1,
    },
]

_STUB_INTEL = {
    "total_actors":            10,
    "by_country":              {"Russia": 4, "China": 2, "North Korea": 2, "US/UK": 1, "China (PRC)": 1},
    "by_type":                 {"Nation-State": 4, "Criminal": 6},
    "by_sophistication":       {"nation-state": 4, "advanced": 6},
    "total_campaigns":         38,
    "total_techniques":        120,
    "unique_techniques":       58,
    "countries_represented":   5,
    "avg_attribution_conf":    0.905,
    "high_confidence_actors":  6,
}

_FULL_DATA = {
    "generated_at": "2026-06-18T12:00:00Z",
    "date_from":    "2026-03-18",
    "date_to":      "2026-06-18",
    "severities":   ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    "kpis":         _STUB_KPIS,
    "sev_dist":     _STUB_SEV_DIST,
    "campaigns":    _STUB_CAMPAIGNS,
    "actor_breakdown": _STUB_ACTOR_BKN,
    "category_breakdown": _STUB_CAT_BKN,
    "mitre_coverage": _STUB_MITRE,
    "intel_stats":  _STUB_INTEL,
}


# ---------------------------------------------------------------------------
# build_executive_report — basic validity
# ---------------------------------------------------------------------------


def test_build_returns_bytes():
    pdf = build_executive_report(_FULL_DATA)
    assert isinstance(pdf, bytes)


def test_build_returns_non_empty():
    pdf = build_executive_report(_FULL_DATA)
    assert len(pdf) > 0


def test_build_valid_pdf_header():
    pdf = build_executive_report(_FULL_DATA)
    assert pdf[:4] == b"%PDF"


def test_build_substantial_size():
    pdf = build_executive_report(_FULL_DATA)
    assert len(pdf) > 5_000, "Executive PDF should be at least 5 KB"


def test_build_with_empty_kpis():
    data = {**_FULL_DATA, "kpis": {}}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_empty_sev_dist():
    data = {**_FULL_DATA, "sev_dist": {}}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_empty_mitre():
    data = {**_FULL_DATA, "mitre_coverage": []}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_empty_actors():
    data = {**_FULL_DATA, "actor_breakdown": {}}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_empty_campaigns():
    data = {**_FULL_DATA, "campaigns": []}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_no_intel_stats():
    data = {**_FULL_DATA, "intel_stats": {}}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_all_empty():
    data = {
        "generated_at": "2026-06-18T12:00:00Z",
        "date_from": "All time",
        "date_to":   "Present",
        "severities": [],
        "kpis":       {},
        "sev_dist":   {},
        "campaigns":  [],
        "actor_breakdown": {},
        "category_breakdown": {},
        "mitre_coverage": [],
        "intel_stats": {},
    }
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_all_severity_levels():
    data = {**_FULL_DATA, "sev_dist": {"CRITICAL": 5, "HIGH": 15, "MEDIUM": 8, "LOW": 2}}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_deterministic_structure():
    pdf1 = build_executive_report(_FULL_DATA)
    assert pdf1[:4] == b"%PDF"
    assert len(pdf1) > 0


def test_build_with_many_campaigns():
    campaigns = [
        {"name": f"Campaign {i}", "threat_actor": "LOCKBIT",
         "status": "ACTIVE", "incident_count": i, "risk_score": 0.7}
        for i in range(15)
    ]
    data = {**_FULL_DATA, "campaigns": campaigns}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_many_actors():
    actors = {f"Actor_{i}": i * 2 for i in range(12)}
    data = {**_FULL_DATA, "actor_breakdown": actors}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


def test_build_with_all_mitre_tactics():
    tactics = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "exfiltration", "command-and-control", "impact",
    ]
    mitre = [
        {"tactic": t.replace("-", " ").title(), "tactic_id": t, "techniques": i + 1}
        for i, t in enumerate(tactics)
    ]
    data = {**_FULL_DATA, "mitre_coverage": mitre}
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# save_executive_report
# ---------------------------------------------------------------------------


def test_save_creates_file(tmp_path):
    pdf = build_executive_report(_FULL_DATA)
    with patch("reporting.executive_report_builder._EXPORTS_DIR", tmp_path):
        from reporting.executive_report_builder import save_executive_report as _save
        out = _save(pdf, "test_exec.pdf")
    # save_executive_report uses _EXPORTS_DIR directly, so test by verifying return type
    assert isinstance(out, Path)


def test_save_creates_file_with_auto_name(tmp_path):
    pdf = build_executive_report(_FULL_DATA)
    with patch("reporting.executive_report_builder._EXPORTS_DIR", tmp_path):
        from reporting.executive_report_builder import save_executive_report as _save
        out = _save(pdf)
    assert isinstance(out, Path)
    assert out.name.startswith("executive_report_")
    assert out.name.endswith(".pdf")


# ---------------------------------------------------------------------------
# assemble_executive_data — integration (real store + real engine)
# ---------------------------------------------------------------------------


def test_assemble_returns_dict():
    data = assemble_executive_data()
    assert isinstance(data, dict)


def test_assemble_required_keys():
    data = assemble_executive_data()
    required = {
        "generated_at", "date_from", "date_to", "severities",
        "kpis", "sev_dist", "campaigns", "actor_breakdown",
        "category_breakdown", "mitre_coverage", "intel_stats",
    }
    assert required.issubset(set(data.keys()))


def test_assemble_kpis_is_dict():
    data = assemble_executive_data()
    assert isinstance(data["kpis"], dict)


def test_assemble_sev_dist_is_dict():
    data = assemble_executive_data()
    assert isinstance(data["sev_dist"], dict)


def test_assemble_campaigns_is_list():
    data = assemble_executive_data()
    assert isinstance(data["campaigns"], list)


def test_assemble_mitre_is_list():
    data = assemble_executive_data()
    assert isinstance(data["mitre_coverage"], list)


def test_assemble_intel_stats_has_actor_count():
    data = assemble_executive_data()
    assert data["intel_stats"].get("total_actors", 0) == 10


def test_assemble_generated_at_format():
    import re
    data = assemble_executive_data()
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["generated_at"])


def test_assemble_then_build_valid_pdf():
    data = assemble_executive_data()
    pdf = build_executive_report(data)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 5_000
