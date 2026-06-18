"""tests/test_executive_store.py — Unit tests for the Executive KPI store.

Covers all pure compute functions and the file-backed aggregation helpers.
Pure (_compute_*) functions are tested without any file I/O.
File-backed (get_*) functions are tested by patching the relevant store paths.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import dashboard.executive_store as es

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _inc(*, threat="LOCKBIT4-RANSOMWARE", severity="CRITICAL",
         campaign="CAMP-A", created_at=None, inc_id="INC-2026-001"):
    ts = created_at or _iso(datetime(2026, 6, 1, tzinfo=timezone.utc))
    return {
        "incident_id": inc_id,
        "threat_name": threat,
        "severity": severity,
        "campaign_id": campaign,
        "created_at": ts,
    }


def _case(*, status="OPEN", priority="P2",
          created_at=None, resolved_at=None):
    now = datetime(2026, 5, 20, tzinfo=timezone.utc)
    return {
        "status": status,
        "priority": priority,
        "created_at": created_at or _iso(now),
        "resolved_at": resolved_at,
    }


def _run(*, confidence=0.75):
    return {
        "run_id": "r1",
        "agents": [
            {"agent_name": "PlannerAgent",      "confidence": 0.5},
            {"agent_name": "AttributionAgent",  "confidence": confidence},
            {"agent_name": "ComplianceAgent",   "confidence": 0.6},
        ],
        "duration_ms": 400.0,
        "severity": "HIGH",
    }


# ---------------------------------------------------------------------------
# compute_mttr
# ---------------------------------------------------------------------------


def test_compute_mttr_empty():
    assert es.compute_mttr([]) == 0.0


def test_compute_mttr_no_resolved():
    cases = [_case(status="OPEN"), _case(status="INVESTIGATING")]
    assert es.compute_mttr(cases) == 0.0


def test_compute_mttr_single_resolved():
    created    = datetime(2026, 5, 20, 0, 0, tzinfo=timezone.utc)
    resolved   = created + timedelta(hours=24)
    case       = _case(status="RESOLVED", created_at=_iso(created), resolved_at=_iso(resolved))
    result     = es.compute_mttr([case])
    assert result == 24.0


def test_compute_mttr_multiple_resolved():
    c1 = _case(
        status="RESOLVED",
        created_at=_iso(datetime(2026, 5, 20, 0, 0, tzinfo=timezone.utc)),
        resolved_at=_iso(datetime(2026, 5, 20, 0, 0, tzinfo=timezone.utc) + timedelta(hours=10)),
    )
    c2 = _case(
        status="CLOSED",
        created_at=_iso(datetime(2026, 5, 21, 0, 0, tzinfo=timezone.utc)),
        resolved_at=_iso(datetime(2026, 5, 21, 0, 0, tzinfo=timezone.utc) + timedelta(hours=30)),
    )
    result = es.compute_mttr([c1, c2])
    assert result == 20.0  # (10 + 30) / 2


def test_compute_mttr_skips_negative_delta():
    # resolved_at before created_at → should be skipped
    created  = datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc)
    resolved = created - timedelta(hours=5)
    case     = _case(status="RESOLVED", created_at=_iso(created), resolved_at=_iso(resolved))
    assert es.compute_mttr([case]) == 0.0


def test_compute_mttr_mixed_open_and_resolved():
    created  = datetime(2026, 5, 20, tzinfo=timezone.utc)
    resolved = created + timedelta(hours=48)
    cases    = [
        _case(status="OPEN"),
        _case(status="RESOLVED", created_at=_iso(created), resolved_at=_iso(resolved)),
    ]
    assert es.compute_mttr(cases) == 48.0


# ---------------------------------------------------------------------------
# compute_mttd
# ---------------------------------------------------------------------------


def test_compute_mttd_empty():
    assert es.compute_mttd([]) == 0.0


def test_compute_mttd_critical_lower_than_low():
    crit = es.compute_mttd([_inc(severity="CRITICAL", inc_id="INC-2026-001")])
    low  = es.compute_mttd([_inc(severity="LOW",      inc_id="INC-2026-001")])
    assert crit < low


def test_compute_mttd_all_severities_positive():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        result = es.compute_mttd([_inc(severity=sev, inc_id="INC-2026-001")])
        assert result > 0.0


def test_compute_mttd_multiple_returns_float():
    incs = [_inc(severity="CRITICAL"), _inc(severity="HIGH"), _inc(severity="MEDIUM")]
    result = es.compute_mttd(incs)
    assert isinstance(result, float)
    assert result > 0.0


# ---------------------------------------------------------------------------
# compute_analyst_utilization
# ---------------------------------------------------------------------------


def test_compute_analyst_utilization_empty():
    assert es.compute_analyst_utilization([]) == 0.0


def test_compute_analyst_utilization_all_active():
    # 10 analysts × 5 capacity = 50; 50 active = 100 %
    assignments = [{"status": "OPEN"}] * 50
    assert es.compute_analyst_utilization(assignments, analyst_count=10) == 100.0


def test_compute_analyst_utilization_half():
    # 25 active out of 50 capacity = 50 %
    assignments = [{"status": "OPEN"}] * 25 + [{"status": "RESOLVED"}] * 25
    result = es.compute_analyst_utilization(assignments, analyst_count=10)
    assert result == 50.0


def test_compute_analyst_utilization_capped_at_100():
    # 60 active against capacity of 50 → capped at 100 %
    assignments = [{"status": "OPEN"}] * 60
    assert es.compute_analyst_utilization(assignments, analyst_count=10) == 100.0


def test_compute_analyst_utilization_resolved_not_counted():
    assignments = [{"status": "RESOLVED"}, {"status": "CLOSED"}]
    assert es.compute_analyst_utilization(assignments, analyst_count=10) == 0.0


# ---------------------------------------------------------------------------
# compute_attribution_confidence
# ---------------------------------------------------------------------------


def test_compute_attribution_confidence_empty():
    assert es.compute_attribution_confidence([]) == 0.0


def test_compute_attribution_confidence_single_run():
    result = es.compute_attribution_confidence([_run(confidence=0.80)])
    assert result == pytest.approx(80.0, abs=0.05)


def test_compute_attribution_confidence_multiple_runs():
    runs   = [_run(confidence=0.60), _run(confidence=0.80)]
    result = es.compute_attribution_confidence(runs)
    assert result == pytest.approx(70.0, abs=0.05)


def test_compute_attribution_confidence_uses_only_attribution_agent():
    run = {
        "agents": [
            {"agent_name": "PlannerAgent",     "confidence": 0.99},
            {"agent_name": "AttributionAgent", "confidence": 0.50},
        ]
    }
    result = es.compute_attribution_confidence([run])
    assert result == pytest.approx(50.0, abs=0.05)


def test_compute_attribution_confidence_no_attribution_agent():
    run = {"agents": [{"agent_name": "PlannerAgent", "confidence": 0.99}]}
    assert es.compute_attribution_confidence([run]) == 0.0


# ---------------------------------------------------------------------------
# incidents_last_n_days
# ---------------------------------------------------------------------------


def test_incidents_last_n_days_empty():
    assert es.incidents_last_n_days([], 7) == 0


def test_incidents_last_n_days_in_range():
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    inc       = _inc(created_at=_iso(yesterday))
    assert es.incidents_last_n_days([inc], 7) == 1


def test_incidents_last_n_days_out_of_range():
    old = datetime.now(timezone.utc) - timedelta(days=10)
    inc = _inc(created_at=_iso(old))
    assert es.incidents_last_n_days([inc], 7) == 0


def test_incidents_last_n_days_boundary():
    exactly_7_days_ago = datetime.now(timezone.utc) - timedelta(days=7, seconds=1)
    inc = _inc(created_at=_iso(exactly_7_days_ago))
    assert es.incidents_last_n_days([inc], 7) == 0


def test_incidents_last_n_days_mixed():
    recent = datetime.now(timezone.utc) - timedelta(days=2)
    old    = datetime.now(timezone.utc) - timedelta(days=20)
    incs   = [_inc(created_at=_iso(recent)), _inc(created_at=_iso(old))]
    assert es.incidents_last_n_days(incs, 7) == 1


# ---------------------------------------------------------------------------
# _compute_executive_kpis
# ---------------------------------------------------------------------------


def test_compute_executive_kpis_all_zeros():
    kpis = es._compute_executive_kpis([], [], [], [])
    assert kpis["open_cases"]          == 0
    assert kpis["critical_incidents"]  == 0
    assert kpis["active_campaigns"]    == 0
    assert kpis["analyst_utilization_pct"] == 0.0
    assert kpis["attribution_confidence"]  == 0.0
    assert kpis["incidents_last_7_days"]   == 0


def test_compute_executive_kpis_required_keys():
    kpis = es._compute_executive_kpis([], [], [], [])
    required = {
        "open_cases", "critical_incidents", "mttr_hours", "mttd_hours",
        "active_campaigns", "analyst_utilization_pct",
        "attribution_confidence", "incidents_last_7_days",
    }
    assert required.issubset(kpis.keys())


def test_compute_executive_kpis_open_cases_count():
    cases = [_case(status="OPEN"), _case(status="RESOLVED"), _case(status="INVESTIGATING")]
    kpis  = es._compute_executive_kpis([], cases, [], [])
    assert kpis["open_cases"] == 2  # OPEN + INVESTIGATING


def test_compute_executive_kpis_critical_incidents():
    incs = [
        _inc(severity="CRITICAL"),
        _inc(severity="HIGH"),
        _inc(severity="CRITICAL"),
        _inc(severity="LOW"),
    ]
    kpis = es._compute_executive_kpis(incs, [], [], [])
    assert kpis["critical_incidents"] == 2


def test_compute_executive_kpis_active_campaigns():
    incs = [
        _inc(campaign="CAMP-A"),
        _inc(campaign="CAMP-B"),
        _inc(campaign="CAMP-A"),  # duplicate
        _inc(campaign=""),        # blank ignored
    ]
    kpis = es._compute_executive_kpis(incs, [], [], [])
    assert kpis["active_campaigns"] == 2


# ---------------------------------------------------------------------------
# _compute_incident_trend
# ---------------------------------------------------------------------------


def test_compute_incident_trend_empty_gives_30_zeros():
    result = es._compute_incident_trend([], 30)
    assert len(result) == 30
    assert all(r["count"] == 0 for r in result)


def test_compute_incident_trend_single_recent_incident():
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    incs      = [_inc(created_at=_iso(yesterday))]
    result    = es._compute_incident_trend(incs, 30)
    total     = sum(r["count"] for r in result)
    assert total == 1


def test_compute_incident_trend_days_param():
    result = es._compute_incident_trend([], 7)
    assert len(result) == 7


def test_compute_incident_trend_out_of_window_not_counted():
    old  = datetime.now(timezone.utc) - timedelta(days=60)
    incs = [_inc(created_at=_iso(old))]
    result = es._compute_incident_trend(incs, 30)
    assert sum(r["count"] for r in result) == 0


def test_compute_incident_trend_sorted_by_date():
    result = es._compute_incident_trend([], 10)
    dates  = [r["date"] for r in result]
    assert dates == sorted(dates)


# ---------------------------------------------------------------------------
# _compute_severity_distribution
# ---------------------------------------------------------------------------


def test_compute_severity_distribution_empty():
    dist = es._compute_severity_distribution([])
    assert dist == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_compute_severity_distribution_counts():
    incs = [
        _inc(severity="CRITICAL"),
        _inc(severity="CRITICAL"),
        _inc(severity="HIGH"),
        _inc(severity="LOW"),
    ]
    dist = es._compute_severity_distribution(incs)
    assert dist["CRITICAL"] == 2
    assert dist["HIGH"]     == 1
    assert dist["MEDIUM"]   == 0
    assert dist["LOW"]      == 1


def test_compute_severity_distribution_unknown_ignored():
    dist = es._compute_severity_distribution([{"severity": "UNKNOWN"}])
    assert sum(dist.values()) == 0


# ---------------------------------------------------------------------------
# _compute_case_status_distribution
# ---------------------------------------------------------------------------


def test_compute_case_status_distribution_empty():
    dist = es._compute_case_status_distribution([])
    for status in ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]:
        assert dist[status] == 0


def test_compute_case_status_distribution_counts():
    cases = [
        _case(status="OPEN"),
        _case(status="OPEN"),
        _case(status="RESOLVED"),
        _case(status="CLOSED"),
    ]
    dist = es._compute_case_status_distribution(cases)
    assert dist["OPEN"]     == 2
    assert dist["RESOLVED"] == 1
    assert dist["CLOSED"]   == 1
    assert dist["INVESTIGATING"] == 0


# ---------------------------------------------------------------------------
# _compute_campaign_activity
# ---------------------------------------------------------------------------


def test_compute_campaign_activity_empty():
    assert es._compute_campaign_activity([]) == []


def test_compute_campaign_activity_sorted_descending():
    incs = [
        _inc(campaign="CAMP-A"),
        _inc(campaign="CAMP-B"),
        _inc(campaign="CAMP-B"),
        _inc(campaign="CAMP-C"),
        _inc(campaign="CAMP-C"),
        _inc(campaign="CAMP-C"),
    ]
    result = es._compute_campaign_activity(incs)
    assert result[0]["campaign_id"] == "CAMP-C"
    assert result[0]["incident_count"] == 3
    assert result[1]["incident_count"] == 2


def test_compute_campaign_activity_top_n():
    incs   = [_inc(campaign=f"CAMP-{i}") for i in range(20)]
    result = es._compute_campaign_activity(incs, top_n=5)
    assert len(result) == 5


def test_compute_campaign_activity_blank_campaign_excluded():
    incs = [_inc(campaign=""), _inc(campaign="CAMP-X")]
    result = es._compute_campaign_activity(incs)
    assert len(result) == 1
    assert result[0]["campaign_id"] == "CAMP-X"


# ---------------------------------------------------------------------------
# _compute_threat_actor_breakdown
# ---------------------------------------------------------------------------


def test_compute_threat_actor_breakdown_empty():
    assert es._compute_threat_actor_breakdown([]) == {}


def test_compute_threat_actor_breakdown_known_mapping():
    incs = [
        _inc(threat="LOCKBIT4-RANSOMWARE"),
        _inc(threat="CLOP-MOVEIT-STYLE-SQLI"),
        _inc(threat="CLOP-MOVEIT-STYLE-SQLI"),
        _inc(threat="LAZARUS-CRYPTO-DRAIN"),
    ]
    dist = es._compute_threat_actor_breakdown(incs)
    assert dist.get("LOCKBIT")  == 1
    assert dist.get("TA505")    == 2
    assert dist.get("Lazarus")  == 1


def test_compute_threat_actor_breakdown_unknown_maps_to_unknown_group():
    incs = [_inc(threat="SOME-UNKNOWN-THREAT")]
    dist = es._compute_threat_actor_breakdown(incs)
    assert dist.get("Unknown Criminal Group") == 1


def test_compute_threat_actor_breakdown_apt41():
    incs = [_inc(threat="VOLT-TYPHOON-LOTL"), _inc(threat="STORM0558-EXCHANGE-TOKEN")]
    dist = es._compute_threat_actor_breakdown(incs)
    assert dist.get("APT41") == 2


def test_compute_threat_actor_breakdown_apt29():
    incs = [_inc(threat="MIDNIGHT-BLIZZARD-OAUTH"), _inc(threat="APT28-SPEARPHISH")]
    dist = es._compute_threat_actor_breakdown(incs)
    assert dist.get("APT29") == 2


# ---------------------------------------------------------------------------
# _compute_threat_category_breakdown
# ---------------------------------------------------------------------------


def test_compute_threat_category_breakdown_empty():
    dist = es._compute_threat_category_breakdown([])
    assert all(v == 0 for v in dist.values())
    assert len(dist) == 8


def test_compute_threat_category_breakdown_ransomware():
    incs = [_inc(threat="LOCKBIT4-RANSOMWARE"), _inc(threat="AKIRA-RANSOMWARE")]
    dist = es._compute_threat_category_breakdown(incs)
    assert dist["Ransomware"] == 2


def test_compute_threat_category_breakdown_lateral_movement():
    incs = [_inc(threat="MIMIKATZ-PASS-THE-HASH"), _inc(threat="KERBEROASTING-ATTACK")]
    dist = es._compute_threat_category_breakdown(incs)
    assert dist["Lateral Movement"] == 2


def test_compute_threat_category_breakdown_insider_threat():
    incs = [_inc(threat="INSIDER-DATA-STAGING")]
    dist = es._compute_threat_category_breakdown(incs)
    assert dist["Insider Threat"] == 1


def test_compute_threat_category_breakdown_malware_delivery():
    incs = [_inc(threat="EMOTET-WAVE-2026"), _inc(threat="QAKBOT-REVIVAL-PHISH")]
    dist = es._compute_threat_category_breakdown(incs)
    assert dist["Malware Delivery"] == 2


def test_compute_threat_category_breakdown_all_8_categories_present():
    dist = es._compute_threat_category_breakdown([])
    expected = {
        "Ransomware", "Phishing", "Credential Theft", "Data Exfiltration",
        "Command & Control", "Insider Threat", "Malware Delivery", "Lateral Movement",
    }
    assert set(dist.keys()) == expected


# ---------------------------------------------------------------------------
# File-backed integration: get_incident_trend / get_severity_distribution
# via _INCIDENTS_PATH patch
# ---------------------------------------------------------------------------


@pytest.fixture
def patch_incidents(tmp_path, monkeypatch):
    incidents_file = tmp_path / "incidents.json"
    monkeypatch.setattr(es, "_INCIDENTS_PATH", incidents_file)
    return incidents_file


def test_get_incident_trend_reads_file(patch_incidents):
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    patch_incidents.write_text(
        json.dumps([_inc(created_at=_iso(yesterday))]), encoding="utf-8"
    )
    result = es.get_incident_trend(30)
    assert sum(r["count"] for r in result) == 1


def test_get_severity_distribution_reads_file(patch_incidents):
    patch_incidents.write_text(
        json.dumps([_inc(severity="CRITICAL"), _inc(severity="HIGH")]),
        encoding="utf-8",
    )
    dist = es.get_severity_distribution()
    assert dist["CRITICAL"] == 1
    assert dist["HIGH"]     == 1


def test_get_campaign_activity_reads_file(patch_incidents):
    patch_incidents.write_text(
        json.dumps([_inc(campaign="CAMP-X"), _inc(campaign="CAMP-X"), _inc(campaign="CAMP-Y")]),
        encoding="utf-8",
    )
    result = es.get_campaign_activity()
    assert result[0]["campaign_id"] == "CAMP-X"
    assert result[0]["incident_count"] == 2


def test_get_threat_actor_breakdown_reads_file(patch_incidents):
    patch_incidents.write_text(
        json.dumps([_inc(threat="LAZARUS-C2-CRYPTO"), _inc(threat="LAZARUS-CRYPTO-DRAIN")]),
        encoding="utf-8",
    )
    dist = es.get_threat_actor_breakdown()
    assert dist.get("Lazarus") == 2


def test_get_threat_category_breakdown_reads_file(patch_incidents):
    patch_incidents.write_text(
        json.dumps([_inc(threat="MIMIKATZ-PASS-THE-HASH")]),
        encoding="utf-8",
    )
    dist = es.get_threat_category_breakdown()
    assert dist["Lateral Movement"] == 1


def test_get_incident_trend_missing_file_returns_empty_window(patch_incidents):
    # File does not exist
    result = es.get_incident_trend(7)
    assert len(result) == 7
    assert all(r["count"] == 0 for r in result)


# ---------------------------------------------------------------------------
# filter_incidents
# ---------------------------------------------------------------------------


def test_filter_incidents_no_filters():
    incs = [_inc(), _inc()]
    assert len(es.filter_incidents(incs)) == 2


def test_filter_incidents_by_severity():
    incs = [_inc(severity="CRITICAL"), _inc(severity="HIGH"), _inc(severity="LOW")]
    result = es.filter_incidents(incs, severities=["CRITICAL"])
    assert len(result) == 1
    assert result[0]["severity"] == "CRITICAL"


def test_filter_incidents_by_date_from():
    from datetime import timezone
    now   = datetime.now(timezone.utc)
    old   = now - timedelta(days=10)
    new   = now - timedelta(days=1)
    incs  = [
        _inc(created_at=_iso(old)),
        _inc(created_at=_iso(new)),
    ]
    cutoff = now - timedelta(days=5)
    result = es.filter_incidents(incs, date_from=cutoff)
    assert len(result) == 1


def test_filter_incidents_by_date_to():
    from datetime import timezone
    now  = datetime.now(timezone.utc)
    old  = now - timedelta(days=10)
    new  = now - timedelta(days=1)
    incs = [
        _inc(created_at=_iso(old)),
        _inc(created_at=_iso(new)),
    ]
    cutoff = now - timedelta(days=5)
    result = es.filter_incidents(incs, date_to=cutoff)
    assert len(result) == 1


def test_filter_incidents_empty():
    assert es.filter_incidents([]) == []


def test_filter_incidents_multiple_severities():
    incs = [
        _inc(severity="CRITICAL"),
        _inc(severity="HIGH"),
        _inc(severity="LOW"),
    ]
    result = es.filter_incidents(incs, severities=["CRITICAL", "HIGH"])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# _compute_mitre_coverage
# ---------------------------------------------------------------------------


def test_compute_mitre_coverage_empty():
    result = es._compute_mitre_coverage([])
    assert isinstance(result, list)
    assert len(result) == 12  # 12 tactics always present
    assert all(r["techniques"] == 0 for r in result)


def test_compute_mitre_coverage_counts_unique_techniques():
    incs = [
        {"attack_techniques": [
            {"technique_id": "T1486", "tactic": "impact"},
            {"technique_id": "T1490", "tactic": "impact"},
        ]},
        {"attack_techniques": [
            {"technique_id": "T1486", "tactic": "impact"},  # duplicate
        ]},
    ]
    result = es._compute_mitre_coverage(incs)
    impact = next(r for r in result if r["tactic_id"] == "impact")
    assert impact["techniques"] == 2  # T1486 and T1490, not 3


def test_compute_mitre_coverage_all_tactics_present():
    result = es._compute_mitre_coverage([])
    tactic_ids = {r["tactic_id"] for r in result}
    expected = {
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "exfiltration", "command-and-control", "impact",
    }
    assert expected == tactic_ids


def test_compute_mitre_coverage_unknown_tactic_ignored():
    incs = [{"attack_techniques": [
        {"technique_id": "T9999", "tactic": "fictional-tactic"},
    ]}]
    result = es._compute_mitre_coverage(incs)
    assert all(r["techniques"] == 0 for r in result)


def test_compute_mitre_coverage_multiple_tactics():
    incs = [{"attack_techniques": [
        {"technique_id": "T1566", "tactic": "initial-access"},
        {"technique_id": "T1059", "tactic": "execution"},
        {"technique_id": "T1486", "tactic": "impact"},
    ]}]
    result = es._compute_mitre_coverage(incs)
    covered = [r for r in result if r["techniques"] > 0]
    assert len(covered) == 3


# ---------------------------------------------------------------------------
# _compute_executive_kpis total_incidents
# ---------------------------------------------------------------------------


def test_compute_executive_kpis_total_incidents():
    incs = [_inc(), _inc(), _inc()]
    kpis = es._compute_executive_kpis(incs, [], [], [])
    assert kpis["total_incidents"] == 3


def test_compute_executive_kpis_total_incidents_empty():
    kpis = es._compute_executive_kpis([], [], [], [])
    assert kpis["total_incidents"] == 0
