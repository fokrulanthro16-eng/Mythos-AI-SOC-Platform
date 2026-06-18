"""tests/test_workbench_store.py — Unit tests for the analyst workbench store."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture: isolated store path so tests don't touch the real logs/
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Redirect the workbench store to a temp file for every test."""
    store_path = tmp_path / "workbench_store.json"
    import dashboard.workbench_store as ws
    monkeypatch.setattr(ws, "_STORE_PATH", store_path)
    yield store_path


# ---------------------------------------------------------------------------
# Import helpers AFTER monkeypatch is applied
# ---------------------------------------------------------------------------

from dashboard.workbench_store import (
    add_workbench_note,
    assign_incident,
    get_activity_feed,
    get_all_assignments,
    get_analyst_assignments,
    get_escalations,
    get_workload_metrics,
    log_activity,
    record_escalation,
    seed_sample_data,
    unassign_incident,
    update_assignment_status,
    get_assignment,
)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


def test_initial_assignments_empty():
    assert get_all_assignments() == []


def test_initial_activity_feed_empty():
    assert get_activity_feed() == []


def test_initial_escalations_empty():
    assert get_escalations() == []


# ---------------------------------------------------------------------------
# assign_incident
# ---------------------------------------------------------------------------


def test_assign_incident_creates_record():
    asgn = assign_incident("INC-001", "Alice Chen", title="Test Threat")
    assert asgn["incident_id"] == "INC-001"
    assert asgn["analyst"] == "Alice Chen"
    assert asgn["title"] == "Test Threat"


def test_assign_incident_is_persisted():
    assign_incident("INC-002", "Bob Ross")
    all_a = get_all_assignments()
    assert any(a["incident_id"] == "INC-002" for a in all_a)


def test_assign_incident_logs_activity():
    assign_incident("INC-003", "Charlie Day", assigned_by="SOC Lead")
    feed = get_activity_feed()
    assert any(e["action"] == "ASSIGNED" and e["target"] == "INC-003" for e in feed)


def test_assign_incident_with_all_fields():
    asgn = assign_incident(
        "INC-004", "Alice Chen",
        assigned_by="Manager",
        title="Ransomware",
        severity="CRITICAL",
        priority="P1",
        case_id="case-abc",
    )
    assert asgn["severity"] == "CRITICAL"
    assert asgn["priority"] == "P1"
    assert asgn["case_id"] == "case-abc"


def test_reassign_incident_updates_existing():
    assign_incident("INC-005", "Alice Chen")
    result = assign_incident("INC-005", "Bob Ross", assigned_by="Lead")
    assert result["analyst"] == "Bob Ross"
    # Only one record for this incident
    all_a = get_all_assignments()
    assert len([a for a in all_a if a["incident_id"] == "INC-005"]) == 1


def test_reassign_logs_reassigned_action():
    assign_incident("INC-006", "Alice Chen")
    assign_incident("INC-006", "Bob Ross")
    feed = get_activity_feed()
    assert any(e["action"] == "REASSIGNED" and e["target"] == "INC-006" for e in feed)


def test_get_assignment_returns_none_for_unknown():
    assert get_assignment("INC-MISSING") is None


def test_get_assignment_returns_record():
    assign_incident("INC-007", "Diana Prince")
    a = get_assignment("INC-007")
    assert a is not None
    assert a["analyst"] == "Diana Prince"


# ---------------------------------------------------------------------------
# unassign_incident
# ---------------------------------------------------------------------------


def test_unassign_removes_record():
    assign_incident("INC-010", "Alice Chen")
    unassign_incident("INC-010")
    assert get_assignment("INC-010") is None


def test_unassign_logs_activity():
    assign_incident("INC-011", "Bob Ross")
    unassign_incident("INC-011", user="SOC Lead")
    feed = get_activity_feed()
    assert any(e["action"] == "UNASSIGNED" and e["target"] == "INC-011" for e in feed)


def test_unassign_nonexistent_does_not_raise():
    unassign_incident("INC-GHOST")  # must not raise
    assert True


# ---------------------------------------------------------------------------
# get_analyst_assignments
# ---------------------------------------------------------------------------


def test_get_analyst_assignments_filters_correctly():
    assign_incident("INC-020", "Alice Chen")
    assign_incident("INC-021", "Bob Ross")
    assign_incident("INC-022", "Alice Chen")
    alice = get_analyst_assignments("Alice Chen")
    assert len(alice) == 2
    assert all(a["analyst"] == "Alice Chen" for a in alice)


def test_get_analyst_assignments_empty_for_unknown():
    assert get_analyst_assignments("Unknown Analyst") == []


# ---------------------------------------------------------------------------
# update_assignment_status
# ---------------------------------------------------------------------------


def test_update_status_changes_field():
    assign_incident("INC-030", "Alice Chen")
    result = update_assignment_status("INC-030", "INVESTIGATING")
    assert result["status"] == "INVESTIGATING"


def test_update_status_logs_activity():
    assign_incident("INC-031", "Bob Ross")
    update_assignment_status("INC-031", "CONTAINED", user="Bob Ross")
    feed = get_activity_feed()
    assert any(e["action"] == "STATUS_CHANGED" and e["target"] == "INC-031" for e in feed)


def test_update_status_to_closed_sets_closed_at():
    assign_incident("INC-032", "Alice Chen")
    result = update_assignment_status("INC-032", "CLOSED")
    assert "closed_at" in result


def test_update_status_returns_none_for_unknown():
    result = update_assignment_status("INC-GHOST", "OPEN")
    assert result is None


# ---------------------------------------------------------------------------
# add_workbench_note
# ---------------------------------------------------------------------------


def test_add_note_appends_to_assignment():
    assign_incident("INC-040", "Alice Chen")
    note = add_workbench_note("INC-040", "Observed lateral movement.", "Alice Chen")
    assert note is not None
    assert note["content"] == "Observed lateral movement."
    a = get_assignment("INC-040")
    assert len(a["notes"]) == 1


def test_add_note_logs_activity():
    assign_incident("INC-041", "Bob Ross")
    add_workbench_note("INC-041", "Initial triage done.", "Bob Ross")
    feed = get_activity_feed()
    assert any(e["action"] == "NOTE_ADDED" and e["target"] == "INC-041" for e in feed)


def test_add_note_returns_none_for_unknown_incident():
    result = add_workbench_note("INC-GHOST", "Note content")
    assert result is None


def test_add_multiple_notes():
    assign_incident("INC-042", "Charlie Day")
    add_workbench_note("INC-042", "Note 1")
    add_workbench_note("INC-042", "Note 2")
    a = get_assignment("INC-042")
    assert len(a["notes"]) == 2


# ---------------------------------------------------------------------------
# record_escalation
# ---------------------------------------------------------------------------


def test_record_escalation_creates_entry():
    assign_incident("INC-050", "Alice Chen")
    esc = record_escalation("INC-050", "P3", "P1", "Alice Chen", "Confirmed ransomware")
    assert esc["from_priority"] == "P3"
    assert esc["to_priority"] == "P1"


def test_record_escalation_updates_assignment_priority():
    assign_incident("INC-051", "Alice Chen", priority="P3")
    record_escalation("INC-051", "P3", "P1", "Alice Chen")
    a = get_assignment("INC-051")
    assert a["priority"] == "P1"


def test_record_escalation_logs_activity():
    assign_incident("INC-052", "Bob Ross")
    record_escalation("INC-052", "P2", "P1", "Bob Ross", "Lateral movement confirmed")
    feed = get_activity_feed()
    assert any(e["action"] == "ESCALATED" and e["target"] == "INC-052" for e in feed)


def test_get_escalations_returns_all():
    assign_incident("INC-053", "Alice Chen")
    assign_incident("INC-054", "Bob Ross")
    record_escalation("INC-053", "P3", "P1", "Alice Chen")
    record_escalation("INC-054", "P2", "P1", "Bob Ross")
    all_escs = get_escalations()
    assert len(all_escs) == 2


def test_get_escalations_filters_by_incident():
    assign_incident("INC-055", "Alice Chen")
    assign_incident("INC-056", "Bob Ross")
    record_escalation("INC-055", "P3", "P1", "Alice Chen")
    record_escalation("INC-056", "P3", "P1", "Bob Ross")
    inc055_escs = get_escalations("INC-055")
    assert len(inc055_escs) == 1
    assert inc055_escs[0]["incident_id"] == "INC-055"


# ---------------------------------------------------------------------------
# log_activity
# ---------------------------------------------------------------------------


def test_log_activity_creates_entry():
    entry = log_activity("Admin", "CUSTOM_ACTION", "INC-060", "Some detail")
    assert entry["action"] == "CUSTOM_ACTION"
    assert entry["user"] == "Admin"
    assert entry["target"] == "INC-060"


def test_get_activity_feed_sorted_desc():
    log_activity("A", "ACTION_1", "INC-070")
    log_activity("B", "ACTION_2", "INC-070")
    feed = get_activity_feed()
    # Most recent first
    assert feed[0]["action"] == "ACTION_2"


def test_get_activity_feed_limit():
    for i in range(10):
        log_activity("A", "ACT", f"INC-{i:03d}")
    feed = get_activity_feed(limit=5)
    assert len(feed) == 5


def test_get_activity_feed_filter_by_analyst():
    log_activity("Alice", "NOTE_ADDED", "INC-080")
    log_activity("Bob",   "ASSIGNED",   "INC-081")
    alice_feed = get_activity_feed(analyst="Alice")
    assert all(e["user"] == "Alice" for e in alice_feed)


# ---------------------------------------------------------------------------
# get_workload_metrics
# ---------------------------------------------------------------------------


def test_workload_metrics_empty():
    m = get_workload_metrics()
    assert m["total_assigned"] == 0
    assert m["active"] == 0
    assert m["resolved"] == 0


def test_workload_metrics_counts_open_cases():
    assign_incident("INC-090", "Alice Chen", priority="P1")
    assign_incident("INC-091", "Bob Ross",   priority="P2")
    m = get_workload_metrics()
    assert m["total_assigned"] == 2
    assert m["active"] == 2


def test_workload_metrics_by_analyst():
    assign_incident("INC-092", "Alice Chen")
    assign_incident("INC-093", "Alice Chen")
    assign_incident("INC-094", "Bob Ross")
    m = get_workload_metrics()
    assert m["by_analyst"]["Alice Chen"]["total"] == 2
    assert m["by_analyst"]["Bob Ross"]["total"] == 1


def test_workload_metrics_counts_resolved():
    assign_incident("INC-095", "Alice Chen")
    update_assignment_status("INC-095", "RESOLVED")
    m = get_workload_metrics()
    assert m["resolved"] == 1
    assert m["active"] == 0


# ---------------------------------------------------------------------------
# seed_sample_data
# ---------------------------------------------------------------------------


def test_seed_sample_data_creates_assignments():
    seed_sample_data()
    all_a = get_all_assignments()
    assert len(all_a) >= 4


def test_seed_sample_data_is_idempotent():
    seed_sample_data()
    count1 = len(get_all_assignments())
    seed_sample_data()  # second call must not add more
    count2 = len(get_all_assignments())
    assert count1 == count2
