"""tests/test_api_case_management.py — Case management: notes, history, stats, auto-creation."""

from __future__ import annotations

import uuid

import pytest

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_CASE_BODY = {"title": "SOC Investigation Alpha", "priority": "P2"}
_INC_BODY  = {"threat_name": "Cobalt Strike", "severity": "CRITICAL", "indicators": ["10.0.0.1"]}


@pytest.fixture
async def client(api_client, seeded_db):
    return api_client


@pytest.fixture
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_auth(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_auth(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture
async def case_id(client, auth):
    r = await client.post("/api/v1/cases", json=_CASE_BODY, headers=auth)
    assert r.status_code == 201
    return r.json()["id"]


# ===========================================================================
# Auto-case creation on incident create
# ===========================================================================


async def test_create_incident_auto_creates_case(client, auth):
    """Each new incident must auto-generate a linked case."""
    r = await client.post("/api/v1/incidents", json=_INC_BODY, headers=auth)
    assert r.status_code == 201
    data = r.json()
    assert data.get("case_id") is not None


async def test_auto_case_priority_from_severity(client, auth):
    """CRITICAL incident → P1 case, LOW incident → P4 case."""
    for sev, expected_prio in [("CRITICAL", "P1"), ("LOW", "P4")]:
        inc_resp = await client.post(
            "/api/v1/incidents",
            json={"threat_name": f"T-{uuid.uuid4().hex[:6]}", "severity": sev},
            headers=auth,
        )
        assert inc_resp.status_code == 201
        case_id = inc_resp.json()["case_id"]
        case_resp = await client.get(f"/api/v1/cases/{case_id}", headers=auth)
        assert case_resp.status_code == 200
        assert case_resp.json()["priority"] == expected_prio


async def test_auto_case_title_contains_threat_name(client, auth):
    threat = f"Ransomware-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        "/api/v1/incidents",
        json={"threat_name": threat, "severity": "HIGH"},
        headers=auth,
    )
    case_id = r.json()["case_id"]
    case = (await client.get(f"/api/v1/cases/{case_id}", headers=auth)).json()
    assert threat in case["title"]


async def test_auto_case_starts_open(client, auth):
    r = await client.post("/api/v1/incidents", json=_INC_BODY, headers=auth)
    case_id = r.json()["case_id"]
    case = (await client.get(f"/api/v1/cases/{case_id}", headers=auth)).json()
    assert case["status"] == "OPEN"


async def test_auto_case_history_has_created_event(client, auth):
    r = await client.post("/api/v1/incidents", json=_INC_BODY, headers=auth)
    case_id = r.json()["case_id"]
    hist = (await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)).json()
    assert any(e["event_type"] == "CREATED" for e in hist)


# ===========================================================================
# CONTAINED status
# ===========================================================================


async def test_status_transition_to_contained(client, auth, case_id):
    r = await client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "CONTAINED"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "CONTAINED"


async def test_full_status_lifecycle(client, auth, case_id):
    """Open → Investigating → Contained → Resolved."""
    for new_status in ("INVESTIGATING", "CONTAINED", "RESOLVED"):
        r = await client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": new_status},
            headers=auth,
        )
        assert r.status_code == 200, f"Failed at {new_status}: {r.text}"
        assert r.json()["status"] == new_status


async def test_resolved_sets_resolved_at(client, auth, case_id):
    r = await client.patch(
        f"/api/v1/cases/{case_id}", json={"status": "RESOLVED"}, headers=auth
    )
    assert r.json()["resolved_at"] is not None


# ===========================================================================
# POST /cases/{id}/notes
# ===========================================================================


async def test_add_note_admin(client, auth, case_id):
    r = await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": "Initial triage: C2 traffic confirmed."},
        headers=auth,
    )
    assert r.status_code == 201
    data = r.json()
    assert data["event_type"] == "NOTE"
    assert "C2 traffic confirmed" in data["content"]


async def test_add_note_analyst(client, analyst_auth, case_id):
    r = await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": "Analyst note from investigation."},
        headers=analyst_auth,
    )
    assert r.status_code == 201


async def test_add_note_viewer_forbidden(client, viewer_auth, case_id):
    r = await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": "Should not be allowed."},
        headers=viewer_auth,
    )
    assert r.status_code == 403


async def test_add_note_empty_content_rejected(client, auth, case_id):
    r = await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": ""},
        headers=auth,
    )
    assert r.status_code == 422


async def test_add_note_missing_content_rejected(client, auth, case_id):
    r = await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={},
        headers=auth,
    )
    assert r.status_code == 422


async def test_add_note_nonexistent_case(client, auth):
    r = await client.post(
        f"/api/v1/cases/{uuid.uuid4()}/notes",
        json={"content": "Note on missing case."},
        headers=auth,
    )
    assert r.status_code == 404


# ===========================================================================
# GET /cases/{id}/notes
# ===========================================================================


async def test_list_notes_empty(client, auth, case_id):
    r = await client.get(f"/api/v1/cases/{case_id}/notes", headers=auth)
    assert r.status_code == 200
    assert r.json() == []


async def test_list_notes_returns_added_notes(client, auth, case_id):
    for i in range(3):
        await client.post(
            f"/api/v1/cases/{case_id}/notes",
            json={"content": f"Note #{i}"},
            headers=auth,
        )
    r = await client.get(f"/api/v1/cases/{case_id}/notes", headers=auth)
    assert r.status_code == 200
    assert len(r.json()) == 3


async def test_list_notes_viewer_can_read(client, viewer_auth, case_id):
    r = await client.get(f"/api/v1/cases/{case_id}/notes", headers=viewer_auth)
    assert r.status_code == 200


async def test_notes_ordered_chronologically(client, auth, case_id):
    for i in range(3):
        await client.post(
            f"/api/v1/cases/{case_id}/notes",
            json={"content": f"Note {i}"},
            headers=auth,
        )
    notes = (await client.get(f"/api/v1/cases/{case_id}/notes", headers=auth)).json()
    timestamps = [n["created_at"] for n in notes]
    assert timestamps == sorted(timestamps)


# ===========================================================================
# GET /cases/{id}/history
# ===========================================================================


async def test_history_contains_created_event(client, auth, case_id):
    r = await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)
    assert r.status_code == 200
    types = [e["event_type"] for e in r.json()]
    assert "CREATED" in types


async def test_history_records_status_change(client, auth, case_id):
    await client.patch(
        f"/api/v1/cases/{case_id}", json={"status": "INVESTIGATING"}, headers=auth
    )
    hist = (await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)).json()
    changes = [e for e in hist if e["event_type"] == "STATUS_CHANGE"]
    assert len(changes) == 1
    assert changes[0]["old_value"] == "OPEN"
    assert changes[0]["new_value"] == "INVESTIGATING"


async def test_history_records_note_event(client, auth, case_id):
    await client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"content": "Timeline test note"},
        headers=auth,
    )
    hist = (await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)).json()
    notes_in_hist = [e for e in hist if e["event_type"] == "NOTE"]
    assert len(notes_in_hist) == 1


async def test_history_records_priority_change(client, auth, case_id):
    await client.patch(
        f"/api/v1/cases/{case_id}", json={"priority": "P1"}, headers=auth
    )
    hist = (await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)).json()
    prio_events = [e for e in hist if e["event_type"] == "PRIORITY_CHANGE"]
    assert len(prio_events) == 1
    assert prio_events[0]["new_value"] == "P1"


async def test_history_viewer_can_read(client, viewer_auth, case_id):
    r = await client.get(f"/api/v1/cases/{case_id}/history", headers=viewer_auth)
    assert r.status_code == 200


async def test_history_ordered_chronologically(client, auth, case_id):
    await client.patch(f"/api/v1/cases/{case_id}", json={"status": "INVESTIGATING"}, headers=auth)
    await client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "Note"}, headers=auth)
    hist = (await client.get(f"/api/v1/cases/{case_id}/history", headers=auth)).json()
    ts_list = [e["created_at"] for e in hist]
    assert ts_list == sorted(ts_list)


# ===========================================================================
# GET /cases/stats
# ===========================================================================


async def test_stats_returns_required_fields(client, auth):
    r = await client.get("/api/v1/cases/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    for field in ("total", "by_status", "by_priority", "open_count",
                  "investigating_count", "contained_count", "resolved_count"):
        assert field in data, f"Missing field: {field}"


async def test_stats_counts_created_case(client, auth):
    before = (await client.get("/api/v1/cases/stats", headers=auth)).json()["total"]
    await client.post("/api/v1/cases", json=_CASE_BODY, headers=auth)
    after = (await client.get("/api/v1/cases/stats", headers=auth)).json()["total"]
    assert after == before + 1


async def test_stats_viewer_can_access(client, viewer_auth):
    r = await client.get("/api/v1/cases/stats", headers=viewer_auth)
    assert r.status_code == 200


# ===========================================================================
# Search / Filter
# ===========================================================================


async def test_search_by_title(client, auth):
    unique = uuid.uuid4().hex[:8]
    await client.post(
        "/api/v1/cases",
        json={"title": f"SearchTarget-{unique}", "priority": "P3"},
        headers=auth,
    )
    r = await client.get(f"/api/v1/cases?search={unique}", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(unique in item["title"] for item in items)


async def test_search_no_match_returns_empty(client, auth):
    r = await client.get("/api/v1/cases?search=XYZNONEXISTENT99999", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] == 0


async def test_filter_by_status(client, auth):
    # Create one OPEN case
    await client.post("/api/v1/cases", json=_CASE_BODY, headers=auth)
    r = await client.get("/api/v1/cases?case_status=OPEN", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["status"] == "OPEN"


async def test_notes_count_in_case_read(client, auth, case_id):
    await client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "N1"}, headers=auth)
    await client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "N2"}, headers=auth)
    r = await client.get(f"/api/v1/cases/{case_id}", headers=auth)
    assert r.json()["notes_count"] == 2


async def test_assign_analyst_to_case(client, auth, seeded_db, case_id):
    analyst_uuid = str(seeded_db["analyst"].id)
    r = await client.patch(
        f"/api/v1/cases/{case_id}",
        json={"assigned_to": analyst_uuid},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["assigned_to"] == analyst_uuid
