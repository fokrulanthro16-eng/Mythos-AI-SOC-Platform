"""tests/test_api_cases.py — Case management endpoint tests."""

from __future__ import annotations

import pytest


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


_CASE = {"title": "APT Investigation Q2-2026", "priority": "P1"}
_INC = {"threat_name": "APT-SHADOW-VIPER", "severity": "CRITICAL", "indicators": ["C2:1.2.3.4"]}


# ---------------------------------------------------------------------------
# POST /api/v1/cases
# ---------------------------------------------------------------------------


async def test_create_case_admin(client, auth):
    resp = await client.post("/api/v1/cases", json=_CASE, headers=auth)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "APT Investigation Q2-2026"
    assert data["status"] == "OPEN"
    assert data["priority"] == "P1"
    assert data["case_number"].startswith("CASE-")


async def test_create_case_analyst(client, analyst_auth):
    resp = await client.post("/api/v1/cases", json=_CASE, headers=analyst_auth)
    assert resp.status_code == 201


async def test_create_case_viewer_forbidden(client, viewer_auth):
    resp = await client.post("/api/v1/cases", json=_CASE, headers=viewer_auth)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/v1/cases
# ---------------------------------------------------------------------------


async def test_list_cases(client, auth):
    await client.post("/api/v1/cases", json=_CASE, headers=auth)
    resp = await client.get("/api/v1/cases", headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert "items" in data


async def test_list_cases_viewer_can_read(client, viewer_auth):
    resp = await client.get("/api/v1/cases", headers=viewer_auth)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/v1/cases/{id}
# ---------------------------------------------------------------------------


async def test_get_case_by_id(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.get(f"/api/v1/cases/{case_id}", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["id"] == case_id


async def test_get_case_not_found(client, auth):
    import uuid
    resp = await client.get(f"/api/v1/cases/{uuid.uuid4()}", headers=auth)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /api/v1/cases/{id}
# ---------------------------------------------------------------------------


async def test_update_case_status(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "INVESTIGATING"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "INVESTIGATING"


async def test_resolve_case_sets_resolved_at(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.patch(
        f"/api/v1/cases/{case_id}", json={"status": "RESOLVED"}, headers=auth
    )
    assert resp.status_code == 200
    assert resp.json()["resolved_at"] is not None


async def test_update_case_viewer_forbidden(client, auth, viewer_auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.patch(
        f"/api/v1/cases/{case_id}", json={"status": "CLOSED"}, headers=viewer_auth
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/v1/cases/{id}
# ---------------------------------------------------------------------------


async def test_delete_case(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.delete(f"/api/v1/cases/{case_id}", headers=auth)
    assert resp.status_code == 204
    assert (await client.get(f"/api/v1/cases/{case_id}", headers=auth)).status_code == 404


# ---------------------------------------------------------------------------
# Link / Unlink incidents
# ---------------------------------------------------------------------------


async def test_link_incident_to_case(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]

    resp = await client.post(
        f"/api/v1/cases/{case_id}/incidents/{inc_id}", headers=auth
    )
    assert resp.status_code == 200
    assert resp.json()["incident_count"] == 1


async def test_unlink_incident_from_case(client, auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]

    await client.post(f"/api/v1/cases/{case_id}/incidents/{inc_id}", headers=auth)
    resp = await client.delete(f"/api/v1/cases/{case_id}/incidents/{inc_id}", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["incident_count"] == 0


async def test_link_nonexistent_incident(client, auth):
    import uuid
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=auth)).json()["id"]
    resp = await client.post(f"/api/v1/cases/{case_id}/incidents/{uuid.uuid4()}", headers=auth)
    assert resp.status_code == 404
