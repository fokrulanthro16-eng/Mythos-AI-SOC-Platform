"""tests/test_api_incidents.py — Incident CRUD endpoint tests."""

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


_PAYLOAD = {
    "threat_name": "APT-SHADOW-VIPER",
    "severity": "CRITICAL",
    "indicators": ["C2:185.220.101.47", "hash:abc123"],
}


# ---------------------------------------------------------------------------
# POST /api/v1/incidents
# ---------------------------------------------------------------------------


async def test_create_incident_as_admin(client, auth):
    resp = await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)
    assert resp.status_code == 201
    data = resp.json()
    assert data["threat_name"] == "APT-SHADOW-VIPER"
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "DETECTED"
    assert "id" in data


async def test_create_incident_as_analyst(client, analyst_auth):
    resp = await client.post("/api/v1/incidents", json=_PAYLOAD, headers=analyst_auth)
    assert resp.status_code == 201


async def test_create_incident_as_viewer_forbidden(client, viewer_auth):
    resp = await client.post("/api/v1/incidents", json=_PAYLOAD, headers=viewer_auth)
    assert resp.status_code == 403


async def test_create_incident_invalid_severity(client, auth):
    bad = {**_PAYLOAD, "severity": "EXTREME"}
    resp = await client.post("/api/v1/incidents", json=bad, headers=auth)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/v1/incidents
# ---------------------------------------------------------------------------


async def test_list_incidents_returns_paginated(client, auth):
    for i in range(3):
        await client.post("/api/v1/incidents", json={**_PAYLOAD, "incident_id": f"INC-00{i}"}, headers=auth)

    resp = await client.get("/api/v1/incidents", headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 3


async def test_list_incidents_filter_by_severity(client, auth):
    await client.post("/api/v1/incidents", json={**_PAYLOAD, "severity": "LOW", "incident_id": "INC-LOW-001"}, headers=auth)

    resp = await client.get("/api/v1/incidents?severity=LOW", headers=auth)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(i["severity"] == "LOW" for i in items)


async def test_list_incidents_viewer_can_read(client, viewer_auth):
    resp = await client.get("/api/v1/incidents", headers=viewer_auth)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/{id}
# ---------------------------------------------------------------------------


async def test_get_incident_by_id(client, auth):
    create_resp = await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)
    inc_id = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/incidents/{inc_id}", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["id"] == inc_id


async def test_get_incident_not_found(client, auth):
    import uuid
    resp = await client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=auth)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /api/v1/incidents/{id}
# ---------------------------------------------------------------------------


async def test_update_incident_severity(client, auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"severity": "HIGH"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["severity"] == "HIGH"


async def test_update_incident_viewer_forbidden(client, auth, viewer_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"severity": "LOW"},
        headers=viewer_auth,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/v1/incidents/{id}
# ---------------------------------------------------------------------------


async def test_delete_incident_as_admin(client, auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.delete(f"/api/v1/incidents/{inc_id}", headers=auth)
    assert resp.status_code == 204

    get_resp = await client.get(f"/api/v1/incidents/{inc_id}", headers=auth)
    assert get_resp.status_code == 404


async def test_delete_incident_analyst_forbidden(client, auth, analyst_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.delete(f"/api/v1/incidents/{inc_id}", headers=analyst_auth)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/v1/incidents/{id}/run
# ---------------------------------------------------------------------------


async def test_run_pipeline_returns_mitigated(client, auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.post(f"/api/v1/incidents/{inc_id}/run", headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "MITIGATED"
    assert data["risk_score"] > 0
    assert data["suspected_actor"] != ""
    assert len(data["mitigation_actions"]) > 0


async def test_run_pipeline_viewer_forbidden(client, auth, viewer_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_PAYLOAD, headers=auth)).json()["id"]

    resp = await client.post(f"/api/v1/incidents/{inc_id}/run", headers=viewer_auth)
    assert resp.status_code == 403
