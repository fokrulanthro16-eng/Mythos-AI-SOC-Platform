"""tests/test_api_rbac.py — RBAC permissions matrix and multi-tenant isolation."""

from __future__ import annotations

import uuid

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


_INC = {"threat_name": "APT-SHADOW-VIPER", "severity": "CRITICAL", "indicators": ["C2:1.1.1.1"]}
_CASE = {"title": "RBAC Test Case", "priority": "P2"}
_USER = {"email": "new@test.corp", "password": "NewUser123!", "role": "VIEWER"}


# ---------------------------------------------------------------------------
# Role: VIEWER
# ---------------------------------------------------------------------------


async def test_viewer_can_list_incidents(client, viewer_auth):
    assert (await client.get("/api/v1/incidents", headers=viewer_auth)).status_code == 200


async def test_viewer_can_list_cases(client, viewer_auth):
    assert (await client.get("/api/v1/cases", headers=viewer_auth)).status_code == 200


async def test_viewer_cannot_create_incident(client, viewer_auth):
    assert (await client.post("/api/v1/incidents", json=_INC, headers=viewer_auth)).status_code == 403


async def test_viewer_cannot_create_case(client, viewer_auth):
    assert (await client.post("/api/v1/cases", json=_CASE, headers=viewer_auth)).status_code == 403


async def test_viewer_cannot_delete_incident(client, auth, viewer_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]
    assert (await client.delete(f"/api/v1/incidents/{inc_id}", headers=viewer_auth)).status_code == 403


async def test_viewer_cannot_run_pipeline(client, auth, viewer_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]
    assert (await client.post(f"/api/v1/incidents/{inc_id}/run", headers=viewer_auth)).status_code == 403


async def test_viewer_cannot_list_users(client, viewer_auth):
    assert (await client.get("/api/v1/users", headers=viewer_auth)).status_code == 403


async def test_viewer_cannot_list_tenants(client, viewer_auth):
    assert (await client.get("/api/v1/tenants", headers=viewer_auth)).status_code == 403


# ---------------------------------------------------------------------------
# Role: ANALYST
# ---------------------------------------------------------------------------


async def test_analyst_can_create_incident(client, analyst_auth):
    assert (await client.post("/api/v1/incidents", json=_INC, headers=analyst_auth)).status_code == 201


async def test_analyst_can_run_pipeline(client, auth, analyst_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]
    resp = await client.post(f"/api/v1/incidents/{inc_id}/run", headers=analyst_auth)
    assert resp.status_code == 200


async def test_analyst_cannot_delete_incident(client, auth, analyst_auth):
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]
    assert (await client.delete(f"/api/v1/incidents/{inc_id}", headers=analyst_auth)).status_code == 403


async def test_analyst_cannot_create_users(client, analyst_auth):
    assert (await client.post("/api/v1/users", json=_USER, headers=analyst_auth)).status_code == 403


async def test_analyst_cannot_manage_tenants(client, analyst_auth):
    assert (await client.get("/api/v1/tenants", headers=analyst_auth)).status_code == 403


async def test_analyst_can_create_and_update_case(client, analyst_auth):
    case_id = (await client.post("/api/v1/cases", json=_CASE, headers=analyst_auth)).json()["id"]
    resp = await client.patch(
        f"/api/v1/cases/{case_id}", json={"status": "INVESTIGATING"}, headers=analyst_auth
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Role: ADMIN
# ---------------------------------------------------------------------------


async def test_admin_can_delete_incident(client, auth):
    inc_id = (await client.post("/api/v1/incidents", json=_INC, headers=auth)).json()["id"]
    assert (await client.delete(f"/api/v1/incidents/{inc_id}", headers=auth)).status_code == 204


async def test_admin_can_create_users(client, auth):
    resp = await client.post("/api/v1/users", json=_USER, headers=auth)
    assert resp.status_code == 201


async def test_admin_can_list_users(client, auth):
    assert (await client.get("/api/v1/users", headers=auth)).status_code == 200


async def test_admin_can_list_tenants(client, auth):
    assert (await client.get("/api/v1/tenants", headers=auth)).status_code == 200


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


async def test_tenant_isolation_incidents(api_client, db_session):
    """Incident created in tenant A must NOT appear when queried from tenant B."""
    from api.models.tenant import Tenant
    from api.models.user import User
    from api.services.auth_service import create_access_token, hash_password

    # Tenant A
    tenant_a = Tenant(name="Tenant A", slug=f"tenant-a-{uuid.uuid4().hex[:4]}")
    db_session.add(tenant_a)
    # Tenant B
    tenant_b = Tenant(name="Tenant B", slug=f"tenant-b-{uuid.uuid4().hex[:4]}")
    db_session.add(tenant_b)
    await db_session.flush()

    admin_a = User(
        tenant_id=tenant_a.id, email="admin@tenant-a.com",
        hashed_password=hash_password("Password123!"), role="ADMIN",
    )
    admin_b = User(
        tenant_id=tenant_b.id, email="admin@tenant-b.com",
        hashed_password=hash_password("Password123!"), role="ADMIN",
    )
    db_session.add_all([admin_a, admin_b])
    await db_session.flush()

    token_a = create_access_token(str(admin_a.id), str(tenant_a.id), "ADMIN")
    token_b = create_access_token(str(admin_b.id), str(tenant_b.id), "ADMIN")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant A creates an incident
    create_resp = await api_client.post("/api/v1/incidents", json=_INC, headers=headers_a)
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # Tenant B cannot see it
    list_b = await api_client.get("/api/v1/incidents", headers=headers_b)
    assert list_b.status_code == 200
    ids_in_b = [i["id"] for i in list_b.json()["items"]]
    assert inc_id not in ids_in_b

    # Tenant B cannot get it directly
    get_resp = await api_client.get(f"/api/v1/incidents/{inc_id}", headers=headers_b)
    assert get_resp.status_code == 404
