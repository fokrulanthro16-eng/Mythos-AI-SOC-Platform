"""tests/test_api_auth.py — Authentication endpoint tests."""

from __future__ import annotations

import pytest


@pytest.fixture
async def client(api_client, seeded_db):
    return api_client


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login
# ---------------------------------------------------------------------------


async def test_login_success(client, seeded_db):
    email = seeded_db["admin"].email
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Password123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


async def test_login_wrong_password(client, seeded_db):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": seeded_db["admin"].email, "password": "WrongPassword1"},
    )
    assert resp.status_code == 401


async def test_login_unknown_email(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@nowhere.com", "password": "Password123!"},
    )
    assert resp.status_code == 401


async def test_login_all_three_roles(client, seeded_db):
    for key in ("admin", "analyst", "viewer"):
        email = seeded_db[key].email
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "Password123!"},
        )
        assert resp.status_code == 200, f"Login failed for {key} ({email})"


# ---------------------------------------------------------------------------
# POST /api/v1/auth/refresh
# ---------------------------------------------------------------------------


async def test_refresh_returns_new_access_token(client, seeded_db):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": seeded_db["admin"].email, "password": "Password123!"},
    )
    refresh_token = login.json()["refresh_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


async def test_refresh_with_access_token_fails(client, seeded_db):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": seeded_db["admin"].email, "password": "Password123!"},
    )
    access_token = login.json()["access_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
    assert resp.status_code == 401


async def test_refresh_with_garbage_fails(client, seeded_db):
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.token"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout
# ---------------------------------------------------------------------------


async def test_logout_success(client, admin_token, seeded_db):
    resp = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


async def test_logout_without_token_fails(client, seeded_db):
    resp = await client.post("/api/v1/auth/logout")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /api/v1/auth/me
# ---------------------------------------------------------------------------


async def test_me_returns_current_user(client, admin_token, seeded_db):
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == seeded_db["admin"].email
    assert data["role"] == "ADMIN"


async def test_me_without_token_fails(client, seeded_db):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403)


async def test_me_with_invalid_token_fails(client, seeded_db):
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.payload"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /health and /metrics (no auth required)
# ---------------------------------------------------------------------------


async def test_health_endpoint(client, seeded_db):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_metrics_endpoint(client, seeded_db):
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert b"mythos_" in resp.content
