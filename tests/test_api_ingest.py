"""tests/test_api_ingest.py — API tests for the /ingest/upload endpoint."""

from __future__ import annotations

import json
import uuid


async def test_upload_json_success(api_client, admin_token, seeded_db):
    threat = f"Ransomware-{uuid.uuid4().hex[:8]}"
    payload = json.dumps([{"threat_name": threat, "severity": "HIGH"}]).encode()
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("incidents.json", payload, "application/json")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["parsed_count"] == 1
    assert data["accepted_count"] == 1
    assert data["format"] == "json"


async def test_upload_csv_success(api_client, admin_token, seeded_db):
    threat = f"SQLInjection-{uuid.uuid4().hex[:8]}"
    csv = f"threat_name,severity,indicators\n{threat},HIGH,192.168.1.1\n"
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("events.csv", csv.encode(), "text/csv")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["parsed_count"] == 1
    assert data["format"] == "csv"


async def test_upload_syslog_success(api_client, admin_token, seeded_db):
    log = b"<134>Jun 17 12:00:01 server01 sshd[1234]: Failed password for root from 10.0.0.1 port 22"
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("system.log", log, "text/plain")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["parsed_count"] >= 1


async def test_upload_requires_auth(api_client, seeded_db):
    payload = json.dumps([{"threat_name": "T"}]).encode()
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        files={"file": ("x.json", payload, "application/json")},
    )
    assert resp.status_code in (401, 403)


async def test_upload_viewer_cannot_upload(api_client, viewer_token, seeded_db):
    payload = json.dumps([{"threat_name": "T"}]).encode()
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {viewer_token}"},
        files={"file": ("x.json", payload, "application/json")},
    )
    assert resp.status_code == 403


async def test_upload_unsupported_extension_rejected(api_client, admin_token, seeded_db):
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("malware.exe", b"binary data", "application/octet-stream")},
    )
    assert resp.status_code == 400


async def test_upload_invalid_json_returns_parse_errors(api_client, admin_token, seeded_db):
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("bad.json", b"{not: valid json}", "application/json")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted_count"] == 0
    assert data["error_count"] >= 1


async def test_upload_analyst_can_upload(api_client, analyst_token, seeded_db):
    threat = f"Phishing-{uuid.uuid4().hex[:8]}"
    payload = json.dumps([{"threat_name": threat, "severity": "MEDIUM"}]).encode()
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {analyst_token}"},
        files={"file": ("x.json", payload, "application/json")},
    )
    assert resp.status_code == 200


async def test_upload_returns_upload_id(api_client, admin_token, seeded_db):
    threat = f"T-{uuid.uuid4().hex[:8]}"
    payload = json.dumps([{"threat_name": threat}]).encode()
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("x.json", payload, "application/json")},
    )
    assert resp.status_code == 200
    assert "upload_id" in resp.json()


async def test_upload_history_endpoint(api_client, admin_token, seeded_db):
    resp = await api_client.get(
        "/api/v1/ingest/history",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_upload_empty_json_array(api_client, admin_token, seeded_db):
    resp = await api_client.post(
        "/api/v1/ingest/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("empty.json", b"[]", "application/json")},
    )
    assert resp.status_code == 200
    assert resp.json()["parsed_count"] == 0
    assert resp.json()["accepted_count"] == 0
