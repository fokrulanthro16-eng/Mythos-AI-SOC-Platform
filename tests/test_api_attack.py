"""tests/test_api_attack.py — API tests for MITRE ATT&CK endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PREFIX = "/api/v1"


# ---------------------------------------------------------------------------
# GET /attack/techniques — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_techniques_returns_list(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) >= 8


@pytest.mark.asyncio
async def test_list_techniques_each_has_required_fields(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    for tech in r.json():
        assert "technique_id" in tech
        assert "technique_name" in tech
        assert "tactic" in tech
        assert "url" in tech


@pytest.mark.asyncio
async def test_list_techniques_unauthenticated_returns_401(api_client: AsyncClient):
    r = await api_client.get(f"{_PREFIX}/attack/techniques")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_techniques_search_filter(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques?search=ransomware",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    ids = [t["technique_id"] for t in data]
    assert "T1486" in ids


@pytest.mark.asyncio
async def test_list_techniques_tactic_filter(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques?tactic=Execution",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data) > 0
    for tech in data:
        assert "execution" in tech["tactic"].lower()


@pytest.mark.asyncio
async def test_list_techniques_limit_respected(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques?limit=3",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert len(r.json()) <= 3


@pytest.mark.asyncio
async def test_list_techniques_search_no_match_returns_empty(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques?search=zzz_no_match_xyz_qrs",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_techniques_analyst_can_access(api_client: AsyncClient, analyst_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_list_techniques_admin_can_access(api_client: AsyncClient, admin_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# GET /attack/techniques/{id} — single technique
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_technique_known_id(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques/T1059",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["technique_id"] == "T1059"


@pytest.mark.asyncio
async def test_get_technique_case_insensitive(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques/t1059",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert r.json()["technique_id"] == "T1059"


@pytest.mark.asyncio
async def test_get_technique_unknown_id_returns_404(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/techniques/T9999",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_technique_unauthenticated_returns_401(api_client: AsyncClient):
    r = await api_client.get(f"{_PREFIX}/attack/techniques/T1059")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_get_each_required_technique(api_client: AsyncClient, viewer_token: str):
    required = ["T1056", "T1059", "T1071", "T1041", "T1110", "T1566", "T1486", "T1027"]
    for tid in required:
        r = await api_client.get(
            f"{_PREFIX}/attack/techniques/{tid}",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 200, f"GET /attack/techniques/{tid} returned {r.status_code}"
        assert r.json()["technique_id"] == tid


# ---------------------------------------------------------------------------
# GET /attack/stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_returns_dict(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_get_stats_has_required_keys(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    data = r.json()
    for key in ("total_techniques", "total_tactics", "techniques_by_tactic", "incidents_with_attack_mapping"):
        assert key in data, f"Missing key: {key}"


@pytest.mark.asyncio
async def test_get_stats_total_techniques_ge_8(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.json()["total_techniques"] >= 8


@pytest.mark.asyncio
async def test_get_stats_most_common_is_list(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert isinstance(r.json()["most_common_techniques"], list)


@pytest.mark.asyncio
async def test_get_stats_unauthenticated_returns_401(api_client: AsyncClient):
    r = await api_client.get(f"{_PREFIX}/attack/stats")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_stats_incidents_with_mapping_zero_when_no_incidents(api_client: AsyncClient, viewer_token: str):
    r = await api_client.get(
        f"{_PREFIX}/attack/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    # Empty DB — no incidents yet, so mapping count must be 0
    assert r.json()["incidents_with_attack_mapping"] == 0


# ---------------------------------------------------------------------------
# Incident creation → ATT&CK mapping integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_incident_populates_attack_techniques(api_client: AsyncClient, analyst_token: str):
    r = await api_client.post(
        f"{_PREFIX}/incidents",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "threat_name": "RANSOMWARE-LOCKBIT3",
            "severity": "CRITICAL",
            "indicators": ["lockbit.exe", "ransom.txt"],
        },
    )
    assert r.status_code == 201
    data = r.json()
    techs = data.get("attack_techniques", [])
    assert isinstance(techs, list)
    # Ransomware should map to T1486 at minimum
    ids = [t["technique_id"] for t in techs]
    assert "T1486" in ids


@pytest.mark.asyncio
async def test_create_incident_phishing_maps_t1566(api_client: AsyncClient, analyst_token: str):
    r = await api_client.post(
        f"{_PREFIX}/incidents",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "threat_name": "PHISH-CREDENTIAL-HARVEST",
            "severity": "HIGH",
            "indicators": ["phishing-link.com"],
        },
    )
    assert r.status_code == 201
    ids = [t["technique_id"] for t in r.json().get("attack_techniques", [])]
    assert "T1566" in ids or "T1056" in ids
