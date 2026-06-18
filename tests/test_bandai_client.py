"""tests/test_bandai_client.py — Unit tests for BandAIClient."""

from __future__ import annotations

from unittest.mock import patch

from integrations.bandai_client import BandAIClient


def _mock_client() -> BandAIClient:
    return BandAIClient()  # no BANDAI_* env vars -> mock_mode=True


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_mock_mode_when_no_credentials():
    client = _mock_client()
    assert client.mock_mode is True


def test_real_mode_when_any_credential_set():
    with patch.dict("os.environ", {"BANDAI_FORENSICS_ID": "forensics-123"}):
        client = BandAIClient()
    assert client.mock_mode is False


def test_default_base_url():
    client = _mock_client()
    assert "bandai" in client.base_url


# ---------------------------------------------------------------------------
# submit_task
# ---------------------------------------------------------------------------


def test_submit_task_returns_string():
    task_id = _mock_client().submit_task("forensics-agent", {"threat": "APT"})
    assert isinstance(task_id, str) and len(task_id) > 0


def test_submit_task_returns_mock_prefix():
    task_id = _mock_client().submit_task("planner-agent", {})
    assert task_id.startswith("MOCK-")


def test_submit_task_unique_ids():
    client = _mock_client()
    ids = {client.submit_task("agent", {}) for _ in range(10)}
    assert len(ids) == 10


def test_submit_task_planner_role_inferred():
    client = _mock_client()
    task_id = client.submit_task("planner-main", {"data": "x"})
    result = client.get_result(task_id)
    assert result.get("agent_role") == "planner"


def test_submit_task_forensics_role_inferred():
    client = _mock_client()
    task_id = client.submit_task("forensics-agent", {})
    result = client.get_result(task_id)
    assert result.get("agent_role") == "forensics"


def test_submit_task_compliance_role_inferred():
    client = _mock_client()
    task_id = client.submit_task("compliance-service", {})
    result = client.get_result(task_id)
    assert result.get("agent_role") == "compliance"


# ---------------------------------------------------------------------------
# get_result
# ---------------------------------------------------------------------------


def test_get_result_returns_dict():
    client = _mock_client()
    task_id = client.submit_task("forensics-agent", {})
    result = client.get_result(task_id)
    assert isinstance(result, dict)


def test_get_result_has_status_key():
    client = _mock_client()
    task_id = client.submit_task("planner-agent", {})
    result = client.get_result(task_id)
    assert "status" in result


def test_get_result_complete_after_submit():
    client = _mock_client()
    task_id = client.submit_task("forensics-agent", {})
    result = client.get_result(task_id)
    assert result["status"] == "complete"


def test_get_result_unknown_task_id_returns_not_found():
    result = _mock_client().get_result("FAKE-TASK-ID")
    assert result["status"] == "not_found"


def test_get_result_forensics_has_attribution():
    client = _mock_client()
    task_id = client.submit_task("forensics-worker", {})
    result = client.get_result(task_id)
    assert "attribution" in result.get("result", {})


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


def test_health_check_returns_dict():
    assert isinstance(_mock_client().health_check(), dict)


def test_health_check_mock_status():
    hc = _mock_client().health_check()
    assert hc["status"] == "mock"


def test_health_check_lists_all_agents():
    hc = _mock_client().health_check()
    agents = hc.get("agents", {})
    assert "planner" in agents
    assert "forensics" in agents
    assert "compliance" in agents


def test_health_check_has_message():
    hc = _mock_client().health_check()
    assert "message" in hc


# ---------------------------------------------------------------------------
# _infer_role
# ---------------------------------------------------------------------------


def test_infer_role_forensics():
    assert _mock_client()._infer_role("forensics-agent") == "forensics"


def test_infer_role_planner():
    assert _mock_client()._infer_role("planner-001") == "planner"


def test_infer_role_unknown():
    assert _mock_client()._infer_role("mystery-service") == "unknown"
