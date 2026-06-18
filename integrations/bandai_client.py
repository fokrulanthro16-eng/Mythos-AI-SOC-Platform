"""
integrations/bandai_client.py — BandAI multi-agent task execution platform client.

Set BANDAI_PLANNER_ID / BANDAI_FORENSICS_ID / BANDAI_COMPLIANCE_ID in .env
to enable live mode; omit all three for mock mode.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from typing import Any

_MOCK_RESULTS_BY_ROLE: dict[str, dict[str, Any]] = {
    "planner": {
        "status": "complete",
        "agent_role": "planner",
        "result": {"action": "analyze_signal", "ioc_count": 3, "confidence": 0.62},
    },
    "forensics": {
        "status": "complete",
        "agent_role": "forensics",
        "result": {
            "attribution": "TA505-AFFILIATE",
            "confidence": 0.87,
            "techniques": ["T1566", "T1071"],
        },
    },
    "compliance": {
        "status": "complete",
        "agent_role": "compliance",
        "result": {"playbook_triggered": True, "actions_count": 5, "escalation_required": True},
    },
}


class BandAIClient:
    """
    BandAI multi-agent task execution platform client.
    Falls back to mock mode when no agent credentials are configured.
    """

    def __init__(self) -> None:
        self.planner_id: str = os.getenv("BANDAI_PLANNER_ID", "")
        self.forensics_id: str = os.getenv("BANDAI_FORENSICS_ID", "")
        self.compliance_id: str = os.getenv("BANDAI_COMPLIANCE_ID", "")
        self.base_url: str = os.getenv("BANDAI_BASE_URL", "https://api.bandai.ai/v1")
        self.mock_mode: bool = not any(
            [self.planner_id, self.forensics_id, self.compliance_id]
        )
        self._mock_store: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def submit_task(self, agent_id: str, task: dict[str, Any]) -> str:
        """Submit a task to the specified agent. Returns a task_id string."""
        if self.mock_mode:
            task_id = f"MOCK-{uuid.uuid4().hex[:8].upper()}"
            role = self._infer_role(agent_id)
            self._mock_store[task_id] = dict(
                _MOCK_RESULTS_BY_ROLE.get(
                    role,
                    {"status": "complete", "agent_role": agent_id, "result": {"processed": True}},
                )
            )
            return task_id
        return self._api_submit_task(agent_id, task)

    def get_result(self, task_id: str) -> dict[str, Any]:
        """Return the result of a submitted task."""
        if self.mock_mode:
            return self._mock_store.get(
                task_id,
                {"status": "not_found", "task_id": task_id, "result": {}},
            )
        return self._api_get_result(task_id)

    def health_check(self) -> dict[str, Any]:
        """Return health status of all registered agents."""
        if self.mock_mode:
            return {
                "status": "mock",
                "mode": "offline",
                "agents": {
                    "planner":    {"id": self.planner_id or "unset",    "status": "mock"},
                    "forensics":  {"id": self.forensics_id or "unset",  "status": "mock"},
                    "compliance": {"id": self.compliance_id or "unset", "status": "mock"},
                },
                "message": "Running in mock mode. Set BANDAI_* env vars to connect.",
            }
        return self._api_health_check()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _infer_role(self, agent_id: str) -> str:
        lowered = agent_id.lower()
        for role in ("planner", "forensics", "compliance"):
            if role in lowered:
                return role
        return "unknown"

    # ------------------------------------------------------------------
    # Real API calls (invoked only when credentials are present)
    # ------------------------------------------------------------------

    def _api_post(self, endpoint: str, payload: dict) -> dict:
        url = f"{self.base_url}/{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _api_get(self, endpoint: str) -> dict:
        url = f"{self.base_url}/{endpoint}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _api_submit_task(self, agent_id: str, task: dict) -> str:
        result = self._api_post(f"agents/{agent_id}/tasks", task)
        return result.get("task_id", "")

    def _api_get_result(self, task_id: str) -> dict:
        return self._api_get(f"tasks/{task_id}")

    def _api_health_check(self) -> dict:
        return self._api_get("health")
