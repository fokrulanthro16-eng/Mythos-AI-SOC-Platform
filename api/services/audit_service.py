"""api/services/audit_service.py — Structured JSON security audit logger.

Writes to logs/audit.jsonl (always) and optionally to the audit_logs DB table.
File-based logging is write-ahead so audit records survive DB failures.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "audit.jsonl"
_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_file_handler = logging.FileHandler(str(_AUDIT_LOG_PATH), encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_logger = logging.getLogger("mythos.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
if not _audit_logger.handlers:
    _audit_logger.addHandler(_file_handler)


def log_event(
    *,
    action: str,
    resource_type: str,
    outcome: str = "SUCCESS",
    user_id: str | None = None,
    user_email: str | None = None,
    tenant_id: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Write one audit event as a JSON line to audit.jsonl."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "resource_type": resource_type,
        "outcome": outcome,
        "user_id": user_id,
        "user_email": user_email,
        "tenant_id": tenant_id,
        "resource_id": resource_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "detail": detail or {},
    }
    _audit_logger.info(json.dumps(record, default=str))


async def persist_to_db(
    db: Any,
    *,
    action: str,
    resource_type: str,
    outcome: str = "SUCCESS",
    user_id: str | None = None,
    user_email: str | None = None,
    tenant_id: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Persist audit record to the audit_logs DB table (best-effort)."""
    try:
        from api.models.audit import AuditLog

        entry = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            user_email=user_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            outcome=outcome,
            detail=detail or {},
        )
        db.add(entry)
        await db.flush()
    except Exception:
        pass
