"""api/services/case_service.py — Case creation helpers and timeline recording."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.models.case import Case, CasePriority, CaseStatus
from api.models.case_event import CaseEvent, CaseEventType

_SEV_TO_PRIORITY: dict[str, CasePriority] = {
    "CRITICAL": CasePriority.P1,
    "HIGH":     CasePriority.P2,
    "MEDIUM":   CasePriority.P3,
    "LOW":      CasePriority.P4,
}


def auto_case_number() -> str:
    year = datetime.now(timezone.utc).strftime("%Y")
    return f"CASE-{year}-{random.randint(1000, 9999)}"


async def auto_create_case(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: str,
    threat_name: str,
    severity: str,
    user_id: uuid.UUID | None = None,
) -> Case:
    """Create a Case for a new incident and emit a CREATED timeline event."""
    case = Case(
        tenant_id=tenant_id,
        case_number=auto_case_number(),
        title=f"[Auto] {threat_name}",
        description=f"Auto-generated case for incident {incident_id}.",
        priority=_SEV_TO_PRIORITY.get(severity.upper(), CasePriority.P3),
        status=CaseStatus.OPEN,
        created_by=user_id,
    )
    db.add(case)
    await db.flush()

    db.add(
        CaseEvent(
            case_id=case.id,
            tenant_id=tenant_id,
            author_id=user_id,
            event_type=CaseEventType.CREATED.value,
            content=f"Case auto-created for incident {incident_id} — {threat_name}",
        )
    )
    await db.flush()
    return case


async def record_event(
    db: AsyncSession,
    *,
    case_id: uuid.UUID,
    tenant_id: uuid.UUID,
    author_id: uuid.UUID | None,
    event_type: CaseEventType | str,
    content: str = "",
    old_value: str = "",
    new_value: str = "",
) -> CaseEvent:
    """Append a timeline event to a case."""
    event = CaseEvent(
        case_id=case_id,
        tenant_id=tenant_id,
        author_id=author_id,
        event_type=getattr(event_type, "value", event_type),
        content=content,
        old_value=old_value,
        new_value=new_value,
    )
    db.add(event)
    await db.flush()
    return event
