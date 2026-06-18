"""api/routers/cases.py — Case management: CRUD, notes, history, stats."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import get_current_user, pagination, require_roles
from api.models.case import Case, CaseStatus
from api.models.case_event import CaseEvent, CaseEventType
from api.models.incident import Incident
from api.models.user import Role, User
from api.schemas.case import (
    CaseCreate,
    CaseEventRead,
    CaseNoteCreate,
    CaseRead,
    CaseStats,
    CaseUpdate,
)
from api.schemas.common import Page, PaginationParams
from api.services.audit_service import log_event
from api.services.case_service import auto_case_number, record_event
from api.services.metrics_service import ACTIVE_CASES, CASES_CREATED

router = APIRouter(prefix="/cases", tags=["cases"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _incident_count(db: AsyncSession, case_id: uuid.UUID) -> int:
    r = await db.execute(
        select(func.count()).select_from(
            select(Incident).where(Incident.case_id == case_id).subquery()
        )
    )
    return r.scalar_one()


async def _notes_count(db: AsyncSession, case_id: uuid.UUID) -> int:
    r = await db.execute(
        select(func.count()).select_from(
            select(CaseEvent)
            .where(CaseEvent.case_id == case_id, CaseEvent.event_type == CaseEventType.NOTE.value)
            .subquery()
        )
    )
    return r.scalar_one()


async def _enrich_read(db: AsyncSession, case: Case) -> CaseRead:
    cr = CaseRead.model_validate(case)
    cr.incident_count = await _incident_count(db, case.id)
    cr.notes_count = await _notes_count(db, case.id)
    return cr


async def _get_case_or_404(db: AsyncSession, case_id: uuid.UUID, tenant_id: uuid.UUID) -> Case:
    r = await db.execute(
        select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
    )
    case = r.scalar_one_or_none()
    if case is None:
        raise HTTPException(404, "Case not found")
    return case


# ---------------------------------------------------------------------------
# Stats  (must be defined BEFORE /{case_id} to avoid UUID parse attempt)
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=CaseStats)
async def case_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CaseStats:
    """Aggregate case statistics for the current tenant."""
    base = select(Case).where(Case.tenant_id == current_user.tenant_id)

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()

    by_status: dict[str, int] = {}
    for status in CaseStatus:
        cnt = (
            await db.execute(
                select(func.count()).select_from(
                    base.where(Case.status == status).subquery()
                )
            )
        ).scalar_one()
        by_status[status.value] = cnt

    from api.models.case import CasePriority

    by_priority: dict[str, int] = {}
    for prio in CasePriority:
        cnt = (
            await db.execute(
                select(func.count()).select_from(
                    base.where(Case.priority == prio).subquery()
                )
            )
        ).scalar_one()
        by_priority[prio.value] = cnt

    # Avg resolution hours (cases that have resolved_at set)
    resolved_rows = (
        await db.execute(
            select(Case.created_at, Case.resolved_at).where(
                Case.tenant_id == current_user.tenant_id,
                Case.resolved_at.isnot(None),
            )
        )
    ).all()
    avg_hours: float | None = None
    if resolved_rows:
        durations = [
            (row.resolved_at - row.created_at).total_seconds() / 3600
            for row in resolved_rows
            if row.resolved_at and row.created_at
        ]
        avg_hours = sum(durations) / len(durations) if durations else None

    return CaseStats(
        total=total,
        by_status=by_status,
        by_priority=by_priority,
        open_count=by_status.get("OPEN", 0),
        investigating_count=by_status.get("INVESTIGATING", 0),
        contained_count=by_status.get("CONTAINED", 0),
        resolved_count=by_status.get("RESOLVED", 0),
        closed_count=by_status.get("CLOSED", 0),
        avg_resolution_hours=avg_hours,
    )


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@router.get("", response_model=Page[CaseRead])
async def list_cases(
    case_status: str | None = None,
    priority: str | None = None,
    search: str | None = Query(default=None, description="Search by title or case number"),
    paging: PaginationParams = Depends(pagination),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Page[CaseRead]:
    q = select(Case).where(Case.tenant_id == current_user.tenant_id)
    if case_status:
        try:
            q = q.where(Case.status == CaseStatus(case_status.upper()))
        except ValueError:
            raise HTTPException(400, f"Invalid status: {case_status}")
    if priority:
        q = q.where(Case.priority == priority.upper())
    if search:
        pattern = f"%{search}%"
        q = q.where(
            Case.title.ilike(pattern) | Case.case_number.ilike(pattern)
        )

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (
        await db.execute(q.order_by(Case.created_at.desc()).offset(paging.offset).limit(paging.size))
    ).scalars().all()

    items = [await _enrich_read(db, c) for c in rows]
    return Page(
        items=items,
        total=total,
        page=paging.page,
        size=paging.size,
        pages=max(1, math.ceil(total / paging.size)),
    )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@router.post("", response_model=CaseRead, status_code=201)
async def create_case(
    body: CaseCreate,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> CaseRead:
    case = Case(
        tenant_id=current_user.tenant_id,
        case_number=auto_case_number(),
        title=body.title,
        description=body.description,
        priority=body.priority,
        assigned_to=body.assigned_to,
        created_by=current_user.id,
    )
    db.add(case)
    await db.flush()

    await record_event(
        db,
        case_id=case.id,
        tenant_id=current_user.tenant_id,
        author_id=current_user.id,
        event_type=CaseEventType.CREATED,
        content=f"Case created: {body.title}",
    )

    CASES_CREATED.labels(
        tenant_id=str(current_user.tenant_id), priority=case.priority.value
    ).inc()
    ACTIVE_CASES.labels(tenant_id=str(current_user.tenant_id)).inc()
    log_event(
        action="CREATE_CASE",
        resource_type="case",
        resource_id=str(case.id),
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
        detail={"case_number": case.case_number, "title": body.title},
    )
    await db.refresh(case)
    return await _enrich_read(db, case)


# ---------------------------------------------------------------------------
# Get by ID
# ---------------------------------------------------------------------------


@router.get("/{case_id}", response_model=CaseRead)
async def get_case(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CaseRead:
    case = await _get_case_or_404(db, case_id, current_user.tenant_id)
    return await _enrich_read(db, case)


# ---------------------------------------------------------------------------
# Update (PATCH)
# ---------------------------------------------------------------------------


@router.patch("/{case_id}", response_model=CaseRead)
async def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> CaseRead:
    case = await _get_case_or_404(db, case_id, current_user.tenant_id)
    updates = body.model_dump(exclude_unset=True)

    old_status = getattr(case.status, "value", str(case.status))
    old_priority = getattr(case.priority, "value", str(case.priority))
    old_assigned = str(case.assigned_to) if case.assigned_to else ""

    # Set resolved_at when transitioning to RESOLVED
    new_status = updates.get("status")
    if new_status in (CaseStatus.RESOLVED, "RESOLVED") and case.resolved_at is None:
        case.resolved_at = datetime.now(timezone.utc)
        ACTIVE_CASES.labels(tenant_id=str(current_user.tenant_id)).dec()
    if new_status in (CaseStatus.CLOSED, "CLOSED"):
        ACTIVE_CASES.labels(tenant_id=str(current_user.tenant_id)).dec()

    for field, val in updates.items():
        setattr(case, field, val)

    await db.flush()
    await db.refresh(case)

    # Record timeline events for each changed field
    new_status_val = getattr(case.status, "value", str(case.status))
    if new_status_val != old_status:
        await record_event(
            db,
            case_id=case.id,
            tenant_id=current_user.tenant_id,
            author_id=current_user.id,
            event_type=CaseEventType.STATUS_CHANGE,
            content=f"Status changed from {old_status} to {new_status_val}",
            old_value=old_status,
            new_value=new_status_val,
        )

    new_priority_val = getattr(case.priority, "value", str(case.priority))
    if new_priority_val != old_priority and "priority" in updates:
        await record_event(
            db,
            case_id=case.id,
            tenant_id=current_user.tenant_id,
            author_id=current_user.id,
            event_type=CaseEventType.PRIORITY_CHANGE,
            content=f"Priority changed from {old_priority} to {new_priority_val}",
            old_value=old_priority,
            new_value=new_priority_val,
        )

    new_assigned = str(case.assigned_to) if case.assigned_to else ""
    if new_assigned != old_assigned and "assigned_to" in updates:
        await record_event(
            db,
            case_id=case.id,
            tenant_id=current_user.tenant_id,
            author_id=current_user.id,
            event_type=CaseEventType.ASSIGNMENT,
            content=f"Assigned to {new_assigned or 'nobody'}",
            old_value=old_assigned,
            new_value=new_assigned,
        )

    log_event(
        action="UPDATE_CASE",
        resource_type="case",
        resource_id=str(case_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
        detail=updates,
    )
    return await _enrich_read(db, case)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> None:
    case = await _get_case_or_404(db, case_id, current_user.tenant_id)
    await db.delete(case)
    log_event(
        action="DELETE_CASE",
        resource_type="case",
        resource_id=str(case_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@router.post("/{case_id}/notes", response_model=CaseEventRead, status_code=201)
async def add_note(
    case_id: uuid.UUID,
    body: CaseNoteCreate,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> CaseEventRead:
    """Append an analyst note to a case timeline."""
    await _get_case_or_404(db, case_id, current_user.tenant_id)

    event = await record_event(
        db,
        case_id=case_id,
        tenant_id=current_user.tenant_id,
        author_id=current_user.id,
        event_type=CaseEventType.NOTE,
        content=body.content,
    )
    log_event(
        action="ADD_NOTE",
        resource_type="case",
        resource_id=str(case_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
        detail={"note_length": len(body.content)},
    )
    return CaseEventRead.model_validate(event)


@router.get("/{case_id}/notes", response_model=list[CaseEventRead])
async def list_notes(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CaseEventRead]:
    """Return all analyst notes for a case (chronological)."""
    await _get_case_or_404(db, case_id, current_user.tenant_id)

    rows = (
        await db.execute(
            select(CaseEvent)
            .where(
                CaseEvent.case_id == case_id,
                CaseEvent.event_type == CaseEventType.NOTE.value,
            )
            .order_by(CaseEvent.created_at.asc())
        )
    ).scalars().all()
    return [CaseEventRead.model_validate(e) for e in rows]


# ---------------------------------------------------------------------------
# History / Timeline
# ---------------------------------------------------------------------------


@router.get("/{case_id}/history", response_model=list[CaseEventRead])
async def case_history(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CaseEventRead]:
    """Return full case timeline (all event types, chronological)."""
    await _get_case_or_404(db, case_id, current_user.tenant_id)

    rows = (
        await db.execute(
            select(CaseEvent)
            .where(CaseEvent.case_id == case_id)
            .order_by(CaseEvent.created_at.asc())
        )
    ).scalars().all()
    return [CaseEventRead.model_validate(e) for e in rows]


# ---------------------------------------------------------------------------
# Link / Unlink incidents
# ---------------------------------------------------------------------------


@router.post("/{case_id}/incidents/{incident_id}", response_model=CaseRead)
async def link_incident(
    case_id: uuid.UUID,
    incident_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> CaseRead:
    case = await _get_case_or_404(db, case_id, current_user.tenant_id)

    inc_r = await db.execute(
        select(Incident).where(
            Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id
        )
    )
    inc = inc_r.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")

    inc.case_id = case_id
    await db.flush()

    await record_event(
        db,
        case_id=case_id,
        tenant_id=current_user.tenant_id,
        author_id=current_user.id,
        event_type=CaseEventType.INCIDENT_LINKED,
        content=f"Incident {inc.incident_id} linked",
        new_value=str(incident_id),
    )
    return await _enrich_read(db, case)


@router.delete("/{case_id}/incidents/{incident_id}", response_model=CaseRead)
async def unlink_incident(
    case_id: uuid.UUID,
    incident_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> CaseRead:
    case = await _get_case_or_404(db, case_id, current_user.tenant_id)

    inc_r = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.case_id == case_id,
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    inc = inc_r.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not linked to this case")

    inc.case_id = None
    await db.flush()

    await record_event(
        db,
        case_id=case_id,
        tenant_id=current_user.tenant_id,
        author_id=current_user.id,
        event_type=CaseEventType.INCIDENT_UNLINKED,
        content=f"Incident {inc.incident_id} unlinked",
        old_value=str(incident_id),
    )
    return await _enrich_read(db, case)
