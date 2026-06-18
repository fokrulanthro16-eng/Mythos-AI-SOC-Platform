"""api/routers/incidents.py — Incident CRUD + pipeline trigger."""

from __future__ import annotations

import asyncio
import math
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import get_current_user, pagination, require_roles
from api.models.incident import Incident
from api.models.user import Role, User
from api.schemas.common import Page, PaginationParams
from api.schemas.incident import IncidentCreate, IncidentRead, IncidentUpdate
from api.services.audit_service import log_event
from api.services.case_service import auto_create_case
from api.services.metrics_service import INCIDENTS_CREATED, PIPELINE_DURATION, PIPELINE_RUNS
from intelligence.attack_engine import AttackEngine

_attack_engine = AttackEngine()

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _to_read(inc: Incident) -> IncidentRead:
    return IncidentRead.model_validate(inc)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@router.get("", response_model=Page[IncidentRead])
async def list_incidents(
    severity: str | None = None,
    status: str | None = None,
    paging: PaginationParams = Depends(pagination),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Page[IncidentRead]:
    q = select(Incident).where(Incident.tenant_id == current_user.tenant_id)
    if severity:
        q = q.where(Incident.severity == severity.upper())
    if status:
        q = q.where(Incident.status == status.upper())

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    rows_result = await db.execute(
        q.order_by(Incident.created_at.desc()).offset(paging.offset).limit(paging.size)
    )
    items = [_to_read(r) for r in rows_result.scalars()]
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


@router.post("", response_model=IncidentRead, status_code=201)
async def create_incident(
    body: IncidentCreate,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> IncidentRead:
    incident_id = body.incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y-%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    inc = Incident(
        tenant_id=current_user.tenant_id,
        incident_id=incident_id,
        threat_name=body.threat_name,
        severity=body.severity.upper(),
        indicators=body.indicators,
        created_by=current_user.id,
    )
    db.add(inc)
    await db.flush()

    # Auto-create a case and link this incident to it
    case = await auto_create_case(
        db,
        tenant_id=current_user.tenant_id,
        incident_id=incident_id,
        threat_name=body.threat_name,
        severity=body.severity.upper(),
        user_id=current_user.id,
    )
    inc.case_id = case.id

    # Immediate ATT&CK mapping so the field is populated before pipeline runs
    techniques = _attack_engine.map_threat(body.threat_name, body.indicators)
    from intelligence.attack_engine import _slim
    inc.attack_techniques = [_slim(t) for t in techniques]

    await db.flush()
    await db.refresh(inc)

    INCIDENTS_CREATED.labels(
        tenant_id=str(current_user.tenant_id), severity=inc.severity
    ).inc()
    log_event(
        action="CREATE_INCIDENT",
        resource_type="incident",
        resource_id=str(inc.id),
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
        detail={"incident_id": incident_id, "threat_name": body.threat_name, "case_id": str(case.id)},
    )
    return _to_read(inc)


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> IncidentRead:
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    inc = result.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")
    return _to_read(inc)


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


@router.patch("/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> IncidentRead:
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    inc = result.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")

    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(inc, field, val)

    await db.flush()
    await db.refresh(inc)
    log_event(
        action="UPDATE_INCIDENT",
        resource_type="incident",
        resource_id=str(inc.id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )
    return _to_read(inc)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(
    incident_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    inc = result.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")
    await db.delete(inc)
    log_event(
        action="DELETE_INCIDENT",
        resource_type="incident",
        resource_id=str(incident_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )


# ---------------------------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------------------------


@router.post("/{incident_id}/run", response_model=IncidentRead)
async def run_pipeline(
    incident_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> IncidentRead:
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    inc = result.scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")

    import sys, time
    from pathlib import Path

    _root = Path(__file__).resolve().parent.parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

    from core.state import IncidentStatus, StateObject, ThreatSeverity
    from core.orchestrator import MythosOrchestrator

    state = StateObject(
        incident_id=inc.incident_id,
        threat_name=inc.threat_name,
        severity=ThreatSeverity(inc.severity),
        indicators=list(inc.indicators or []),
    )

    t0 = time.perf_counter()
    try:
        final = await asyncio.to_thread(MythosOrchestrator().run_incident, state)
        outcome = "success"
    except Exception as exc:
        PIPELINE_RUNS.labels(
            tenant_id=str(current_user.tenant_id),
            threat_name=inc.threat_name,
            outcome="error",
        ).inc()
        raise HTTPException(500, f"Pipeline error: {exc}") from exc
    finally:
        duration = time.perf_counter() - t0
        PIPELINE_DURATION.labels(threat_name=inc.threat_name).observe(duration)

    # Persist pipeline results back to DB
    inc.status = final.status.value
    inc.confidence_score = final.confidence_score
    inc.risk_score = final.risk_score
    inc.attribution_confidence = final.attribution_confidence
    inc.campaign_id = final.campaign_id
    inc.threat_summary = final.threat_summary
    inc.suspected_actor = final.suspected_actor
    inc.indicators = list(final.indicators)
    inc.ioc_enrichments = list(final.ioc_enrichments)
    inc.mitigation_actions = list(final.mitigation_actions)
    inc.enrichment_data = dict(final.enrichment_data)
    inc.attack_techniques = list(final.enrichment_data.get("attack_techniques", []))

    await db.flush()
    await db.refresh(inc)

    PIPELINE_RUNS.labels(
        tenant_id=str(current_user.tenant_id),
        threat_name=inc.threat_name,
        outcome=outcome,
    ).inc()
    log_event(
        action="RUN_PIPELINE",
        resource_type="incident",
        resource_id=str(inc.id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
        detail={"final_status": inc.status, "risk_score": inc.risk_score},
    )
    return _to_read(inc)
