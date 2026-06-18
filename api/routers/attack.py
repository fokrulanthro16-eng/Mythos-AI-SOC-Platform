"""api/routers/attack.py — MITRE ATT&CK intelligence endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import get_current_user
from api.models.incident import Incident
from api.models.user import User
from intelligence.attack_engine import AttackEngine

router = APIRouter(prefix="/attack", tags=["attack"])

_engine = AttackEngine()


@router.get("/techniques", response_model=list[dict])
async def list_techniques(
    search: str | None = Query(None, description="Free-text search"),
    tactic: str | None = Query(None, description="Filter by tactic name"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """List ATT&CK techniques with optional search and tactic filter."""
    if search:
        results = _engine.search(search, limit=limit)
    else:
        results = _engine.all_techniques()

    if tactic:
        tactic_lower = tactic.strip().lower()
        results = [t for t in results if tactic_lower in t.get("tactic", "").lower()]

    return results[:limit]


@router.get("/techniques/{technique_id}", response_model=dict)
async def get_technique(
    technique_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve a specific ATT&CK technique by ID (e.g. T1059)."""
    tech = _engine.lookup(technique_id)
    if tech is None:
        raise HTTPException(404, f"Technique '{technique_id}' not found in ATT&CK database")
    return tech


@router.get("/stats", response_model=dict)
async def get_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """ATT&CK statistics — database coverage plus incident technique frequency."""
    base = _engine.stats()

    # Count technique frequency across incidents in this tenant
    result = await db.execute(
        select(Incident.attack_techniques).where(
            Incident.tenant_id == current_user.tenant_id,
        )
    )
    freq: dict[str, int] = {}
    tactic_freq: dict[str, int] = {}
    incident_count_with_mapping = 0

    for (techniques,) in result:
        if not techniques:
            continue
        incident_count_with_mapping += 1
        for t in techniques:
            tid = t.get("technique_id", "")
            tact = t.get("tactic", "")
            if tid:
                freq[tid] = freq.get(tid, 0) + 1
            if tact:
                tactic_freq[tact] = tactic_freq.get(tact, 0) + 1

    most_common = sorted(
        [{"technique_id": k, "count": v} for k, v in freq.items()],
        key=lambda x: -x["count"],
    )[:10]

    most_common_tactics = sorted(
        [{"tactic": k, "count": v} for k, v in tactic_freq.items()],
        key=lambda x: -x["count"],
    )

    return {
        **base,
        "incidents_with_attack_mapping": incident_count_with_mapping,
        "most_common_techniques": most_common,
        "most_common_tactics": most_common_tactics,
    }
