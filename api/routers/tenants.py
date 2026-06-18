"""api/routers/tenants.py — Tenant management (ADMIN only)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import require_roles
from api.models.tenant import Tenant
from api.models.user import Role, User
from api.schemas.tenant import TenantCreate, TenantRead, TenantUpdate
from api.services.audit_service import log_event

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("", response_model=list[TenantRead])
async def list_tenants(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[Tenant]:
    result = await db.execute(select(Tenant))
    return list(result.scalars())


@router.post("", response_model=TenantRead, status_code=201)
async def create_tenant(
    body: TenantCreate,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    existing = (
        await db.execute(select(Tenant).where(Tenant.slug == body.slug))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Tenant slug already exists")

    tenant = Tenant(name=body.name, slug=body.slug)
    db.add(tenant)
    await db.flush()

    log_event(
        action="CREATE_TENANT",
        resource_type="tenant",
        resource_id=str(tenant.id),
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
        detail={"slug": body.slug},
    )
    return tenant


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant(
    tenant_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "Tenant not found")
    return tenant


@router.patch("/{tenant_id}", response_model=TenantRead)
async def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantUpdate,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "Tenant not found")

    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(tenant, field, val)
    await db.flush()

    log_event(
        action="UPDATE_TENANT",
        resource_type="tenant",
        resource_id=str(tenant_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )
    return tenant
