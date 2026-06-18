"""api/routers/users.py — User management (ADMIN) + self-service profile."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import get_current_user, require_roles
from api.models.user import Role, User
from api.schemas.user import UserCreate, UserRead, UserUpdate
from api.services.audit_service import log_event
from api.services.auth_service import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
async def list_users(
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[User]:
    result = await db.execute(
        select(User).where(User.tenant_id == current_user.tenant_id)
    )
    return list(result.scalars())


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> User:
    existing = (
        await db.execute(
            select(User).where(
                User.email == body.email,
                User.tenant_id == current_user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Email already registered in this tenant")

    user = User(
        tenant_id=current_user.tenant_id,
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
    )
    db.add(user)
    await db.flush()

    log_event(
        action="CREATE_USER",
        resource_type="user",
        resource_id=str(user.id),
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
        detail={"email": body.email, "role": body.role.value},
    )
    return user


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    # ADMIN can see any user in tenant; others can only see themselves
    if current_user.role != Role.ADMIN and current_user.id != user_id:
        raise HTTPException(403, "Insufficient permissions")

    result = await db.execute(
        select(User).where(
            User.id == user_id, User.tenant_id == current_user.tenant_id
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404, "User not found")
    return user


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    is_self = current_user.id == user_id
    is_admin = current_user.role == Role.ADMIN

    if not is_self and not is_admin:
        raise HTTPException(403, "Insufficient permissions")

    result = await db.execute(
        select(User).where(
            User.id == user_id, User.tenant_id == current_user.tenant_id
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404, "User not found")

    updates = body.model_dump(exclude_unset=True)

    # Non-admins cannot change their own role
    if not is_admin and "role" in updates:
        raise HTTPException(403, "Cannot change own role")

    if "password" in updates:
        user.hashed_password = hash_password(updates.pop("password"))

    for field, val in updates.items():
        setattr(user, field, val)

    await db.flush()
    log_event(
        action="UPDATE_USER",
        resource_type="user",
        resource_id=str(user_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        select(User).where(
            User.id == user_id, User.tenant_id == current_user.tenant_id
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == current_user.id:
        raise HTTPException(400, "Cannot delete your own account")
    await db.delete(user)
    log_event(
        action="DELETE_USER",
        resource_type="user",
        resource_id=str(user_id),
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
    )
