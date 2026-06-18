"""api/routers/auth.py — Authentication: login, refresh, logout, /me."""

from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import get_current_user
from api.models.user import User
from api.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
)
from api.schemas.user import UserRead
from api.services.audit_service import log_event
from api.services.auth_service import (
    access_token_ttl,
    create_access_token,
    create_refresh_token,
    decode_token,
    refresh_token_ttl,
    verify_password,
)
from api.services.cache_service import cache
from api.services.metrics_service import AUTH_FAILURES, AUTH_LOGINS

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    result = await db.execute(
        select(User).where(User.email == body.email, User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.hashed_password):
        AUTH_FAILURES.labels(reason="bad_credentials").inc()
        log_event(
            action="LOGIN",
            resource_type="session",
            outcome="FAILURE",
            user_email=body.email,
            detail={"reason": "bad_credentials"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    role_str = getattr(user.role, "value", str(user.role))
    access = create_access_token(str(user.id), str(user.tenant_id), role_str)
    refresh = create_refresh_token(str(user.id), str(user.tenant_id))

    AUTH_LOGINS.labels(tenant_id=str(user.tenant_id)).inc()
    log_event(
        action="LOGIN",
        resource_type="session",
        outcome="SUCCESS",
        user_id=str(user.id),
        user_email=user.email,
        tenant_id=str(user.tenant_id),
    )
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=access_token_ttl(),
    )


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> AccessTokenResponse:
    try:
        payload = decode_token(body.refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")

    jti = payload.get("jti", "")
    if jti and await cache.is_blacklisted(jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked")

    import uuid

    user_id = uuid.UUID(payload["sub"])
    tenant_id = uuid.UUID(payload["tenant_id"])

    result = await db.execute(
        select(User).where(
            User.id == user_id, User.tenant_id == tenant_id, User.is_active.is_(True)
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")

    role_str = getattr(user.role, "value", str(user.role))
    access = create_access_token(str(user.id), str(user.tenant_id), role_str)
    return AccessTokenResponse(access_token=access, expires_in=access_token_ttl())


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: User = Depends(get_current_user)) -> None:
    log_event(
        action="LOGOUT",
        resource_type="session",
        outcome="SUCCESS",
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
    )


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
