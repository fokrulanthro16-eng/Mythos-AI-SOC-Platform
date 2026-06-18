"""api/services/auth_service.py — JWT creation/validation and password hashing."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt as _bcrypt
import jwt

_SECRET = os.getenv("JWT_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-USE-256-BIT-RANDOM-VALUE")
_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_ACCESS_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
_REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))


# ---------------------------------------------------------------------------
# Password helpers (direct bcrypt — compatible with bcrypt 4.x and 5.x)
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------


def create_access_token(user_id: str, tenant_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=_ACCESS_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def create_refresh_token(user_id: str, tenant_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=_REFRESH_EXPIRE_DAYS)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises jwt.InvalidTokenError on failure."""
    return jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])


def access_token_ttl() -> int:
    return _ACCESS_EXPIRE_MINUTES * 60


def refresh_token_ttl() -> int:
    return _REFRESH_EXPIRE_DAYS * 86_400
