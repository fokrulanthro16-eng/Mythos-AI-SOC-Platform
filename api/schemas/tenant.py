"""api/schemas/tenant.py — Tenant request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9\-]+$")


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    is_active: bool | None = None


class TenantRead(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
