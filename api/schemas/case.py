"""api/schemas/case.py — Case management request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from api.models.case import CasePriority, CaseStatus


# ---------------------------------------------------------------------------
# Case CRUD
# ---------------------------------------------------------------------------


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(default="", max_length=4096)
    priority: CasePriority = CasePriority.P3
    assigned_to: uuid.UUID | None = None


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    assigned_to: uuid.UUID | None = None


class CaseRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    case_number: str
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    assigned_to: uuid.UUID | None
    created_by: uuid.UUID | None
    resolved_at: datetime | None
    incident_count: int = 0
    notes_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


class CaseNoteCreate(BaseModel):
    content: str = Field(min_length=1, max_length=4096)


# ---------------------------------------------------------------------------
# Timeline events
# ---------------------------------------------------------------------------


class CaseEventRead(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    author_id: uuid.UUID | None
    event_type: str
    content: str
    old_value: str
    new_value: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class CaseStats(BaseModel):
    total: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
    open_count: int
    investigating_count: int
    contained_count: int
    resolved_count: int
    closed_count: int
    avg_resolution_hours: float | None
