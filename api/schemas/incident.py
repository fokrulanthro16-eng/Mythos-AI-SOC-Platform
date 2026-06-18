"""api/schemas/incident.py — Incident request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    incident_id: str = Field(default="", max_length=64)
    threat_name: str = Field(max_length=128)
    severity: str = Field(default="MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    indicators: list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    threat_name: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    indicators: list[str] | None = None
    status: str | None = None


class IncidentRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    incident_id: str
    threat_name: str
    severity: str
    status: str
    confidence_score: float
    risk_score: float
    attribution_confidence: float
    campaign_id: str
    threat_summary: str
    suspected_actor: str
    indicators: list[str]
    ioc_enrichments: list[str]
    mitigation_actions: list[str]
    enrichment_data: dict
    attack_techniques: list[dict] = Field(default_factory=list)
    case_id: uuid.UUID | None
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
