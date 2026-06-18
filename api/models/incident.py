"""api/models/incident.py — Incident model (mirrors StateObject, multi-tenant)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    threat_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="DETECTED", nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    attribution_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    threat_summary: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    suspected_actor: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    indicators: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    ioc_enrichments: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mitigation_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    enrichment_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="incidents")  # type: ignore[name-defined]
    case: Mapped["Case | None"] = relationship("Case", back_populates="incidents")  # type: ignore[name-defined]
