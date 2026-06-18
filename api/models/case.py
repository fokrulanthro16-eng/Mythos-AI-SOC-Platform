"""api/models/case.py — Incident Case model for case management."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.database import Base


class CaseStatus(str, Enum):
    OPEN          = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED     = "CONTAINED"
    RESOLVED      = "RESOLVED"
    CLOSED        = "CLOSED"


class CasePriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[CaseStatus] = mapped_column(
        SAEnum(CaseStatus, name="case_status_enum", create_constraint=True),
        default=CaseStatus.OPEN,
        nullable=False,
    )
    priority: Mapped[CasePriority] = mapped_column(
        SAEnum(CasePriority, name="case_priority_enum", create_constraint=True),
        default=CasePriority.P3,
        nullable=False,
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="cases")  # type: ignore[name-defined]
    incidents: Mapped[list["Incident"]] = relationship(  # type: ignore[name-defined]
        "Incident", back_populates="case"
    )
    events: Mapped[list["CaseEvent"]] = relationship(  # type: ignore[name-defined]
        "CaseEvent", back_populates="case", cascade="all, delete-orphan",
        order_by="CaseEvent.created_at",
    )
