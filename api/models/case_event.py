"""api/models/case_event.py — Case audit timeline (notes + all state changes)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.database import Base


class CaseEventType(str, Enum):
    CREATED          = "CREATED"
    NOTE             = "NOTE"
    STATUS_CHANGE    = "STATUS_CHANGE"
    ASSIGNMENT       = "ASSIGNMENT"
    PRIORITY_CHANGE  = "PRIORITY_CHANGE"
    INCIDENT_LINKED  = "INCIDENT_LINKED"
    INCIDENT_UNLINKED = "INCIDENT_UNLINKED"


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    old_value: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    new_value: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    case: Mapped["Case"] = relationship("Case", back_populates="events")  # type: ignore[name-defined]
