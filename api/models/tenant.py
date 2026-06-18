"""api/models/tenant.py — Tenant (organisation) model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    users: Mapped[list["User"]] = relationship(  # type: ignore[name-defined]
        "User", back_populates="tenant", cascade="all, delete-orphan"
    )
    incidents: Mapped[list["Incident"]] = relationship(  # type: ignore[name-defined]
        "Incident", back_populates="tenant", cascade="all, delete-orphan"
    )
    cases: Mapped[list["Case"]] = relationship(  # type: ignore[name-defined]
        "Case", back_populates="tenant", cascade="all, delete-orphan"
    )
