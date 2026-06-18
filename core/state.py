"""
core/state.py — Canonical data model for Project Mythos (Phase 3).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    DETECTED   = "DETECTED"
    ANALYZED   = "ANALYZED"
    ENRICHED   = "ENRICHED"    # Phase 3: intelligence enrichment stage
    ATTRIBUTED = "ATTRIBUTED"
    MITIGATED  = "MITIGATED"


class ThreatSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


LOG_FIELDS: list[str] = [
    "incident_id", "status", "threat_name", "severity",
    "confidence_score", "risk_score", "attribution_confidence", "campaign_id",
    "indicators", "ioc_enrichments", "suspected_actor", "mitigation_actions",
    "threat_summary", "enrichment_data", "created_at", "updated_at",
]


class StateObject(BaseModel):
    # Core identity
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: IncidentStatus = IncidentStatus.DETECTED

    # Threat characterisation
    threat_name: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0)

    # Phase 3 — intelligence & attribution
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    campaign_id: str = ""
    threat_summary: str = ""
    enrichment_data: dict[str, Any] = Field(default_factory=dict)
    ioc_enrichments: list[str] = Field(default_factory=list)

    # Evidence
    indicators: list[str] = Field(default_factory=list)
    suspected_actor: str = ""
    mitigation_actions: list[str] = Field(default_factory=list)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "incident_id":          self.incident_id,
            "status":               self.status.value,
            "threat_name":          self.threat_name,
            "severity":             self.severity.value,
            "confidence_score":     self.confidence_score,
            "risk_score":           self.risk_score,
            "attribution_confidence": self.attribution_confidence,
            "campaign_id":          self.campaign_id,
            "indicators":           "|".join(self.indicators),
            "ioc_enrichments":      "|".join(self.ioc_enrichments),
            "suspected_actor":      self.suspected_actor,
            "mitigation_actions":   "|".join(self.mitigation_actions),
            "threat_summary":       self.threat_summary,
            "enrichment_data":      json.dumps(self.enrichment_data),
            "created_at":           self.created_at.isoformat(),
            "updated_at":           self.updated_at.isoformat(),
        }
