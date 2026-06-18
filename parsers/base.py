"""parsers/base.py — Shared data models and base class for all incident parsers."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from pydantic import BaseModel, Field

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

_SEVERITY_ALIASES: dict[str, str] = {
    # Info / low
    "info": "LOW", "information": "LOW", "informational": "LOW",
    "notice": "LOW", "debug": "LOW", "trace": "LOW", "low": "LOW", "1": "LOW",
    # Medium / warning
    "warning": "MEDIUM", "warn": "MEDIUM", "medium": "MEDIUM",
    "moderate": "MEDIUM", "mod": "MEDIUM", "2": "MEDIUM",
    # High / error
    "high": "HIGH", "error": "HIGH", "err": "HIGH", "major": "HIGH", "3": "HIGH",
    # Critical
    "critical": "CRITICAL", "crit": "CRITICAL", "alert": "CRITICAL",
    "emergency": "CRITICAL", "emerg": "CRITICAL", "fatal": "CRITICAL",
    "panic": "CRITICAL", "4": "CRITICAL",
}

_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_HASH = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
)


def normalize_severity(raw: str) -> str:
    """Map arbitrary severity strings to LOW/MEDIUM/HIGH/CRITICAL."""
    return _SEVERITY_ALIASES.get(raw.strip().lower(), "MEDIUM")


def extract_indicators(text: str) -> list[str]:
    """Extract IPs, hex hashes, and domain-like strings from free text."""
    found: list[str] = []
    found.extend(_RE_IPV4.findall(text))
    found.extend(_RE_HASH.findall(text))
    found.extend(_RE_DOMAIN.findall(text))
    seen: set[str] = set()
    result: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


class NormalizedIncident(BaseModel):
    """Canonical incident representation after parsing from any source format."""
    incident_id: str = ""
    threat_name: str
    severity: str = "MEDIUM"
    indicators: list[str] = Field(default_factory=list)
    source_format: str = ""
    source_file: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable dedup hash: threat_name + severity + sorted indicators."""
        key = (
            f"{self.threat_name.strip().lower()}"
            f"|{self.severity}"
            f"|{'|'.join(sorted(self.indicators))}"
        )
        return hashlib.sha256(key.encode()).hexdigest()


class ParseResult(BaseModel):
    """Result of parsing a single file."""
    incidents: list[NormalizedIncident] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    source_file: str = ""
    source_format: str = ""


class BaseParser:
    """Base class for all incident parsers."""
    format_name: str = "base"

    def parse(self, content: str | bytes, filename: str = "") -> ParseResult:
        raise NotImplementedError

    @staticmethod
    def _normalize_severity(raw: str) -> str:
        return normalize_severity(raw)

    @staticmethod
    def _extract_indicators(text: str) -> list[str]:
        return extract_indicators(text)
