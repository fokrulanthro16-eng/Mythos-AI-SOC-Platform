"""parsers/json_parser.py — Parse incident JSON files (array or single object)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from parsers.base import BaseParser, NormalizedIncident, ParseResult

# Flexible column aliases
_THREAT_KEYS = ("threat_name", "threat", "name", "alert_name", "event_name", "title", "rule")
_SEV_KEYS    = ("severity", "level", "priority", "criticality", "risk_level")
_IND_KEYS    = ("indicators", "iocs", "ioc_list", "artifacts", "observables")
_ID_KEYS     = ("incident_id", "id", "alert_id", "event_id", "case_id", "ticket_id")


def _pick(record: dict, keys: tuple[str, ...], default: Any = "") -> Any:
    """Return first matching value by key (case-insensitive)."""
    lower_map = {k.lower(): v for k, v in record.items()}
    for k in keys:
        if k in lower_map:
            return lower_map[k]
    return default


class JSONParser(BaseParser):
    format_name = "json"

    def parse(self, content: str | bytes, filename: str = "") -> ParseResult:
        result = ParseResult(source_file=filename, source_format="json")

        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except UnicodeDecodeError:
                result.errors.append("File is not valid UTF-8")
                return result

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            result.errors.append(f"Invalid JSON: {exc}")
            return result

        records: list[dict] = []
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            for wrapper in ("incidents", "alerts", "events", "data", "results"):
                if wrapper in data and isinstance(data[wrapper], list):
                    records = data[wrapper]
                    break
            else:
                records = [data]
        else:
            result.errors.append(
                f"Expected JSON object or array, got {type(data).__name__}"
            )
            return result

        for i, record in enumerate(records):
            if not isinstance(record, dict):
                result.errors.append(
                    f"Record {i}: expected object, got {type(record).__name__}"
                )
                continue

            threat_name = str(_pick(record, _THREAT_KEYS, "")).strip()
            if not threat_name:
                result.errors.append(f"Record {i}: missing required field 'threat_name'")
                continue

            raw_sev = str(_pick(record, _SEV_KEYS, "medium"))
            severity = self._normalize_severity(raw_sev)

            raw_ioc = _pick(record, _IND_KEYS, [])
            if isinstance(raw_ioc, str):
                indicators = [s.strip() for s in raw_ioc.split("|") if s.strip()]
            elif isinstance(raw_ioc, list):
                indicators = [str(x).strip() for x in raw_ioc if str(x).strip()]
            else:
                indicators = []

            inc_id = str(_pick(record, _ID_KEYS, "")).strip()
            if not inc_id:
                inc_id = f"INC-UPLOAD-{uuid.uuid4().hex[:8].upper()}"

            result.incidents.append(
                NormalizedIncident(
                    incident_id=inc_id,
                    threat_name=threat_name,
                    severity=severity,
                    indicators=indicators,
                    source_format="json",
                    source_file=filename,
                    raw=record,
                )
            )

        return result
