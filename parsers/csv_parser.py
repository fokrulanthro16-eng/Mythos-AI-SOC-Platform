"""parsers/csv_parser.py — Parse incident CSV files."""

from __future__ import annotations

import csv
import io
import uuid

from parsers.base import BaseParser, NormalizedIncident, ParseResult

_COL_THREAT = ("threat_name", "threat", "name", "alert_name", "event_name", "title", "rule")
_COL_SEV    = ("severity", "level", "priority", "criticality", "risk_level")
_COL_IND    = ("indicators", "iocs", "ioc_list", "artifacts", "observables")
_COL_ID     = ("incident_id", "id", "alert_id", "event_id")


def _map_col(headers: list[str], candidates: tuple[str, ...]) -> str | None:
    """Return the first header that matches any candidate (case-insensitive)."""
    lower_map = {h.lower(): h for h in headers}
    for c in candidates:
        if c in lower_map:
            return lower_map[c]
    return None


class CSVParser(BaseParser):
    format_name = "csv"

    def parse(self, content: str | bytes, filename: str = "") -> ParseResult:
        result = ParseResult(source_file=filename, source_format="csv")

        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except UnicodeDecodeError:
                result.errors.append("File is not valid UTF-8")
                return result

        content = content.lstrip("﻿")  # strip BOM

        try:
            reader = csv.DictReader(io.StringIO(content))
            rows = list(reader)
        except Exception as exc:
            result.errors.append(f"CSV parse error: {exc}")
            return result

        if not rows:
            result.errors.append("CSV file is empty or has no data rows")
            return result

        headers = list(rows[0].keys())
        col_threat = _map_col(headers, _COL_THREAT)
        col_sev    = _map_col(headers, _COL_SEV)
        col_ind    = _map_col(headers, _COL_IND)
        col_id     = _map_col(headers, _COL_ID)

        if col_threat is None:
            result.errors.append(
                f"No 'threat_name' column found. Headers: {headers}"
            )
            return result

        for i, row in enumerate(rows):
            threat_name = (row.get(col_threat) or "").strip()
            if not threat_name:
                result.errors.append(f"Row {i + 1}: empty threat_name, skipping")
                continue

            raw_sev = (row.get(col_sev) or "medium").strip() if col_sev else "medium"
            severity = self._normalize_severity(raw_sev)

            raw_ind = (row.get(col_ind) or "") if col_ind else ""
            indicators = (
                [s.strip() for s in raw_ind.split("|") if s.strip()]
                if raw_ind.strip()
                else []
            )

            inc_id = (row.get(col_id) or "").strip() if col_id else ""
            if not inc_id:
                inc_id = f"INC-UPLOAD-{uuid.uuid4().hex[:8].upper()}"

            result.incidents.append(
                NormalizedIncident(
                    incident_id=inc_id,
                    threat_name=threat_name,
                    severity=severity,
                    indicators=indicators,
                    source_format="csv",
                    source_file=filename,
                    raw=dict(row),
                )
            )

        return result
