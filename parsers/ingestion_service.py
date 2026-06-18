"""parsers/ingestion_service.py — Orchestrates parsing, dedup, and pipeline entry."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from parsers.base import NormalizedIncident, ParseResult
from parsers.csv_parser import CSVParser
from parsers.dedup import DuplicateDetector
from parsers.json_parser import JSONParser
from parsers.syslog_parser import SyslogParser

_UPLOADS_DIR = Path(__file__).parent.parent / "uploads"
_MANIFEST_PATH = _UPLOADS_DIR / "upload_manifest.jsonl"

_PARSERS: dict[str, object] = {
    "json": JSONParser(),
    "csv":  CSVParser(),
    "syslog": SyslogParser(),
    "log":  SyslogParser(),
    "txt":  SyslogParser(),
}


def _detect_format(filename: str, content: str | bytes) -> str:
    """Detect file format from extension; fall back to content sniffing."""
    ext = Path(filename).suffix.lower().lstrip(".")
    if ext in _PARSERS:
        return ext
    sample = (
        content[:200].decode("utf-8", errors="ignore")
        if isinstance(content, bytes)
        else content[:200]
    ).strip()
    if sample.startswith(("{", "[")):
        return "json"
    first_line = sample.split("\n")[0]
    if "," in first_line and len(first_line.split(",")) >= 2:
        return "csv"
    return "syslog"


class IngestionResult(BaseModel):
    upload_id: str
    filename: str
    format: str
    parsed_count: int
    duplicate_count: int
    error_count: int
    accepted_count: int
    errors: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)
    uploaded_at: str


class IngestionService:
    def __init__(
        self,
        dedup: DuplicateDetector | None = None,
        uploads_dir: Path | str | None = None,
        run_pipeline: bool = True,
    ) -> None:
        self._dedup = dedup or DuplicateDetector()
        self._uploads_dir = Path(uploads_dir) if uploads_dir else _UPLOADS_DIR
        self._run_pipeline = run_pipeline

    def ingest(
        self, content: str | bytes, filename: str
    ) -> tuple[IngestionResult, list[NormalizedIncident]]:
        """Parse a file, dedup, optionally run pipeline. Returns (result, accepted)."""
        upload_id = uuid.uuid4().hex
        fmt = _detect_format(filename, content)
        parser = _PARSERS.get(fmt, SyslogParser())

        # Persist raw upload file
        self._uploads_dir.mkdir(parents=True, exist_ok=True)
        raw_path = self._uploads_dir / f"{upload_id}_{filename}"
        if isinstance(content, bytes):
            raw_path.write_bytes(content)
        else:
            raw_path.write_text(content, encoding="utf-8")

        parse_result: ParseResult = parser.parse(content, filename=filename)  # type: ignore[union-attr]

        accepted: list[NormalizedIncident] = []
        dup_count = 0

        for inc in parse_result.incidents:
            fp = inc.fingerprint()
            if self._dedup.is_duplicate(fp):
                dup_count += 1
                continue
            self._dedup.mark_seen(fp, {"incident_id": inc.incident_id, "filename": filename})
            accepted.append(inc)

        if self._run_pipeline and accepted:
            self._trigger_pipeline(accepted)

        result = IngestionResult(
            upload_id=upload_id,
            filename=filename,
            format=fmt,
            parsed_count=len(parse_result.incidents),
            duplicate_count=dup_count,
            error_count=len(parse_result.errors),
            accepted_count=len(accepted),
            errors=parse_result.errors,
            incident_ids=[inc.incident_id for inc in accepted],
            uploaded_at=datetime.now(timezone.utc).isoformat(),
        )

        manifest_path = self._uploads_dir / "upload_manifest.jsonl"
        with manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(result.model_dump()) + "\n")

        return result, accepted

    def _trigger_pipeline(self, incidents: list[NormalizedIncident]) -> None:
        """Feed accepted incidents into the local Mythos pipeline."""
        import sys
        root = Path(__file__).parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))

        from core.orchestrator import MythosOrchestrator
        from core.state import StateObject, ThreatSeverity

        orchestrator = MythosOrchestrator()
        for inc in incidents:
            try:
                sev = (
                    ThreatSeverity(inc.severity)
                    if inc.severity in ThreatSeverity.__members__
                    else ThreatSeverity.MEDIUM
                )
                state = StateObject(
                    incident_id=inc.incident_id,
                    threat_name=inc.threat_name,
                    severity=sev,
                    indicators=inc.indicators,
                )
                orchestrator.run_incident(state)
            except Exception:
                pass  # don't fail ingestion if individual pipeline run errors

    def load_manifest(self) -> list[dict]:
        """Return all historical upload manifest entries."""
        manifest = self._uploads_dir / "upload_manifest.jsonl"
        if not manifest.exists():
            return []
        entries: list[dict] = []
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries
