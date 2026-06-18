"""api/routers/ingest.py — File upload endpoint for incident ingestion."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.database import get_db
from api.dependencies import require_roles
from api.models.incident import Incident
from api.models.user import Role, User
from api.services.audit_service import log_event

# Ensure project root is on sys.path for parsers import
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

router = APIRouter(prefix="/ingest", tags=["ingest"])

_ALLOWED_EXTENSIONS = {".json", ".csv", ".txt", ".log"}
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


@router.post("/upload", status_code=status.HTTP_200_OK)
async def upload_incidents(
    file: UploadFile = File(...),
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Upload a JSON, CSV, or syslog file and ingest incidents into the platform."""
    if not file.filename:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Filename is required")

    ext = Path(file.filename).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported file type '{ext}'. Allowed: {sorted(_ALLOWED_EXTENSIONS)}",
        )

    content = await file.read()
    if len(content) > _MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 10 MB limit")

    try:
        from parsers.ingestion_service import IngestionService

        service = IngestionService(run_pipeline=False)
        result, accepted = service.ingest(content, filename=file.filename)
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"Ingestion error: {exc}") from exc

    # Persist accepted incidents to the tenant's DB
    for norm_inc in accepted:
        inc = Incident(
            tenant_id=current_user.tenant_id,
            incident_id=norm_inc.incident_id,
            threat_name=norm_inc.threat_name,
            severity=norm_inc.severity,
            indicators=norm_inc.indicators,
            created_by=current_user.id,
        )
        db.add(inc)

    if accepted:
        await db.flush()

    log_event(
        action="INGEST_UPLOAD",
        resource_type="upload",
        resource_id=result.upload_id,
        user_id=str(current_user.id),
        user_email=current_user.email,
        tenant_id=str(current_user.tenant_id),
        detail={
            "filename": file.filename,
            "format": result.format,
            "parsed": result.parsed_count,
            "accepted": result.accepted_count,
            "duplicates": result.duplicate_count,
            "errors": result.error_count,
        },
    )

    return result.model_dump()


@router.get("/history", status_code=status.HTTP_200_OK)
async def upload_history(
    current_user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST)),
) -> list[dict]:
    """Return upload history from the manifest file."""
    try:
        from parsers.ingestion_service import IngestionService

        service = IngestionService(run_pipeline=False)
        return service.load_manifest()
    except Exception:
        return []
