"""api/middleware.py — Prometheus instrumentation and structured audit middleware."""

from __future__ import annotations

import time

import jwt
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from api.services.metrics_service import API_LATENCY, API_REQUESTS

_AUTH_HEADER = "Authorization"
_JWT_SECRET = None  # resolved lazily from auth_service


def _extract_jwt_claims(request: Request) -> tuple[str | None, str | None, str | None]:
    """Best-effort extraction of user_id, tenant_id, jti from the request JWT."""
    from api.services.auth_service import decode_token

    auth = request.headers.get(_AUTH_HEADER, "")
    if not auth.startswith("Bearer "):
        return None, None, None
    try:
        payload = decode_token(auth.split(" ", 1)[1])
        return (
            payload.get("sub"),
            payload.get("tenant_id"),
            payload.get("jti"),
        )
    except Exception:
        return None, None, None


def _normalise_path(path: str) -> str:
    """Collapse UUID segments to keep Prometheus label cardinality low."""
    import re

    return re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "{id}",
        path,
    )


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        endpoint = _normalise_path(request.url.path)
        API_REQUESTS.labels(
            method=request.method,
            endpoint=endpoint,
            status_code=str(response.status_code),
        ).inc()
        API_LATENCY.labels(method=request.method, endpoint=endpoint).observe(duration)
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Write a structured audit line for every mutating request."""

    _SKIP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
    _SKIP_PATHS = frozenset({"/health", "/metrics", "/docs", "/openapi.json", "/redoc"})

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        if (
            request.method in self._SKIP_METHODS
            or request.url.path in self._SKIP_PATHS
        ):
            return response

        user_id, tenant_id, _ = _extract_jwt_claims(request)

        from api.services.audit_service import log_event

        outcome = "SUCCESS" if response.status_code < 400 else "FAILURE"
        log_event(
            action=f"{request.method} {_normalise_path(request.url.path)}",
            resource_type=request.url.path.split("/")[3] if request.url.path.count("/") >= 3 else "unknown",
            outcome=outcome,
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
            detail={"status_code": response.status_code},
        )
        return response
