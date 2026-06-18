"""api/main.py — Mythos FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from api.middleware import AuditMiddleware, PrometheusMiddleware
from api.routers import attack, auth, cases, incidents, ingest, tenants, users
from api.services.cache_service import cache


@asynccontextmanager
async def lifespan(app: FastAPI):
    await cache.connect()
    yield
    await cache.disconnect()


app = FastAPI(
    title="Mythos Command Center API",
    description=(
        "Enterprise-grade defensive cyber incident orchestration API. "
        "Supports multi-tenancy, RBAC (Admin/Analyst/Viewer), JWT authentication, "
        "Prometheus metrics, and structured audit logging."
    ),
    version="5.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Custom middleware (added in reverse order — last added = outermost)
# ---------------------------------------------------------------------------

app.add_middleware(AuditMiddleware)
app.add_middleware(PrometheusMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=_PREFIX)
app.include_router(incidents.router, prefix=_PREFIX)
app.include_router(cases.router, prefix=_PREFIX)
app.include_router(users.router, prefix=_PREFIX)
app.include_router(tenants.router, prefix=_PREFIX)
app.include_router(ingest.router, prefix=_PREFIX)
app.include_router(attack.router, prefix=_PREFIX)

# ---------------------------------------------------------------------------
# Utility endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {
        "status": "ok",
        "service": "mythos-api",
        "version": "5.0.0",
        "cache": "connected" if cache.available else "unavailable",
    }


@app.get("/metrics", tags=["ops"], include_in_schema=False)
async def metrics() -> Response:
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
