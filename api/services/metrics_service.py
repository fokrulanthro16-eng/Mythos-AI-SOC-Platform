"""api/services/metrics_service.py — Prometheus metrics registry for Mythos API."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, REGISTRY  # noqa: F401

# ---------------------------------------------------------------------------
# API telemetry
# ---------------------------------------------------------------------------

API_REQUESTS = Counter(
    "mythos_api_requests_total",
    "Total HTTP requests handled",
    ["method", "endpoint", "status_code"],
)

API_LATENCY = Histogram(
    "mythos_api_latency_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# ---------------------------------------------------------------------------
# Auth telemetry
# ---------------------------------------------------------------------------

AUTH_FAILURES = Counter(
    "mythos_auth_failures_total",
    "Authentication and authorisation failures",
    ["reason"],
)

AUTH_LOGINS = Counter(
    "mythos_auth_logins_total",
    "Successful logins",
    ["tenant_id"],
)

# ---------------------------------------------------------------------------
# Incident / pipeline telemetry
# ---------------------------------------------------------------------------

INCIDENTS_CREATED = Counter(
    "mythos_incidents_created_total",
    "Incidents created via API",
    ["tenant_id", "severity"],
)

PIPELINE_RUNS = Counter(
    "mythos_pipeline_runs_total",
    "Orchestrator pipeline executions",
    ["tenant_id", "threat_name", "outcome"],
)

PIPELINE_DURATION = Histogram(
    "mythos_pipeline_duration_seconds",
    "Time to run full incident pipeline",
    ["threat_name"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
)

# ---------------------------------------------------------------------------
# Case management telemetry
# ---------------------------------------------------------------------------

ACTIVE_CASES = Gauge(
    "mythos_active_cases",
    "Number of non-closed cases",
    ["tenant_id"],
)

CASES_CREATED = Counter(
    "mythos_cases_created_total",
    "Cases created via API",
    ["tenant_id", "priority"],
)
