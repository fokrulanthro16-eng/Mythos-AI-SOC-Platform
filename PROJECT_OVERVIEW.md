# Project Mythos — Technical Overview

## What Is Mythos?

Mythos is a full-stack, AI-augmented Security Operations Centre (SOC) platform built from scratch in Python. It orchestrates the complete incident response lifecycle through a pipeline of specialised agents, exposes a live 11-page Streamlit dashboard, provides a production-grade FastAPI REST layer, and generates professional PDF incident reports — all backed by a realistic 2026 enterprise threat dataset.

It was designed as a reference implementation of what a modern, extensible SOC automation platform looks like when all layers (data, agents, API, UI, observability) are built to production standards.

---

## Technical Highlights

| Metric | Value |
|---|---|
| Total lines of Python | ~12,000 |
| Test files | 24 |
| Total tests | 588 |
| Dashboard pages | 11 |
| Agent pipeline stages | 5 |
| REST API endpoints | 30+ |
| Threat actor profiles | 23 |
| ATT&CK techniques mapped | 250+ |
| Tracked campaigns | 22 |
| Sample incidents (2026 dataset) | 50 |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Dashboard | Streamlit 1.33+, Plotly 5.x |
| REST API | FastAPI 0.115+, uvicorn |
| ORM | SQLAlchemy 2.x async (asyncpg) |
| Database | PostgreSQL 16 (prod) / SQLite (dev/CI) |
| Cache / Session | Redis 7 |
| Auth | PyJWT 2.9 (HS256), bcrypt |
| Schema validation | Pydantic v2 |
| PDF generation | ReportLab (platypus) |
| Testing | pytest, pytest-asyncio 0.24, httpx |
| Observability | Prometheus client, Grafana |
| Migrations | Alembic |
| Containerisation | Docker, Docker Compose |
| Data format | JSON, JSONL, CSV, Syslog |

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                       MYTHOS PLATFORM                                │
│                                                                      │
│  ┌──────────────┐    ┌────────────────────────────────────────────┐ │
│  │ Incident     │    │ Agent Pipeline                             │ │
│  │ Sources      │───▶│ Planner → Intelligence → Attribution       │ │
│  │              │    │ → Forensics → Compliance                   │ │
│  │ JSON/CSV/    │    │                          ↓                 │ │
│  │ Syslog/API   │    │              JSONL + PostgreSQL            │ │
│  └──────────────┘    └────────────────────────────────────────────┘ │
│                                      ↓                               │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Streamlit Dashboard (11 pages)                                  │ │
│  │                                                                  │ │
│  │  Overview · Intel · Timeline · Logs · Intake · Cases · MITRE   │ │
│  │  Workbench · Agents · Executive · Threat Actor Intelligence     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌──────────────────┐    ┌──────────────────────────────────────┐   │
│  │ FastAPI REST API  │    │ Observability                         │   │
│  │                   │    │                                        │   │
│  │ /incidents /cases │    │ Prometheus · Grafana · audit.jsonl   │   │
│  │ /auth /ingest     │    │ 10 custom metrics · 10 dashboard     │   │
│  │ /attack /users    │    │ panels · structured audit trail      │   │
│  │                   │    │                                        │   │
│  │ JWT RBAC          │    └──────────────────────────────────────┘   │
│  │ Multi-tenant      │                                               │
│  └──────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Agent Pipeline Design

Each agent is an independent, stateless class with a single `run(state: StateObject) -> StateObject` method. The orchestrator applies them in sequence; any agent can raise to abort the pipeline.

```python
class PlannerAgent:
    def run(self, state: StateObject) -> StateObject:
        # DETECTED → ANALYZED
        # assigns IOCs, sets confidence, computes risk_score
        ...
```

State is a Pydantic model — all fields are type-validated at every transition. Every transition is persisted to JSONL before the next agent runs, so pipeline failures are forensically recoverable.

**Why this design:**
- Each agent can be unit-tested in complete isolation
- Agents can be reordered or replaced without touching others
- The pipeline is synchronous by default but can be parallelised at the orchestrator level
- State serialisation to JSONL creates a full audit trail with no extra code

---

## Data Architecture

### File-backed stores (dashboard layer)

The dashboard uses lightweight JSON file stores — no database required for the UI:

| Store | File | Contents |
|---|---|---|
| `case_store.py` | `logs/case_store.json` | 15 seeded cases with staggered timestamps |
| `workbench_store.py` | `logs/workbench_store.json` | Assignments, escalations, activity feed |
| `agent_store.py` | `logs/agent_runs.jsonl` | Pipeline run records |
| `executive_store.py` | reads all 3 stores | Aggregated KPIs for Executive Dashboard |
| `threat_actor_store.py` | `data/threat_profiles.json` + `campaigns.json` | Actor profiles + campaign data |

All stores follow the same pattern: pure `_compute_*` functions (no I/O, fully testable) + file-backed wrapper functions for production use. Tests inject test files via `monkeypatch`.

### Production data (2026 dataset)

The 50-incident dataset was designed to produce realistic dashboard metrics:

| Metric | Seeded value |
|---|---|
| MTTR (mean time to resolve) | ~75 hours across 4 resolved cases |
| MTTD (mean time to detect) | ~10 hours (severity-weighted model) |
| Attribution confidence | 0.88 average across all runs |
| Analyst utilisation | ~68% (10 analysts, 15 open cases) |
| Threat categories | Ransomware 32%, C2 20%, Phishing 16%, Exfil 14%, Cred 10%, Other 8% |

---

## Testing Strategy

The test suite is structured in four layers:

1. **Unit tests** — pure functions with no I/O (risk scoring, MTTR compute, technique frequency). Fast, no fixtures.

2. **Store tests** — test file-backed functions with `monkeypatch` to inject temporary JSON files. All dashboard stores have 100% function coverage.

3. **Agent tests** — test each agent class independently by constructing `StateObject` instances directly. No orchestrator, no file system.

4. **API integration tests** — test FastAPI endpoints with `httpx.AsyncClient` and an in-memory SQLite database (via `StaticPool`). Each test gets a fresh database from `conftest.py`.

Key patterns:
- `asyncio_mode = "auto"` — no `@pytest.mark.asyncio` decorators needed
- `StaticPool` SQLite for database tests — isolated, no file cleanup
- `monkeypatch.setattr(module, "_PATH", tmp_path / "file.json")` for store tests
- `pytest.approx()` for all float comparisons

---

## Security Model

### Authentication

JWT Bearer tokens using HS256. Two-token pattern:
- **Access token** (15 min) — used on every API request
- **Refresh token** (7 days) — used only to issue new access tokens

On logout, the refresh token is added to a Redis blacklist. Expired tokens are automatically evicted from Redis (TTL = token expiry).

### Multi-tenancy

Every ORM model has a `tenant_id` foreign key. All database queries filter by `current_user.tenant_id` extracted from the JWT `sub` claim. A cross-tenant resource request returns `404` (not `403`) to avoid leaking resource existence.

### RBAC

Three roles with hierarchical permissions:

```
ADMIN   > ANALYST   > VIEWER
 ↓          ↓           ↓
full       read+write   read-only
```

The `require_roles(*roles)` dependency factory is used as a FastAPI `Depends()`:

```python
@router.delete("/{id}", dependencies=[Depends(require_roles("ADMIN"))])
async def delete_incident(...)
```

---

## Extension Points

### Add a new agent

```python
# agents/my_new_agent.py
class MyNewAgent:
    def run(self, state: StateObject) -> StateObject:
        # your logic here
        state.status = IncidentStatus.ANALYZED
        return state

# core/orchestrator.py
class MythosOrchestrator:
    _PIPELINE = [
        PlannerAgent(),
        IntelligenceAgent(),
        MyNewAgent(),        # insert anywhere in the pipeline
        AttributionAgent(),
        ForensicsAgent(),
        ComplianceAgent(),
    ]
```

### Add a new dashboard page

Create `dashboard/pages/12_My_Page.py`. Streamlit auto-discovers pages by filename. Use the `_ROOT` sys.path pattern from existing pages for imports.

### Add a new threat actor profile

Add an entry to `data/threat_profiles.json` following the existing schema. The `threat_actor_store.py` automatically picks it up — no code changes required.

### Add a new API endpoint

Add a router in `api/routers/`, register it in `api/main.py`, add schemas in `api/schemas/`, and service logic in `api/services/`. Follow the existing CRUD pattern with `require_roles()` for access control.

---

## Known Limitations

- **Streamlit file stores** are not suitable for concurrent multi-user writes in production. For a deployed multi-analyst environment, the FastAPI + PostgreSQL backend should be the authoritative source for all case/assignment state.
- **PDF generation** requires `reportlab` which is not in `requirements.txt` by default (avoid forcing a heavy dependency on API-only deployments).
- **MITRE ATT&CK data** in `data/mitre_attack.json` was current as of mid-2026. Refresh by downloading the latest STIX bundle from `attack.mitre.org`.
- **Featherless/BandAI integrations** (`integrations/`) are mock-first — they make real HTTP calls only when `FEATHERLESS_API_KEY` / `BANDAI_API_KEY` are set in the environment.
