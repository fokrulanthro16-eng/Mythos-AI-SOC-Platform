# Mythos — AI-Powered SOC Incident Orchestration Platform

> A production-grade, multi-agent Security Operations Centre platform with a real-time Streamlit Command Center, FastAPI REST layer, MITRE ATT&CK enrichment, PDF reporting, and threat actor intelligence.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Feature Matrix](#feature-matrix)
- [Quick Start](#quick-start)
- [Dashboard Pages](#dashboard-pages)
- [Agent Workflow](#agent-workflow)
- [MITRE ATT&CK Integration](#mitre-attck-integration)
- [Case Management](#case-management)
- [Analyst Workbench](#analyst-workbench)
- [Agent Collaboration](#agent-collaboration)
- [PDF Report Generation](#pdf-report-generation)
- [Threat Actor Intelligence](#threat-actor-intelligence)
- [REST API](#rest-api)
- [Test Coverage](#test-coverage)
- [Project Structure](#project-structure)
- [Configuration](#configuration)

---

## Overview

Mythos is a full-stack cybersecurity operations platform that orchestrates the complete incident response lifecycle — from detection to mitigation — using a pipeline of specialised AI agents. Every component is independently testable, production-deployable, and integrated into an 11-page live SOC dashboard.

**Core capabilities:**

| Capability | Description |
|---|---|
| Multi-agent pipeline | 5 specialised agents handle detection → analysis → attribution → compliance → forensics |
| Live SOC dashboard | 11-page Streamlit Command Center with Plotly charts |
| MITRE ATT&CK engine | Full technique-to-tactic enrichment with lazy-loaded singleton |
| Case management | Full CRUD with status flow, analyst notes, priority escalation, and PDF export |
| Analyst workbench | Assignment management, 6-tab action panel, activity feed |
| Executive dashboard | C-suite KPIs: MTTR, MTTD, attribution confidence, analyst utilisation |
| Threat actor intelligence | 23 tracked actors, 6-actor featured center with comparison radar |
| PDF incident reports | 8-section ReportLab reports with MITRE mapping and recommendations |
| REST API | FastAPI with JWT auth, RBAC (ADMIN/ANALYST/VIEWER), multi-tenant isolation |
| Observability | Prometheus metrics, Grafana dashboards, structured audit log |

---

## Architecture

```mermaid
graph TB
    subgraph Intake["Incident Intake"]
        A[Incident JSON / CSV / Syslog] --> B[Ingestion Service]
        B --> C[Parser + Dedup]
        C --> D[StateObject]
    end

    subgraph Pipeline["Agent Pipeline  ·  core/orchestrator.py"]
        D --> E[PlannerAgent\nDETECTED → ANALYZED\nIOC assignment · confidence · risk score]
        E --> F[IntelligenceAgent\nATT&CK enrichment · IOC lookup]
        F --> G[AttributionAgent\nANALYZED → ATTRIBUTED\nthreat actor mapping · campaign clustering]
        G --> H[ForensicsAgent\nATT&CK technique enrichment]
        H --> I[ComplianceAgent\nATTRIBUTED → MITIGATED\nplaybook selection]
    end

    subgraph Persistence["Persistence"]
        I --> J[(logs/attribution_log.jsonl)]
        I --> K[(logs/attribution_log.csv)]
        I --> L[(PostgreSQL\nincidents · cases · users · tenants)]
    end

    subgraph API["REST API  ·  api/main.py"]
        L --> M[FastAPI /api/v1/\nJWT · RBAC · multi-tenant]
        M --> N[Prometheus /metrics]
        N --> O[Grafana dashboards]
    end

    subgraph Dashboard["Streamlit Command Center  ·  port 8501"]
        J --> P[data_loader.py]
        L --> P
        P --> Q[1 Incident Overview]
        P --> R[2 Threat Intelligence]
        P --> S[3 Incident Timeline]
        P --> T[4 Logs Explorer]
        P --> U[5 Incident Intake]
        P --> V[6 Case Management]
        P --> W[7 MITRE ATT&CK]
        P --> X[8 Analyst Workbench]
        P --> Y[9 Agent Collaboration]
        P --> Z[10 Executive Dashboard]
        P --> AA[11 Threat Actor Intel]
    end

    subgraph Reporting["PDF Reporting  ·  reporting/"]
        V --> BB[report_builder.py\nReportLab PDF engine]
        X --> BB
        Q --> BB
    end

    subgraph ThreatData["Threat Intelligence Data"]
        CC[(data/threat_profiles.json\n23 actors)] --> AA
        DD[(data/campaigns.json\n20 campaigns)] --> AA
        EE[(data/mitre_attack.json\nATT&CK matrix)] --> W
    end
```

### Component Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser / CLI / API Client                                      │
├───────────────────────┬─────────────────────────────────────────┤
│  Streamlit Dashboard  │  FastAPI REST API                        │
│  port 8501            │  port 8000  /api/v1/*                   │
│  11 pages             │  JWT HS256 · RBAC · Pydantic v2         │
├───────────────────────┴─────────────────────────────────────────┤
│  Agent Pipeline  (core/orchestrator.py)                          │
│  PlannerAgent → IntelligenceAgent → AttributionAgent             │
│  → ForensicsAgent → ComplianceAgent                              │
├─────────────────────────────────────────────────────────────────┤
│  Data Stores                                                     │
│  PostgreSQL (production) · SQLite (CI/local)                    │
│  Redis (JWT blacklist + response cache)                          │
│  JSONL log files (dashboard data source)                         │
├─────────────────────────────────────────────────────────────────┤
│  Observability                                                   │
│  Prometheus /metrics · Grafana dashboards · audit.jsonl          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Feature Matrix

| Phase | Features | Status |
|---|---|---|
| 1–2 | Core agent pipeline, state machine, risk scoring, JSONL/CSV logging | ✅ |
| 3 | IntelligenceAgent, AttributionAgent, Featherless/BandAI integrations | ✅ |
| 4 | Streamlit Command Center (4 pages), Plotly charts, sidebar filters | ✅ |
| 5 | FastAPI + PostgreSQL + Redis, JWT auth, RBAC, Alembic, Prometheus/Grafana | ✅ |
| 6 | Multi-format parsers, ingest API, MITRE ATT&CK engine, case API | ✅ |
| 7.1 | Production 2026 dataset (50 incidents, 20 campaigns), Executive Dashboard | ✅ |
| 7.2 | PDF incident reports (ReportLab, 8 sections), integrated into 3 pages | ✅ |
| 7.3 | Threat Actor Intelligence Center (23 actors, 5-tab page) | ✅ |

---

## Quick Start

### Prerequisites

```bash
python -m pip install -r requirements.txt
# For PDF generation
pip install reportlab
```

### Generate incident data and launch dashboard

```bash
# 1. Run the agent pipeline (generates attribution_log.jsonl)
python core/orchestrator.py

# 2. Start the Streamlit Command Center
python -m streamlit run dashboard/app.py
```

Dashboard opens at **http://localhost:8501**

### Run the full test suite

```bash
pytest tests/ -v --tb=short
```

### Docker Compose (full stack)

```bash
cp .env.example .env          # configure secrets
docker compose up -d
docker compose run --rm migrate
```

Services: API `http://localhost:8000` · Dashboard `http://localhost:8501` · Grafana `http://localhost:3000`

---

## Dashboard Pages

| # | Page | Key Features |
|---|---|---|
| 1 | **Incident Overview** | KPI row, severity pie, risk histogram, status progression, confidence scatter, incident table, PDF export |
| 2 | **Threat Intelligence** | Actor profiles, campaign frequency, IOC type distribution, attribution confidence chart |
| 3 | **Incident Timeline** | State-transition scatter, status heatmap, full history |
| 4 | **Logs Explorer** | Raw JSONL viewer, searchable CSV table, field-level export |
| 5 | **Incident Intake** | Manual incident submission form with validation |
| 6 | **Case Management** | Full CRUD, status flow (OPEN→CLOSED), notes, case timeline, PDF export |
| 7 | **MITRE ATT&CK** | Technique browser, tactic filtering, enrichment search |
| 8 | **Analyst Workbench** | Incident assignment, 6-tab action panel, activity feed, workload chart, PDF export |
| 9 | **Agent Collaboration** | Multi-agent run viewer, agent message timeline |
| 10 | **Executive Dashboard** | MTTR, MTTD, active campaigns, analyst utilisation, incident trend, severity distribution |
| 11 | **Threat Actor Intel** | 23 actors, search/filter, profiles, campaign Gantt, techniques matrix, radar comparison, geo activity |

---

## Agent Workflow

```
Incident ingested (JSON / CSV / Syslog / API)
        │
        ▼
┌─────────────────────────────────────┐
│  PlannerAgent                        │
│  DETECTED → ANALYZED                 │
│  • Assigns IOCs from threat name     │
│  • Sets initial confidence score     │
│  • Computes risk_score               │
│    = (confidence × 0.7) +            │
│      (severity_weight × 0.3)         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  IntelligenceAgent                   │
│  • Enriches with MITRE ATT&CK data  │
│  • Maps techniques to tactics        │
│  • Queries Featherless/BandAI APIs  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  AttributionAgent                    │
│  ANALYZED → ATTRIBUTED               │
│  • Maps threat_name → actor ID       │
│  • Clusters incidents to campaigns   │
│  • Adjusts confidence                │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  ForensicsAgent                      │
│  • Lazy-loads AttackEngine singleton │
│  • Enriches with full technique set  │
│  • Adds tactic + URL per technique   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  ComplianceAgent                     │
│  ATTRIBUTED → MITIGATED              │
│  • Selects playbook for threat name  │
│  • Populates mitigation_actions      │
└──────────────┬──────────────────────┘
               │
               ▼
        persist() → JSONL + CSV + PostgreSQL
```

### Risk Scoring Model

```
risk_score = (confidence × 0.7) + (severity_weight × 0.3)

Severity weights:  CRITICAL=1.00  HIGH=0.75  MEDIUM=0.50  LOW=0.25
Risk labels:       ≥0.80=CRITICAL  ≥0.60=HIGH  ≥0.40=MEDIUM  <0.40=LOW
```

---

## MITRE ATT&CK Integration

The `AttackEngine` in `intelligence/attack_engine.py` provides a lazy-loading singleton over the full ATT&CK dataset:

```python
from intelligence.attack_engine import AttackEngine

engine = AttackEngine()                          # lazy — loads on first access
techs  = engine.get_techniques_for_tactic("execution")
detail = engine.get_technique("T1059.001")       # Command-Line Interface
mapped = engine.map_threat_to_techniques("LOCKBIT4-RANSOMWARE")
```

**ATT&CK Browser** (page 7) allows analysts to:
- Browse all tactics and techniques
- Search by technique ID or name
- View full technique descriptions and mitigations
- Filter by tactic category

---

## Case Management

Cases live in `dashboard/case_store.py` (file-backed JSON) and mirror the `api/models/case.py` ORM model.

**Status flow:** `OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`

**Priority levels:** `P1` (Critical) · `P2` (High) · `P3` (Medium) · `P4` (Low)

Each case stores:
- Linked `incident_id`
- Analyst assignment
- Timestamped note history
- Audit trail (`history[]` with action, user, timestamp)
- `created_at` / `updated_at` / `resolved_at` (staggered for realistic MTTR)

**MTTR model** (seeded data): P1=36h · P2=72h · P3=120h · P4=48h

REST API endpoints (require authentication):

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/cases` | List cases (paginated, tenant-scoped) |
| POST | `/api/v1/cases` | Create case |
| GET | `/api/v1/cases/{id}` | Get case detail |
| PATCH | `/api/v1/cases/{id}` | Update status / priority / analyst |
| DELETE | `/api/v1/cases/{id}` | Delete case |
| POST | `/api/v1/cases/{id}/incidents/{inc_id}` | Link incident to case |
| DELETE | `/api/v1/cases/{id}/incidents/{inc_id}` | Unlink incident |

---

## Analyst Workbench

`dashboard/pages/8_Analyst_Workbench.py` is the primary analyst workflow interface.

**Features:**
- **Assign Incident** — assign to any of 10 named SOC analysts with severity/priority
- **Assignments Table** — sortable by priority, filterable by analyst and status
- **6-tab Action Panel:**
  1. Change Status — move through OPEN→INVESTIGATING→CONTAINED→RESOLVED
  2. Escalate Priority — P3→P2→P1 with free-text escalation reason
  3. Add Note — timestamped investigation notes with author
  4. Reassign — handoff to different analyst
  5. Close — closing notes + automatic case_store sync
  6. 📄 Report — generate and download PDF incident report
- **Case Timeline** — chronological event feed per incident
- **Analyst Activity Feed** — real-time action log (last 30 events)
- **Workload Distribution Chart** — grouped bar by analyst (Open vs Resolved vs Critical)

---

## Agent Collaboration

`dashboard/pages/9_Agent_Collaboration.py` visualises the multi-agent pipeline execution.

- View individual agent runs from `logs/agent_runs.jsonl`
- Inspect per-agent input/output state diffs
- Track pipeline duration and agent confidence contributions
- Filter by incident ID or agent name

The `dashboard/agent_store.py` provides:
- `seed_sample_runs()` — loads 10 seeded 2026 agent execution records
- `get_agent_runs(limit, incident_id, agent)` — filtered log retrieval
- `get_run_stats()` — pipeline execution metrics

---

## PDF Report Generation

The `reporting/` package generates professional 8-section PDF reports using ReportLab platypus.

```python
from reporting import assemble_report_data, build_incident_report

data = assemble_report_data(
    "INC-2026-001",
    incident_record=inc,
    case_record=case,
    assignment_record=assignment,
    generated_by="Sarah Kim",
    classification="CONFIDENTIAL",
)
pdf_bytes = build_incident_report(data)  # returns raw bytes starting with %PDF
```

**Report sections:**
1. Cover page — classification banner, severity badge, metadata
2. Incident Summary — KV table with confidence and risk scores
3. Incident Timeline — chronological event table
4. MITRE ATT&CK Mapping — technique ID, name, tactic, reference URL
5. Threat Actor Attribution — actor profile with aliases, TTPs, tools
6. Analyst Notes — per-note with author and timestamp
7. Case Status — current status, priority, case history
8. Evidence Summary — parsed IOC table (type / value)
9. Recommendations — category and ATT&CK-tactic-aware remediation steps

PDF export is integrated into **Incident Overview**, **Case Management**, and **Analyst Workbench** via `st.download_button` with session-state caching.

---

## Threat Actor Intelligence

`dashboard/pages/11_Threat_Actors.py` provides a 5-tab intelligence center across 23 tracked actors.

**Featured actors:** LOCKBIT4 · TA505 · FIN7 · APT29 · APT41 · Lazarus Group

**Risk scoring model:**

```
risk_score = (sophistication_score × 0.45) + (severity_score × 0.40) + (ttp_breadth × 0.15)

Sophistication:  nation-state=0.95  advanced=0.80  intermediate=0.60  basic=0.35
```

**Five tabs:**

| Tab | Content |
|---|---|
| Actor Profiles | Full profile card, risk gauge, attribution confidence gauge, target sector bar, TTP/tool/IOC/campaign expanders |
| Campaign Activity | Plotly Gantt timeline, campaign detail table with status/sector/victim filters |
| Techniques Matrix | Top-25 technique frequency bar, actor × technique coverage grid, tactic category distribution |
| Actor Comparison | Radar chart (risk, attribution, TTP coverage, campaign activity, victim reach), side-by-side comparison table |
| Geographic Activity | Origin donut, sophistication distribution, target region stacked bar, target sector stacked bar |

---

## REST API

Base URL: `http://localhost:8000/api/v1`  
Interactive docs: `http://localhost:8000/docs`

### Authentication

```bash
# Login
curl -X POST /api/v1/auth/login \
  -d '{"email":"admin@example.com","password":"Password123!"}'
# → {"access_token":"...", "refresh_token":"...", "token_type":"Bearer"}

# Use token
curl -H "Authorization: Bearer $TOKEN" /api/v1/incidents
```

Token TTLs: access=15 min · refresh=7 days

### RBAC Matrix

| Resource | ADMIN | ANALYST | VIEWER |
|---|---|---|---|
| Read incidents/cases | ✓ | ✓ | ✓ |
| Create/update incidents | ✓ | ✓ | — |
| Run pipeline | ✓ | ✓ | — |
| Delete incidents | ✓ | — | — |
| Manage users/tenants | ✓ | — | — |

### Key Endpoints

```
POST   /auth/login                 Obtain JWT token pair
POST   /auth/refresh               Refresh access token
POST   /auth/logout                Blacklist refresh token
GET    /auth/me                    Current user profile

GET    /incidents                  List incidents (paginated)
POST   /incidents                  Create incident
POST   /incidents/{id}/run         Trigger agent pipeline
GET    /incidents/{id}             Get incident detail
PATCH  /incidents/{id}             Update incident
DELETE /incidents/{id}             Delete incident

GET    /cases                      List cases
POST   /cases                      Create case
PATCH  /cases/{id}                 Update case status/priority/analyst
POST   /cases/{id}/incidents/{id}  Link incident to case

POST   /ingest/json                Bulk ingest JSON incidents
POST   /ingest/csv                 Bulk ingest CSV log file
POST   /ingest/syslog              Parse syslog entries

GET    /attack/techniques          Browse ATT&CK techniques
GET    /attack/tactics             List ATT&CK tactics

GET    /health                     Health check (no auth)
GET    /metrics                    Prometheus metrics (no auth)
```

---

## Test Coverage

| Test File | Tests | Scope |
|---|---|---|
| `test_state.py` | 11 | StateObject, IncidentStatus, ThreatSeverity enums |
| `test_agents.py` | 18 | PlannerAgent, ForensicsAgent, ComplianceAgent |
| `test_orchestrator.py` | 13 | MythosOrchestrator batch pipeline |
| `test_intelligence_agent.py` | 16 | IntelligenceAgent, MITRE ATT&CK enrichment |
| `test_attribution_agent.py` | 24 | AttributionAgent, campaign clustering |
| `test_featherless_client.py` | 21 | FeatherlessClient mock-first API |
| `test_bandai_client.py` | 22 | BandAIClient mock-first task platform |
| `test_phase3_pipeline.py` | 18 | End-to-end Phase 3 integration |
| `test_dashboard_data.py` | 39 | data_loader all functions |
| `test_dashboard_charts.py` | 32 | Plotly chart builders |
| `test_api_auth.py` | 14 | Login, refresh, logout, /me |
| `test_api_incidents.py` | 17 | Incident CRUD + pipeline trigger |
| `test_api_cases.py` | 14 | Case CRUD + link/unlink |
| `test_api_rbac.py` | 21 | RBAC matrix + multi-tenant isolation |
| `test_api_ingest.py` | 18 | Parser endpoints (JSON/CSV/syslog) |
| `test_api_attack.py` | 15 | ATT&CK technique/tactic endpoints |
| `test_api_case_management.py` | 16 | Case service layer |
| `test_parsers.py` | 19 | JSON/CSV/syslog parsers + dedup |
| `test_attack_engine.py` | 14 | AttackEngine lazy singleton |
| `test_workbench_store.py` | 22 | Workbench assignment/note/escalation |
| `test_agent_store.py` | 18 | Agent run store + seed |
| `test_executive_store.py` | 79 | Executive KPI compute, filters, MITRE coverage |
| `test_report_builder.py` | 34 | PDF builder, recommendations, assemble_report_data |
| `test_threat_actor_store.py` | 62 | Threat actor store, pure compute, search/filter |
| `test_validators.py` | 72 | Incident/campaign/case/analyst validators + dataset |
| `test_production_dataset.py` | 37 | Data integrity: 50 incidents, 10 analysts, campaigns |
| **Total** | **795** | |

---

## Production Dataset

Phase 7.1 ships a fully enriched SOC dataset that drives all dashboard views:

### Incidents (`data/sample_incidents.json`)

50 realistic enterprise incidents spanning 30 days, covering all 10 threat categories:

| Category | Incidents | Example Threats |
|---|---|---|
| Ransomware | 13 | LockBit 4.0, BlackCat/ALPHV, Akira, PLAY, Rhysida |
| Command & Control | 9 | Cobalt Strike, Brute Ratel C4, Sliver, Havoc, Mythic |
| Data Exfiltration | 7 | Cl0p MOVEit-style, TA505 FTP, Scattered Spider Azure |
| Lateral Movement | 5 | Mimikatz PTH, Kerberoasting, RDP brute-force, WMIC |
| Credential Theft | 5 | EvilGinx2 AITM, Midnight Blizzard OAuth, Storm-0558 |
| Phishing / Malware | 5 | DarkGate, QakBot, BumbleBee, Emotet, Carbanak |
| Nation-State LOTL | 3 | Volt Typhoon, APT28, APT29 |
| Insider Threat | 1 | Contractor USB staging |
| Crypto / Supply Chain | 2 | Lazarus TraderTraitor, npm backdoor |

Each incident includes:
- Realistic MITRE ATT&CK techniques (3–6 per incident, 47 unique technique IDs)
- Confidence score, risk score, attribution confidence (0.0–1.0)
- Analyst assignment (one of 10 SOC analysts)
- Status progression (DETECTED → INVESTIGATING → CONTAINED → MITIGATED → RESOLVED)
- IOC enrichments, mitigation actions, AI threat summary

### Analysts (`data/analysts.json`)

10 SOC analysts with realistic profiles:

| Name | Tier | Specialization |
|---|---|---|
| Sarah Kim | Tier 3 | Ransomware, IR, Forensics |
| James Okafor | Tier 3 | Critical Infrastructure, OT/ICS |
| Elena Vasquez | Tier 2 | Identity & Access, Phishing, BEC |
| Priya Nair | Tier 3 | APT Tracking, Threat Intelligence |
| Nia Thompson | Tier 2 | Financial Threat Actors, Crypto |
| Carlos Mendez | Tier 3 | Data Exfiltration, Compliance |
| Marcus Webb | Tier 2 | C2 Detection, Network Forensics |
| Aisha Patel | Tier 2 | Endpoint Detection, Lateral Movement |
| Tom Brandt | Tier 1 | Triage, Alert Monitoring |
| Ryan O'Brien | Tier 2 | Nation-State Threats, LOTL |

---

## Executive Dashboard

**Page 10 · `dashboard/pages/10_Executive_Dashboard.py`**

A C-suite / CISO command view with live date-range and severity filters applied to all metrics.

### KPI Cards (8)

| KPI | Source |
|---|---|
| Total Incidents | Count of incidents in selected range |
| Critical Incidents | Severity == CRITICAL in selected range |
| Open Cases | Active cases (all time) |
| Active Campaigns | Distinct campaigns in selected range |
| MTTD | Severity-weighted detection time model |
| MTTR | Mean hours to resolve closed cases |
| Analyst Utilization | Active assignments as % of capacity |
| Avg Attribution Conf | Mean AttributionAgent confidence |

### Visualizations (7)

- **Incident Trend** — Area chart for selected date window
- **Severity Distribution** — Donut chart (CRITICAL / HIGH / MEDIUM / LOW)
- **Case Status Distribution** — Bar chart by status
- **Threat Category Breakdown** — Horizontal bar (8 categories)
- **Campaign Activity** — Top 10 campaigns by incident count
- **Threat Actor Attribution** — Donut chart by actor family
- **MITRE ATT&CK Coverage** — Bar chart showing unique techniques per tactic

### Filters

- **Date range** — From / To date pickers + quick range buttons (7d, 30d, 90d, All time)
- **Severity** — Multi-select (CRITICAL, HIGH, MEDIUM, LOW)
- **Export** — Download KPI Summary as CSV

### Launch

```bash
streamlit run dashboard/app.py
# Navigate to: Executive Dashboard (page 10 in sidebar)
```

### Sample KPI Output (30-day window, all severities)

```
Total Incidents:       50
Critical Incidents:    11
Open Cases:            10
Active Campaigns:      20
MTTD:                  7.4 hrs
MTTR:                  72.0 hrs
Analyst Utilization:   16.0%
Avg Attribution Conf:  75.0%
```

---

## Project Structure

```
Mythos/
├── agents/
│   ├── attribution_agent.py     # threat_name → actor mapping (55 entries)
│   ├── compliance_agent.py      # ATTRIBUTED → MITIGATED, playbook selection
│   ├── forensics_agent.py       # ATT&CK enrichment, AttackEngine wrapper
│   ├── intelligence_agent.py    # IOC enrichment, Featherless/BandAI
│   └── planner_agent.py         # DETECTED → ANALYZED, risk scoring (54 entries)
│
├── api/
│   ├── db/database.py           # AsyncSession, Base, get_db, init_db
│   ├── models/                  # SQLAlchemy ORM: incident, case, user, tenant, audit
│   ├── routers/                 # auth, incidents, cases, users, tenants, ingest, attack
│   ├── schemas/                 # Pydantic v2 schemas
│   ├── services/                # auth, audit, cache (Redis), metrics (Prometheus)
│   ├── dependencies.py          # get_current_user, require_roles(*roles)
│   └── main.py                  # FastAPI app + middleware + lifespan
│
├── core/
│   ├── logger.py                # logging setup, persist(), JSONL/CSV sinks
│   ├── orchestrator.py          # MythosOrchestrator, 5-agent pipeline
│   └── state.py                 # StateObject (Pydantic), IncidentStatus, ThreatSeverity
│
├── dashboard/
│   ├── pages/
│   │   ├── 1_Incident_Overview.py
│   │   ├── 2_Threat_Intelligence.py
│   │   ├── 3_Incident_Timeline.py
│   │   ├── 4_Logs_Explorer.py
│   │   ├── 5_Incident_Intake.py
│   │   ├── 6_Case_Management.py
│   │   ├── 7_MITRE_ATT&CK.py
│   │   ├── 8_Analyst_Workbench.py
│   │   ├── 9_Agent_Collaboration.py
│   │   ├── 10_Executive_Dashboard.py
│   │   └── 11_Threat_Actors.py
│   ├── components/              # charts.py, filters.py, metrics.py
│   ├── agent_store.py           # agent run log + seed
│   ├── case_store.py            # case CRUD, 15-case 2026 seed
│   ├── data_loader.py           # JSONL loader, KPI compute, filter_df
│   ├── executive_store.py       # MTTR/MTTD/utilisation KPI aggregation
│   ├── threat_actor_store.py    # 23 actors, risk/confidence scoring, search
│   └── workbench_store.py       # assignment, escalation, activity feed
│
├── data/
│   ├── campaigns.json           # 22 campaigns (20 original + FIN7 + APT41)
│   ├── mitre_attack.json        # full ATT&CK dataset
│   ├── sample_incidents.json    # 50 2026 incidents
│   └── threat_profiles.json     # 23 actor profiles
│
├── intelligence/
│   └── attack_engine.py         # lazy-loading ATT&CK singleton
│
├── integrations/
│   ├── bandai_client.py         # BandAI task platform client
│   └── featherless_client.py    # Featherless LLM inference client
│
├── logs/                        # attribution_log.jsonl/.csv, audit.jsonl, agent_runs.jsonl
│
├── parsers/
│   ├── base.py / json_parser.py / csv_parser.py / syslog_parser.py
│   ├── dedup.py                 # content-hash deduplication
│   └── ingestion_service.py     # multi-format coordinator
│
├── reporting/
│   ├── __init__.py
│   ├── report_builder.py        # 8-section PDF engine (ReportLab platypus)
│   └── styles.py                # colour palette + paragraph styles
│
├── reports/                     # generated PDF output directory
│
├── tests/                       # 24 test files, 588 tests total
│
├── alembic/                     # database migration scripts
├── monitoring/                  # Prometheus config + Grafana dashboard JSON
│
├── .env.example
├── conftest.py
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Configuration

Copy `.env.example` to `.env` and set:

```bash
# Required for production
JWT_SECRET_KEY=<openssl rand -hex 32>
DATABASE_URL=postgresql+asyncpg://mythos:password@localhost:5432/mythos
REDIS_URL=redis://localhost:6379/0

# Optional
MYTHOS_LOG_LEVEL=INFO          # DEBUG | INFO | WARNING
CONFIDENCE_THRESHOLD=0.75      # minimum confidence to flag as attributed
RISK_CRITICAL_THRESHOLD=0.80   # risk score threshold for CRITICAL label
SQL_ECHO=false                 # set true only in local dev
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
```

For local development without PostgreSQL/Redis, the application automatically uses SQLite + in-memory cache (no configuration needed).
