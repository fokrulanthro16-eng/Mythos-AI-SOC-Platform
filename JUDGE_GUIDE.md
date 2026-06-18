# Mythos — Judge Evaluation Guide

**Platform:** Mythos AI-Powered SOC Incident Orchestration Platform  
**Category:** AI / Cybersecurity / Full-Stack Engineering  
**Repo:** https://github.com/fokrulanthro16-eng/Mythos-AI-SOC-Platform

---

## Quick Start (under 3 minutes)

```bash
# 1. Clone and install
git clone https://github.com/fokrulanthro16-eng/Mythos-AI-SOC-Platform.git
cd Mythos-AI-SOC-Platform
pip install -r requirements.txt

# 2. Run the agent pipeline
python core/orchestrator.py

# 3. Launch the dashboard
python -m streamlit run dashboard/app.py
# → http://localhost:8501

# 4. Verify tests
pytest tests/ -q --tb=no
# → 874 passed
```

No database, no Docker, no API keys required for local evaluation.

---

## What to Evaluate

### 1. AI Agent Pipeline (`core/orchestrator.py`, `agents/`)

**What it does:** 5 specialised agents process each security incident sequentially. Each agent has a single, well-defined responsibility.

**Where to look:**
- `agents/planner_agent.py` — IOC assignment from 54-entry lookup, risk scoring formula
- `agents/attribution_agent.py` — 55-entry threat-name-to-actor mapping, campaign clustering
- `agents/forensics_agent.py` — lazy-loading `AttackEngine` singleton, MITRE enrichment
- `agents/compliance_agent.py` — playbook selection, mitigation action population
- `core/orchestrator.py` — pipeline orchestration, state machine, batch processing

**Evaluate:**
- Is the agent separation of concerns clean and logical?
- Does confidence propagate meaningfully across agents?
- Is the risk scoring model justified and documented?

---

### 2. Live Dashboard (12 pages, `dashboard/pages/`)

**What it does:** A production-grade Streamlit Command Center covering every SOC workflow from raw alert to executive report.

**High-value pages to visit:**

| Page | URL | What to assess |
|---|---|---|
| Incident Overview | `/` (first page) | KPI accuracy, chart quality, PDF export |
| Analyst Workbench | Page 8 | 6-tab UX, state transitions, activity log |
| Executive Dashboard | Page 10a | Filter responsiveness, KPI correctness |
| Executive Reports | Page 10b | PDF generation, section quality |
| Threat Actor Intel | Page 11 | 5-tab depth, radar chart, Gantt timeline |

**Evaluate:**
- Does each page serve a distinct, real SOC function?
- Are filters applied consistently across all charts?
- Is the dark-theme Plotly visualisation professional and readable?

---

### 3. Threat Actor Intelligence (`intelligence/`, `data/`)

**What it does:** Two-tier intelligence system — 23 actor profiles for the dashboard (threat_profiles.json) and 10 deep-profiled actors for the engine (threat_actors.json).

**Where to look:**
- `intelligence/threat_actor_engine.py` — 6 public functions, 4-tier attribution cascade
- `data/threat_actors.json` — 10 actor profiles with real-world accuracy
- `data/threat_profiles.json` — 23 actors with risk/confidence scoring

**Test the engine directly:**
```python
from intelligence.threat_actor_engine import get_actor, search_actor, map_incident_to_actor

# Alias lookup
print(get_actor("Cozy Bear")["name"])        # APT29
print(get_actor("Midnight Blizzard")["name"]) # APT29

# Attribution cascade
inc = {"threat_name": "LOCKBIT4-RANSOMWARE", "attack_techniques": []}
print(map_incident_to_actor(inc))  # LockBit

# Text search
print([a["name"] for a in search_actor("cryptocurrency")])  # [Lazarus]
```

**Evaluate:**
- Are the 10 actor profiles factually accurate against public threat intelligence?
- Does the 4-tier attribution cascade resolve correctly and in the right priority?
- Is the engine fully testable (no file I/O in pure compute functions)?

---

### 4. PDF Report Generation (`reporting/`)

**What it does:** Two PDF builders — 9-section incident reports and 4-section executive board reports. Generated entirely in Python using ReportLab platypus.

**Generate manually:**
```python
from reporting.executive_report_builder import assemble_executive_data, build_executive_report

data = assemble_executive_data()
pdf  = build_executive_report(data)
open("test_report.pdf", "wb").write(pdf)
```

**Evaluate:**
- Is the PDF output professional enough for a real executive audience?
- Are the MITRE technique table, KPI cards, and threat intelligence sections well-formatted?
- Does the generation handle edge cases (empty data, missing fields) without crashing?

---

### 5. REST API (`api/`)

**What it does:** FastAPI with JWT HS256 auth, 3-role RBAC, multi-tenant isolation, full incident/case CRUD, multi-format ingest, ATT&CK endpoints.

**Quick test:**
```bash
# Start the API
uvicorn api.main:app --port 8000

# Login
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Password123!"}' \
  | python -m json.tool

# API docs (no auth needed)
open http://localhost:8000/docs
```

**Evaluate:**
- Does the RBAC matrix enforce correctly (VIEWER cannot trigger pipeline)?
- Are Pydantic v2 schemas comprehensive and well-named?
- Is the multi-tenant isolation implemented at the query layer, not just the endpoint?

---

### 6. Test Suite (`tests/`)

**What it does:** 874 tests across 26 files. Every component independently verified — agents, API endpoints, dashboard stores, PDF builders, intelligence engine, data integrity.

```bash
# Full suite
pytest tests/ -v

# By category
pytest tests/test_threat_actor_engine.py -v    # 53 engine tests
pytest tests/test_executive_report.py -v       # 26 PDF tests
pytest tests/test_executive_store.py -v        # 79 KPI aggregation tests
pytest tests/test_production_dataset.py -v     # 37 data integrity tests
pytest tests/test_api_rbac.py -v               # 21 RBAC tests
```

**Evaluate:**
- Are tests isolated (no test modifies shared state)?
- Are edge cases covered (empty data, invalid input, boundary values)?
- Do `_compute_*` functions follow pure-function patterns testable without I/O?

---

### 7. Production Dataset (`data/`)

**What it does:** 50 fully enriched 2026 incidents with realistic MITRE techniques, confidence/risk/attribution scores, analyst assignments, and campaign links.

**Verify integrity:**
```bash
pytest tests/test_production_dataset.py -v
# Checks: 50 incidents, 10 analysts, 22 campaigns, cross-dataset consistency,
#         technique ID format, timestamp ordering, score ranges
```

**Evaluate:**
- Do incident descriptions read like real security events?
- Are MITRE technique selections realistic for each threat category?
- Is the analyst roster tier distribution plausible (T1/T2/T3)?

---

## Key Technical Decisions to Note

| Decision | Rationale |
|---|---|
| Pure `_compute_*` functions | All aggregation logic is I/O-free — fully testable without mocking file reads |
| Lazy-loading `AttackEngine` | 100K+ ATT&CK records load on first use only — zero startup cost |
| Two actor data formats | `threat_profiles.json` (dashboard store, 23 actors, risk-scored) is independent from `threat_actors.json` (engine format, 10 deep profiles) — separation of concerns |
| `monkeypatch.setattr(module, "_PATH", tmp)` | Standard pattern for path injection in store tests — no environment variable leakage |
| `filter_incidents(incidents, date_from, date_to, severities)` | All executive KPIs reuse a single filtering function — one place to fix, all charts update |
| ReportLab platypus (not a template engine) | Programmatic PDF construction gives pixel-precise control over layout — no HTML/CSS rendering |
| SQLite fallback on missing DATABASE_URL | Zero-config local development — judges can run immediately with no database setup |

---

## Scoring Dimensions

| Dimension | Evidence |
|---|---|
| **Technical depth** | 5-agent pipeline · JWT RBAC API · ReportLab PDF · MITRE ATT&CK engine · threat actor intelligence engine |
| **Code quality** | Pure functions · single responsibility · 874 tests · no global state in stores |
| **Completeness** | End-to-end: ingest → pipeline → dashboard → case management → PDF → executive report |
| **Real-world accuracy** | 10 factually grounded threat actor profiles · 47 real ATT&CK technique IDs · realistic MTTR/MTTD models |
| **UX polish** | Plotly dark theme · sidebar filters responsive to all charts · one-click PDF on every relevant page |
| **Scalability design** | PostgreSQL + Redis production path · Alembic migrations · multi-tenant isolation · Docker Compose |

---

## Known Scope Boundaries

- **LLM integration:** `FeatherlessClient` and `BandAIClient` are real client implementations that fall back to mock responses when API keys are absent. The agents are designed to be LLM-augmented but function fully without external calls.
- **Real-time ingest:** The pipeline runs in batch mode (`python core/orchestrator.py`). A production deployment would add a Kafka/Redis queue consumer — the ingest API and parsers are already in place.
- **Authentication storage:** The default SQLite backend stores users in a local file. A production deployment uses PostgreSQL + Redis as shown in `docker-compose.yml`.

---

## Files Most Worth Reading

```
core/orchestrator.py                 # Pipeline orchestration
agents/attribution_agent.py          # Threat actor mapping logic
intelligence/threat_actor_engine.py  # Attribution cascade
dashboard/executive_store.py         # KPI aggregation with filter composition
reporting/executive_report_builder.py# Board PDF construction
dashboard/pages/8_Analyst_Workbench.py  # Most complex dashboard page
tests/test_threat_actor_engine.py    # Engine test design pattern
tests/test_production_dataset.py     # Cross-dataset integrity tests
```
