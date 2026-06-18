<div align="center">

# Mythos — AI-Powered SOC Incident Orchestration Platform

**A production-grade, multi-agent Security Operations Centre platform built for the modern enterprise.**

Mythos automates the full incident response lifecycle — detection through mitigation — using a 5-agent AI pipeline, a 12-page live SOC Command Center, a FastAPI REST layer with JWT/RBAC, ReportLab PDF reporting, and a comprehensive threat actor intelligence engine.

[![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.x-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.11x-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-874%20passing-brightgreen?logo=pytest)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)
[![ReportLab](https://img.shields.io/badge/PDF-ReportLab-orange)](https://reportlab.com)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

</div>

---

<div align="center">

### The Problem

Security Operations Centres drown in alert noise. Analysts spend 60–70% of their time on manual triage — correlating indicators, attributing actors, selecting playbooks, drafting reports — tasks that are repetitive, error-prone, and slow when seconds matter.

### The Solution

Mythos replaces manual triage with a coordinated pipeline of specialised AI agents. Each agent owns one responsibility: planning, intelligence enrichment, attribution, forensics, or compliance. Together they reduce a 45-minute triage cycle to under 30 seconds — with full audit trails, MITRE ATT&CK mapping, and one-click PDF reports.

</div>

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Features](#features)
- [Dashboard Pages](#dashboard-pages)
- [Screenshots](#screenshots)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Threat Actor Intelligence](#threat-actor-intelligence)
- [Executive Reporting](#executive-reporting)
- [Analyst Workflow](#analyst-workflow)
- [Agent Collaboration](#agent-collaboration)
- [REST API](#rest-api)
- [Installation](#installation)
- [Demo Steps](#demo-steps)
- [Test Coverage](#test-coverage)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Configuration](#configuration)

---

## Project Overview

Mythos is a full-stack cybersecurity operations platform purpose-built to demonstrate what an AI-native SOC looks like. Every component reflects real-world enterprise security engineering:

| Dimension | What Mythos delivers |
|---|---|
| **AI Agents** | 5 specialised agents orchestrated in a deterministic pipeline with confidence scoring and risk propagation |
| **Live Dashboard** | 12-page Streamlit Command Center with Plotly dark-theme charts, sidebar filters, and drill-down views |
| **Threat Intelligence** | 23 tracked threat actors (profiles) + 10 deep-profiled actors (engine) with MITRE technique mapping |
| **PDF Reports** | ReportLab-generated incident reports (9 sections) and executive board reports (4 sections) |
| **REST API** | FastAPI with JWT HS256 auth, role-based access control (ADMIN/ANALYST/VIEWER), multi-tenant isolation |
| **Production Dataset** | 50 enriched 2026 incidents, 20 campaigns, 10 SOC analysts, 23 threat actor profiles |
| **Test Suite** | 874 passing tests across 26 files — agents, API, dashboard stores, PDF generation, intelligence engine |
| **Observability** | Prometheus /metrics endpoint, Grafana dashboard JSON, structured JSONL audit log |

**Built for:** Security competitions, portfolio demonstration, enterprise SOC prototyping, and AI-in-cybersecurity research.

---

## Architecture

### System Architecture

```mermaid
graph TB
    subgraph Intake["Incident Intake"]
        A["Incident<br/>JSON · CSV · Syslog · API"] --> B[Ingestion Service]
        B --> C["Parser + Dedup<br/>(content-hash)"]
        C --> D[StateObject]
    end

    subgraph Pipeline["Agent Pipeline  ·  core/orchestrator.py"]
        D --> E["PlannerAgent<br/>DETECTED → ANALYZED<br/>IOC assignment · confidence · risk score"]
        E --> F["IntelligenceAgent<br/>ATT&CK enrichment · IOC lookup<br/>Featherless · BandAI"]
        F --> G["AttributionAgent<br/>ANALYZED → ATTRIBUTED<br/>threat actor mapping · campaign clustering"]
        G --> H["ForensicsAgent<br/>ATT&CK technique enrichment<br/>AttackEngine lazy singleton"]
        H --> I["ComplianceAgent<br/>ATTRIBUTED → MITIGATED<br/>playbook selection · mitigation actions"]
    end

    subgraph Persistence["Persistence Layer"]
        I --> J[("logs/<br/>attribution_log.jsonl<br/>attribution_log.csv")]
        I --> K[("PostgreSQL<br/>incidents · cases<br/>users · tenants")]
        I --> L[("Redis<br/>JWT blacklist<br/>response cache")]
    end

    subgraph API["REST API  ·  api/main.py  ·  :8000"]
        K --> M["FastAPI /api/v1/<br/>JWT HS256 · RBAC · Pydantic v2"]
        M --> N[Prometheus /metrics]
        N --> O[Grafana Dashboards]
    end

    subgraph Dashboard["Streamlit Command Center  ·  :8501"]
        J --> P[data_loader.py]
        K --> P
        P --> Q["1 · Incident Overview"]
        P --> R["2 · Threat Intelligence"]
        P --> S["3 · Incident Timeline"]
        P --> T["4 · Logs Explorer"]
        P --> U["5 · Incident Intake"]
        P --> V["6 · Case Management"]
        P --> W["7 · MITRE ATT&CK"]
        P --> X["8 · Analyst Workbench"]
        P --> Y["9 · Agent Collaboration"]
        P --> Z["10a · Executive Dashboard"]
        P --> ZA["10b · Executive Reports"]
        P --> AA["11 · Threat Actor Intel"]
    end

    subgraph Intel["Threat Intelligence"]
        CC[("data/threat_profiles.json<br/>23 actors")] --> R
        CC --> AA
        DD[("data/threat_actors.json<br/>10 deep profiles")] --> EE["threat_actor_engine.py"]
        FF[("data/mitre_attack.json<br/>ATT&CK matrix")] --> W
        EE --> ZA
    end

    subgraph Reporting["PDF Reporting  ·  reporting/"]
        V --> BB["report_builder.py<br/>9-section incident PDF"]
        X --> BB
        Q --> BB
        ZA --> GG["executive_report_builder.py<br/>4-section board PDF"]
    end
```

### Component Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser / API Client / curl                                         │
├──────────────────────────┬──────────────────────────────────────────┤
│  Streamlit Dashboard     │  FastAPI REST API                         │
│  localhost:8501          │  localhost:8000/api/v1/*                 │
│  12 pages · Plotly dark  │  JWT HS256 · RBAC · Pydantic v2          │
├──────────────────────────┴──────────────────────────────────────────┤
│  Agent Pipeline  ·  core/orchestrator.py                             │
│  PlannerAgent → IntelligenceAgent → AttributionAgent                 │
│                → ForensicsAgent   → ComplianceAgent                  │
├─────────────────────────────────────────────────────────────────────┤
│  Intelligence Layer                                                  │
│  AttackEngine (MITRE ATT&CK) · ThreatActorEngine (10 actors)        │
│  ThreatActorStore (23 actors) · ExecutiveStore (KPI aggregation)    │
├─────────────────────────────────────────────────────────────────────┤
│  Data Stores                                                         │
│  PostgreSQL (production) · SQLite (local/CI)                        │
│  Redis (JWT blacklist + response cache)                              │
│  JSONL log files (dashboard primary data source)                    │
├─────────────────────────────────────────────────────────────────────┤
│  Observability                                                       │
│  Prometheus /metrics · Grafana dashboards · audit.jsonl             │
└─────────────────────────────────────────────────────────────────────┘
```

### Agent State Machine

```
DETECTED ──► ANALYZED ──► ATTRIBUTED ──► MITIGATED ──► RESOLVED
    │             │              │              │
PlannerAgent  Intelligence  Attribution   Compliance
              + Forensics    Agent        Agent
```

### Risk Scoring Model

```
risk_score = (confidence_score × 0.70) + (severity_weight × 0.30)

Severity weights:   CRITICAL = 1.00   HIGH = 0.75   MEDIUM = 0.50   LOW = 0.25
Risk thresholds:    ≥ 0.80 → CRITICAL  ≥ 0.60 → HIGH  ≥ 0.40 → MEDIUM  < 0.40 → LOW

Threat actor risk:  (sophistication × 0.45) + (severity × 0.40) + (ttp_breadth × 0.15)
Nation-state = 0.95   Advanced = 0.80   Intermediate = 0.60   Basic = 0.35
```

---

## Features

### AI Agent Pipeline

| Agent | Transition | Responsibilities |
|---|---|---|
| **PlannerAgent** | DETECTED → ANALYZED | IOC assignment from threat name (54-entry lookup), confidence score initialisation, risk score computation |
| **IntelligenceAgent** | ANALYZED | MITRE ATT&CK technique enrichment, IOC type classification, Featherless LLM and BandAI task platform queries |
| **AttributionAgent** | ANALYZED → ATTRIBUTED | Maps `threat_name` to actor ID (55-entry lookup), clusters incidents into campaigns, adjusts attribution confidence |
| **ForensicsAgent** | ATTRIBUTED | Lazy-loads `AttackEngine` singleton, enriches each technique with full ATT&CK tactic/sub-technique/URL data |
| **ComplianceAgent** | ATTRIBUTED → MITIGATED | Selects remediation playbook (8 categories), populates `mitigation_actions`, tags compliance obligations |

### Dashboard (12 Pages)

- Live Incident Overview with severity/risk KPIs and confidence scatter plot
- Threat Intelligence with actor profiles, campaign frequency, IOC type breakdown
- Incident Timeline with state-transition scatter and status heatmap
- Logs Explorer with searchable JSONL/CSV table and export
- Incident Intake form with field validation
- Case Management — full CRUD, OPEN→CLOSED flow, linked incidents, notes, PDF export
- MITRE ATT&CK browser — technique lookup, tactic filter, enrichment view
- Analyst Workbench — 6-tab action panel, workload chart, activity feed, PDF export
- Agent Collaboration viewer — per-agent run inspection, confidence timeline
- Executive Dashboard — 8 KPIs, 7 charts, date/severity filters, CSV export
- Executive Reports — board-level PDF generator with one-click download
- Threat Actor Intelligence Center — 5-tab deep dive across 23 tracked actors

### Threat Intelligence

- **23 threat actor profiles** in `threat_profiles.json` — origin, sophistication, motivation, TTPs, tools, IOC patterns, campaign history
- **10 deep-profiled actors** in `threat_actors.json` — APT29, APT28, Lazarus, Volt Typhoon, FIN7, TA505, LockBit, BlackCat, Scattered Spider, Mustang Panda
- **Threat actor engine** with 6 public functions: load, get, search, statistics, campaign count, incident-to-actor attribution
- **4-tier attribution cascade**: suspected_actor field → threat-name keywords → threat-category mapping → MITRE technique match
- **Campaign database**: 22 campaigns with status, victim count, ransom demands, tactic categories, Gantt timeline
- **5-tab intelligence center**: Actor Profiles · Campaign Activity · Techniques Matrix · Actor Comparison · Geographic Activity

### PDF Reporting

- **Incident reports** (9 sections): Cover, Incident Summary, Timeline, MITRE ATT&CK Mapping, Actor Attribution, Analyst Notes, Case Status, Evidence/IOC Table, Recommendations
- **Executive reports** (4 sections): Cover + KPIs, Incident Summary, MITRE Coverage, Threat Intelligence
- Integrated download buttons on Incident Overview, Case Management, Analyst Workbench, and Executive Reports pages
- ReportLab platypus engine — `Table`, `Paragraph`, `HRFlowable`, brand colour palette (NAVY/RED/GRAY)

### Production Dataset

- **50 enriched incidents** — 2026-dated, realistic MITRE techniques (47 unique IDs), confidence/risk/attribution scores
- **10 named SOC analysts** — tiered (T1/T2/T3), certifications, specialisations, active case counts
- **20 campaigns** — threat actor attribution, tactic categories, victim counts, date ranges

### REST API

- JWT HS256 authentication — access token (15 min) + refresh token (7 days)
- Role-based access control — ADMIN · ANALYST · VIEWER with per-resource permissions
- Multi-tenant isolation — every resource scoped to tenant ID
- Full incident CRUD + pipeline trigger endpoint
- Case CRUD with link/unlink to incidents
- Multi-format ingest — JSON · CSV · syslog
- ATT&CK technique/tactic browse endpoints
- Prometheus `/metrics` — request counts, latency histograms, active connections

### Observability & Quality

- Prometheus metrics + Grafana dashboard JSON
- Structured JSONL audit log for all mutations
- Alembic migrations for PostgreSQL schema management
- 874 passing tests across 26 files — 0 failures

---

## Dashboard Pages

### Page 1 — Incident Overview

The primary analyst landing page. Shows real-time SOC health at a glance.

**Key elements:**
- 5 KPI cards: Active Incidents · Critical Count · Open Cases · Avg Risk · Avg Confidence
- Severity distribution pie chart (CRITICAL / HIGH / MEDIUM / LOW)
- Risk score histogram — distribution of all incidents
- Status progression bar — pipeline state across the incident pool
- Confidence × Risk scatter — identify under-investigated high-risk incidents
- Full sortable incident table with inline severity badges
- One-click PDF report generation per incident

---

### Page 2 — Threat Intelligence

Cross-incident threat actor and IOC intelligence view.

**Key elements:**
- Attribution confidence trend by actor family
- Campaign frequency chart — incidents per campaign
- IOC type breakdown (IP · domain · hash · email · URL)
- Actor profile summary cards for top 6 actors
- Attribution coverage rate (% attributed vs unknown)

---

### Page 3 — Incident Timeline

Temporal view of how incidents evolve through the pipeline.

**Key elements:**
- State-transition scatter — when each incident moved through DETECTED→MITIGATED
- Status heatmap — density by hour-of-day and day-of-week
- Full history table with transition timestamps
- Individual incident trace selector

---

### Page 4 — Logs Explorer

Raw data access layer for analysts who need to inspect pipeline output directly.

**Key elements:**
- Searchable JSONL attribution log table
- CSV export with field-level column selection
- Full-text search across threat name, actor, status
- Pagination and row limit controls

---

### Page 5 — Incident Intake

Manual incident submission form for incidents not ingested via API or file parsers.

**Key elements:**
- Structured form: threat name, severity, IOC list, description, campaign link
- Client-side validation before submission
- Confirmation with generated incident ID
- Directly feeds into the agent pipeline on submit

---

### Page 6 — Case Management

Full case lifecycle management. Mirrors the REST API case model.

**Key elements:**
- Case list with priority badges, status chips, linked incident count
- Create/edit case with analyst assignment and priority selection
- Status flow: `OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`
- Timestamped note history per case
- Full audit trail (action · user · timestamp)
- MTTR tracking — `created_at` to `resolved_at` delta
- PDF case report download

---

### Page 7 — MITRE ATT&CK Browser

Full ATT&CK matrix exploration, seeded from `data/mitre_attack.json`.

**Key elements:**
- Tactic selector (12 ATT&CK tactics)
- Technique search by ID or keyword
- Full technique detail panel: description, mitigations, sub-techniques, external references
- Enrichment status — which techniques are mapped in the current incident pool

---

### Page 8 — Analyst Workbench

The primary day-to-day analyst workflow interface.

**Key elements:**
- Assign incident to any of 10 named SOC analysts with priority and severity override
- Live assignments table — sortable by priority, filterable by analyst/status
- 6-tab action panel per selected incident:
  1. **Change Status** — OPEN → INVESTIGATING → CONTAINED → RESOLVED
  2. **Escalate Priority** — P3 → P2 → P1 with free-text escalation reason
  3. **Add Note** — timestamped investigation notes with analyst attribution
  4. **Reassign** — handoff to different analyst with reason
  5. **Close** — closing summary + automatic sync to `case_store`
  6. **Report** — one-click PDF incident report generation and download
- Analyst Activity Feed — last 30 actions across all analysts, chronological
- Workload Distribution Chart — grouped bar (Open · Resolved · Critical) per analyst

---

### Page 9 — Agent Collaboration

Visibility into the multi-agent pipeline execution history.

**Key elements:**
- Per-run inspection: input state → agent processing → output state diff
- Agent confidence contribution timeline (bar chart per agent)
- Pipeline duration per incident (total and per-agent breakdown)
- Filter by incident ID or agent name
- 10 seeded 2026 agent run records for demonstration

---

### Page 10a — Executive Dashboard

C-suite command view. All metrics respond to date range and severity filters.

**Key elements:**
- **8 KPI cards**: Total Incidents · Critical Incidents · Open Cases · Active Campaigns · MTTD · MTTR · Analyst Utilisation · Avg Attribution Confidence
- **7 visualisations**:
  - Incident Trend (area chart, configurable window)
  - Severity Donut (CRITICAL/HIGH/MEDIUM/LOW)
  - Case Status Distribution (bar)
  - Threat Category Breakdown (horizontal bar, 8 categories)
  - Campaign Activity (top 10 by incident count)
  - Threat Actor Attribution Donut
  - MITRE ATT&CK Coverage (techniques per tactic)
- Sidebar date range picker + quick ranges (7d · 30d · 90d · All time)
- Severity multiselect filter
- CSV export of KPI summary

**Sample output (all severities, 90-day window):**

```
Total Incidents:      50     MTTD:                  7.4 hrs
Critical Incidents:   11     MTTR:                 72.0 hrs
Open Cases:           10     Analyst Utilisation:   16.0%
Active Campaigns:     20     Avg Attribution Conf:  75.0%
```

---

### Page 10b — Executive Reports

On-demand board-level PDF generation with full data assembly.

**Key elements:**
- Date range filter + severity multiselect (identical to Executive Dashboard)
- Quick range buttons: 30d · 90d · All time
- 8 KPI metric cards (mirrored from Executive Dashboard)
- Incident severity donut + threat category bar
- Campaign activity table
- MITRE ATT&CK tactic coverage bar chart
- Threat actor attribution bar chart
- Intelligence database summary panel
- **Generate Executive PDF** button — assembles all data and returns downloadable PDF

---

### Page 11 — Threat Actor Intelligence Center

Five-tab deep-dive intelligence center across 23 tracked threat actors.

**Tab 1 — Actor Profiles:**
- Full actor profile card with aliases, description, motivation, target sectors/regions
- Risk Score gauge (0–100%) with colour-coded thresholds
- Attribution Confidence gauge
- Target sectors chart (from campaign data)
- Expandable panels: ATT&CK Techniques · Known Tools · IOC Patterns · Campaign History

**Tab 2 — Campaign Activity:**
- Plotly Gantt timeline — all campaigns with start/end dates, coloured by actor
- Campaign stats row: Total · Active · Victim Count · Largest Ransom Demand
- Detailed campaign table with status filter

**Tab 3 — Techniques Matrix:**
- Top-25 technique frequency bar (count of actors using each technique)
- Actor × technique coverage grid (top 15 techniques × up to 12 actors)
- Tactic category distribution bar

**Tab 4 — Actor Comparison:**
- Multi-dimensional radar chart: Risk Score · Attribution · TTP Coverage · Campaign Activity · Victim Reach
- Side-by-side comparison table (up to 4 actors)
- Risk vs Attribution grouped bar chart

**Tab 5 — Geographic Activity:**
- Actor origin donut chart
- Sophistication distribution bar
- Target region stacked bar (activity by region by actor)
- Target sector stacked bar

---

## Screenshots

> Screenshots are in `assets/screenshots/`. Run `python assets/generate_placeholders.py` to create labelled placeholders, then replace with live captures from `streamlit run dashboard/app.py`.

<table>
<tr>
<td width="50%" align="center">

**Incident Overview**

![Incident Overview](assets/screenshots/01_dashboard_overview.png)

*KPI row · severity pie · risk histogram · confidence scatter · full incident table*

</td>
<td width="50%" align="center">

**Incident Intake**

![Incident Intake](assets/screenshots/02_incident_intake.png)

*Structured form · field validation · campaign link · pipeline trigger*

</td>
</tr>
<tr>
<td width="50%" align="center">

**Case Management**

![Case Management](assets/screenshots/03_case_management.png)

*OPEN→CLOSED status flow · priority badges · timestamped note history · PDF export*

</td>
<td width="50%" align="center">

**MITRE ATT&CK Browser**

![MITRE ATT&CK](assets/screenshots/04_mitre_attack.png)

*Tactic selector · technique search · full detail panel · mitigations*

</td>
</tr>
<tr>
<td width="50%" align="center">

**Analyst Workbench**

![Analyst Workbench](assets/screenshots/05_analyst_workbench.png)

*6-tab action panel · workload chart · analyst activity feed · PDF export*

</td>
<td width="50%" align="center">

**Agent Collaboration**

![Agent Collaboration](assets/screenshots/06_agent_collaboration.png)

*Per-agent run inspection · confidence timeline · pipeline duration*

</td>
</tr>
<tr>
<td width="50%" align="center">

**Executive Reports**

![Executive Reports](assets/screenshots/07_executive_reports.png)

*Board-level PDF generator · 8 KPIs · MITRE coverage · threat attribution*

</td>
<td width="50%" align="center">

**Threat Actor Intelligence Center**

![Threat Actor Intelligence](assets/screenshots/08_threat_actor_intelligence.png)

*Actor profiles · risk gauges · campaign Gantt · techniques matrix · radar*

</td>
</tr>
</table>

---

## MITRE ATT&CK Mapping

Mythos implements full MITRE ATT&CK integration across three layers:

### 1. AttackEngine (intelligence/attack_engine.py)

Lazy-loading singleton over the complete ATT&CK dataset:

```python
from intelligence.attack_engine import AttackEngine

engine = AttackEngine()                              # lazy — loads on first call
tech   = engine.get_technique("T1059.001")           # full technique dict
techs  = engine.get_techniques_for_tactic("execution")
mapped = engine.map_threat_to_techniques("LOCKBIT4-RANSOMWARE")
```

### 2. ForensicsAgent enrichment

Every incident that passes through the pipeline gets its `attack_techniques[]` array enriched:

```json
{
  "technique_id":   "T1486",
  "technique_name": "Data Encrypted for Impact",
  "tactic":         "impact",
  "tactic_id":      "TA0040",
  "url":            "https://attack.mitre.org/techniques/T1486"
}
```

### 3. Executive KPI coverage

`executive_store.py` computes per-tactic technique counts across the full incident pool:

```python
from dashboard.executive_store import get_mitre_coverage

coverage = get_mitre_coverage()
# → [{"tactic": "Initial Access", "tactic_id": "initial-access", "techniques": 5}, ...]
```

### ATT&CK Coverage in Production Dataset

| Tactic | Techniques Observed | Example Technique IDs |
|---|---|---|
| Initial Access | 5 | T1566, T1190, T1133, T1195, T1078 |
| Execution | 4 | T1059.001, T1059.005, T1047, T1203 |
| Persistence | 3 | T1547.001, T1053, T1098 |
| Defence Evasion | 6 | T1027, T1036, T1055, T1562, T1070, T1218 |
| Credential Access | 5 | T1539, T1528, T1110, T1003.001, T1552 |
| Lateral Movement | 3 | T1550, T1021.001, T1021.002 |
| Collection | 3 | T1074, T1056, T1119 |
| Exfiltration | 4 | T1041, T1048, T1560, T1567 |
| Command & Control | 4 | T1071.001, T1095, T1572, T1219 |
| Impact | 4 | T1486, T1490, T1485, T1489 |

**47 unique technique IDs** mapped across 50 production incidents.

---

## Threat Actor Intelligence

### Actor Database (data/threat_actors.json)

10 deeply profiled threat actors with intelligence-grade detail:

| Actor | Country | Type | Sophistication | Attribution Conf. | Notable For |
|---|---|---|---|---|---|
| **APT29** | Russia | Nation-State | Nation-State | 95% | SolarWinds supply chain, OAuth phishing |
| **APT28** | Russia | Nation-State | Nation-State | 93% | DNC hack, GRU Unit 26165 |
| **Lazarus** | North Korea | Nation-State | Nation-State | 91% | $3B+ crypto theft, WannaCry |
| **Volt Typhoon** | China | Nation-State | Nation-State | 88% | LOTL pre-positioning in US CNI |
| **FIN7** | Russia | Criminal | Advanced | 89% | Carbanak banking malware, $1.2B stolen |
| **TA505** | Russia | Criminal | Advanced | 92% | Cl0p RaaS, MOVEit zero-day |
| **LockBit** | Russia | Criminal | Advanced | 94% | #1 RaaS globally, 2,000+ victims |
| **BlackCat** | Russia | Criminal | Advanced | 87% | Rust-based cross-platform ransomware |
| **Scattered Spider** | US/UK | Criminal | Advanced | 85% | MGM Resorts attack, social engineering |
| **Mustang Panda** | China | Nation-State | Advanced | 86% | PlugX, Southeast Asia espionage |

### Threat Actor Engine (intelligence/threat_actor_engine.py)

```python
from intelligence.threat_actor_engine import (
    get_actor, search_actor, actor_statistics,
    actor_campaign_count, map_incident_to_actor,
)

# Lookup by name or any alias
actor  = get_actor("Cozy Bear")        # → APT29 full dict
actor  = get_actor("Midnight Blizzard")# → APT29 full dict (alias match)

# Full-text search (name, description, aliases, campaigns, techniques)
actors = search_actor("ransomware")    # → [BlackCat, LockBit, TA505]
actors = search_actor("T1566")         # → actors using phishing

# Database-wide statistics
stats = actor_statistics()
# {
#   "total_actors":           10,
#   "by_country":             {"Russia": 6, "China": 2, "North Korea": 1, "US/UK": 1},
#   "by_type":                {"Nation-State": 4, "Criminal": 6},
#   "unique_techniques":      58,
#   "total_campaigns":        38,
#   "countries_represented":  4,
#   "avg_attribution_conf":   0.905,
#   "high_confidence_actors": 6
# }

# Per-actor campaign counts
counts = actor_campaign_count()
# → {"APT29": 4, "LockBit": 4, "TA505": 4, ...}

# Incident → actor attribution (4-tier cascade)
incident = {"threat_name": "LOCKBIT4-RANSOMWARE", "attack_techniques": [...]}
actor    = map_incident_to_actor(incident)  # → "LockBit"
```

### Attribution Cascade

```
1. suspected_actor field          → exact name/alias match in actor database
          │
          ▼ (if UNKNOWN or empty)
2. threat_name keywords           → LOCKBIT→LockBit, CLOP→TA505, MIDNIGHT-BLIZZARD→APT29 ...
          │
          ▼ (no keyword match)
3. threat_category mapping        → Credential Harvesting → APT29
                                    PowerShell Abuse      → FIN7
                                    Command and Control   → TA505
                                    Ransomware            → LockBit
                                    Lateral Movement      → BlackCat
          │
          ▼ (no category match)
4. MITRE technique match          → T1486 → LockBit
                                    T1539 → APT29
                                    T1190 → TA505
                                    T1195 → Lazarus
```

---

## Executive Reporting

### Executive PDF Report

```python
from reporting.executive_report_builder import assemble_executive_data, build_executive_report, save_executive_report

# Assemble from all live data stores
data = assemble_executive_data(
    date_from="2026-03-01",
    date_to="2026-06-18",
    severities=["CRITICAL", "HIGH"],
)

# Build PDF — returns raw bytes
pdf_bytes = build_executive_report(data)

# Save to exports/ directory
path = save_executive_report(pdf_bytes)
# → exports/executive_report_20260618_143022.pdf
```

### Report Sections

```
┌────────────────────────────────────────────┐
│  COVER PAGE                                 │
│  Mythos AI SOC Platform                    │
│  Executive Intelligence Report             │
│  Analysis Period: 2026-03-01 — 2026-06-18 │
│  CONFIDENTIAL — FOR AUTHORISED RECIPIENTS  │
├────────────────────────────────────────────┤
│  1. EXECUTIVE SUMMARY                       │
│     8 KPI cards (2 rows × 4)               │
│     Total Incidents · Critical · Open Cases │
│     Active Campaigns · MTTD · MTTR         │
│     Analyst Utilisation · Avg Attribution  │
├────────────────────────────────────────────┤
│  2. INCIDENT SUMMARY                        │
│     Severity distribution table            │
│     Threat category breakdown              │
│     Top 10 active campaigns                │
├────────────────────────────────────────────┤
│  3. MITRE ATT&CK COVERAGE                  │
│     All 12 tactics with technique counts   │
│     Tactic ID · Human label · Count        │
├────────────────────────────────────────────┤
│  4. THREAT INTELLIGENCE SUMMARY            │
│     Incident attribution by actor table    │
│     Intelligence database statistics       │
│     (actors, nations, campaigns, techniques│
└────────────────────────────────────────────┘
```

### Incident PDF Report (9 sections)

```python
from reporting import assemble_report_data, build_incident_report

data = assemble_report_data(
    "INC-2026-001",
    incident_record=incident,
    case_record=case,
    assignment_record=assignment,
    generated_by="Sarah Kim",
    classification="CONFIDENTIAL",
)
pdf_bytes = build_incident_report(data)
```

Sections: Cover · Incident Summary · Timeline · MITRE Mapping · Actor Attribution · Analyst Notes · Case Status · Evidence/IOC Table · Recommendations

---

## Analyst Workflow

A complete analyst session, from alert triage to case closure:

```
1. DETECT                           2. INVESTIGATE
   Alert arrives via JSON/CSV/API      Open Analyst Workbench (page 8)
   Ingestion Service parses + dedupes  Select incident · view enriched detail
   Agent pipeline auto-runs           Add investigation note
   Incident appears in Overview        Change status: OPEN → INVESTIGATING
        │                                    │
        ▼                                    ▼
3. ESCALATE (if needed)             4. CONTAIN
   Escalate Priority P3 → P1          Add containment note
   Reassign to senior analyst          Change status: INVESTIGATING → CONTAINED
   System logs escalation action       IOC enrichments inform block actions
        │                                    │
        ▼                                    ▼
5. CLOSE                            6. REPORT
   Add closing summary note            Generate PDF incident report
   Status: CONTAINED → RESOLVED        Download for stakeholders
   Case auto-syncs resolved_at         Include in Executive PDF batch
   MTTR calculated automatically       C-suite receives board-level report
```

### Case Priority Levels

| Priority | Label | Target MTTR | Use When |
|---|---|---|---|
| **P1** | Critical | 36 hours | Active ransomware · data exfiltration in progress · CNI threat |
| **P2** | High | 72 hours | Confirmed compromise · lateral movement detected |
| **P3** | Medium | 120 hours | Phishing with credential capture · suspicious C2 contact |
| **P4** | Low | 48 hours | Policy violations · failed authentication spikes |

### SOC Analyst Roster

| Analyst | Tier | Specialisation | Certs |
|---|---|---|---|
| Sarah Kim | Tier 3 | Ransomware, IR, Forensics | GCFE, GCIH, CISSP |
| James Okafor | Tier 3 | Critical Infrastructure, OT/ICS | GICSP, GCIH, CISM |
| Elena Vasquez | Tier 2 | Identity & Access, Phishing, BEC | GSEC, CEH, Security+ |
| Priya Nair | Tier 3 | APT Tracking, Threat Intelligence | GCTI, GCFE, CISSP |
| Nia Thompson | Tier 2 | Financial Threat Actors, Crypto | GCIH, CFE, Security+ |
| Carlos Mendez | Tier 3 | Data Exfiltration, Compliance | GCFE, CISM, CISA |
| Marcus Webb | Tier 2 | C2 Detection, Network Forensics | GNFA, GCIH, Security+ |
| Aisha Patel | Tier 2 | Endpoint Detection, Lateral Movement | GCFE, CEH, Security+ |
| Tom Brandt | Tier 1 | Triage, Alert Monitoring | CompTIA Security+ |
| Ryan O'Brien | Tier 2 | Nation-State Threats, LOTL | GCTI, GREM, Security+ |

---

## Agent Collaboration

Page 9 exposes the full multi-agent pipeline execution log:

```
agent_run record schema
{
  "run_id":        "RUN-001",
  "incident_id":   "INC-2026-001",
  "timestamp":     "2026-05-18T02:14:33Z",
  "agents": [
    {
      "name":          "PlannerAgent",
      "duration_ms":   12,
      "confidence_in": 0.00,
      "confidence_out":0.75,
      "actions":       ["Assigned 3 IOCs", "Set risk_score=0.81", "Status → ANALYZED"]
    },
    {
      "name":          "IntelligenceAgent",
      "duration_ms":   8,
      "confidence_in": 0.75,
      "confidence_out":0.83,
      "actions":       ["Enriched 4 ATT&CK techniques", "IOC type: hash/IP/domain"]
    },
    { "name": "AttributionAgent",  "confidence_out": 0.91, ... },
    { "name": "ForensicsAgent",    "confidence_out": 0.91, ... },
    { "name": "ComplianceAgent",   "confidence_out": 0.91, ... }
  ],
  "total_duration_ms": 43,
  "final_status": "MITIGATED"
}
```

The page renders:
- Agent confidence contribution bar chart (per-agent delta)
- Pipeline duration breakdown
- Input → output state diff per agent
- Filter by incident ID or agent name

---

## REST API

Base URL: `http://localhost:8000/api/v1`  
Interactive docs: `http://localhost:8000/docs`  
OpenAPI schema: `http://localhost:8000/openapi.json`

### Authentication

```bash
# 1. Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Password123!"}'
# → {"access_token":"eyJ...", "refresh_token":"eyJ...", "token_type":"Bearer"}

# 2. Use token
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/incidents

# 3. Trigger agent pipeline on a specific incident
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/incidents/INC-2026-001/run
```

### RBAC Matrix

| Resource | ADMIN | ANALYST | VIEWER |
|---|---|---|---|
| Read incidents / cases / actors | ✓ | ✓ | ✓ |
| Create / update incidents | ✓ | ✓ | — |
| Run agent pipeline | ✓ | ✓ | — |
| Delete incidents | ✓ | — | — |
| Manage users / tenants | ✓ | — | — |

### Endpoint Reference

```
Authentication
  POST  /auth/login                 Obtain JWT token pair
  POST  /auth/refresh               Refresh access token
  POST  /auth/logout                Blacklist refresh token (Redis)
  GET   /auth/me                    Current user + tenant profile

Incidents
  GET   /incidents                  List (paginated, tenant-scoped, filterable)
  POST  /incidents                  Create incident
  GET   /incidents/{id}             Get incident detail
  PATCH /incidents/{id}             Update incident fields
  DELETE /incidents/{id}            Delete incident (ADMIN only)
  POST  /incidents/{id}/run         Trigger 5-agent pipeline

Cases
  GET   /cases                      List cases
  POST  /cases                      Create case
  GET   /cases/{id}                 Case detail
  PATCH /cases/{id}                 Update status · priority · analyst
  POST  /cases/{id}/incidents/{id}  Link incident to case
  DELETE /cases/{id}/incidents/{id} Unlink incident

Ingest
  POST  /ingest/json                Bulk ingest JSON incidents array
  POST  /ingest/csv                 Bulk ingest CSV log file (multipart)
  POST  /ingest/syslog              Parse and ingest syslog entries

ATT&CK
  GET   /attack/techniques          Browse all ATT&CK techniques
  GET   /attack/techniques/{id}     Technique detail by ID
  GET   /attack/tactics             List all ATT&CK tactics

Observability
  GET   /health                     Health check (no auth)
  GET   /metrics                    Prometheus metrics (no auth)
```

---

## Installation

### Prerequisites

- Python 3.11+ (developed on 3.14.2)
- `pip` or `uv`
- PostgreSQL 14+ (optional — SQLite used automatically for local dev)
- Redis 7+ (optional — in-memory used automatically for local dev)

### Quick Start (local — no Docker)

```bash
# 1. Clone the repository
git clone https://github.com/fokrulanthro16-eng/Mythos-AI-SOC-Platform.git
cd Mythos-AI-SOC-Platform

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (SQLite + in-memory cache by default — no changes needed)
cp .env.example .env

# 5. Generate the agent pipeline log (creates logs/attribution_log.jsonl)
python core/orchestrator.py

# 6. Launch the Streamlit Command Center
python -m streamlit run dashboard/app.py
```

Dashboard: **http://localhost:8501**

### Run the REST API (optional)

```bash
# In a second terminal
uvicorn api.main:app --reload --port 8000

# Interactive API docs
open http://localhost:8000/docs
```

### Full Stack with Docker Compose

```bash
# Start all services (API · Dashboard · PostgreSQL · Redis · Grafana)
cp .env.example .env               # set JWT_SECRET_KEY and DATABASE_URL
docker compose up -d

# Run database migrations
docker compose run --rm migrate

# Seed sample data
docker compose run --rm seed
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:8501 |
| REST API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |

### Run the Test Suite

```bash
# Full suite (all 874 tests)
pytest tests/ -v --tb=short

# Specific module
pytest tests/test_threat_actor_engine.py -v
pytest tests/test_executive_report.py -v
pytest tests/test_executive_store.py -v

# With coverage report
pytest tests/ --cov=. --cov-report=html
```

---

## Demo Steps

A complete end-to-end demonstration of every major capability:

### Step 1 — Run the Agent Pipeline

```bash
python core/orchestrator.py
```

Watch 50 incidents process through all 5 agents. Observe confidence propagation and risk scoring. Output: `logs/attribution_log.jsonl` and `logs/attribution_log.csv`.

### Step 2 — Explore the Incident Overview (Page 1)

Navigate to **http://localhost:8501** → Incident Overview.

1. Observe KPI row: 50 incidents, 11 critical, avg risk 0.79
2. Click any incident in the table → status badge, confidence score, MITRE techniques
3. Click **Generate PDF Report** → download 9-section incident PDF
4. Filter by severity CRITICAL → 11 incidents remain

### Step 3 — View MITRE ATT&CK Coverage (Page 7)

1. Navigate to **MITRE ATT&CK**
2. Select tactic: **Impact**
3. Search for `T1486` — Data Encrypted for Impact
4. View full technique detail: description, sub-techniques, mitigations, ATT&CK URL

### Step 4 — Work an Incident (Page 8)

Navigate to **Analyst Workbench**.

1. Assign `INC-2026-001` to **Sarah Kim** (Tier 3 · Ransomware specialist)
2. Open the 6-tab action panel
3. Tab 1: Change status to **INVESTIGATING**
4. Tab 3: Add note `"Confirmed LockBit 4.0 IOCs — isolating affected endpoints"`
5. Tab 2: Escalate priority to **P1**
6. Tab 6: Generate and download the incident PDF
7. View the **Activity Feed** — your actions appear chronologically

### Step 5 — Executive Dashboard (Page 10a)

Navigate to **Executive Dashboard**.

1. Set date range: Last 90 days
2. Observe 8 KPI cards — MTTD 7.4h, MTTR 72h, attribution 75%
3. Review MITRE ATT&CK coverage bar — 12 tactics covered
4. Threat actor donut — attribution distribution across actor families
5. Click **Export KPI Summary (CSV)**

### Step 6 — Generate Executive PDF (Page 10b)

Navigate to **Executive Reports**.

1. Set filter: Last 90 days · CRITICAL + HIGH severities
2. Review all charts (same as Executive Dashboard, now in report context)
3. Click **Generate Executive PDF**
4. Download the board-level report — 4-section, classified header

### Step 7 — Threat Actor Intelligence (Page 11)

Navigate to **Threat Actor Intelligence Center**.

1. Tab 1 — Actor Profiles: Select **LockBit** → risk gauge 94%, confidence 94%
2. Expand **ATT&CK Techniques** → T1486, T1490, T1078, T1059.001
3. Tab 2 — Campaign Activity: Gantt timeline of all campaigns
4. Tab 3 — Techniques Matrix: T1566 appears across 8 actors
5. Tab 4 — Actor Comparison: Compare LockBit vs APT29 vs TA505 radar chart
6. Tab 5 — Geographic: Russia dominates (4 actors), nation-state vs criminal split

### Step 8 — REST API Demo

```bash
# Get a JWT token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Password123!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List incidents
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/incidents?limit=5"

# Trigger agent pipeline
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/incidents/INC-2026-001/run"

# Ingest a new incident via JSON
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"threat_name":"NEW-THREAT","severity":"HIGH","indicators":["1.2.3.4"]}]' \
  "http://localhost:8000/api/v1/ingest/json"

# Browse ATT&CK techniques
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/attack/techniques/T1486"
```

---

## Test Coverage

874 passing tests across 26 files. Zero failures.

```bash
pytest tests/ -q
# 874 passed in 84.58s
```

| Test File | Tests | What It Covers |
|---|---|---|
| `test_state.py` | 11 | StateObject, IncidentStatus, ThreatSeverity enums |
| `test_agents.py` | 18 | PlannerAgent, ForensicsAgent, ComplianceAgent |
| `test_orchestrator.py` | 13 | MythosOrchestrator batch pipeline end-to-end |
| `test_intelligence_agent.py` | 16 | IntelligenceAgent, MITRE ATT&CK enrichment |
| `test_attribution_agent.py` | 24 | AttributionAgent, threat-name lookup, campaign clustering |
| `test_featherless_client.py` | 21 | FeatherlessClient mock-first API |
| `test_bandai_client.py` | 22 | BandAIClient mock-first task platform |
| `test_phase3_pipeline.py` | 18 | Phase 3 end-to-end integration (agents 1–5) |
| `test_dashboard_data.py` | 39 | `data_loader` all KPI and filter functions |
| `test_dashboard_charts.py` | 32 | Plotly chart builder functions |
| `test_api_auth.py` | 14 | Login, refresh, logout, /me, token validation |
| `test_api_incidents.py` | 17 | Incident CRUD + pipeline trigger via REST |
| `test_api_cases.py` | 14 | Case CRUD + link/unlink incidents |
| `test_api_rbac.py` | 21 | RBAC matrix, multi-tenant isolation, permission edges |
| `test_api_ingest.py` | 18 | JSON · CSV · syslog ingest endpoints |
| `test_api_attack.py` | 15 | ATT&CK technique/tactic browse endpoints |
| `test_api_case_management.py` | 16 | Case service layer (status transitions, MTTR) |
| `test_parsers.py` | 19 | JSON/CSV/syslog parsers + deduplication |
| `test_attack_engine.py` | 14 | AttackEngine lazy singleton, lookup, tactic filter |
| `test_workbench_store.py` | 22 | Assignment, note, escalation, reassign, close |
| `test_agent_store.py` | 18 | Agent run log store + seed records |
| `test_executive_store.py` | 79 | Executive KPI compute, filters, MITRE coverage |
| `test_report_builder.py` | 34 | PDF builder, `assemble_report_data`, recommendations |
| `test_threat_actor_store.py` | 62 | Threat actor store, pure compute, search/filter/comparison |
| `test_validators.py` | 72 | Incident/campaign/case/analyst validators + dataset |
| `test_production_dataset.py` | 37 | Data integrity: 50 incidents, 10 analysts, 20 campaigns |
| `test_threat_actor_engine.py` | 53 | Engine: load, get (name+alias), search, statistics, attribution |
| `test_executive_report.py` | 26 | Executive PDF builder, `assemble_executive_data`, save |
| **Total** | **874** | |

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.14 | Core runtime |
| **Dashboard** | Streamlit 1.x | 12-page interactive SOC Command Center |
| **Charts** | Plotly Express + Graph Objects | Dark-theme interactive visualisations |
| **REST API** | FastAPI | Async REST layer with OpenAPI docs |
| **Data validation** | Pydantic v2 | Schema validation throughout API and agents |
| **ORM** | SQLAlchemy 2 + asyncpg | PostgreSQL async ORM |
| **Migrations** | Alembic | Database schema versioning |
| **Auth** | python-jose + passlib | JWT HS256 + bcrypt password hashing |
| **Cache / JWT blacklist** | Redis + aioredis | Token invalidation + response cache |
| **PDF generation** | ReportLab platypus | 9-section incident + 4-section executive PDFs |
| **ATT&CK data** | MITRE ATT&CK JSON v14 | Technique enrichment and tactic mapping |
| **Testing** | pytest + pytest-asyncio | 874 tests, async test support |
| **Mocking** | unittest.mock | External API isolation |
| **Observability** | Prometheus + Grafana | /metrics endpoint + dashboard JSON |
| **Containerisation** | Docker Compose | Full-stack local + production deployment |
| **Data formats** | JSON · CSV · JSONL · syslog | Multi-format incident ingest |

---

## Project Structure

```
Mythos/
│
├── agents/                          # AI agent implementations
│   ├── attribution_agent.py         # threat_name → actor mapping (55 entries)
│   ├── compliance_agent.py          # ATTRIBUTED → MITIGATED, playbook selection
│   ├── forensics_agent.py           # ATT&CK enrichment, AttackEngine wrapper
│   ├── intelligence_agent.py        # IOC enrichment, Featherless/BandAI
│   └── planner_agent.py             # DETECTED → ANALYZED, risk scoring
│
├── api/                             # FastAPI REST layer
│   ├── db/database.py               # AsyncSession, Base, get_db, init_db
│   ├── models/                      # SQLAlchemy ORM: incident, case, user, tenant, audit
│   ├── routers/                     # auth, incidents, cases, users, tenants, ingest, attack
│   ├── schemas/                     # Pydantic v2 request/response schemas
│   ├── services/                    # auth, audit, cache (Redis), metrics (Prometheus)
│   ├── dependencies.py              # get_current_user, require_roles(*roles)
│   └── main.py                      # FastAPI app + CORS middleware + lifespan events
│
├── core/                            # Pipeline core
│   ├── logger.py                    # persist(), JSONL/CSV sinks, structured audit log
│   ├── orchestrator.py              # MythosOrchestrator, 5-agent sequential pipeline
│   └── state.py                     # StateObject (Pydantic model), IncidentStatus, ThreatSeverity
│
├── dashboard/                       # Streamlit Command Center
│   ├── pages/
│   │   ├── 1_Incident_Overview.py   # KPI row, severity pie, risk histogram, PDF export
│   │   ├── 2_Threat_Intelligence.py # Actor profiles, campaign frequency, IOC breakdown
│   │   ├── 3_Incident_Timeline.py   # State-transition scatter, status heatmap
│   │   ├── 4_Logs_Explorer.py       # JSONL/CSV viewer, full-text search
│   │   ├── 5_Incident_Intake.py     # Manual incident submission form
│   │   ├── 6_Case_Management.py     # Full CRUD, status flow, notes, PDF export
│   │   ├── 7_MITRE_ATT&CK.py        # Technique browser, tactic filter, detail panel
│   │   ├── 8_Analyst_Workbench.py   # 6-tab action panel, workload chart, activity feed
│   │   ├── 9_Agent_Collaboration.py # Multi-agent run viewer, confidence timeline
│   │   ├── 10_Executive_Dashboard.py# 8 KPIs, 7 charts, date/severity filters, CSV export
│   │   ├── 10_Executive_Reports.py  # Board PDF generator, download button
│   │   └── 11_Threat_Actors.py      # 5-tab intelligence center, 23 actors
│   ├── components/                  # charts.py, filters.py, metrics.py
│   ├── agent_store.py               # Agent run log + 10 seeded 2026 records
│   ├── case_store.py                # Case CRUD, 15-case 2026 seed, MTTR tracking
│   ├── data_loader.py               # JSONL loader, KPI compute, filter_df
│   ├── executive_store.py           # MTTR/MTTD/utilisation KPI aggregation, MITRE coverage
│   ├── threat_actor_store.py        # 23 actors, risk/confidence scoring, search/filter
│   ├── validators.py                # Incident/campaign/case/analyst validation functions
│   └── workbench_store.py           # Assignment, escalation, notes, activity feed
│
├── data/                            # Production intelligence data
│   ├── analysts.json                # 10 SOC analysts (tier, certs, specialisations)
│   ├── campaigns.json               # 22 campaigns (actor, dates, victims, demands)
│   ├── mitre_attack.json            # Full MITRE ATT&CK v14 dataset
│   ├── sample_incidents.json        # 50 enriched 2026 incidents (47 unique techniques)
│   ├── threat_actors.json           # 10 deep-profiled actors (engine format)
│   └── threat_profiles.json         # 23 actor profiles (store format)
│
├── exports/                         # Generated executive PDF output
│
├── intelligence/                    # Intelligence engines
│   ├── attack_engine.py             # Lazy-loading ATT&CK singleton
│   └── threat_actor_engine.py       # 6-function actor intelligence engine
│
├── integrations/                    # External API clients
│   ├── bandai_client.py             # BandAI task platform client (mock-first)
│   └── featherless_client.py        # Featherless LLM inference client (mock-first)
│
├── logs/                            # Pipeline output (gitignored)
│   ├── attribution_log.jsonl        # Primary dashboard data source
│   ├── attribution_log.csv
│   ├── agent_runs.jsonl             # Agent collaboration viewer data
│   └── audit.jsonl                  # Immutable mutation audit log
│
├── parsers/                         # Multi-format incident ingest
│   ├── base.py                      # Abstract BaseParser
│   ├── json_parser.py               # JSON incident array parser
│   ├── csv_parser.py                # CSV log parser with field mapping
│   ├── syslog_parser.py             # RFC 3164/5424 syslog parser
│   ├── dedup.py                     # Content-hash deduplication
│   └── ingestion_service.py         # Multi-format coordinator
│
├── reporting/                       # PDF report engines
│   ├── __init__.py                  # Public API exports
│   ├── executive_report_builder.py  # Board-level PDF (4 sections)
│   ├── report_builder.py            # Incident PDF (9 sections, ReportLab platypus)
│   └── styles.py                    # Brand colour palette + ReportLab paragraph styles
│
├── reports/                         # Generated incident PDFs (gitignored)
│
├── screenshots/                     # Dashboard screenshots for documentation
│
├── tests/                           # 26 test files · 874 passing tests
│
├── alembic/                         # PostgreSQL migration scripts
├── monitoring/                      # Prometheus config + Grafana dashboard JSON
│
├── .env.example                     # Environment variable template
├── conftest.py                      # Shared pytest fixtures
├── docker-compose.yml               # Full-stack container orchestration
├── requirements.txt                 # Python dependencies
└── README.md
```

---

## Configuration

Copy `.env.example` to `.env`. The application runs with zero configuration for local development (SQLite + in-memory cache).

```bash
# ── Core (required for production) ──────────────────────────────────────────
JWT_SECRET_KEY=<openssl rand -hex 32>            # HS256 signing key
DATABASE_URL=postgresql+asyncpg://mythos:password@localhost:5432/mythos
REDIS_URL=redis://localhost:6379/0

# ── Tuning (optional) ────────────────────────────────────────────────────────
MYTHOS_LOG_LEVEL=INFO              # DEBUG | INFO | WARNING | ERROR
CONFIDENCE_THRESHOLD=0.75          # minimum attribution confidence to flag as attributed
RISK_CRITICAL_THRESHOLD=0.80       # risk score cutoff for CRITICAL label
SQL_ECHO=false                     # set true only in local dev
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ── External integrations (optional) ─────────────────────────────────────────
FEATHERLESS_API_KEY=<key>          # LLM inference — omit to use mock client
BANDAI_API_KEY=<key>               # Task platform — omit to use mock client
```

**Local development** (no PostgreSQL/Redis): The application detects missing connection strings and automatically substitutes SQLite (file-backed) + in-memory dict cache. No configuration needed — `python core/orchestrator.py` works immediately after `pip install -r requirements.txt`.

---

<div align="center">

Built with Python · Streamlit · FastAPI · MITRE ATT&CK · ReportLab

**874 tests · 12 dashboard pages · 5 AI agents · 23 threat actors · 50 enriched incidents**

</div>
