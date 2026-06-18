# Mythos — Live Demo Script

**Platform:** Mythos AI-Powered SOC Incident Orchestration Platform  
**Runtime:** ~12 minutes (full) · ~6 minutes (condensed)  
**URL:** http://localhost:8501 · API: http://localhost:8000

---

## Pre-Demo Checklist

- [ ] Pipeline has run: `python core/orchestrator.py` (generates `logs/attribution_log.jsonl`)
- [ ] Dashboard running: `python -m streamlit run dashboard/app.py`
- [ ] Browser open at **http://localhost:8501**
- [ ] Terminal visible for CLI sections
- [ ] PDF viewer ready (to show generated reports)

---

## Opening Statement (30 sec)

> "Mythos is a full-stack AI Security Operations Centre platform. It replaces manual incident triage with a 5-agent AI pipeline that takes any alert from detection to mitigation in under 30 seconds — with automatic MITRE ATT&CK enrichment, threat actor attribution, case management, and one-click PDF reporting. Let me show you the complete workflow."

---

## Act 1 — The Agent Pipeline (2 min)

**Terminal:**
```bash
python core/orchestrator.py
```

**Talk track:**
- "50 real-world 2026 incidents are processing through 5 specialised AI agents — each agent owns one responsibility."
- "Watch the confidence score rise from 0.75 to 0.91 as each agent enriches the data."
- "PlannerAgent assigns IOCs and risk score. IntelligenceAgent enriches with MITRE ATT&CK. AttributionAgent maps to threat actor and campaign. ForensicsAgent adds full technique detail. ComplianceAgent selects the remediation playbook."
- "Every incident is logged to JSONL and CSV — that feeds the live dashboard."

**Point to in output:**
- `PlannerAgent: DETECTED → ANALYZED, risk_score=0.91`
- `AttributionAgent: actor=LOCKBIT, campaign=CAMP-LOCKBIT4-2026`
- `ForensicsAgent: enriched 4 ATT&CK techniques`
- `ComplianceAgent: ATTRIBUTED → MITIGATED`

---

## Act 2 — Incident Overview (2 min)

**Navigate to:** Page 1 — Incident Overview

**Talk track:**
- "This is the SOC analyst landing page. Five KPIs at the top — 50 incidents, 11 critical, average risk 0.79."
- "The severity donut: 26 HIGH, 11 CRITICAL. The confidence scatter lets analysts find under-investigated incidents — high risk, low confidence in the top-left quadrant."

**Live actions:**
1. Point to the KPI row — total, critical, open cases, avg risk, avg confidence
2. Sidebar: filter severity to **CRITICAL only** → table drops to 11 incidents
3. Click row `INC-2026-001` (LOCKBIT4-RANSOMWARE) to expand detail
4. Point to: severity badge, MITRE techniques listed, confidence 0.91, actor attribution
5. Click **Generate PDF Report** → 9-section PDF downloads
6. Open the PDF — show cover page, MITRE mapping table, IOC evidence table, recommendations

**Key line:**
> "A professional incident report with MITRE ATT&CK mapping, IOC table, actor profile, and remediation steps — generated automatically. No analyst writes this."

---

## Act 3 — Analyst Workbench (2.5 min)

**Navigate to:** Page 8 — Analyst Workbench

**Talk track:**
- "This is day-to-day analyst workflow. Let me work the LockBit incident from triage to closure."

**Live actions:**
1. Assign dropdown: select `INC-2026-001`
2. Analyst: **Sarah Kim** (Tier 3 · Ransomware specialist)
3. Priority: **P1** · Severity: **CRITICAL** → click **Assign**
4. Open the **6-tab action panel** — read tab names aloud
5. Tab 1 — **Change Status**: move to INVESTIGATING
6. Tab 3 — **Add Note**: type `"Confirmed LockBit 4.0 IOCs on HOSTNAME-042. Isolating network segment. Backup verification in progress."`
7. Tab 2 — **Escalate**: P1 reason: `"Active encryption detected on 3 endpoints"`
8. Tab 6 — **Report**: click Generate → PDF downloads
9. Scroll to **Analyst Activity Feed** — show all actions logged chronologically
10. Show **Workload Distribution Chart** — Sarah Kim's queue highlighted

**Key line:**
> "Full triage workflow — assign, update, escalate, note, report — in 60 seconds. No context-switching to a separate ticketing system."

---

## Act 4 — MITRE ATT&CK (1.5 min)

**Navigate to:** Page 7 — MITRE ATT&CK Browser

**Live actions:**
1. Select tactic: **Impact**
2. Search technique ID: `T1486`
3. Show full detail panel: description, sub-techniques, mitigations, ATT&CK URL
4. Navigate to **Executive Dashboard** (page 10a) → MITRE ATT&CK coverage bar chart
5. Point to: 12 tactics covered, showing technique count per tactic

**Key line:**
> "47 unique ATT&CK technique IDs across our 50 incidents. The ForensicsAgent enriches every technique automatically — analysts don't look anything up."

---

## Act 5 — Threat Actor Intelligence (2 min)

**Navigate to:** Page 11 — Threat Actor Intelligence Center

**Talk track:**
- "We track 23 threat actors across 5 intelligence tabs. Let me zoom into LockBit."

**Live actions:**
1. Sidebar search: type `LockBit`
2. **Tab 1 — Actor Profiles**: show risk gauge 94%, confidence gauge 94%
3. Expand **ATT&CK Techniques** → T1486, T1490, T1078, T1059.001
4. Expand **Campaign History** → LockBit 3.0 Global, Hospital Network 2026
5. **Tab 2 — Campaign Activity**: show Gantt timeline
6. **Tab 4 — Actor Comparison**: select LockBit + APT29 + TA505 → radar renders
7. Point to radar axes: Risk · Attribution · TTP Coverage · Campaign Activity · Victim Reach

**Key line:**
> "This is decision-support, not a data table. Which actor has the widest TTP breadth? Which is currently active? Which should we brief the board on? One glance."

---

## Act 6 — Executive Dashboard and Reports (1.5 min)

**Navigate to:** Page 10a — Executive Dashboard

**Live actions:**
1. Set quick range: **90d**
2. Read KPI cards: `Total 50 · Critical 11 · MTTD 7.4h · MTTR 72h · Attribution 75%`
3. Severity filter: remove LOW and MEDIUM → KPIs update live
4. Click **Export KPI Summary (CSV)**

**Navigate to:** Page 10b — Executive Reports

**Live actions:**
1. Date: Last 90 days · Severity: CRITICAL + HIGH
2. Review charts: severity donut, category bar, attribution chart, MITRE coverage bar
3. Click **Generate Executive PDF**
4. Open the PDF — show: cover page with classification banner, 8 KPI cards, MITRE tactic coverage table, actor attribution table

**Key line:**
> "A board-ready executive intelligence report in one click. This is what a CISO sends to the executive committee — generated directly from live SOC data."

---

## Act 7 — Test Suite (30 sec)

**Terminal:**
```bash
pytest tests/ -q --tb=no
```

**Expected output:**
```
874 passed in 84.58s
```

**Key line:**
> "874 tests, zero failures. Every component verified — agents, API, stores, PDF generation, threat actor engine, data integrity. This is production-quality code."

---

## Closing Statement (30 sec)

> "Mythos delivers a complete production SOC platform: 5-agent AI pipeline, 12-page live dashboard, FastAPI REST layer with JWT auth and RBAC, professional PDF generation, full MITRE ATT&CK integration, 23-actor threat intelligence, and 874 passing tests. The entire triage lifecycle — from raw alert to executive board report — automated and auditable."

---

## Condensed Version (6 min)

| Act | Keep | Cut |
|---|---|---|
| 1 | Run pipeline, mention 5 agents | Skip detailed output narration |
| 2 | Show KPI row + PDF download | Skip filter demo |
| 3 | Show 3 tabs max (Status, Note, Report) | Skip escalation and activity feed |
| 4 | Skip entirely | — |
| 5 | Tab 1 + Tab 4 radar only | Skip campaign Gantt |
| 6 | Executive PDF only | Skip dashboard filter demo |
| 7 | Show test count only | — |

---

## Troubleshooting

| Symptom | Resolution |
|---|---|
| No incidents on page 1 | Run `python core/orchestrator.py` first |
| Dashboard won't start | `pip install -r requirements.txt` |
| PDF download fails | `pip install reportlab` |
| Page 11 empty | Check `data/threat_profiles.json` exists |
| Port conflict | `streamlit run dashboard/app.py --server.port 8502` |
| Slow first load | MITRE ATT&CK engine loads lazily — first request takes ~2s |
