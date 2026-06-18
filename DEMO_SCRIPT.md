# Mythos — 3-Minute Demo Script

**Target audience:** Security engineers, SOC leads, engineering hiring managers  
**Format:** Screen recording with voiceover  
**Total runtime:** 3:00  
**Prerequisite:** Dashboard running at http://localhost:8501, orchestrator has been run

---

## Pre-recording Setup

```bash
# Terminal 1 — ensure fresh data
python core/orchestrator.py

# Terminal 2 — start dashboard
python -m streamlit run dashboard/app.py

# Browser — open in full screen, dark mode, 1920×1080
# Close all other browser tabs
# Set browser zoom to 100%
```

Pre-position: browser on **http://localhost:8501** showing the home page.

---

## Scene 1 — Hook & Overview (0:00–0:18)

**[Screen: Dashboard home page]**

> "This is Mythos — a full-stack AI-powered SOC platform I built from scratch.
> It orchestrates the complete incident response lifecycle through a five-stage
> agent pipeline, exposes a live eleven-page command center, and generates
> professional PDF reports. Everything you're about to see is real data from
> a realistic 2026 enterprise threat dataset."

**[Action]** Slowly scroll the home page to show the navigation sidebar with all 11 pages listed.

---

## Scene 2 — Executive Dashboard (0:18–0:40)

**[Action]** Click **"10 Executive Dashboard"** in the sidebar.

> "Starting at the top — the Executive Dashboard gives a C-suite view of the
> SOC's current posture."

**[Action]** Point to the 8 KPI cards across the top row.

> "Eight live KPIs: open cases, critical incidents, mean time to respond at
> seventy-five hours, mean time to detect, active campaigns, analyst
> utilisation, and attribution confidence."

**[Action]** Scroll down to the incident trend area chart.

> "The thirty-day incident trend shows our 2026 dataset spread across the
> month — staggered timestamps so MTTR and MTTD calculations are meaningful."

**[Action]** Point briefly at the severity donut and threat category bar.

> "Severity distribution and threat category breakdown — ransomware leads at
> thirty-two percent."

---

## Scene 3 — Incident Overview + PDF Export (0:40–1:05)

**[Action]** Click **"1 Incident Overview"** in the sidebar.

> "The Incident Overview is the analyst's primary triage view."

**[Action]** Point to the KPI row, then the four charts.

> "Severity pie, risk score histogram, status progression over time, and a
> confidence scatter by severity. All fifty incidents from the 2026 dataset."

**[Action]** Scroll to the Incident Table and hover over a CRITICAL row.

> "Every row in the incident table is a live data point from the agent pipeline."

**[Action]** Scroll to the PDF Report Generator expander at the bottom. Expand it.

> "New in Phase Seven-Two: one-click PDF incident reports. Select any incident—"

**[Action]** Select "INC-2026-001" from the dropdown. Click **"Generate PDF"**.

> "—and Mythos generates a professional eight-section report covering the
> incident summary, MITRE ATT&CK mapping, threat actor attribution, analyst
> notes, case status, evidence, and tailored recommendations."

**[Action]** The Download button appears. Point to it without clicking.

> "Download button is ready. The report uses ReportLab platypus and degrades
> gracefully on any data — an empty incident still produces a valid PDF."

---

## Scene 4 — Agent Pipeline & ATT&CK (1:05–1:28)

**[Action]** Click **"7 MITRE ATT&CK"** in the sidebar.

> "The MITRE ATT&CK page uses a lazy-loading singleton over the full ATT&CK
> dataset. Analysts can browse by tactic, search by technique ID—"

**[Action]** Type "T1486" into the search box if one exists, or navigate to a tactic.

> "—and see full technique descriptions linked back to the official ATT&CK site."

**[Action]** Click **"9 Agent Collaboration"** in the sidebar.

> "The Agent Collaboration page shows the multi-agent pipeline in action.
> Five specialised agents — Planner, Intelligence, Attribution, Forensics,
> and Compliance — each handle one stage of the DETECTED-to-MITIGATED
> state machine. Every transition is persisted to JSONL before the next
> agent runs."

**[Action]** Show one agent run record if visible, or point to the timeline area.

---

## Scene 5 — Case Management (1:28–1:50)

**[Action]** Click **"6 Case Management"** in the sidebar.

> "Case management gives the SOC full lifecycle control over incidents."

**[Action]** Point to the stats row at the top (Total, Open, Investigating, Contained, Resolved, Closed).

> "Six status counters at a glance. The status flow is Open → Investigating →
> Contained → Resolved → Closed."

**[Action]** Scroll to the case detail panel. Select the first case in the dropdown.

> "Each case has a live update panel — change status, escalate priority, add
> timestamped notes, reassign to a different analyst."

**[Action]** Scroll to show the Notes section and the Timeline side-by-side.

> "Notes and the full case timeline in a two-column layout. The Generate PDF
> button at the bottom produces the same eight-section report scoped to this
> specific case."

---

## Scene 6 — Analyst Workbench (1:50–2:12)

**[Action]** Click **"8 Analyst Workbench"** in the sidebar.

> "The Analyst Workbench is where individual analysts live. Assign incidents
> to any of ten named analysts, set severity and priority."

**[Action]** Scroll to the Case Actions panel. Click the "Escalate Priority" tab.

> "The six-tab action panel covers every workflow: status change, escalation
> with a reason field, notes, reassignment, close with resolution summary,
> and the new Report tab for PDF export."

**[Action]** Click the "📄 Report" tab.

> "One click generates a PDF with the incident's current state — including
> the linked case record and all workbench notes."

**[Action]** Scroll down to the Analyst Workload Distribution chart.

> "And a live grouped bar chart showing open versus resolved cases per analyst.
> This is the data feeding the analyst utilisation KPI in the Executive Dashboard."

---

## Scene 7 — Threat Actor Intelligence Center (2:12–2:40)

**[Action]** Click **"11 Threat Actors"** in the sidebar.

> "Phase Seven-Three added the Threat Actor Intelligence Center — twenty-three
> tracked actors, six featured in the header."

**[Action]** Point to the six KPI cards (LOCKBIT4, TA505, FIN7, APT29, APT41, Lazarus).

> "Each card shows origin flag, severity badge, risk score, and active campaign count."

**[Action]** The Actor Profiles tab should be active. Click on APT41 in the dropdown.

> "Actor profiles include a ReportLab-style risk gauge, attribution confidence,
> target sector breakdown from live campaign data, and expandable sections for
> TTPs, tools, IOC patterns, and campaign history."

**[Action]** Click the **"⚖️ Actor Comparison"** tab.

> "The comparison tab lets you radar-chart up to four actors simultaneously —
> normalized across risk score, attribution confidence, TTP coverage, campaign
> activity, and victim reach."

**[Action]** Show the radar chart briefly.

**[Action]** Click the **"📅 Campaign Activity"** tab.

> "And a Gantt timeline of all active campaigns."

---

## Scene 8 — Closing (2:40–3:00)

**[Action]** Open a terminal and show `pytest tests/ --tb=short -q` (or show a previous run result).

> "The platform ships with five hundred and eighty-eight tests across twenty-four
> test files — unit, integration, and end-to-end coverage for every layer.
> Pure compute functions, file-backed stores tested with monkeypatching, and
> FastAPI endpoints tested against an in-memory SQLite database."

**[Action]** Return to the browser. Show the Executive Dashboard one last time.

> "Mythos is extensible by design. Adding a new agent is one class with one method.
> Adding a new dashboard page is one file. Adding a new threat actor is one JSON
> entry. The architecture scales from a single local process to a Docker Compose
> stack with Postgres, Redis, Prometheus, and Grafana."

> "Source code and full documentation at github.com/your-org/mythos."

**[Fade out]**

---

## Recording Tips

- Use OBS Studio or QuickTime at 1920×1080 60fps
- Record audio separately (Blue Yeti / Rode PodMic) and sync in post
- Add subtle zoom animations when pointing at specific UI elements
- Keep mouse movements slow and deliberate
- Pause 0.5s before each voiceover sentence to allow cut points
- Export at H.264, constant quality 18, for GitHub/YouTube upload

## Thumbnail suggestion

Dark background · Mythos logo (if any) · "AI-Powered SOC Platform" subtitle · 11 dashboard page thumbnails in a grid · "588 tests · Python · FastAPI · Streamlit"
