"""dashboard/pages/9_Agent_Collaboration.py — Agent Collaboration & Pipeline Execution View."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.agent_store import (
    _AGENT_NAMES,
    _STATUS_ICON,
    get_agent_stats,
    get_latest_agent_states,
    get_processing_metrics,
    load_runs,
    seed_sample_runs,
)
from dashboard.workbench_store import get_workload_metrics

st.set_page_config(
    page_title="Agent Collaboration",
    page_icon="🤖",
    layout="wide",
)

seed_sample_runs()

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🤖 Agent Collaboration View")
st.caption(
    "Real-time execution monitoring for the Mythos multi-agent pipeline: "
    "Planner → Intelligence → Attribution → Compliance"
)

# ---------------------------------------------------------------------------
# Processing metrics cards
# ---------------------------------------------------------------------------

metrics = get_processing_metrics()

p1, p2, p3, p4, p5 = st.columns(5)
p1.metric("Total Pipeline Runs",  metrics["total_runs"])
p2.metric("Avg Duration (ms)",    metrics["avg_pipeline_ms"])
p3.metric("Min Duration (ms)",    metrics["min_pipeline_ms"] or "—")
p4.metric("Max Duration (ms)",    metrics["max_pipeline_ms"] or "—")
p5.metric("Throughput / hr",      metrics["throughput_per_hour"])

st.divider()

# ---------------------------------------------------------------------------
# Per-agent status cards
# ---------------------------------------------------------------------------

st.subheader("🔷 Agent Status Overview")

runs = load_runs(limit=1)
latest_run = runs[0] if runs else {}

agent_stats = get_agent_stats()

cols = st.columns(4)
for i, agent_name in enumerate(_AGENT_NAMES):
    with cols[i]:
        s = agent_stats.get(agent_name, {})
        latest_agent = next(
            (a for a in latest_run.get("agents", []) if a["agent_name"] == agent_name), {}
        )
        status = latest_agent.get("status", "PENDING")
        icon = _STATUS_ICON.get(status, "⏳")
        dur_ms = latest_agent.get("duration_ms")
        started = (latest_agent.get("started_at") or "")[:19].replace("T", " ")
        ended   = (latest_agent.get("ended_at")   or "")[:19].replace("T", " ")

        st.markdown(f"### {icon} {agent_name.replace('Agent', '')}")
        st.markdown(f"**Status:** `{status}`")
        st.markdown(f"**Last Start:** {started or '—'}")
        st.markdown(f"**Last End:** {ended or '—'}")
        st.markdown(f"**Last Duration:** {f'{dur_ms:.1f} ms' if dur_ms is not None else '—'}")
        st.markdown(f"**Avg Duration:** {s.get('avg_ms', 0):.1f} ms")
        st.markdown(f"**Runs:** {s.get('runs', 0)}")
        st.markdown(f"**Success Rate:** {s.get('success_rate', 0):.1f}%")
        if latest_agent.get("output_summary"):
            st.caption(latest_agent["output_summary"])

st.divider()

# ---------------------------------------------------------------------------
# Layout: Workflow timeline | Execution table
# ---------------------------------------------------------------------------

tl_col, tbl_col = st.columns([3, 2], gap="large")

# ===========================================================================
# WORKFLOW TIMELINE (Gantt)
# ===========================================================================

with tl_col:
    st.subheader("⏱️ Workflow Timeline (Gantt)")

    # Let user pick a run
    all_runs = load_runs(limit=50)
    if not all_runs:
        st.info("No pipeline runs recorded yet. Run a pipeline to see the timeline.")
    else:
        run_labels = [
            f"{r.get('threat_name', 'Unknown')} — {r.get('completed_at', '')[:16].replace('T', ' ')}"
            for r in all_runs
        ]
        selected_idx = st.selectbox("Select Pipeline Run", range(len(all_runs)), format_func=lambda i: run_labels[i])
        selected_run = all_runs[selected_idx]

        try:
            import plotly.figure_factory as ff
            import plotly.express as px

            gantt_rows = []
            for agent_rec in selected_run.get("agents", []):
                if not agent_rec.get("started_at") or not agent_rec.get("ended_at"):
                    continue
                gantt_rows.append({
                    "Task": agent_rec["agent_name"],
                    "Start": agent_rec["started_at"],
                    "Finish": agent_rec["ended_at"],
                    "Status": agent_rec.get("status", "COMPLETED"),
                    "Duration ms": agent_rec.get("duration_ms", 0),
                })

            if gantt_rows:
                gantt_df = pd.DataFrame(gantt_rows)
                fig_gantt = ff.create_gantt(
                    gantt_df.rename(columns={"Task": "Task", "Start": "Start", "Finish": "Finish"}).to_dict("records"),
                    colors={"COMPLETED": "#22c55e", "FAILED": "#ef4444", "PENDING": "#94a3b8"},
                    index_col="Status",
                    show_colorbar=True,
                    group_tasks=True,
                    title=f"Pipeline Execution — {selected_run.get('threat_name', '')}",
                    height=300,
                )
                fig_gantt.update_layout(margin=dict(l=0, r=0, t=60, b=0))
                st.plotly_chart(fig_gantt, use_container_width=True)
            else:
                st.info("No agent timing data for this run.")

        except (ImportError, Exception) as e:
            # Fallback: simple table
            st.caption(f"Gantt chart unavailable ({e}). Showing table instead.")
            rows = []
            for ag in selected_run.get("agents", []):
                rows.append({
                    "Agent": ag["agent_name"],
                    "Status": ag.get("status", ""),
                    "Start": (ag.get("started_at") or "")[:19].replace("T", " "),
                    "End": (ag.get("ended_at") or "")[:19].replace("T", " "),
                    "Duration (ms)": ag.get("duration_ms", ""),
                    "Output": ag.get("output_status", ""),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # Run metadata
        with st.expander("Run Details"):
            meta_rows = [
                ("Run ID",        selected_run.get("run_id", "")[:20]),
                ("Incident",      selected_run.get("incident_id", "")),
                ("Threat",        selected_run.get("threat_name", "")),
                ("Severity",      selected_run.get("severity", "")),
                ("Final Status",  selected_run.get("final_status", "")),
                ("Campaign",      selected_run.get("campaign_id", "")),
                ("Actor",         selected_run.get("suspected_actor", "")),
                ("Total ms",      selected_run.get("duration_ms", "")),
            ]
            st.table(pd.DataFrame(meta_rows, columns=["Field", "Value"]))

# ===========================================================================
# EXECUTION TABLE
# ===========================================================================

with tbl_col:
    st.subheader("📋 Recent Pipeline Runs")

    all_runs_tbl = load_runs(limit=20)
    if all_runs_tbl:
        _SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        rows = []
        for r in all_runs_tbl:
            sev = r.get("severity", "")
            rows.append({
                "Threat":  r.get("threat_name", "")[:30],
                "Sev":     _SEV_ICON.get(sev, "") + " " + sev,
                "Status":  r.get("final_status", ""),
                "ms":      r.get("duration_ms", ""),
                "Run At":  (r.get("completed_at") or "")[:16].replace("T", " "),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=400)
    else:
        st.info("No runs yet.")

    # Per-agent average duration bar chart
    st.subheader("📊 Agent Avg Duration")
    if agent_stats:
        try:
            import plotly.express as px
            dur_rows = [
                {"Agent": k.replace("Agent", ""), "Avg ms": v["avg_ms"]}
                for k, v in agent_stats.items()
                if v["runs"] > 0
            ]
            if dur_rows:
                fig_dur = px.bar(
                    pd.DataFrame(dur_rows),
                    x="Agent", y="Avg ms",
                    color="Avg ms",
                    color_continuous_scale="Blues",
                    title="Average Duration per Agent",
                    height=280,
                )
                fig_dur.update_layout(showlegend=False, margin=dict(l=0, r=0, t=40, b=0))
                st.plotly_chart(fig_dur, use_container_width=True)
            else:
                st.info("No agent timing data yet.")
        except ImportError:
            dur_rows = [{"Agent": k, "Avg ms": v["avg_ms"]} for k, v in agent_stats.items()]
            st.dataframe(pd.DataFrame(dur_rows), use_container_width=True, hide_index=True)

st.divider()

# ---------------------------------------------------------------------------
# Processing metrics: by severity + by status
# ---------------------------------------------------------------------------

st.subheader("⚙️ Processing Metrics")

m_col1, m_col2, m_col3 = st.columns(3)

with m_col1:
    st.markdown("**Runs by Severity**")
    if metrics["by_severity"]:
        sev_df = pd.DataFrame(
            [{"Severity": k, "Count": v} for k, v in metrics["by_severity"].items()]
        )
        try:
            import plotly.express as px
            fig_sev = px.pie(sev_df, names="Severity", values="Count", hole=0.4, height=240)
            fig_sev.update_layout(margin=dict(l=0, r=0, t=0, b=0), showlegend=True)
            st.plotly_chart(fig_sev, use_container_width=True)
        except ImportError:
            st.dataframe(sev_df, hide_index=True, use_container_width=True)
    else:
        st.info("No data.")

with m_col2:
    st.markdown("**Runs by Final Status**")
    if metrics["by_status"]:
        st_df = pd.DataFrame(
            [{"Status": k, "Count": v} for k, v in metrics["by_status"].items()]
        )
        try:
            import plotly.express as px
            fig_st = px.pie(st_df, names="Status", values="Count", hole=0.4, height=240)
            fig_st.update_layout(margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig_st, use_container_width=True)
        except ImportError:
            st.dataframe(st_df, hide_index=True, use_container_width=True)
    else:
        st.info("No data.")

with m_col3:
    st.markdown("**Agent Run Counts**")
    agent_count_rows = [
        {"Agent": k.replace("Agent", ""), "Runs": v.get("runs", 0)}
        for k, v in agent_stats.items()
    ]
    if any(r["Runs"] > 0 for r in agent_count_rows):
        try:
            import plotly.express as px
            fig_cnt = px.bar(
                pd.DataFrame(agent_count_rows), x="Agent", y="Runs",
                color="Runs", color_continuous_scale="Greens", height=240
            )
            fig_cnt.update_layout(showlegend=False, margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig_cnt, use_container_width=True)
        except ImportError:
            st.dataframe(pd.DataFrame(agent_count_rows), hide_index=True, use_container_width=True)
    else:
        st.info("No agent runs recorded.")

# ---------------------------------------------------------------------------
# Case ownership metrics
# ---------------------------------------------------------------------------

st.divider()
st.subheader("🏷️ Case Ownership Metrics")

workload = get_workload_metrics()
by_analyst = workload.get("by_analyst", {})

if by_analyst:
    ow_rows = []
    for analyst, counts in sorted(by_analyst.items(), key=lambda x: -x[1]["total"]):
        ow_rows.append({
            "Analyst":  analyst,
            "Total":    counts["total"],
            "Open":     counts["open"],
            "Resolved": counts["resolved"],
            "Critical": counts["critical"],
            "Load":     f"{'█' * counts['open']}{'░' * counts['resolved']}"[:12],
        })
    ow_df = pd.DataFrame(ow_rows)
    try:
        import plotly.express as px
        fig_ow = px.bar(
            ow_df, x="Analyst", y=["Open", "Resolved", "Critical"],
            barmode="stack",
            color_discrete_map={"Open": "#ef4444", "Resolved": "#22c55e", "Critical": "#7c3aed"},
            title="Case Ownership per Analyst",
            height=340,
        )
        fig_ow.update_layout(margin=dict(l=0, r=0, t=40, b=0), legend_title="")
        st.plotly_chart(fig_ow, use_container_width=True)
    except ImportError:
        st.dataframe(ow_df, use_container_width=True, hide_index=True)
else:
    st.info("No analyst assignments recorded. Use the Analyst Workbench to assign incidents.")

# ---------------------------------------------------------------------------
# Agent Execution Graph (Mermaid-style text fallback)
# ---------------------------------------------------------------------------

st.divider()
st.subheader("🔗 Agent Execution Graph")
st.markdown("""
```
INCIDENT DETECTED
       │
       ▼
┌─────────────────┐
│  PlannerAgent   │  DETECTED → ANALYZED
│  IOC Analysis   │  Populates IOCs, sets initial confidence
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  IntelligenceAgent  │  ANALYZED → ENRICHED
│  Threat Enrichment  │  IOC lookup, TTPs, Featherless AI
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  AttributionAgent   │  ENRICHED → ATTRIBUTED
│  Actor Attribution  │  Campaign clustering, BandAI log
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  ComplianceAgent    │  ATTRIBUTED → MITIGATED
│  Mitigation + Audit │  NIST controls, audit trail
└──────────┬──────────┘
           │
           ▼
    CASE AUTO-CREATED
    ATT&CK MAPPED
    AUDIT LOGGED
```
""")
