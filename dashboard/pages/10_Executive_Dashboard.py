"""dashboard/pages/10_Executive_Dashboard.py — SOC Executive Dashboard.

C-suite-level KPI overview: open cases, critical incidents, MTTR, MTTD,
active campaigns, analyst utilization, attribution confidence, and incident trend.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.agent_store import seed_sample_runs
from dashboard.case_store import seed_sample_cases
from dashboard.executive_store import (
    get_analyst_utilization_breakdown,
    get_campaign_activity,
    get_case_status_distribution,
    get_executive_kpis,
    get_incident_trend,
    get_severity_distribution,
    get_threat_actor_breakdown,
    get_threat_category_breakdown,
)
from dashboard.workbench_store import seed_sample_data

st.set_page_config(
    page_title="Executive Dashboard",
    page_icon="📊",
    layout="wide",
)

# Seed demo data on first load
seed_sample_cases()
seed_sample_data()
seed_sample_runs()

# ---------------------------------------------------------------------------
# Shared style constants (matches project theme)
# ---------------------------------------------------------------------------

_DARK = "plotly_dark"

_SEV_COLORS = {
    "CRITICAL": "#FF4B4B",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00CC44",
}

_STATUS_COLORS = {
    "OPEN":          "#5C6BC0",
    "INVESTIGATING": "#AB47BC",
    "CONTAINED":     "#FF8C00",
    "RESOLVED":      "#00CC44",
    "CLOSED":        "#607D8B",
}

_ACTOR_COLORS = {
    "LOCKBIT":               "#FF4B4B",
    "TA505":                 "#FF8C00",
    "FIN7":                  "#FFD700",
    "APT29":                 "#AB47BC",
    "APT41":                 "#5C6BC0",
    "Lazarus":               "#00BCD4",
    "Unknown Criminal Group":"#78909C",
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("📊 Executive Dashboard")
st.caption(
    f"Mythos SOC · Command-level overview · "
    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
)

# ---------------------------------------------------------------------------
# KPI cards — row 1
# ---------------------------------------------------------------------------

kpis = get_executive_kpis()

k1, k2, k3, k4 = st.columns(4)
k1.metric(
    "Open Cases",
    kpis["open_cases"],
    help="Active cases not yet resolved or closed",
)
k2.metric(
    "Critical Incidents",
    kpis["critical_incidents"],
    help="Incidents carrying a CRITICAL severity rating",
)
k3.metric(
    "MTTR",
    f"{kpis['mttr_hours']:.1f} hrs" if kpis["mttr_hours"] else "N/A",
    help="Mean time to resolve — average across all closed cases",
)
k4.metric(
    "MTTD",
    f"{kpis['mttd_hours']:.1f} hrs",
    help="Mean time to detect — severity-weighted estimate across all incidents",
)

# ---------------------------------------------------------------------------
# KPI cards — row 2
# ---------------------------------------------------------------------------

k5, k6, k7, k8 = st.columns(4)
k5.metric(
    "Active Campaigns",
    kpis["active_campaigns"],
    help="Distinct threat campaigns active across the incident dataset",
)
k6.metric(
    "Analyst Utilization",
    f"{kpis['analyst_utilization_pct']:.1f}%",
    help="Percentage of analyst capacity currently engaged (5 concurrent incidents/analyst)",
)
k7.metric(
    "Avg Attribution",
    f"{kpis['attribution_confidence']:.1f}%",
    help="Mean attribution confidence from the AI pipeline runs",
)
k8.metric(
    "Incidents (7d)",
    kpis["incidents_last_7_days"],
    help="Total incidents created in the last 7 days",
)

st.divider()

# ---------------------------------------------------------------------------
# Row 1: Incident Trend (wide) | Severity Donut
# ---------------------------------------------------------------------------

col_trend, col_sev = st.columns([3, 2], gap="large")

with col_trend:
    st.subheader("Incident Trend — Last 30 Days")
    trend_rows = get_incident_trend(30)
    trend_df   = pd.DataFrame(trend_rows)
    if not trend_df.empty and trend_df["count"].sum() > 0:
        fig_trend = px.area(
            trend_df,
            x="date",
            y="count",
            template=_DARK,
            color_discrete_sequence=["#5C6BC0"],
            labels={"date": "Date", "count": "Incidents"},
        )
        fig_trend.update_traces(
            fill="tozeroy",
            line_color="#5C6BC0",
            fillcolor="rgba(92,107,192,0.25)",
        )
        fig_trend.update_layout(
            margin=dict(t=10, b=40, l=10, r=10),
            xaxis_tickangle=-45,
            xaxis_tickformat="%b %d",
            showlegend=False,
            hovermode="x unified",
            height=300,
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("No incident trend data available for the past 30 days.")

with col_sev:
    st.subheader("Severity Distribution")
    sev_dist = get_severity_distribution()
    sev_df   = pd.DataFrame(
        [{"severity": k, "count": v} for k, v in sev_dist.items() if v > 0]
    )
    if not sev_df.empty:
        fig_sev = px.pie(
            sev_df,
            names="severity",
            values="count",
            color="severity",
            color_discrete_map=_SEV_COLORS,
            template=_DARK,
            hole=0.42,
        )
        fig_sev.update_traces(textposition="inside", textinfo="percent+label")
        fig_sev.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            showlegend=True,
            height=300,
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No severity data available.")

st.divider()

# ---------------------------------------------------------------------------
# Row 2: Case Status | Threat Category
# ---------------------------------------------------------------------------

col_status, col_cat = st.columns(2, gap="large")

with col_status:
    st.subheader("Case Status Distribution")
    case_dist = get_case_status_distribution()
    case_df   = pd.DataFrame(
        [{"status": k, "count": v} for k, v in case_dist.items()]
    )
    if not case_df.empty and case_df["count"].sum() > 0:
        fig_case = px.bar(
            case_df,
            x="status",
            y="count",
            color="status",
            color_discrete_map=_STATUS_COLORS,
            template=_DARK,
            category_orders={"status": list(_STATUS_COLORS.keys())},
        )
        fig_case.update_layout(
            showlegend=False,
            xaxis_title="",
            yaxis_title="Cases",
            margin=dict(t=10, b=20, l=10, r=10),
            height=300,
        )
        st.plotly_chart(fig_case, use_container_width=True)
    else:
        st.info("No case status data available.")

with col_cat:
    st.subheader("Threat Category Breakdown")
    cat_dist = get_threat_category_breakdown()
    cat_df   = pd.DataFrame(
        [{"category": k, "count": v} for k, v in cat_dist.items() if v > 0]
    ).sort_values("count", ascending=True)
    if not cat_df.empty:
        fig_cat = px.bar(
            cat_df,
            x="count",
            y="category",
            orientation="h",
            template=_DARK,
            color="count",
            color_continuous_scale="Blues",
            labels={"count": "Incidents", "category": ""},
        )
        fig_cat.update_layout(
            coloraxis_showscale=False,
            xaxis_title="Incidents",
            yaxis_title="",
            margin=dict(t=10, b=20, l=10, r=10),
            height=300,
        )
        st.plotly_chart(fig_cat, use_container_width=True)
    else:
        st.info("No threat category data available.")

st.divider()

# ---------------------------------------------------------------------------
# Row 3: Campaign Activity | Threat Actor Breakdown
# ---------------------------------------------------------------------------

col_camp, col_actor = st.columns(2, gap="large")

with col_camp:
    st.subheader("Campaign Activity — Top 10")
    camp_rows = get_campaign_activity(10)
    camp_df   = pd.DataFrame(camp_rows)
    if not camp_df.empty:
        camp_df["label"] = (
            camp_df["campaign_id"]
            .str.replace("CAMP-", "", regex=False)
            .str.replace("-2026", "", regex=False)
        )
        fig_camp = px.bar(
            camp_df.sort_values("incident_count"),
            x="incident_count",
            y="label",
            orientation="h",
            template=_DARK,
            color="incident_count",
            color_continuous_scale="Reds",
            labels={"incident_count": "Incidents", "label": ""},
        )
        fig_camp.update_layout(
            coloraxis_showscale=False,
            xaxis_title="Incidents",
            yaxis_title="",
            margin=dict(t=10, b=20, l=10, r=10),
            height=320,
        )
        st.plotly_chart(fig_camp, use_container_width=True)
    else:
        st.info("No campaign data available.")

with col_actor:
    st.subheader("Threat Actor Breakdown")
    actor_dist = get_threat_actor_breakdown()
    actor_df   = pd.DataFrame(
        [{"actor": k, "count": v} for k, v in actor_dist.items() if v > 0]
    ).sort_values("count", ascending=False)
    if not actor_df.empty:
        fig_actor = px.pie(
            actor_df,
            names="actor",
            values="count",
            color="actor",
            color_discrete_map=_ACTOR_COLORS,
            template=_DARK,
            hole=0.38,
        )
        fig_actor.update_traces(textposition="inside", textinfo="percent+label")
        fig_actor.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            showlegend=True,
            height=320,
        )
        st.plotly_chart(fig_actor, use_container_width=True)
    else:
        st.info("No actor attribution data available.")

st.divider()

# ---------------------------------------------------------------------------
# Analyst Workload
# ---------------------------------------------------------------------------

st.subheader("Analyst Workload")
analyst_data = get_analyst_utilization_breakdown()
if analyst_data:
    rows = [
        {
            "analyst":  name,
            "open":     m.get("open", 0),
            "resolved": m.get("resolved", 0),
            "critical": m.get("critical", 0),
        }
        for name, m in analyst_data.items()
    ]
    wl_df = pd.DataFrame(rows).sort_values("open", ascending=False)

    fig_wl = go.Figure()
    fig_wl.add_trace(go.Bar(
        x=wl_df["analyst"], y=wl_df["open"],
        name="Open", marker_color="#5C6BC0",
    ))
    fig_wl.add_trace(go.Bar(
        x=wl_df["analyst"], y=wl_df["resolved"],
        name="Resolved", marker_color="#00CC44",
    ))
    fig_wl.add_trace(go.Bar(
        x=wl_df["analyst"], y=wl_df["critical"],
        name="Critical", marker_color="#FF4B4B",
    ))
    fig_wl.update_layout(
        barmode="group",
        template=_DARK,
        xaxis_title="Analyst",
        yaxis_title="Incidents",
        legend_title="Category",
        margin=dict(t=10, b=60, l=10, r=10),
        height=340,
    )
    st.plotly_chart(fig_wl, use_container_width=True)
else:
    st.info("No workload data available.")

# ---------------------------------------------------------------------------
# Footer summary table
# ---------------------------------------------------------------------------

st.divider()
st.subheader("KPI Summary")

kpi_rows = [
    {"KPI": "Open Cases",            "Value": str(kpis["open_cases"])},
    {"KPI": "Critical Incidents",    "Value": str(kpis["critical_incidents"])},
    {"KPI": "MTTR",                  "Value": f"{kpis['mttr_hours']:.1f} hours" if kpis["mttr_hours"] else "N/A"},
    {"KPI": "MTTD",                  "Value": f"{kpis['mttd_hours']:.1f} hours"},
    {"KPI": "Active Campaigns",      "Value": str(kpis["active_campaigns"])},
    {"KPI": "Analyst Utilization",   "Value": f"{kpis['analyst_utilization_pct']:.1f}%"},
    {"KPI": "Avg Attribution Conf",  "Value": f"{kpis['attribution_confidence']:.1f}%"},
    {"KPI": "Incidents Last 7 Days", "Value": str(kpis["incidents_last_7_days"])},
]
st.dataframe(pd.DataFrame(kpi_rows), use_container_width=True, hide_index=True)
