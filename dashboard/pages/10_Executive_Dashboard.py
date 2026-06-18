"""dashboard/pages/10_Executive_Dashboard.py — SOC Executive Dashboard.

C-suite / CISO view: KPI cards, trend charts, severity distribution, case status,
threat actor breakdown, MITRE ATT&CK coverage, and analyst workload — all with
live date-range and severity filters plus CSV export.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
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
    _compute_case_status_distribution,
    _compute_executive_kpis,
    _compute_incident_trend,
    _compute_mitre_coverage,
    _compute_severity_distribution,
    _compute_threat_actor_breakdown,
    _compute_threat_category_breakdown,
    filter_incidents,
    get_analyst_utilization_breakdown,
    get_analysts,
    get_campaign_activity_filtered,
    get_case_status_distribution,
    get_executive_kpis_filtered,
    get_incident_trend_filtered,
    get_mitre_coverage_filtered,
    get_severity_distribution_filtered,
    get_threat_actor_breakdown_filtered,
    get_threat_category_breakdown_filtered,
)
from dashboard.workbench_store import seed_sample_data

st.set_page_config(
    page_title="Executive Dashboard",
    page_icon="📊",
    layout="wide",
)

seed_sample_cases()
seed_sample_data()
seed_sample_runs()

# ---------------------------------------------------------------------------
# Style constants
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
    "LOCKBIT":                "#FF4B4B",
    "LOCKBIT4":               "#FF4B4B",
    "ALPHV-BLACKCAT":         "#FF6B6B",
    "TA505":                  "#FF8C00",
    "CLOP-TA505":             "#FFA500",
    "FIN7":                   "#FFD700",
    "APT29":                  "#AB47BC",
    "APT28":                  "#CE93D8",
    "STORM-0558":             "#9C27B0",
    "APT41":                  "#5C6BC0",
    "VOLT-TYPHOON":           "#3F51B5",
    "Lazarus":                "#00BCD4",
    "LAZARUS-GROUP":          "#00ACC1",
    "Unknown Criminal Group": "#78909C",
    "SCATTERED-SPIDER":       "#26A69A",
    "INSIDER-THREAT":         "#F44336",
    "UNKNOWN-CRIMINAL":       "#90A4AE",
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
# Sidebar — filters
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Filters")

    now_utc   = datetime.now(timezone.utc)
    min_date  = (now_utc - timedelta(days=365)).date()
    max_date  = now_utc.date()

    col_from, col_to = st.columns(2)
    with col_from:
        d_from = st.date_input("From", value=(now_utc - timedelta(days=30)).date(),
                               min_value=min_date, max_value=max_date, key="exec_from")
    with col_to:
        d_to   = st.date_input("To",   value=max_date,
                               min_value=min_date, max_value=max_date, key="exec_to")

    f_sevs = st.multiselect(
        "Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=[],
        help="Leave blank to include all severities",
    )

    st.divider()
    st.markdown("**Quick ranges**")
    qc1, qc2 = st.columns(2)
    if qc1.button("Last 7d",  use_container_width=True):
        st.session_state["exec_from"] = (now_utc - timedelta(days=7)).date()
        st.session_state["exec_to"]   = max_date
        st.rerun()
    if qc2.button("Last 30d", use_container_width=True):
        st.session_state["exec_from"] = (now_utc - timedelta(days=30)).date()
        st.session_state["exec_to"]   = max_date
        st.rerun()
    if qc1.button("Last 90d", use_container_width=True):
        st.session_state["exec_from"] = (now_utc - timedelta(days=90)).date()
        st.session_state["exec_to"]   = max_date
        st.rerun()
    if qc2.button("All time", use_container_width=True):
        st.session_state["exec_from"] = min_date
        st.session_state["exec_to"]   = max_date
        st.rerun()

# Convert date → tz-aware datetime
date_from = datetime(d_from.year, d_from.month, d_from.day, tzinfo=timezone.utc)
date_to   = datetime(d_to.year,   d_to.month,   d_to.day, 23, 59, 59, tzinfo=timezone.utc)
sev_filter = f_sevs if f_sevs else None

# ---------------------------------------------------------------------------
# KPI cards — row 1
# ---------------------------------------------------------------------------

kpis = get_executive_kpis_filtered(date_from=date_from, date_to=date_to, severities=sev_filter)

k1, k2, k3, k4 = st.columns(4)
k1.metric(
    "Total Incidents",
    kpis["total_incidents"],
    help="All incidents in the selected date/severity range",
)
k2.metric(
    "Critical Incidents",
    kpis["critical_incidents"],
    help="Incidents carrying CRITICAL severity in the selected range",
)
k3.metric(
    "Open Cases",
    kpis["open_cases"],
    help="Active cases not yet resolved or closed (all cases, unfiltered)",
)
k4.metric(
    "Active Campaigns",
    kpis["active_campaigns"],
    help="Distinct campaigns observed in the filtered incident range",
)

# ---------------------------------------------------------------------------
# KPI cards — row 2
# ---------------------------------------------------------------------------

k5, k6, k7, k8 = st.columns(4)
k5.metric(
    "MTTD",
    f"{kpis['mttd_hours']:.1f} hrs",
    help="Mean time to detect — severity-weighted model",
)
k6.metric(
    "MTTR",
    f"{kpis['mttr_hours']:.1f} hrs" if kpis["mttr_hours"] else "N/A",
    help="Mean time to resolve across all closed cases",
)
k7.metric(
    "Analyst Utilization",
    f"{kpis['analyst_utilization_pct']:.1f}%",
    help="Active workbench assignments as % of theoretical capacity",
)
k8.metric(
    "Avg Attribution",
    f"{kpis['attribution_confidence']:.1f}%",
    help="Mean attribution confidence from AI pipeline runs",
)

st.divider()

# ---------------------------------------------------------------------------
# Row 1: Incident Trend | Severity Donut
# ---------------------------------------------------------------------------

col_trend, col_sev = st.columns([3, 2], gap="large")

with col_trend:
    st.subheader("Incident Trend — Selected Range")
    days_span = max(1, (d_to - d_from).days + 1)
    trend_rows = get_incident_trend_filtered(days=days_span,
                                             date_from=date_from, date_to=date_to,
                                             severities=sev_filter)
    trend_df = pd.DataFrame(trend_rows)
    if not trend_df.empty and trend_df["count"].sum() > 0:
        fig_trend = px.area(
            trend_df, x="date", y="count", template=_DARK,
            color_discrete_sequence=["#5C6BC0"],
            labels={"date": "Date", "count": "Incidents"},
        )
        fig_trend.update_traces(
            fill="tozeroy", line_color="#5C6BC0",
            fillcolor="rgba(92,107,192,0.25)",
        )
        fig_trend.update_layout(
            margin=dict(t=10, b=40, l=10, r=10),
            xaxis_tickangle=-45, xaxis_tickformat="%b %d",
            showlegend=False, hovermode="x unified", height=300,
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("No incidents in the selected range.")

with col_sev:
    st.subheader("Severity Distribution")
    sev_dist = get_severity_distribution_filtered(date_from=date_from, date_to=date_to,
                                                  severities=sev_filter)
    sev_df = pd.DataFrame(
        [{"severity": k, "count": v} for k, v in sev_dist.items() if v > 0]
    )
    if not sev_df.empty:
        fig_sev = px.pie(
            sev_df, names="severity", values="count",
            color="severity", color_discrete_map=_SEV_COLORS,
            template=_DARK, hole=0.42,
        )
        fig_sev.update_traces(textposition="inside", textinfo="percent+label")
        fig_sev.update_layout(
            margin=dict(t=10, b=10, l=10, r=10), showlegend=True, height=300,
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No severity data for the selected range.")

st.divider()

# ---------------------------------------------------------------------------
# Row 2: Case Status | Threat Category
# ---------------------------------------------------------------------------

col_status, col_cat = st.columns(2, gap="large")

with col_status:
    st.subheader("Case Status Distribution")
    case_dist = get_case_status_distribution()
    case_df = pd.DataFrame(
        [{"status": k, "count": v} for k, v in case_dist.items()]
    )
    if not case_df.empty and case_df["count"].sum() > 0:
        fig_case = px.bar(
            case_df, x="status", y="count",
            color="status", color_discrete_map=_STATUS_COLORS,
            template=_DARK,
            category_orders={"status": list(_STATUS_COLORS.keys())},
        )
        fig_case.update_layout(
            showlegend=False, xaxis_title="", yaxis_title="Cases",
            margin=dict(t=10, b=20, l=10, r=10), height=300,
        )
        st.plotly_chart(fig_case, use_container_width=True)
    else:
        st.info("No case data available.")

with col_cat:
    st.subheader("Threat Category Breakdown")
    cat_dist = get_threat_category_breakdown_filtered(date_from=date_from, date_to=date_to,
                                                      severities=sev_filter)
    cat_df = pd.DataFrame(
        [{"category": k, "count": v} for k, v in cat_dist.items() if v > 0]
    ).sort_values("count", ascending=True)
    if not cat_df.empty:
        fig_cat = px.bar(
            cat_df, x="count", y="category", orientation="h",
            template=_DARK, color="count", color_continuous_scale="Blues",
            labels={"count": "Incidents", "category": ""},
        )
        fig_cat.update_layout(
            coloraxis_showscale=False, xaxis_title="Incidents", yaxis_title="",
            margin=dict(t=10, b=20, l=10, r=10), height=300,
        )
        st.plotly_chart(fig_cat, use_container_width=True)
    else:
        st.info("No threat category data for the selected range.")

st.divider()

# ---------------------------------------------------------------------------
# Row 3: Campaign Activity | Threat Actor Breakdown
# ---------------------------------------------------------------------------

col_camp, col_actor = st.columns(2, gap="large")

with col_camp:
    st.subheader("Campaign Activity — Top 10")
    camp_rows = get_campaign_activity_filtered(10, date_from=date_from,
                                               date_to=date_to, severities=sev_filter)
    camp_df = pd.DataFrame(camp_rows)
    if not camp_df.empty:
        camp_df["label"] = (
            camp_df["campaign_id"]
            .str.replace("CAMP-", "", regex=False)
            .str.replace("-2026", "", regex=False)
        )
        fig_camp = px.bar(
            camp_df.sort_values("incident_count"),
            x="incident_count", y="label", orientation="h",
            template=_DARK, color="incident_count",
            color_continuous_scale="Reds",
            labels={"incident_count": "Incidents", "label": ""},
        )
        fig_camp.update_layout(
            coloraxis_showscale=False, xaxis_title="Incidents", yaxis_title="",
            margin=dict(t=10, b=20, l=10, r=10), height=320,
        )
        st.plotly_chart(fig_camp, use_container_width=True)
    else:
        st.info("No campaign data for the selected range.")

with col_actor:
    st.subheader("Threat Actor Attribution")
    actor_dist = get_threat_actor_breakdown_filtered(date_from=date_from, date_to=date_to,
                                                     severities=sev_filter)
    actor_df = pd.DataFrame(
        [{"actor": k, "count": v} for k, v in actor_dist.items() if v > 0]
    ).sort_values("count", ascending=False)
    if not actor_df.empty:
        fig_actor = px.pie(
            actor_df, names="actor", values="count",
            color="actor", color_discrete_map=_ACTOR_COLORS,
            template=_DARK, hole=0.38,
        )
        fig_actor.update_traces(textposition="inside", textinfo="percent+label")
        fig_actor.update_layout(
            margin=dict(t=10, b=10, l=10, r=10), showlegend=True, height=320,
        )
        st.plotly_chart(fig_actor, use_container_width=True)
    else:
        st.info("No actor attribution data for the selected range.")

st.divider()

# ---------------------------------------------------------------------------
# MITRE ATT&CK Coverage Overview
# ---------------------------------------------------------------------------

st.subheader("MITRE ATT&CK Coverage Overview")
mitre_rows = get_mitre_coverage_filtered(date_from=date_from, date_to=date_to,
                                          severities=sev_filter)
mitre_df = pd.DataFrame(mitre_rows)
if not mitre_df.empty and mitre_df["techniques"].sum() > 0:
    fig_mitre = px.bar(
        mitre_df,
        x="tactic",
        y="techniques",
        template=_DARK,
        color="techniques",
        color_continuous_scale="Viridis",
        labels={"tactic": "ATT&CK Tactic", "techniques": "Unique Techniques"},
        text="techniques",
    )
    fig_mitre.update_traces(texttemplate="%{text}", textposition="outside")
    fig_mitre.update_layout(
        coloraxis_showscale=False,
        xaxis_tickangle=-30,
        xaxis_title="",
        yaxis_title="Unique Techniques Observed",
        margin=dict(t=30, b=60, l=10, r=10),
        height=350,
    )
    st.plotly_chart(fig_mitre, use_container_width=True)

    total_techs = mitre_df["techniques"].sum()
    covered_tactics = (mitre_df["techniques"] > 0).sum()
    mc1, mc2, mc3 = st.columns(3)
    mc1.metric("Total Tactics Covered",    f"{covered_tactics} / {len(mitre_df)}")
    mc2.metric("Total Unique Techniques",  total_techs)
    mc3.metric("Avg Techniques / Tactic",  f"{total_techs / max(covered_tactics,1):.1f}")
else:
    st.info("No MITRE ATT&CK technique data for the selected range.")

st.divider()

# ---------------------------------------------------------------------------
# Analyst Workload
# ---------------------------------------------------------------------------

st.subheader("Analyst Workload")
analyst_data = get_analyst_utilization_breakdown()
analysts_list = get_analysts()

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
    fig_wl.add_trace(go.Bar(x=wl_df["analyst"], y=wl_df["open"],
                            name="Open",     marker_color="#5C6BC0"))
    fig_wl.add_trace(go.Bar(x=wl_df["analyst"], y=wl_df["resolved"],
                            name="Resolved", marker_color="#00CC44"))
    fig_wl.add_trace(go.Bar(x=wl_df["analyst"], y=wl_df["critical"],
                            name="Critical", marker_color="#FF4B4B"))
    fig_wl.update_layout(
        barmode="group", template=_DARK,
        xaxis_title="Analyst", yaxis_title="Incidents",
        legend_title="Category",
        margin=dict(t=10, b=60, l=10, r=10), height=340,
    )
    st.plotly_chart(fig_wl, use_container_width=True)

    if analysts_list:
        st.subheader("Analyst Roster")
        roster_df = pd.DataFrame([
            {
                "Name":             a["name"],
                "Tier":             a.get("tier", ""),
                "Specializations":  ", ".join(a.get("specializations", [])),
                "Certifications":   ", ".join(a.get("certifications", [])),
                "Active Cases":     a.get("active_cases", 0),
                "Experience (yrs)": a.get("years_experience", 0),
            }
            for a in analysts_list
        ])
        st.dataframe(roster_df, use_container_width=True, hide_index=True)
else:
    st.info("No workload data available.")

st.divider()

# ---------------------------------------------------------------------------
# KPI Summary table + export
# ---------------------------------------------------------------------------

st.subheader("KPI Summary")

kpi_rows = [
    {"KPI": "Total Incidents",       "Value": str(kpis["total_incidents"])},
    {"KPI": "Critical Incidents",    "Value": str(kpis["critical_incidents"])},
    {"KPI": "Open Cases",            "Value": str(kpis["open_cases"])},
    {"KPI": "Active Campaigns",      "Value": str(kpis["active_campaigns"])},
    {"KPI": "MTTD",                  "Value": f"{kpis['mttd_hours']:.1f} hours"},
    {"KPI": "MTTR",                  "Value": f"{kpis['mttr_hours']:.1f} hours" if kpis["mttr_hours"] else "N/A"},
    {"KPI": "Analyst Utilization",   "Value": f"{kpis['analyst_utilization_pct']:.1f}%"},
    {"KPI": "Avg Attribution Conf",  "Value": f"{kpis['attribution_confidence']:.1f}%"},
    {"KPI": "Incidents Last 7 Days", "Value": str(kpis["incidents_last_7_days"])},
    {"KPI": "Date Range Applied",    "Value": f"{d_from} to {d_to}"},
    {"KPI": "Severity Filter",       "Value": ", ".join(sev_filter) if sev_filter else "All"},
]
kpi_df = pd.DataFrame(kpi_rows)
st.dataframe(kpi_df, use_container_width=True, hide_index=True)

csv_bytes = kpi_df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="⬇ Export KPI Summary (CSV)",
    data=csv_bytes,
    file_name=f"mythos_executive_kpis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.csv",
    mime="text/csv",
    use_container_width=True,
)
