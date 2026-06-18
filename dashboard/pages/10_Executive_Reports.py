"""dashboard/pages/10_Executive_Reports.py — Executive Intelligence Reports.

Streamlit page for generating and downloading board-level PDF reports.
Pulls data from executive_store, MITRE coverage, threat actor intelligence,
and the executive PDF report builder.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.executive_store import (
    get_campaign_activity_filtered,
    get_executive_kpis_filtered,
    get_mitre_coverage_filtered,
    get_severity_distribution_filtered,
    get_threat_actor_breakdown_filtered,
    get_threat_category_breakdown_filtered,
)
from intelligence.threat_actor_engine import actor_statistics
from reporting.executive_report_builder import assemble_executive_data, build_executive_report

st.set_page_config(
    page_title="Executive Reports | Mythos",
    page_icon="📊",
    layout="wide",
)

_DARK = "plotly_dark"

# ---------------------------------------------------------------------------
# Sidebar — Date Range + Severity Filters
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("📊 Report Builder")
    st.markdown("---")
    st.subheader("Analysis Period")

    _TODAY = date.today()
    _DEFAULT_FROM = _TODAY - timedelta(days=90)

    col_from, col_to = st.columns(2)
    date_from = col_from.date_input("From", value=_DEFAULT_FROM, key="rep_date_from")
    date_to   = col_to.date_input("To",   value=_TODAY,          key="rep_date_to")

    st.markdown("---")
    st.subheader("Quick Range")
    qr_cols = st.columns(3)
    if qr_cols[0].button("30d",  key="qr30"):
        date_from = _TODAY - timedelta(days=30)
    if qr_cols[1].button("90d",  key="qr90"):
        date_from = _TODAY - timedelta(days=90)
    if qr_cols[2].button("All",  key="qrall"):
        date_from = date(2024, 1, 1)

    st.markdown("---")
    st.subheader("Severity Filter")
    severities = st.multiselect(
        "Include severities",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        key="rep_severities",
    )

    st.markdown("---")
    st.caption("Report includes KPIs, incidents, MITRE coverage, and threat actor attribution.")

# ---------------------------------------------------------------------------
# Convert dates to ISO strings for store functions
# ---------------------------------------------------------------------------

_date_from_str = date_from.isoformat() if date_from else None
_date_to_str   = date_to.isoformat()   if date_to   else None
_sevs = severities or None

# ---------------------------------------------------------------------------
# Load all data
# ---------------------------------------------------------------------------

kpis      = get_executive_kpis_filtered(_date_from_str, _date_to_str, _sevs)
sev_dist  = get_severity_distribution_filtered(_date_from_str, _date_to_str, _sevs)
campaigns = get_campaign_activity_filtered(8, _date_from_str, _date_to_str, _sevs)
actor_bkdn = get_threat_actor_breakdown_filtered(_date_from_str, _date_to_str, _sevs)
cat_bkdn  = get_threat_category_breakdown_filtered(_date_from_str, _date_to_str, _sevs)
mitre_cov = get_mitre_coverage_filtered(_date_from_str, _date_to_str, _sevs)
intel_stats = actor_statistics()

# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------

st.title("📊 Executive Intelligence Reports")
period_str = f"{date_from} — {date_to}"
st.caption(f"Analysis period: {period_str}  ·  Severity filter: {', '.join(severities) if severities else 'All'}")
st.markdown("---")

# ---------------------------------------------------------------------------
# Generate PDF button (top of page)
# ---------------------------------------------------------------------------

pdf_col, spacer = st.columns([2, 5])

with pdf_col:
    if st.button("🖨️ Generate Executive PDF", type="primary", use_container_width=True):
        with st.spinner("Assembling executive report…"):
            try:
                report_data = assemble_executive_data(
                    date_from=_date_from_str,
                    date_to=_date_to_str,
                    severities=_sevs,
                )
                pdf_bytes = build_executive_report(report_data)
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
                fname = f"mythos_executive_report_{ts}.pdf"
                st.download_button(
                    label="⬇ Download Executive PDF",
                    data=pdf_bytes,
                    file_name=fname,
                    mime="application/pdf",
                    use_container_width=True,
                )
                st.success(f"Report generated: {fname}")
            except Exception as exc:  # noqa: BLE001
                st.error(f"Failed to generate PDF: {exc}")

st.markdown("---")

# ---------------------------------------------------------------------------
# SECTION 1 — Executive KPI Cards
# ---------------------------------------------------------------------------

st.markdown("### Executive KPIs")

def _fmt_min(m: float) -> str:
    if not m or m < 0:
        return "N/A"
    h = m / 60
    return f"{h:.1f}h" if h >= 1 else f"{int(m)}m"

kc = st.columns(4)
kc[0].metric("Total Incidents",   kpis.get("total_incidents",   "—"))
kc[1].metric("Critical",          kpis.get("critical_incidents", "—"),
             delta=None, delta_color="inverse")
kc[2].metric("Open Cases",        kpis.get("open_cases",         "—"))
kc[3].metric("Active Campaigns",  kpis.get("active_campaigns",   "—"))

kc2 = st.columns(4)
kc2[0].metric("MTTD",             _fmt_min(kpis.get("mttd_minutes", 0)))
kc2[1].metric("MTTR",             _fmt_min(kpis.get("mttr_minutes", 0)))
kc2[2].metric("Analyst Util.",    f"{kpis.get('analyst_utilization', 0)*100:.0f}%")
kc2[3].metric("Avg Attribution",  f"{kpis.get('avg_attribution_confidence', 0)*100:.0f}%")

st.markdown("---")

# ---------------------------------------------------------------------------
# SECTION 2 — Incident Summary Charts
# ---------------------------------------------------------------------------

st.markdown("### Incident Summary")
row2_left, row2_right = st.columns(2)

with row2_left:
    if sev_dist:
        sev_df_data = [{"Severity": k, "Count": v} for k, v in sev_dist.items() if v > 0]
        if sev_df_data:
            import pandas as pd
            sev_df = pd.DataFrame(sev_df_data)
            _SEV_CLR = {
                "CRITICAL": "#FF4B4B", "HIGH": "#FF8C00",
                "MEDIUM":   "#FFD700", "LOW":  "#00CC44",
            }
            fig_sev = px.pie(
                sev_df, names="Severity", values="Count",
                title="Incident Severity Distribution",
                color="Severity",
                color_discrete_map=_SEV_CLR,
                hole=0.45,
            )
            fig_sev.update_layout(
                template=_DARK, height=320,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No severity data for the selected period.")

with row2_right:
    if cat_bkdn:
        import pandas as pd
        cat_df = pd.DataFrame(
            sorted(cat_bkdn.items(), key=lambda x: x[1], reverse=True)[:8],
            columns=["Category", "Incidents"],
        )
        fig_cat = px.bar(
            cat_df, x="Incidents", y="Category", orientation="h",
            title="Top Threat Categories",
            color="Incidents",
            color_continuous_scale=[[0, "#1a3a5c"], [1, "#FF4B4B"]],
        )
        fig_cat.update_layout(
            template=_DARK, height=320,
            margin=dict(l=0, r=0, t=40, b=0),
            yaxis={"categoryorder": "total ascending"},
            paper_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_cat, use_container_width=True)
    else:
        st.info("No category data for the selected period.")

# Campaign activity
if campaigns:
    import pandas as pd
    st.markdown("#### Active Campaigns")
    camp_rows = [
        {
            "Campaign":    c.get("name", c.get("campaign_id", "—")),
            "Threat Actor": c.get("threat_actor", "—"),
            "Status":      c.get("status", "—"),
            "Incidents":   c.get("incident_count", c.get("count", 0)),
            "Risk Score":  f"{float(c.get('risk_score', c.get('avg_risk', 0)))*100:.0f}%",
        }
        for c in campaigns
    ]
    st.dataframe(pd.DataFrame(camp_rows), use_container_width=True, hide_index=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# SECTION 3 — MITRE ATT&CK Coverage
# ---------------------------------------------------------------------------

st.markdown("### MITRE ATT&CK Coverage")

if mitre_cov:
    import pandas as pd

    mitre_rows = []
    for entry in mitre_cov:
        techs_raw = entry.get("techniques", 0)
        count = len(techs_raw) if isinstance(techs_raw, list) else int(techs_raw)
        if count > 0:
            mitre_rows.append({
                "Tactic":       str(entry.get("tactic", "")),
                "Tactic ID":    str(entry.get("tactic_id", "")),
                "Techniques":   count,
            })

    if mitre_rows:
        mitre_df = pd.DataFrame(mitre_rows)
        fig_mitre = px.bar(
            mitre_df.sort_values("Techniques", ascending=True),
            x="Techniques", y="Tactic", orientation="h",
            title="MITRE ATT&CK — Techniques Observed by Tactic",
            color="Techniques",
            color_continuous_scale=[[0, "#1a2e3a"], [0.5, "#FF8C00"], [1, "#FF4B4B"]],
        )
        fig_mitre.update_layout(
            template=_DARK, height=400,
            margin=dict(l=0, r=0, t=40, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_mitre, use_container_width=True)

        with st.expander("Tactic Coverage Table"):
            st.dataframe(mitre_df, use_container_width=True, hide_index=True)
else:
    st.info("No MITRE coverage data for the selected period.")

st.markdown("---")

# ---------------------------------------------------------------------------
# SECTION 4 — Threat Intelligence
# ---------------------------------------------------------------------------

st.markdown("### Threat Intelligence")
intel_left, intel_right = st.columns(2)

with intel_left:
    if actor_bkdn:
        import pandas as pd
        actor_df = pd.DataFrame(
            sorted(actor_bkdn.items(), key=lambda x: x[1], reverse=True),
            columns=["Actor", "Incidents"],
        )
        fig_actor = px.bar(
            actor_df.head(8), x="Incidents", y="Actor", orientation="h",
            title="Incident Attribution by Threat Actor",
            color="Incidents",
            color_continuous_scale=[[0, "#1a3a5c"], [1, "#FF4B4B"]],
        )
        fig_actor.update_layout(
            template=_DARK, height=320,
            margin=dict(l=0, r=0, t=40, b=0),
            yaxis={"categoryorder": "total ascending"},
            paper_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_actor, use_container_width=True)
    else:
        st.info("No attribution data for the selected period.")

with intel_right:
    st.markdown("#### Intelligence Database")
    intel_metrics = [
        ("Tracked Actors",         intel_stats.get("total_actors", 0)),
        ("Nations Represented",    intel_stats.get("countries_represented", 0)),
        ("Tracked Campaigns",      intel_stats.get("total_campaigns", 0)),
        ("Unique MITRE Techniques", intel_stats.get("unique_techniques", 0)),
        ("High-Confidence Actors", intel_stats.get("high_confidence_actors", 0)),
        ("Avg Attribution Conf.",  f"{intel_stats.get('avg_attribution_conf', 0)*100:.1f}%"),
    ]
    for label, value in intel_metrics:
        col_l, col_v = st.columns([3, 1])
        col_l.markdown(f"**{label}**")
        col_v.markdown(f"`{value}`")

    st.markdown("---")
    by_type = intel_stats.get("by_type", {})
    if by_type:
        import pandas as pd
        type_df = pd.DataFrame(list(by_type.items()), columns=["Actor Type", "Count"])
        fig_type = px.pie(
            type_df, names="Actor Type", values="Count",
            title="Actors by Type",
            color_discrete_sequence=["#FF4B4B", "#5b8dd9", "#00CC44"],
            hole=0.4,
        )
        fig_type.update_layout(
            template=_DARK, height=260,
            margin=dict(l=0, r=0, t=40, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_type, use_container_width=True)
