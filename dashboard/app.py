"""
dashboard/app.py — Mythos Command Center home page.

Launch: streamlit run dashboard/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

st.set_page_config(
    page_title="Mythos Command Center",
    layout="wide",
    initial_sidebar_state="expanded",
)

from dashboard.components.metrics import inject_css, render_kpi_row
from dashboard.data_loader import compute_kpis, load_jsonl, latest_per_incident

_CSS = Path(__file__).parent / "assets" / "style.css"
inject_css(str(_CSS))


@st.cache_data(ttl=30)
def _load():
    return load_jsonl()


# ---------------------------------------------------------------------------
# Sidebar brand
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("# Mythos")
    st.markdown("**Command Center v3.0**")
    st.markdown("---")
    st.markdown(
        "Multi-agent defensive cyber incident orchestration dashboard. "
        "Navigate using the pages above."
    )
    st.markdown("---")
    st.caption("Powered by Project Mythos — Phase 4")

# ---------------------------------------------------------------------------
# Home content
# ---------------------------------------------------------------------------

st.markdown("# Mythos Command Center")
st.markdown(
    "Real-time visibility into cyber incident detection, intelligence enrichment, "
    "attribution, and mitigation. Use the sidebar to navigate to a detailed view."
)
st.markdown("---")

df = _load()
kpis = compute_kpis(df)

st.markdown("## Platform Overview")
render_kpi_row(kpis)

st.markdown("---")
st.markdown("## Navigation Guide")

col1, col2 = st.columns(2)

with col1:
    st.markdown(
        """
**Incident Overview**
- Severity and risk distribution charts
- Status progression across pipeline stages
- Detection vs attribution confidence scatter

**Threat Intelligence**
- Threat actor frequency and profiles
- IOC enrichment type breakdown
- Campaign cluster table
"""
    )

with col2:
    st.markdown(
        """
**Incident Timeline**
- State transition scatter timeline
- Status heatmap per incident
- Full incident history table

**Logs Explorer**
- Raw JSONL log viewer
- Searchable CSV table
- One-click CSV and JSON export
"""
    )

st.markdown("---")

if not df.empty:
    latest = latest_per_incident(df)
    st.markdown(f"**{len(latest):,}** unique incidents tracked across "
                f"**{latest['campaign_id'].replace('', None).dropna().nunique()}** campaigns. "
                f"Most recent status: **{latest.sort_values('updated_at').iloc[-1]['status']}**.")
else:
    st.info(
        "No incident data found in `logs/attribution_log.jsonl`. "
        "Run `python core/orchestrator.py` to generate data."
    )
