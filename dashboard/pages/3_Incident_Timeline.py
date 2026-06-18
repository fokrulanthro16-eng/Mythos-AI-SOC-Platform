"""
Incident Timeline — state transition scatter, heatmap, full history table.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

st.set_page_config(page_title="Incident Timeline | Mythos", layout="wide")

from dashboard.components.charts import timeline_scatter_chart, transition_heatmap
from dashboard.components.filters import render_sidebar_filters
from dashboard.components.metrics import inject_css, render_export_buttons
from dashboard.data_loader import filter_df, load_jsonl

inject_css(str(Path(__file__).parent.parent / "assets" / "style.css"))


@st.cache_data(ttl=30)
def _load():
    return load_jsonl()


df_all = _load()
filters = render_sidebar_filters(df_all)
df = filter_df(df_all, **filters)

st.markdown("# Incident Timeline")
st.markdown("---")

if df.empty:
    st.info("No timeline data available. Run the orchestrator or adjust filters.")
    st.stop()

# --- State transition scatter ---
st.markdown("## State Transition Timeline")
st.markdown(
    "Each point represents a state transition. "
    "Size reflects risk score; colour reflects pipeline stage."
)
st.plotly_chart(timeline_scatter_chart(df), use_container_width=True)

st.markdown("---")

# --- Heatmap ---
st.markdown("## Status Heatmap per Incident")
st.plotly_chart(transition_heatmap(df), use_container_width=True)

st.markdown("---")

# --- Full history table ---
st.markdown("## Full Transition History")
history_cols = [
    "incident_id", "status", "threat_name", "severity",
    "risk_score", "attribution_confidence", "campaign_id",
    "suspected_actor", "updated_at",
]
existing = [c for c in history_cols if c in df.columns]
view = df[existing].sort_values("updated_at", ascending=False).reset_index(drop=True)
if "risk_score" in view.columns:
    view["risk_score"] = view["risk_score"].map(lambda v: f"{v:.4f}")
if "attribution_confidence" in view.columns:
    view["attribution_confidence"] = view["attribution_confidence"].map(lambda v: f"{v:.2%}")

st.dataframe(view, use_container_width=True, hide_index=True)

# --- Stats ---
st.markdown("---")
col1, col2, col3 = st.columns(3)
col1.metric("Total Transitions", len(df))
col2.metric("Unique Incidents", df["incident_id"].nunique())
col3.metric("Unique Statuses", df["status"].nunique())

st.markdown("---")
render_export_buttons(view, label="timeline")
