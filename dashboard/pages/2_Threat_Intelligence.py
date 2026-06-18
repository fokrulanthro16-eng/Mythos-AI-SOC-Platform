"""
Threat Intelligence — actor profiles, IOC enrichment, campaign clusters.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

st.set_page_config(page_title="Threat Intelligence | Mythos", layout="wide")

from dashboard.components.charts import (
    actor_frequency_chart,
    attribution_confidence_chart,
    campaign_frequency_chart,
    ioc_type_distribution,
)
from dashboard.components.filters import render_sidebar_filters
from dashboard.components.metrics import inject_css, render_export_buttons
from dashboard.data_loader import (
    filter_df,
    latest_per_incident,
    load_jsonl,
    load_profiles,
    parse_ioc_enrichments,
)

inject_css(str(Path(__file__).parent.parent / "assets" / "style.css"))


@st.cache_data(ttl=30)
def _load():
    df = load_jsonl()
    profiles = load_profiles()
    return df, profiles


df_all, profiles = _load()
filters = render_sidebar_filters(df_all)
df = filter_df(df_all, **filters)

st.markdown("# Threat Intelligence")
st.markdown("---")

if df.empty:
    st.info("No data available. Run the orchestrator or adjust filters.")
    st.stop()

latest = latest_per_incident(df)

# --- Actor & Campaign row ---
col1, col2 = st.columns(2)
with col1:
    st.plotly_chart(actor_frequency_chart(latest), use_container_width=True)
with col2:
    st.plotly_chart(campaign_frequency_chart(df_all), use_container_width=True)

# --- IOC & Attribution row ---
col3, col4 = st.columns(2)
ioc_df = parse_ioc_enrichments(df_all)
with col3:
    st.plotly_chart(ioc_type_distribution(ioc_df), use_container_width=True)
with col4:
    st.plotly_chart(attribution_confidence_chart(latest), use_container_width=True)

st.markdown("---")

# --- Threat actor profiles ---
st.markdown("## Threat Actor Profiles")
if profiles:
    actor_tab_names = list(profiles.keys())
    tabs = st.tabs(actor_tab_names)
    for tab, actor_id in zip(tabs, actor_tab_names):
        profile = profiles[actor_id]
        with tab:
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"**Origin:** {profile.get('origin', 'Unknown')}")
            c1.markdown(f"**Sophistication:** {profile.get('sophistication', 'Unknown')}")
            c2.markdown(f"**Motivation:** {', '.join(profile.get('motivation', []))}")
            c2.markdown(f"**Severity:** {profile.get('severity', 'Unknown')}")
            c3.markdown(f"**Aliases:** {', '.join(profile.get('aliases', []))}")
            st.markdown(f"*{profile.get('description', '')}*")
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.markdown("**TTPs (MITRE ATT&CK)**")
                for t in profile.get("ttps", []):
                    st.code(t, language=None)
            with col_b:
                st.markdown("**Known Tools**")
                for tool in profile.get("known_tools", []):
                    st.markdown(f"- {tool}")
            with col_c:
                st.markdown("**Known Campaigns**")
                for camp in profile.get("campaigns", []):
                    st.markdown(f"- {camp}")
else:
    st.info("Threat profiles not found. Check `data/threat_profiles.json`.")

st.markdown("---")

# --- Campaign clusters table ---
st.markdown("## Campaign Clusters")
if not latest.empty and "campaign_id" in latest.columns:
    camp_df = (
        latest[latest["campaign_id"].str.strip() != ""]
        [["campaign_id", "suspected_actor", "threat_name", "attribution_confidence", "risk_score"]]
        .sort_values("attribution_confidence", ascending=False)
        .drop_duplicates("campaign_id")
        .reset_index(drop=True)
    )
    camp_df["attribution_confidence"] = camp_df["attribution_confidence"].map(lambda v: f"{v:.2%}")
    camp_df["risk_score"] = camp_df["risk_score"].map(lambda v: f"{v:.4f}")
    st.dataframe(camp_df, use_container_width=True, hide_index=True)
else:
    st.info("No campaign data available.")

st.markdown("---")

# --- IOC enrichment details ---
st.markdown("## IOC Enrichment Details")
if not ioc_df.empty:
    st.dataframe(ioc_df.sort_values("confidence", ascending=False), use_container_width=True, hide_index=True)
    render_export_buttons(ioc_df, label="ioc_enrichments")
else:
    st.info("No IOC enrichment data available.")
