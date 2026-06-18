"""
dashboard/components/filters.py — Sidebar filter renderer.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st


def render_sidebar_filters(df: pd.DataFrame) -> dict:
    """
    Render filter widgets in the sidebar.
    Returns a dict ready to splat into data_loader.filter_df(**filters).
    """
    with st.sidebar:
        st.markdown("## Filters")
        st.markdown("---")

        # Severity
        all_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severities = st.multiselect(
            "Severity",
            options=all_severities,
            default=[],
            help="Leave empty to show all severities.",
        )

        # Threat Actor
        actor_options: list[str] = []
        if not df.empty and "suspected_actor" in df.columns:
            actor_options = sorted(
                df["suspected_actor"].replace("", pd.NA).dropna().unique().tolist()
            )
        actors = st.multiselect(
            "Threat Actor",
            options=actor_options,
            default=[],
        )

        # Campaign ID
        campaign_options: list[str] = []
        if not df.empty and "campaign_id" in df.columns:
            campaign_options = sorted(
                df["campaign_id"].replace("", pd.NA).dropna().unique().tolist()
            )
        campaigns = st.multiselect(
            "Campaign ID",
            options=campaign_options,
            default=[],
        )

        # Attribution Confidence Range
        st.markdown("**Attribution Confidence**")
        conf_range = st.slider(
            "Range",
            min_value=0.0,
            max_value=1.0,
            value=(0.0, 1.0),
            step=0.05,
            label_visibility="collapsed",
        )

        st.markdown("---")
        st.caption(f"Showing {len(df):,} log entries")

    return {
        "severities":  severities or None,
        "actors":      actors or None,
        "campaigns":   campaigns or None,
        "conf_range":  conf_range if conf_range != (0.0, 1.0) else None,
    }
