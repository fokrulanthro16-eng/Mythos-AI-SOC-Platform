"""
dashboard/components/metrics.py — KPI cards, summary tables, export buttons.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.data_loader import df_to_csv_bytes, df_to_json_bytes


def render_kpi_row(kpis: dict) -> None:
    """Render four headline KPI metric cards in a single row."""
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Incidents",          kpis["total_incidents"])
    c2.metric("Active Campaigns",         kpis["active_campaigns"])
    c3.metric("High Risk Incidents",      kpis["high_risk_incidents"])
    c4.metric(
        "Avg Attribution Confidence",
        f"{kpis['avg_attribution_confidence']:.1%}",
    )


def render_export_buttons(df: pd.DataFrame, label: str = "incidents") -> None:
    """Render side-by-side CSV and JSON download buttons."""
    col1, col2, *_ = st.columns([1, 1, 3])
    col1.download_button(
        label="Export CSV",
        data=df_to_csv_bytes(df),
        file_name=f"mythos_{label}.csv",
        mime="text/csv",
    )
    col2.download_button(
        label="Export JSON",
        data=df_to_json_bytes(df),
        file_name=f"mythos_{label}.json",
        mime="application/json",
    )


def render_incident_table(df: pd.DataFrame, cols: list[str] | None = None) -> None:
    """Render a styled incident summary table."""
    display_cols = cols or [
        "incident_id", "threat_name", "severity",
        "status", "risk_score", "attribution_confidence",
        "suspected_actor", "campaign_id",
    ]
    existing = [c for c in display_cols if c in df.columns]
    view = df[existing].copy()
    if "risk_score" in view.columns:
        view["risk_score"] = view["risk_score"].map(lambda v: f"{v:.4f}")
    if "attribution_confidence" in view.columns:
        view["attribution_confidence"] = view["attribution_confidence"].map(
            lambda v: f"{v:.2%}"
        )
    st.dataframe(view, use_container_width=True, hide_index=True)


def inject_css(css_path: str) -> None:
    """Inject custom CSS from file."""
    from pathlib import Path
    p = Path(css_path)
    if p.exists():
        with p.open(encoding="utf-8") as fh:
            st.markdown(f"<style>{fh.read()}</style>", unsafe_allow_html=True)
