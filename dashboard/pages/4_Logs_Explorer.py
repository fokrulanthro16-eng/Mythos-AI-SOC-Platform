"""
Logs Explorer — raw JSONL viewer, searchable CSV table, export.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Logs Explorer | Mythos", layout="wide")

from dashboard.components.filters import render_sidebar_filters
from dashboard.components.metrics import inject_css, render_export_buttons
from dashboard.data_loader import (
    CSV_PATH,
    JSONL_PATH,
    filter_df,
    load_jsonl,
)

inject_css(str(Path(__file__).parent.parent / "assets" / "style.css"))


@st.cache_data(ttl=30)
def _load_df():
    return load_jsonl()


@st.cache_data(ttl=30)
def _load_raw_jsonl() -> list[str]:
    if not JSONL_PATH.exists():
        return []
    with JSONL_PATH.open(encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


df_all = _load_df()
filters = render_sidebar_filters(df_all)
df_filtered = filter_df(df_all, **filters)

st.markdown("# Logs Explorer")
st.markdown(f"Log directory: `{JSONL_PATH.parent}`")
st.markdown("---")

tab_jsonl, tab_csv = st.tabs(["JSONL Viewer", "CSV Viewer"])

# ---------------------------------------------------------------------------
# JSONL Viewer
# ---------------------------------------------------------------------------

with tab_jsonl:
    st.markdown("## Raw JSONL Log")
    raw_lines = _load_raw_jsonl()

    if not raw_lines:
        st.info(f"No data in `{JSONL_PATH.name}`. Run `python core/orchestrator.py` first.")
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            search_term = st.text_input(
                "Filter lines (substring match)", placeholder="e.g. MITIGATED or INC-2026-001"
            )
        with col2:
            max_lines = st.number_input("Max lines to show", min_value=10, max_value=500, value=50, step=10)

        display_lines = (
            [l for l in raw_lines if search_term.lower() in l.lower()]
            if search_term
            else raw_lines
        )
        display_lines = display_lines[-int(max_lines):]

        st.caption(
            f"Showing {len(display_lines)} of {len(raw_lines)} entries "
            f"({'filtered' if search_term else 'most recent'})."
        )

        for line in display_lines:
            try:
                parsed = json.loads(line)
                status = parsed.get("status", "")
                incident = parsed.get("incident_id", "?")
                threat = parsed.get("threat_name", "?")
                st.code(json.dumps(parsed, indent=2), language="json")
            except json.JSONDecodeError:
                st.code(line, language="text")

        st.markdown("---")
        st.download_button(
            "Export full JSONL",
            data="\n".join(raw_lines).encode("utf-8"),
            file_name="attribution_log.jsonl",
            mime="application/x-ndjson",
        )

# ---------------------------------------------------------------------------
# CSV Viewer
# ---------------------------------------------------------------------------

with tab_csv:
    st.markdown("## CSV Log Table")

    if df_filtered.empty:
        st.info("No data matches the current filters.")
    else:
        # Column selector
        all_cols = list(df_filtered.columns)
        default_display = [
            "incident_id", "status", "threat_name", "severity",
            "risk_score", "attribution_confidence", "campaign_id",
            "suspected_actor", "updated_at",
        ]
        selected_cols = st.multiselect(
            "Columns to display",
            options=all_cols,
            default=[c for c in default_display if c in all_cols],
        )

        if not selected_cols:
            selected_cols = all_cols

        view = df_filtered[selected_cols].copy()

        # Quick search
        search = st.text_input("Search table", placeholder="e.g. TA505 or MITIGATED", key="csv_search")
        if search:
            mask = view.apply(lambda col: col.astype(str).str.contains(search, case=False, na=False))
            view = view[mask.any(axis=1)]

        st.caption(f"{len(view):,} rows | {len(selected_cols)} columns")
        st.dataframe(view.reset_index(drop=True), use_container_width=True, hide_index=True)

        st.markdown("---")
        render_export_buttons(df_filtered, label="logs")
