"""dashboard/pages/7_MITRE_ATT&CK.py — MITRE ATT&CK Intelligence Dashboard."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is on the path
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from intelligence.attack_engine import AttackEngine

st.set_page_config(
    page_title="MITRE ATT&CK Intelligence",
    page_icon="🎯",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@st.cache_resource
def _load_engine() -> AttackEngine:
    return AttackEngine()


engine = _load_engine()
techniques = engine.all_techniques()
db_stats = engine.stats()

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🎯 MITRE ATT&CK Intelligence")
st.caption("Technique browser, tactic heatmap, frequency analysis, and export.")

# ---------------------------------------------------------------------------
# Stats row
# ---------------------------------------------------------------------------

s1, s2, s3, s4, s5 = st.columns(5)
s1.metric("Techniques", db_stats["total_techniques"])
s2.metric("Tactics Covered", db_stats["total_tactics"])
s3.metric("Subtechniques", db_stats["total_subtechniques"])

# Count techniques per top-level tactic category
by_tactic = db_stats["techniques_by_tactic"]
top_tactic = max(by_tactic, key=by_tactic.get) if by_tactic else "N/A"
s4.metric("Most Loaded Tactic", top_tactic, f"{by_tactic.get(top_tactic, 0)} techniques")
s5.metric("Avg Techniques / Tactic",
          f"{db_stats['total_techniques'] / max(db_stats['total_tactics'], 1):.1f}")

st.divider()

# ---------------------------------------------------------------------------
# Layout: left = browser, right = charts
# ---------------------------------------------------------------------------

left, right = st.columns([3, 2], gap="large")

# ------------------------------------------------------------------
# LEFT: Technique Browser
# ------------------------------------------------------------------

with left:
    st.subheader("🔍 Technique Browser")

    search_q = st.text_input("Search techniques", placeholder="e.g. phishing, T1059, Execution …")
    tactic_filter = st.selectbox(
        "Filter by Tactic",
        options=["All"] + sorted(by_tactic.keys()),
        index=0,
    )

    if search_q:
        display_techs = engine.search(search_q, limit=100)
    else:
        display_techs = techniques[:]

    if tactic_filter != "All":
        display_techs = [t for t in display_techs if t.get("tactic") == tactic_filter]

    if display_techs:
        rows = []
        for t in display_techs:
            rows.append({
                "ID": t["technique_id"],
                "Name": t.get("display_name", t["technique_name"]),
                "Tactic": t.get("tactic", ""),
                "Platforms": ", ".join(t.get("platforms", [])[:3]),
                "Sub-techniques": len(t.get("subtechniques", [])),
                "Severity Weight": t.get("severity_weight", 0),
            })
        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity Weight": st.column_config.ProgressColumn(
                    "Severity Weight", min_value=0, max_value=1, format="%.2f"
                ),
            },
        )
        st.caption(f"Showing {len(display_techs)} technique(s)")
    else:
        st.info("No techniques match the current filter.")

    # Technique detail expander
    st.subheader("📄 Technique Detail")
    tid_input = st.text_input("Enter Technique ID", placeholder="T1059")
    if tid_input:
        tech_detail = engine.lookup(tid_input.strip())
        if tech_detail:
            st.markdown(f"### {tech_detail['technique_id']} — {tech_detail.get('display_name', tech_detail['technique_name'])}")
            col_a, col_b = st.columns(2)
            col_a.markdown(f"**Tactic:** {tech_detail.get('tactic', '')}")
            col_a.markdown(f"**Tactic ID:** {tech_detail.get('tactic_id', '')}")
            col_b.markdown(f"**Platforms:** {', '.join(tech_detail.get('platforms', []))}")
            col_b.markdown(f"**Severity Weight:** {tech_detail.get('severity_weight', 'N/A')}")
            st.markdown(f"**Description:** {tech_detail.get('description', '')}")
            if tech_detail.get("subtechniques"):
                st.markdown(f"**Subtechniques:** {', '.join(tech_detail['subtechniques'])}")
            if tech_detail.get("data_sources"):
                st.markdown(f"**Data Sources:** {', '.join(tech_detail['data_sources'])}")
            st.markdown(f"[🔗 View on MITRE ATT&CK]({tech_detail['url']})")
        else:
            st.warning(f"Technique '{tid_input}' not found in database.")

# ------------------------------------------------------------------
# RIGHT: Visualizations
# ------------------------------------------------------------------

with right:
    try:
        import plotly.express as px
        import plotly.graph_objects as go
        _HAS_PLOTLY = True
    except ImportError:
        _HAS_PLOTLY = False

    st.subheader("📊 Tactic Distribution")

    if _HAS_PLOTLY and by_tactic:
        tactic_df = pd.DataFrame(
            [{"Tactic": k, "Techniques": v} for k, v in sorted(by_tactic.items(), key=lambda x: -x[1])]
        )
        fig_bar = px.bar(
            tactic_df,
            x="Techniques",
            y="Tactic",
            orientation="h",
            color="Techniques",
            color_continuous_scale="Blues",
            title="Techniques per Tactic",
            height=380,
        )
        fig_bar.update_layout(showlegend=False, margin=dict(l=0, r=0, t=40, b=0))
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        tactic_df = pd.DataFrame(
            [{"Tactic": k, "Techniques": v} for k, v in by_tactic.items()]
        )
        st.bar_chart(tactic_df.set_index("Tactic"))

    st.subheader("🔥 ATT&CK Tactic Heatmap")

    # Build heatmap data: tactic × severity_weight bucket
    heatmap_tactics = sorted(by_tactic.keys())
    weight_buckets = {"Low (0–0.4)": (0, 0.4), "Med (0.4–0.7)": (0.4, 0.7), "High (0.7+)": (0.7, 1.1)}
    heatmap_data = {bucket: {tactic: 0 for tactic in heatmap_tactics} for bucket in weight_buckets}

    for t in techniques:
        tact = t.get("tactic", "")
        sw = t.get("severity_weight", 0)
        if tact not in heatmap_tactics:
            continue
        for bucket, (lo, hi) in weight_buckets.items():
            if lo <= sw < hi:
                heatmap_data[bucket][tact] += 1
                break

    heatmap_matrix = [[heatmap_data[b][tact] for tact in heatmap_tactics] for b in weight_buckets]

    if _HAS_PLOTLY:
        fig_heat = go.Figure(data=go.Heatmap(
            z=heatmap_matrix,
            x=heatmap_tactics,
            y=list(weight_buckets.keys()),
            colorscale="YlOrRd",
            showscale=True,
            text=heatmap_matrix,
            texttemplate="%{text}",
        ))
        fig_heat.update_layout(
            title="Technique Count by Tactic & Severity",
            height=280,
            margin=dict(l=0, r=0, t=40, b=0),
            xaxis={"tickangle": -35},
        )
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        hm_df = pd.DataFrame(heatmap_matrix, index=list(weight_buckets.keys()), columns=heatmap_tactics)
        st.dataframe(hm_df, use_container_width=True)

    st.subheader("⚖️ Technique Severity Weights")
    if _HAS_PLOTLY:
        sev_df = pd.DataFrame([
            {"ID": t["technique_id"], "Name": t.get("display_name", t["technique_name"]),
             "Weight": t.get("severity_weight", 0)}
            for t in sorted(techniques, key=lambda x: -x.get("severity_weight", 0))
        ])
        fig_sev = px.bar(
            sev_df, x="Weight", y="ID", orientation="h",
            hover_data=["Name"],
            color="Weight", color_continuous_scale="RdYlGn_r",
            title="Severity Weight by Technique",
            height=420,
        )
        fig_sev.update_layout(showlegend=False, margin=dict(l=0, r=0, t=40, b=0))
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        sev_rows = [{"ID": t["technique_id"], "Weight": t.get("severity_weight", 0)} for t in techniques]
        st.dataframe(pd.DataFrame(sev_rows), use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Export section
# ---------------------------------------------------------------------------

st.divider()
st.subheader("📥 Export ATT&CK Data")

export_col1, export_col2, export_col3 = st.columns(3)

# CSV export
with export_col1:
    export_rows = []
    for t in techniques:
        export_rows.append({
            "technique_id": t["technique_id"],
            "technique_name": t["technique_name"],
            "display_name": t.get("display_name", ""),
            "tactic": t.get("tactic", ""),
            "tactic_id": t.get("tactic_id", ""),
            "url": t["url"],
            "severity_weight": t.get("severity_weight", ""),
            "platforms": "|".join(t.get("platforms", [])),
            "keywords": "|".join(t.get("keywords", [])),
        })
    csv_bytes = pd.DataFrame(export_rows).to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download CSV",
        data=csv_bytes,
        file_name="mitre_attack_techniques.csv",
        mime="text/csv",
        use_container_width=True,
    )

# JSON export
with export_col2:
    json_bytes = json.dumps(techniques, indent=2).encode("utf-8")
    st.download_button(
        "⬇️ Download JSON",
        data=json_bytes,
        file_name="mitre_attack_techniques.json",
        mime="application/json",
        use_container_width=True,
    )

# Stats JSON export
with export_col3:
    stats_json = json.dumps(db_stats, indent=2).encode("utf-8")
    st.download_button(
        "⬇️ Download Stats JSON",
        data=stats_json,
        file_name="mitre_attack_stats.json",
        mime="application/json",
        use_container_width=True,
    )
