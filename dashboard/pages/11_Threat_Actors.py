"""dashboard/pages/11_Threat_Actors.py — Threat Actor Intelligence Center.

Five-tab intelligence overview:
  1. Actor Profiles    — full profile cards with risk/confidence gauges
  2. Campaign Activity — Gantt timeline + campaign table
  3. Techniques Matrix — ATT&CK technique frequency heatmap + tactic bars
  4. Actor Comparison  — radar chart + side-by-side table for up to 4 actors
  5. Geographic Activity — origin donut + region/sector heatmaps
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.threat_actor_store import (
    FEATURED_ACTOR_IDS,
    ORIGIN_FLAGS,
    SEV_BADGE,
    filter_actors,
    get_actor,
    get_actor_campaigns,
    get_all_actors,
    get_comparison_data,
    get_featured_actors,
    get_region_matrix,
    get_sector_matrix,
    get_technique_frequency_for_actors,
    search_actors,
)

st.set_page_config(
    page_title="Threat Actor Intelligence Center | Mythos",
    page_icon="🕵️",
    layout="wide",
)

_DARK = "plotly_dark"

_SEV_COLORS = {
    "CRITICAL": "#FF4B4B",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00CC44",
    "UNKNOWN":  "#888888",
}

_SOPH_COLORS = {
    "nation-state": "#FF4B4B",
    "advanced":     "#FF8C00",
    "intermediate": "#FFD700",
    "basic":        "#00CC44",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flag(origin: str) -> str:
    for key, flag in ORIGIN_FLAGS.items():
        if key.lower() in origin.lower():
            return flag
    return "🌐"


def _pct(v: float) -> str:
    return f"{v * 100:.0f}%"


def _usd(v: int) -> str:
    if v >= 1_000_000:
        return f"${v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"${v / 1_000:.0f}K"
    return f"${v:,}"


def _badge(label: str, style: str) -> str:
    return f'<span style="{style};border-radius:4px;padding:2px 8px;font-size:.75rem;font-weight:600">{label}</span>'


def _risk_color(score: float) -> str:
    if score >= 0.85:
        return _SEV_COLORS["CRITICAL"]
    if score >= 0.70:
        return _SEV_COLORS["HIGH"]
    if score >= 0.50:
        return _SEV_COLORS["MEDIUM"]
    return _SEV_COLORS["LOW"]


# ---------------------------------------------------------------------------
# Sidebar — search + filters
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("🕵️ Intel Center")
    search_q = st.text_input("🔍 Search actors", placeholder="e.g. ransomware, Russia, T1486…")
    st.markdown("---")
    st.subheader("Filters")

    all_actors_raw = get_all_actors()
    origins_all = sorted({a.get("origin", "Unknown") for a in all_actors_raw})
    sophs_all   = ["nation-state", "advanced", "intermediate", "basic"]
    motiv_all   = sorted({
        m for a in all_actors_raw for m in a.get("motivation", [])
    })
    sevs_all    = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    f_origins = st.multiselect("Origin", origins_all, default=[])
    f_sophs   = st.multiselect("Sophistication", sophs_all, default=[])
    f_motiv   = st.multiselect("Motivation", motiv_all, default=[])
    f_sevs    = st.multiselect("Severity", sevs_all, default=[])

    st.markdown("---")
    show_all = st.toggle("Show all actors (not just featured)", value=False)
    st.caption(f"{len(all_actors_raw)} actors in database")

# Apply search + filters
if search_q.strip():
    display_actors = search_actors(search_q.strip())
elif any([f_origins, f_sophs, f_motiv, f_sevs]):
    display_actors = filter_actors(
        origins=f_origins or None,
        sophistication_levels=f_sophs or None,
        motivations=f_motiv or None,
        severities=f_sevs or None,
    )
elif show_all:
    display_actors = all_actors_raw
else:
    display_actors = get_featured_actors()

# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------

st.title("🕵️ Threat Actor Intelligence Center")

featured = get_featured_actors()
all_camps = sum(a.get("campaign_stats", {}).get("total", 0) for a in all_actors_raw)
active_camps = sum(a.get("campaign_stats", {}).get("active", 0) for a in all_actors_raw)
st.caption(
    f"{len(all_actors_raw)} tracked actors · "
    f"{all_camps} campaigns ({active_camps} active) · "
    f"Last updated 2026-06-17"
)

# ---------------------------------------------------------------------------
# Featured actor KPI cards
# ---------------------------------------------------------------------------

st.markdown("### Featured Threat Actors")
kpi_cols = st.columns(6)
for col, actor in zip(kpi_cols, featured):
    flag  = _flag(actor.get("origin", ""))
    sev   = actor.get("severity", "UNKNOWN")
    risk  = actor.get("risk_score", 0.0)
    conf  = actor.get("attribution_confidence", 0.0)
    camps = actor.get("campaign_stats", {}).get("active", 0)
    col.markdown(
        f"<div style='background:#1E1E2E;border-radius:8px;padding:.6rem .8rem;text-align:center'>"
        f"<div style='font-size:1.3rem'>{flag}</div>"
        f"<div style='font-weight:700;font-size:.85rem;color:#FF4B4B'>{actor['actor_id']}</div>"
        f"<div style='font-size:.7rem;color:#aaa'>{actor.get('origin','?')}</div>"
        f"<div style='margin:.3rem 0'>"
        f"{_badge(sev, SEV_BADGE.get(sev,''))}"
        f"</div>"
        f"<div style='font-size:.75rem'>Risk <b style='color:{_risk_color(risk)}'>{_pct(risk)}</b></div>"
        f"<div style='font-size:.75rem'>🎯 {camps} active campaign{'s' if camps != 1 else ''}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown("---")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🎯 Actor Profiles",
    "📅 Campaign Activity",
    "🔧 Techniques Matrix",
    "⚖️ Actor Comparison",
    "🗺️ Geographic Activity",
])


# ===========================================================================
# TAB 1 — ACTOR PROFILES
# ===========================================================================

with tab1:
    if not display_actors:
        st.info("No actors match the current search/filters.")
        st.stop()

    actor_map = {a["actor_id"]: a for a in display_actors}
    selected_id = st.selectbox(
        "Select Actor",
        list(actor_map.keys()),
        format_func=lambda k: f"{_flag(actor_map[k].get('origin',''))}  {k}  —  {actor_map[k].get('origin','?')}",
        key="profile_actor_select",
    )
    actor = actor_map[selected_id]
    st.markdown("---")

    # ---- Two-column layout ----
    left_col, right_col = st.columns([3, 2], gap="large")

    with left_col:
        # Header
        flag  = _flag(actor.get("origin", ""))
        sev   = actor.get("severity", "UNKNOWN")
        soph  = actor.get("sophistication", "unknown")
        risk  = actor.get("risk_score", 0.0)
        conf  = actor.get("attribution_confidence", 0.0)

        st.markdown(
            f"<h2 style='margin-bottom:.1rem'>{flag} {actor['actor_id']}</h2>",
            unsafe_allow_html=True,
        )
        aliases_str = " · ".join(actor.get("aliases", []))
        if aliases_str:
            st.caption(f"Also known as: {aliases_str}")

        badges_html = (
            f"{_badge(sev, SEV_BADGE.get(sev, ''))} &nbsp;"
            f"{_badge(soph.upper(), 'background:#1a2e3a;color:#7dd3fc')} &nbsp;"
            f"{_badge(actor.get('origin','?'), 'background:#1a1a2e;color:#c4b5fd')}"
        )
        st.markdown(badges_html, unsafe_allow_html=True)
        st.markdown("")

        st.markdown(actor.get("description", "_No description available._"))
        st.markdown("---")

        # Metric row
        stats = actor.get("campaign_stats", {})
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Score",    _pct(risk))
        m2.metric("Attribution",   _pct(conf))
        m3.metric("Techniques",    len(actor.get("ttps", [])))
        m4.metric("Campaigns",     stats.get("total", 0))

        # Motivation + targets
        motiv = ", ".join(actor.get("motivation", []))
        st.markdown(f"**Motivation:** `{motiv}`")
        if actor.get("target_sectors"):
            st.markdown("**Target Sectors:** " + " ".join(
                f"`{s}`" for s in actor["target_sectors"]
            ))
        if actor.get("target_regions"):
            st.markdown("**Geographic Focus:** " + " ".join(
                f"`{r}`" for r in actor["target_regions"]
            ))

        st.markdown("")

        # TTPs
        with st.expander(f"🎯 ATT&CK Techniques ({len(actor.get('ttps', []))})"):
            if actor.get("ttps"):
                ttp_rows = [{"Technique ID": t} for t in actor["ttps"]]
                st.dataframe(pd.DataFrame(ttp_rows), use_container_width=True, hide_index=True)
            else:
                st.caption("No techniques mapped.")

        # Known Tools
        with st.expander(f"🔧 Known Tools ({len(actor.get('known_tools', []))})"):
            tools = actor.get("known_tools", [])
            if tools:
                tools_html = " &nbsp; ".join(
                    f"<code style='background:#1E1E2E;padding:2px 8px;border-radius:4px'>{t}</code>"
                    for t in tools
                )
                st.markdown(tools_html, unsafe_allow_html=True)
            else:
                st.caption("No tools mapped.")

        # IOC Patterns
        ioc_patterns = actor.get("known_ioc_patterns", [])
        if ioc_patterns:
            with st.expander(f"🔍 IOC Patterns ({len(ioc_patterns)})"):
                for ioc in ioc_patterns:
                    st.code(ioc, language=None)

        # Campaign History
        campaigns = actor.get("campaign_list", [])
        with st.expander(f"📋 Campaign History ({len(campaigns)})"):
            if campaigns:
                camp_rows = [
                    {
                        "Campaign":     c.get("name", ""),
                        "Status":       c.get("status", ""),
                        "First Seen":   c.get("first_seen", "")[:10],
                        "Last Seen":    c.get("last_seen", "")[:10],
                        "Victims":      c.get("estimated_victims", 0),
                        "Max Demand":   _usd(c.get("known_ransom_demands_usd") or 0),
                        "Tactic":       c.get("tactic_category", ""),
                    }
                    for c in campaigns
                ]
                st.dataframe(pd.DataFrame(camp_rows), use_container_width=True, hide_index=True)
            else:
                st.caption("No campaigns tracked.")

    with right_col:
        # Risk Score gauge
        fig_risk = go.Figure(go.Indicator(
            mode="gauge+number",
            value=round(risk * 100, 1),
            title={"text": "Risk Score", "font": {"size": 14, "color": "#aaa"}},
            number={"suffix": "%", "font": {"size": 20}},
            gauge={
                "axis":  {"range": [0, 100], "tickcolor": "#aaa"},
                "bar":   {"color": _risk_color(risk)},
                "bgcolor": "#1E1E2E",
                "steps": [
                    {"range": [0,  50],  "color": "#0d3321"},
                    {"range": [50, 70],  "color": "#3d3300"},
                    {"range": [70, 85],  "color": "#4d1f00"},
                    {"range": [85, 100], "color": "#4d0000"},
                ],
                "threshold": {
                    "line": {"color": "#fff", "width": 2},
                    "thickness": 0.75,
                    "value": risk * 100,
                },
            },
        ))
        fig_risk.update_layout(
            template=_DARK,
            height=220,
            margin=dict(l=10, r=10, t=30, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_risk, use_container_width=True)

        # Attribution Confidence bar
        fig_conf = go.Figure(go.Indicator(
            mode="gauge+number",
            value=round(conf * 100, 1),
            title={"text": "Attribution Confidence", "font": {"size": 13, "color": "#aaa"}},
            number={"suffix": "%", "font": {"size": 18}},
            gauge={
                "axis":  {"range": [0, 100], "tickcolor": "#aaa"},
                "bar":   {"color": "#5b8dd9"},
                "bgcolor": "#1E1E2E",
                "steps": [
                    {"range": [0,  50], "color": "#1a1a2e"},
                    {"range": [50, 80], "color": "#1a2640"},
                    {"range": [80, 100],"color": "#1a3a5c"},
                ],
            },
        ))
        fig_conf.update_layout(
            template=_DARK,
            height=200,
            margin=dict(l=10, r=10, t=30, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_conf, use_container_width=True)

        # Target sectors from campaigns
        sector_counts: dict[str, int] = {}
        for c in campaigns:
            for s in c.get("target_sectors", []):
                sector_counts[s] = sector_counts.get(s, 0) + 1
        # Also from profile
        for s in actor.get("target_sectors", []):
            sector_counts[s] = sector_counts.get(s, 0) + 1

        if sector_counts:
            sec_df = pd.DataFrame(
                sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                columns=["Sector", "Count"],
            )
            fig_sec = px.bar(
                sec_df, x="Count", y="Sector", orientation="h",
                title="Target Sectors",
                color="Count",
                color_continuous_scale=[[0, "#1a3a5c"], [1, "#FF4B4B"]],
            )
            fig_sec.update_layout(
                template=_DARK, height=280, showlegend=False,
                margin=dict(l=0, r=0, t=30, b=0),
                yaxis={"categoryorder": "total ascending"},
                paper_bgcolor="rgba(0,0,0,0)",
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_sec, use_container_width=True)


# ===========================================================================
# TAB 2 — CAMPAIGN ACTIVITY
# ===========================================================================

with tab2:
    import json as _json

    all_campaigns: list[dict] = []
    for a in display_actors:
        for c in a.get("campaign_list", []):
            all_campaigns.append({**c, "_actor": a["actor_id"]})

    if not all_campaigns:
        st.info("No campaign data for the current actor selection.")
    else:
        # Stats row
        total_v = sum(c.get("estimated_victims", 0) for c in all_campaigns)
        max_d   = max((c.get("known_ransom_demands_usd") or 0 for c in all_campaigns), default=0)
        active  = sum(1 for c in all_campaigns if c.get("status") == "ACTIVE")

        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.metric("Total Campaigns", len(all_campaigns))
        sc2.metric("Active",          active)
        sc3.metric("Total Victims",   f"{total_v:,}")
        sc4.metric("Largest Demand",  _usd(max_d))

        st.markdown("---")

        # Gantt-style timeline
        gantt_rows = []
        for c in sorted(all_campaigns, key=lambda x: x.get("first_seen", "")):
            fs = c.get("first_seen", "")
            ls = c.get("last_seen", "")
            if fs and ls:
                gantt_rows.append({
                    "Campaign":  c.get("name", c.get("campaign_id", "")),
                    "Actor":     c.get("threat_actor", c.get("_actor", "")),
                    "Start":     fs,
                    "End":       ls,
                    "Status":    c.get("status", ""),
                    "Victims":   c.get("estimated_victims", 0),
                    "Tactic":    c.get("tactic_category", ""),
                })

        if gantt_rows:
            gdf = pd.DataFrame(gantt_rows)
            gdf["Start"] = pd.to_datetime(gdf["Start"])
            gdf["End"]   = pd.to_datetime(gdf["End"])
            gdf = gdf.sort_values("Start")

            _STATUS_CAMP_COLORS = {
                "ACTIVE":    "#FF4B4B",
                "CONTAINED": "#FFD700",
                "RESOLVED":  "#00CC44",
            }

            fig_gantt = px.timeline(
                gdf,
                x_start="Start", x_end="End", y="Campaign",
                color="Actor",
                hover_data=["Status", "Victims", "Tactic"],
                title="Campaign Timeline",
                height=max(300, len(gantt_rows) * 28 + 80),
            )
            fig_gantt.update_layout(
                template=_DARK,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                yaxis={"autorange": "reversed"},
                legend_title_text="Actor",
            )
            st.plotly_chart(fig_gantt, use_container_width=True)

        # Campaign table
        st.markdown("### Campaign Details")
        filt_status = st.multiselect(
            "Filter by Status", ["ACTIVE", "CONTAINED", "RESOLVED"], default=[], key="camp_status_filter"
        )
        camp_df = pd.DataFrame([
            {
                "Campaign":   c.get("name", ""),
                "Actor":      c.get("threat_actor", ""),
                "Category":   c.get("tactic_category", ""),
                "Status":     c.get("status", ""),
                "First Seen": c.get("first_seen", "")[:10],
                "Last Seen":  c.get("last_seen", "")[:10],
                "Victims":    c.get("estimated_victims", 0),
                "Max Demand": _usd(c.get("known_ransom_demands_usd") or 0),
            }
            for c in all_campaigns
        ])
        if filt_status:
            camp_df = camp_df[camp_df["Status"].isin(filt_status)]
        st.dataframe(camp_df, use_container_width=True, hide_index=True)


# ===========================================================================
# TAB 3 — TECHNIQUES MATRIX
# ===========================================================================

with tab3:
    actor_ids_for_tech = [a["actor_id"] for a in display_actors]
    freq = get_technique_frequency_for_actors(actor_ids_for_tech)

    if not freq:
        st.info("No technique data for the current actor selection.")
    else:
        st.markdown("### ATT&CK Technique Frequency")

        freq_df = pd.DataFrame(
            sorted(freq.items(), key=lambda x: x[1], reverse=True)[:25],
            columns=["Technique", "Actor Count"],
        )
        fig_freq = px.bar(
            freq_df, x="Actor Count", y="Technique",
            orientation="h",
            title=f"Top {len(freq_df)} Techniques Across Tracked Actors",
            color="Actor Count",
            color_continuous_scale=[[0, "#1a3a5c"], [0.5, "#FF8C00"], [1, "#FF4B4B"]],
        )
        fig_freq.update_layout(
            template=_DARK, height=520,
            margin=dict(l=0, r=0, t=40, b=0),
            yaxis={"categoryorder": "total ascending"},
            paper_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_freq, use_container_width=True)

        st.markdown("---")
        st.markdown("### Technique Coverage by Actor")

        # Build actor × technique presence matrix
        tech_rows = []
        top_techs = [t for t, _ in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:15]]
        for actor in display_actors[:12]:  # cap at 12 actors for readability
            row: dict = {"Actor": actor["actor_id"]}
            for t in top_techs:
                row[t] = "✓" if t in actor.get("ttps", []) else ""
            tech_rows.append(row)

        if tech_rows:
            tech_df = pd.DataFrame(tech_rows).set_index("Actor")
            st.dataframe(tech_df, use_container_width=True)
            st.caption("✓ = technique observed in actor's TTP profile")

        st.markdown("---")
        st.markdown("### Tactic Category Distribution")

        # Rough tactic groupings
        _TACTIC_PREFIX = {
            "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
            "T1078": "Credential Access", "T1621": "Credential Access", "T1528": "Credential Access",
            "T1059": "Execution",
            "T1055": "Defense Evasion", "T1027": "Defense Evasion", "T1036": "Defense Evasion",
            "T1071": "C2", "T1095": "C2",
            "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
            "T1486": "Impact", "T1490": "Impact",
            "T1195": "Supply Chain", "T1550": "Lateral Movement",
            "T1114": "Collection", "T1119": "Collection", "T1056": "Collection",
        }

        tactic_freq: dict[str, int] = {}
        for ttp, count in freq.items():
            tac = next(
                (v for k, v in _TACTIC_PREFIX.items() if ttp.startswith(k)),
                "Other",
            )
            tactic_freq[tac] = tactic_freq.get(tac, 0) + count

        tac_df = pd.DataFrame(
            sorted(tactic_freq.items(), key=lambda x: x[1], reverse=True),
            columns=["Tactic", "Frequency"],
        )
        fig_tac = px.bar(
            tac_df, x="Tactic", y="Frequency",
            title="Technique Frequency by Tactic Category",
            color="Frequency",
            color_continuous_scale=[[0, "#1a3a5c"], [1, "#FF4B4B"]],
        )
        fig_tac.update_layout(
            template=_DARK, height=320,
            margin=dict(l=0, r=0, t=40, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_tac, use_container_width=True)


# ===========================================================================
# TAB 4 — ACTOR COMPARISON
# ===========================================================================

with tab4:
    st.markdown("### Compare Threat Actors")
    all_ids = [a["actor_id"] for a in all_actors_raw]

    compare_selection = st.multiselect(
        "Select actors to compare (2–4)",
        all_ids,
        default=FEATURED_ACTOR_IDS[:4],
        max_selections=4,
        key="compare_select",
    )

    if len(compare_selection) < 2:
        st.info("Select at least 2 actors to compare.")
    else:
        comp_rows = get_comparison_data(compare_selection)
        if not comp_rows:
            st.warning("Could not load comparison data.")
        else:
            # --- Radar chart ---
            _MAX_VICTIMS = max(r["victim_count"] for r in comp_rows) or 1
            _MAX_TTPS    = max(r["ttp_count"] for r in comp_rows) or 1
            _MAX_CAMPS   = max(r["campaign_count"] for r in comp_rows) or 1

            dimensions = ["Risk Score", "Attribution", "TTP Coverage", "Campaign Activity", "Victim Reach"]

            fig_radar = go.Figure()
            for row in comp_rows:
                fig_radar.add_trace(go.Scatterpolar(
                    r=[
                        row["risk_score"],
                        row["attribution_confidence"],
                        row["ttp_count"] / _MAX_TTPS,
                        row["campaign_count"] / _MAX_CAMPS,
                        row["victim_count"] / _MAX_VICTIMS,
                    ],
                    theta=dimensions,
                    fill="toself",
                    name=row["actor_id"],
                    opacity=0.7,
                ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 1], color="#aaa"),
                    bgcolor="#1E1E2E",
                ),
                template=_DARK,
                height=420,
                title="Multi-Dimensional Actor Comparison (normalised 0–1)",
                margin=dict(l=40, r=40, t=60, b=20),
                paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", y=-0.05),
            )
            st.plotly_chart(fig_radar, use_container_width=True)

            st.markdown("---")
            st.markdown("### Comparison Table")

            cmp_df = pd.DataFrame([
                {
                    "Actor":             r["actor_id"],
                    "Origin":            r["origin"],
                    "Sophistication":    r["sophistication"],
                    "Severity":          r["severity"],
                    "Risk Score":        _pct(r["risk_score"]),
                    "Attribution Conf.": _pct(r["attribution_confidence"]),
                    "Techniques":        r["ttp_count"],
                    "Tools":             r["tool_count"],
                    "Campaigns":         r["campaign_count"],
                    "Active":            r["active_campaigns"],
                    "Victims":           r["victim_count"],
                    "Total Demands":     _usd(r["total_demand_usd"]),
                }
                for r in comp_rows
            ])
            st.dataframe(cmp_df.set_index("Actor"), use_container_width=True)

            st.markdown("---")
            st.markdown("### Side-by-Side Risk & Attribution")

            bar_df = pd.DataFrame([
                {"Actor": r["actor_id"], "Metric": "Risk Score",             "Value": r["risk_score"] * 100}
                for r in comp_rows
            ] + [
                {"Actor": r["actor_id"], "Metric": "Attribution Confidence", "Value": r["attribution_confidence"] * 100}
                for r in comp_rows
            ])
            fig_bar = px.bar(
                bar_df, x="Actor", y="Value", color="Metric", barmode="group",
                title="Risk Score vs Attribution Confidence (%)",
                color_discrete_map={"Risk Score": "#FF4B4B", "Attribution Confidence": "#5b8dd9"},
                height=320,
            )
            fig_bar.update_layout(
                template=_DARK,
                margin=dict(l=0, r=0, t=40, b=0),
                yaxis_title="Score (%)",
                paper_bgcolor="rgba(0,0,0,0)",
                legend_title="",
            )
            st.plotly_chart(fig_bar, use_container_width=True)


# ===========================================================================
# TAB 5 — GEOGRAPHIC ACTIVITY
# ===========================================================================

with tab5:
    geo_actor_ids = [a["actor_id"] for a in display_actors]

    # Origin distribution
    origin_counts: dict[str, int] = {}
    for actor in display_actors:
        orig = actor.get("origin", "Unknown")
        origin_counts[orig] = origin_counts.get(orig, 0) + 1

    left_g, right_g = st.columns(2)

    with left_g:
        st.markdown("#### Actor Origins")
        if origin_counts:
            orig_df = pd.DataFrame(
                list(origin_counts.items()), columns=["Origin", "Count"]
            ).sort_values("Count", ascending=False)
            fig_orig = px.pie(
                orig_df, names="Origin", values="Count",
                title="Tracked Actors by Origin",
                color_discrete_sequence=px.colors.sequential.RdBu,
                hole=0.4,
            )
            fig_orig.update_layout(
                template=_DARK, height=340,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_orig, use_container_width=True)

    with right_g:
        st.markdown("#### Sophistication Distribution")
        soph_counts: dict[str, int] = {}
        for actor in display_actors:
            s = actor.get("sophistication", "unknown")
            soph_counts[s] = soph_counts.get(s, 0) + 1
        if soph_counts:
            soph_df = pd.DataFrame(
                list(soph_counts.items()), columns=["Sophistication", "Count"]
            )
            soph_order = ["nation-state", "advanced", "intermediate", "basic"]
            soph_df["_order"] = soph_df["Sophistication"].map(
                {s: i for i, s in enumerate(soph_order)}
            ).fillna(99)
            soph_df = soph_df.sort_values("_order").drop(columns="_order")
            fig_soph = px.bar(
                soph_df, x="Sophistication", y="Count",
                title="Actor Sophistication Levels",
                color="Sophistication",
                color_discrete_map=_SOPH_COLORS,
                height=340,
            )
            fig_soph.update_layout(
                template=_DARK,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
            )
            st.plotly_chart(fig_soph, use_container_width=True)

    st.markdown("---")
    st.markdown("#### Target Regions by Actor")

    region_matrix = get_region_matrix(geo_actor_ids)
    if region_matrix:
        region_rows = []
        for region, actor_counts in region_matrix.items():
            for actor_id, count in actor_counts.items():
                region_rows.append({"Region": region, "Actor": actor_id, "Count": count})

        region_df = pd.DataFrame(region_rows)
        # Limit to top regions by total activity
        top_regions = (
            region_df.groupby("Region")["Count"].sum()
            .sort_values(ascending=False)
            .head(12)
            .index.tolist()
        )
        region_df = region_df[region_df["Region"].isin(top_regions)]

        fig_reg = px.bar(
            region_df,
            x="Region", y="Count", color="Actor",
            title="Campaign Activity by Target Region",
            barmode="stack",
            height=380,
        )
        fig_reg.update_layout(
            template=_DARK,
            margin=dict(l=0, r=0, t=40, b=80),
            xaxis_tickangle=-40,
            legend_title="Actor",
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_reg, use_container_width=True)
    else:
        st.info("No regional campaign data for the current actor selection.")

    st.markdown("---")
    st.markdown("#### Target Sectors by Actor")

    sector_matrix = get_sector_matrix(geo_actor_ids)
    if sector_matrix:
        sector_rows = []
        for sector, actor_counts in sector_matrix.items():
            for actor_id, count in actor_counts.items():
                sector_rows.append({"Sector": sector, "Actor": actor_id, "Count": count})

        sector_df = pd.DataFrame(sector_rows)
        top_sectors = (
            sector_df.groupby("Sector")["Count"].sum()
            .sort_values(ascending=False)
            .head(15)
            .index.tolist()
        )
        sector_df = sector_df[sector_df["Sector"].isin(top_sectors)]

        fig_sec_geo = px.bar(
            sector_df,
            x="Sector", y="Count", color="Actor",
            title="Campaign Activity by Target Sector",
            barmode="stack",
            height=400,
        )
        fig_sec_geo.update_layout(
            template=_DARK,
            margin=dict(l=0, r=0, t=40, b=100),
            xaxis_tickangle=-45,
            legend_title="Actor",
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_sec_geo, use_container_width=True)
    else:
        st.info("No sector campaign data for the current actor selection.")
