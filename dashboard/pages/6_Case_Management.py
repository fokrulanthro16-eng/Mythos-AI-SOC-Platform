"""dashboard/pages/6_Case_Management.py — SOC Case Management Console."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.case_store import (
    _PRIORITY_LABELS,
    _STATUS_FLOW,
    add_note,
    create_case,
    get_all_cases,
    get_stats,
    seed_sample_cases,
    update_case,
)

try:
    from reporting import assemble_report_data, build_incident_report
    _REPORTING_AVAILABLE = True
except ImportError:
    _REPORTING_AVAILABLE = False

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Mythos · Case Management",
    page_icon="🗂️",
    layout="wide",
)

seed_sample_cases()  # populate demo data on first run

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .cm-header{font-size:1.8rem;font-weight:700;color:#FF4B4B}
    .cm-sub{color:#aaa;margin-bottom:1rem}
    .stat-card{background:#1E1E2E;border-radius:8px;padding:.8rem 1rem;text-align:center;margin:.25rem}
    .badge-p1{background:#7d0000;color:#fff;border-radius:4px;padding:2px 8px;font-size:.78rem}
    .badge-p2{background:#7d3200;color:#fff;border-radius:4px;padding:2px 8px;font-size:.78rem}
    .badge-p3{background:#4d4d00;color:#fff;border-radius:4px;padding:2px 8px;font-size:.78rem}
    .badge-p4{background:#003d00;color:#fff;border-radius:4px;padding:2px 8px;font-size:.78rem}
    .timeline-item{border-left:2px solid #444;padding-left:1rem;margin-bottom:.7rem}
    .note-box{background:#1a1a2e;border-radius:6px;padding:.7rem 1rem;margin-bottom:.5rem}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<p class="cm-header">🗂️ Case Management</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="cm-sub">SOC incident case tracking — Open → Investigating → Contained → Resolved → Closed</p>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Stats row
# ---------------------------------------------------------------------------
stats = get_stats()
s1, s2, s3, s4, s5, s6 = st.columns(6)
s1.metric("Total Cases", stats["total"])
s2.metric("Open", stats["open"], delta=None)
s3.metric("Investigating", stats["investigating"])
s4.metric("Contained", stats["contained"])
s5.metric("Resolved", stats["resolved"])
s6.metric("Closed", stats["closed"])

st.markdown("---")

# ---------------------------------------------------------------------------
# Sidebar — filters + new case
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("🔎 Filters")
    filter_status = st.multiselect(
        "Status", _STATUS_FLOW, default=[]
    )
    filter_priority = st.multiselect(
        "Priority", list(_PRIORITY_LABELS.keys()),
        format_func=lambda k: f"{k} — {_PRIORITY_LABELS[k]}",
        default=[],
    )
    search_query = st.text_input("Search title / case #", "")

    st.markdown("---")
    st.header("➕ New Case")
    with st.form("new_case_form", clear_on_submit=True):
        nc_title = st.text_input("Title", placeholder="APT Investigation Q2-2026")
        nc_priority = st.selectbox("Priority", list(_PRIORITY_LABELS.keys()), index=2)
        nc_analyst = st.text_input("Assigned Analyst", placeholder="Alice Chen")
        nc_desc = st.text_area("Description", height=60)
        nc_submit = st.form_submit_button("Create Case")

    if nc_submit and nc_title.strip():
        create_case(
            title=nc_title.strip(),
            priority=nc_priority,
            description=nc_desc.strip(),
            assigned_analyst=nc_analyst.strip() or None,
        )
        st.success(f"Case created: {nc_title}")
        st.rerun()

# ---------------------------------------------------------------------------
# Cases table
# ---------------------------------------------------------------------------
cases = get_all_cases()

if filter_status:
    cases = [c for c in cases if c.get("status") in filter_status]
if filter_priority:
    cases = [c for c in cases if c.get("priority") in filter_priority]
if search_query:
    q = search_query.lower()
    cases = [
        c for c in cases
        if q in c.get("title", "").lower() or q in c.get("case_number", "").lower()
    ]

if not cases:
    st.info("No cases match the current filters.")
    st.stop()

_STATUS_COLORS = {
    "OPEN":          "#1a3a5c",
    "INVESTIGATING": "#3d2800",
    "CONTAINED":     "#1a2e00",
    "RESOLVED":      "#0d3321",
    "CLOSED":        "#2a2a2a",
}

df = pd.DataFrame(
    [
        {
            "Case #":   c.get("case_number", ""),
            "Title":    c.get("title", ""),
            "Status":   c.get("status", "OPEN"),
            "Priority": c.get("priority", "P3"),
            "Analyst":  c.get("assigned_analyst") or "—",
            "Notes":    len(c.get("notes", [])),
            "Created":  (c.get("created_at", "") or "")[:10],
            "_id":      c.get("id", ""),
        }
        for c in cases
    ]
)

_prio_bg = {"P1": "background-color:#7d0000", "P2": "background-color:#7d3200",
             "P3": "background-color:#4d4d00", "P4": "background-color:#003d00"}
_stat_bg = {s: f"background-color:{v}" for s, v in _STATUS_COLORS.items()}

styled = df.drop(columns=["_id"]).style.map(
    lambda v: _stat_bg.get(v, ""), subset=["Status"]
).map(
    lambda v: _prio_bg.get(v, ""), subset=["Priority"]
)

st.dataframe(styled, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Case detail panel
# ---------------------------------------------------------------------------
st.markdown("---")
st.subheader("Case Detail")

case_options = {c["case_number"]: c["id"] for c in cases}
selected_num = st.selectbox("Select case", list(case_options.keys()), index=0)
selected_id = case_options[selected_num]
case = next((c for c in cases if c["id"] == selected_id), None)

if case:
    col_info, col_actions = st.columns([2, 1])

    with col_info:
        st.markdown(f"**{case['case_number']}** — {case['title']}")
        st.markdown(
            f"Status: `{case.get('status','OPEN')}` | "
            f"Priority: `{case.get('priority','P3')}` | "
            f"Analyst: `{case.get('assigned_analyst') or 'Unassigned'}`"
        )
        if case.get("description"):
            st.caption(case["description"])

    with col_actions:
        st.markdown("**Update Case**")
        with st.form(f"update_{selected_id}", clear_on_submit=False):
            new_status = st.selectbox(
                "Status",
                _STATUS_FLOW,
                index=_STATUS_FLOW.index(case.get("status", "OPEN")),
            )
            new_priority = st.selectbox(
                "Priority",
                list(_PRIORITY_LABELS.keys()),
                index=list(_PRIORITY_LABELS.keys()).index(case.get("priority", "P3")),
            )
            new_analyst = st.text_input("Analyst", value=case.get("assigned_analyst") or "")
            upd_submit = st.form_submit_button("Save Changes")

        if upd_submit:
            updates: dict = {}
            if new_status != case.get("status"):
                updates["status"] = new_status
            if new_priority != case.get("priority"):
                updates["priority"] = new_priority
            analyst_val = new_analyst.strip() or None
            if analyst_val != case.get("assigned_analyst"):
                updates["assigned_analyst"] = analyst_val
            if updates:
                update_case(selected_id, updates, user=new_analyst or "Analyst")
                st.success("Case updated.")
                st.rerun()
            else:
                st.info("No changes to save.")

    # Notes section
    st.markdown("---")
    note_col, hist_col = st.columns(2)

    with note_col:
        st.markdown("**📝 Notes**")
        notes = case.get("notes", [])
        if notes:
            for note in reversed(notes):
                st.markdown(
                    f'<div class="note-box"><b>{note.get("author","?")} '
                    f'<small>({(note.get("timestamp","")[:19]).replace("T"," ")})</small></b><br>'
                    f'{note.get("content","")}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No notes yet.")

        with st.form(f"note_{selected_id}", clear_on_submit=True):
            note_author = st.text_input("Your name", "SOC Analyst")
            note_content = st.text_area("Note", height=80, placeholder="Add investigation notes...")
            note_submit = st.form_submit_button("Add Note")

        if note_submit and note_content.strip():
            add_note(selected_id, note_content.strip(), author=note_author.strip() or "SOC Analyst")
            st.success("Note added.")
            st.rerun()

    with hist_col:
        st.markdown("**🕐 Case Timeline**")
        history = case.get("history", [])
        if history:
            _ev_icons = {
                "CREATED": "🟢", "STATUS_CHANGE": "🔄", "NOTE_ADDED": "📝",
                "ASSIGNMENT": "👤", "PRIORITY_CHANGE": "⚡", "INCIDENT_LINKED": "🔗",
            }
            for ev in reversed(history):
                action = ev.get("action", "")
                icon = _ev_icons.get(action, "◾")
                ts = (ev.get("timestamp", "")[:19]).replace("T", " ")
                st.markdown(
                    f'<div class="timeline-item">'
                    f'{icon} <b>{action.replace("_", " ").title()}</b>'
                    f' <small>({ts})</small><br>'
                    f'<small>{ev.get("content","")}</small></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No timeline events.")

    st.markdown("---")
    st.markdown("**📄 Generate PDF Report**")
    if _REPORTING_AVAILABLE:
        pdf_by_cm = st.text_input(
            "Generated By",
            value=case.get("assigned_analyst") or "SOC Analyst",
            key=f"pdf_by_{case['id']}",
        )
        pdf_cls_cm = st.selectbox(
            "Classification",
            ["CONFIDENTIAL", "RESTRICTED", "INTERNAL"],
            key=f"pdf_cls_{case['id']}",
        )
        inc_id_for_pdf = case.get("incident_id") or case.get("case_number", "UNKNOWN")
        if st.button("Generate PDF", key=f"btn_pdf_{case['id']}"):
            report_data = assemble_report_data(
                inc_id_for_pdf,
                case_record=case,
                generated_by=pdf_by_cm,
                classification=pdf_cls_cm,
            )
            st.session_state[f"_pdf_cm_{case['id']}"] = (
                build_incident_report(report_data),
                inc_id_for_pdf,
            )
        cm_pdf = st.session_state.get(f"_pdf_cm_{case['id']}")
        if cm_pdf:
            pdf_bytes, pdf_id = cm_pdf
            st.download_button(
                "⬇ Download PDF Report",
                data=pdf_bytes,
                file_name=f"mythos_{pdf_id}_report.pdf",
                mime="application/pdf",
                key=f"dl_pdf_{case['id']}",
            )
    else:
        st.warning("ReportLab not installed — PDF generation unavailable. Run `pip install reportlab`.")

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
st.markdown("---")
import json as _json

col_csv, col_json = st.columns(2)
with col_csv:
    st.download_button(
        "⬇ Export Cases CSV",
        data=df.drop(columns=["_id"]).to_csv(index=False),
        file_name="mythos_cases.csv",
        mime="text/csv",
    )
with col_json:
    st.download_button(
        "⬇ Export Cases JSON",
        data=_json.dumps(get_all_cases(), indent=2, default=str),
        file_name="mythos_cases.json",
        mime="application/json",
    )
