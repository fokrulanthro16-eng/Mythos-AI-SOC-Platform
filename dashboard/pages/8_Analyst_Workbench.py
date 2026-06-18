"""dashboard/pages/8_Analyst_Workbench.py — SOC Analyst Workbench."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.workbench_store import (
    _ANALYSTS,
    _PRIORITY_RANK,
    add_workbench_note,
    assign_incident,
    get_activity_feed,
    get_all_assignments,
    get_analyst_assignments,
    get_escalations,
    get_workload_metrics,
    log_activity,
    record_escalation,
    seed_sample_data,
    unassign_incident,
    update_assignment_status,
)
from dashboard.case_store import get_all_cases, seed_sample_cases, update_case

try:
    from reporting import assemble_report_data, build_incident_report
    _REPORTING_AVAILABLE = True
except ImportError:
    _REPORTING_AVAILABLE = False

st.set_page_config(
    page_title="Analyst Workbench",
    page_icon="🔬",
    layout="wide",
)

# Seed demo data on first load
seed_sample_data()
seed_sample_cases()

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🔬 Analyst Workbench")
st.caption("Assign incidents, manage cases, escalate priorities, and track analyst activity.")

# ---------------------------------------------------------------------------
# Metrics row
# ---------------------------------------------------------------------------

metrics = get_workload_metrics()
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Assigned",  metrics["total_assigned"])
m2.metric("Active",          metrics["active"])
m3.metric("Resolved",        metrics["resolved"])
m4.metric("Escalations Today", metrics["escalations_today"])
m5.metric("Analysts Active", len(metrics["by_analyst"]))

st.divider()

# ---------------------------------------------------------------------------
# Main layout: left panel (assignment + actions) | right panel (feed + timeline)
# ---------------------------------------------------------------------------

left, right = st.columns([3, 2], gap="large")

# ===========================================================================
# LEFT PANEL — Assign & Manage
# ===========================================================================

with left:

    # -----------------------------------------------------------------------
    # Assign Incident
    # -----------------------------------------------------------------------
    st.subheader("📋 Assign Incident")
    with st.form("assign_form", clear_on_submit=True):
        a_col1, a_col2, a_col3 = st.columns([2, 2, 1])
        inc_id = a_col1.text_input("Incident ID", placeholder="INC-2026-001")
        inc_title = a_col1.text_input("Title / Threat Name", placeholder="Ransomware detected")
        analyst_sel = a_col2.selectbox("Assign to Analyst", [""] + _ANALYSTS)
        severity_sel = a_col2.selectbox("Severity", ["MEDIUM", "LOW", "HIGH", "CRITICAL"])
        priority_sel = a_col3.selectbox("Priority", ["P3", "P1", "P2", "P4"])
        assigned_by = a_col3.text_input("Assigned By", value="SOC Lead")
        submitted_assign = st.form_submit_button("Assign", use_container_width=True)
    if submitted_assign:
        if not inc_id or not analyst_sel:
            st.warning("Incident ID and analyst are required.")
        else:
            assign_incident(
                inc_id.strip(),
                analyst_sel,
                assigned_by=assigned_by or "SOC Lead",
                title=inc_title,
                severity=severity_sel,
                priority=priority_sel,
            )
            st.success(f"Incident **{inc_id}** assigned to **{analyst_sel}**.")
            st.rerun()

    # -----------------------------------------------------------------------
    # Current Assignments Table
    # -----------------------------------------------------------------------
    st.subheader("📊 Current Assignments")

    analyst_filter = st.selectbox("Filter by Analyst", ["All"] + _ANALYSTS, key="analyst_filter")
    status_filter = st.selectbox(
        "Filter by Status",
        ["All", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"],
        key="status_filter",
    )

    assignments = get_all_assignments()
    if analyst_filter != "All":
        assignments = [a for a in assignments if a.get("analyst") == analyst_filter]
    if status_filter != "All":
        assignments = [a for a in assignments if a.get("status") == status_filter]

    if assignments:
        _STATUS_COLORS = {
            "OPEN": "🔴", "INVESTIGATING": "🟠", "CONTAINED": "🟡",
            "RESOLVED": "🟢", "CLOSED": "⚫",
        }
        _PRIORITY_COLORS = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}
        rows = []
        for a in sorted(assignments, key=lambda x: _PRIORITY_RANK.get(x.get("priority", "P4"), 4)):
            rows.append({
                "Priority": _PRIORITY_COLORS.get(a.get("priority", "P4"), "") + " " + a.get("priority", "P4"),
                "Incident ID": a["incident_id"],
                "Title": a.get("title", "")[:45],
                "Severity": a.get("severity", ""),
                "Status": _STATUS_COLORS.get(a.get("status", ""), "") + " " + a.get("status", ""),
                "Analyst": a.get("analyst", "Unassigned"),
                "Notes": len(a.get("notes", [])),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.caption(f"{len(assignments)} assignment(s) shown")
    else:
        st.info("No assignments match the current filter.")

    # -----------------------------------------------------------------------
    # Case Action Panel
    # -----------------------------------------------------------------------
    st.subheader("⚙️ Case Actions")

    all_asgn = get_all_assignments()
    inc_ids = [a["incident_id"] for a in all_asgn]

    if not inc_ids:
        st.info("No incidents assigned yet.")
    else:
        selected_inc = st.selectbox("Select Incident", inc_ids, key="action_incident")
        selected_asgn = next((a for a in all_asgn if a["incident_id"] == selected_inc), None)

        tab_status, tab_priority, tab_notes, tab_assign, tab_close, tab_report = st.tabs(
            ["Change Status", "Escalate Priority", "Add Note", "Reassign", "Close", "📄 Report"]
        )

        with tab_status:
            st.markdown(f"**Current:** `{selected_asgn.get('status', 'OPEN') if selected_asgn else '—'}`")
            new_status = st.selectbox(
                "New Status",
                ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"],
                key="new_status",
            )
            actor_status = st.text_input("Your name", value="Analyst", key="actor_status")
            if st.button("Update Status", key="btn_status"):
                result = update_assignment_status(selected_inc, new_status, user=actor_status)
                if result:
                    st.success(f"Status updated to **{new_status}**.")
                    # Also update case_store if there's a linked case
                    cases = [c for c in get_all_cases() if c.get("incident_id") == selected_inc]
                    if cases:
                        update_case(cases[0]["id"], {"status": new_status}, user=actor_status)
                    st.rerun()

        with tab_priority:
            cur_p = selected_asgn.get("priority", "P3") if selected_asgn else "P3"
            st.markdown(f"**Current Priority:** `{cur_p}`")
            new_priority = st.selectbox("Escalate To", ["P1", "P2", "P3", "P4"], key="new_priority")
            esc_reason = st.text_area("Escalation Reason", placeholder="Why is this being escalated?", key="esc_reason")
            esc_actor = st.text_input("Your name", value="Analyst", key="actor_priority")
            if st.button("Escalate Priority", key="btn_priority"):
                record_escalation(selected_inc, cur_p, new_priority, esc_actor, esc_reason)
                st.success(f"Escalated from **{cur_p}** to **{new_priority}**.")
                st.rerun()

        with tab_notes:
            note_content = st.text_area("Note", placeholder="Analyst observations, findings, next steps…", key="note_content")
            note_author = st.text_input("Author", value="Analyst", key="note_author")
            if st.button("Add Note", key="btn_note"):
                if note_content.strip():
                    result = add_workbench_note(selected_inc, note_content, author=note_author)
                    if result:
                        st.success("Note added.")
                    else:
                        log_activity(note_author, "NOTE_ADDED", selected_inc, note_content[:80])
                        st.success("Activity logged.")
                    st.rerun()
                else:
                    st.warning("Note content is required.")

            # Show existing notes
            if selected_asgn and selected_asgn.get("notes"):
                st.markdown("**Existing Notes:**")
                for n in reversed(selected_asgn["notes"]):
                    st.markdown(f"> **{n['author']}** · {n['timestamp'][:16].replace('T', ' ')} UTC")
                    st.markdown(f"> {n['content']}")
                    st.markdown("---")

        with tab_assign:
            new_analyst = st.selectbox("Reassign To", [""] + _ANALYSTS, key="reassign_analyst")
            reassign_by = st.text_input("Reassigned By", value="SOC Lead", key="reassign_by")
            if st.button("Reassign", key="btn_reassign"):
                if new_analyst:
                    assign_incident(
                        selected_inc,
                        new_analyst,
                        assigned_by=reassign_by,
                        title=selected_asgn.get("title", "") if selected_asgn else "",
                        severity=selected_asgn.get("severity", "MEDIUM") if selected_asgn else "MEDIUM",
                        priority=selected_asgn.get("priority", "P3") if selected_asgn else "P3",
                    )
                    st.success(f"Reassigned to **{new_analyst}**.")
                    st.rerun()

        with tab_close:
            close_note = st.text_area("Closing Notes", placeholder="Summary of actions taken and resolution…", key="close_note")
            close_actor = st.text_input("Closed By", value="Analyst", key="close_actor")
            if st.button("Close Case", type="primary", key="btn_close"):
                update_assignment_status(selected_inc, "CLOSED", user=close_actor)
                if close_note.strip():
                    add_workbench_note(selected_inc, f"[CLOSE] {close_note}", author=close_actor)
                log_activity(close_actor, "CASE_CLOSED", selected_inc, close_note[:80])
                # Update case_store
                cases = [c for c in get_all_cases() if c.get("incident_id") == selected_inc]
                if cases:
                    update_case(cases[0]["id"], {"status": "CLOSED"}, user=close_actor)
                st.success(f"Incident **{selected_inc}** closed.")
                st.rerun()

        with tab_report:
            st.markdown("**Generate PDF Incident Report**")
            if _REPORTING_AVAILABLE:
                rep_by = st.text_input(
                    "Generated By",
                    value=selected_asgn.get("analyst", "SOC Analyst") if selected_asgn else "SOC Analyst",
                    key="rep_by_wb",
                )
                rep_cls = st.selectbox(
                    "Classification",
                    ["CONFIDENTIAL", "RESTRICTED", "INTERNAL"],
                    key="rep_cls_wb",
                )
                if st.button("Generate Report", key="btn_gen_pdf_wb"):
                    linked_cases = [c for c in get_all_cases() if c.get("incident_id") == selected_inc]
                    case_rec = linked_cases[0] if linked_cases else None
                    report_data = assemble_report_data(
                        selected_inc,
                        case_record=case_rec,
                        assignment_record=selected_asgn,
                        generated_by=rep_by,
                        classification=rep_cls,
                    )
                    st.session_state[f"_pdf_wb_{selected_inc}"] = (
                        build_incident_report(report_data),
                        selected_inc,
                    )
                wb_pdf = st.session_state.get(f"_pdf_wb_{selected_inc}")
                if wb_pdf:
                    pdf_bytes, pdf_id = wb_pdf
                    st.download_button(
                        "⬇ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"mythos_{pdf_id}_report.pdf",
                        mime="application/pdf",
                        key=f"dl_pdf_wb_{selected_inc}",
                    )
            else:
                st.warning("ReportLab not installed — PDF generation unavailable. Run `pip install reportlab`.")


# ===========================================================================
# RIGHT PANEL — Case Timeline + Activity Feed
# ===========================================================================

with right:

    # -----------------------------------------------------------------------
    # Case Timeline
    # -----------------------------------------------------------------------
    st.subheader("🕐 Case Timeline")

    all_asgn_r = get_all_assignments()
    if all_asgn_r:
        timeline_inc = st.selectbox(
            "Timeline for", [a["incident_id"] for a in all_asgn_r], key="timeline_inc"
        )
        tl_asgn = next((a for a in all_asgn_r if a["incident_id"] == timeline_inc), None)

        if tl_asgn:
            # Collect timeline events from notes + activity
            events = []
            events.append({
                "time": tl_asgn.get("assigned_at", ""),
                "icon": "📌",
                "event": f"Assigned to {tl_asgn.get('analyst', 'N/A')}",
            })
            for n in tl_asgn.get("notes", []):
                events.append({
                    "time": n.get("timestamp", ""),
                    "icon": "📝",
                    "event": f"Note by {n['author']}: {n['content'][:60]}",
                })
            escs = get_escalations(timeline_inc)
            for e in escs:
                events.append({
                    "time": e["timestamp"],
                    "icon": "⬆️",
                    "event": f"Escalated {e['from_priority']} → {e['to_priority']}: {e.get('reason', '')[:50]}",
                })
            events.sort(key=lambda x: x["time"])

            for ev in events:
                ts_display = ev["time"][:16].replace("T", " ") + " UTC" if ev["time"] else ""
                st.markdown(
                    f"{ev['icon']} **{ts_display}**  \n{ev['event']}"
                )
                st.markdown("---")
        else:
            st.info("No timeline data.")
    else:
        st.info("Assign an incident to view its timeline.")

    # -----------------------------------------------------------------------
    # Analyst Activity Feed
    # -----------------------------------------------------------------------
    st.subheader("📡 Analyst Activity Feed")

    feed_analyst = st.selectbox("Filter Feed By", ["All"] + _ANALYSTS, key="feed_analyst")
    feed = get_activity_feed(limit=30, analyst=None if feed_analyst == "All" else feed_analyst)

    _ACTION_ICONS = {
        "ASSIGNED": "📌", "REASSIGNED": "🔄", "UNASSIGNED": "❌",
        "STATUS_CHANGED": "🔀", "NOTE_ADDED": "📝", "ESCALATED": "⬆️",
        "CASE_CLOSED": "🔒",
    }

    if feed:
        for entry in feed[:20]:
            icon = _ACTION_ICONS.get(entry.get("action", ""), "•")
            ts = entry.get("timestamp", "")[:16].replace("T", " ")
            st.markdown(
                f"{icon} `{ts}` · **{entry.get('user', '?')}** "
                f"[{entry.get('action', '')}] → `{entry.get('target', '')}` "
                f"— {entry.get('detail', '')[:60]}"
            )
    else:
        st.info("No activity yet.")

# ---------------------------------------------------------------------------
# Analyst Workload Chart
# ---------------------------------------------------------------------------

st.divider()
st.subheader("📈 Analyst Workload Distribution")

metrics = get_workload_metrics()
by_analyst = metrics.get("by_analyst", {})

if by_analyst:
    try:
        import plotly.express as px
        wl_rows = []
        for analyst, counts in sorted(by_analyst.items()):
            wl_rows.append({
                "Analyst": analyst,
                "Open": counts.get("open", 0),
                "Resolved": counts.get("resolved", 0),
                "Critical": counts.get("critical", 0),
            })
        wl_df = pd.DataFrame(wl_rows)
        fig = px.bar(
            wl_df, x="Analyst", y=["Open", "Resolved"],
            barmode="group", color_discrete_map={"Open": "#ef4444", "Resolved": "#22c55e"},
            title="Cases per Analyst (Open vs Resolved)",
            height=320,
        )
        fig.update_layout(margin=dict(l=0, r=0, t=40, b=0), legend_title="")
        st.plotly_chart(fig, use_container_width=True)
    except ImportError:
        rows = [{"Analyst": k, **v} for k, v in by_analyst.items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No workload data yet.")
