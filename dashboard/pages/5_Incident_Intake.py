"""dashboard/pages/5_Incident_Intake.py — SOC Incident Intake & File Upload."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is on sys.path
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

st.set_page_config(
    page_title="Mythos · Incident Intake",
    page_icon="📥",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .intake-header{font-size:1.8rem;font-weight:700;color:#FF4B4B;margin-bottom:0.2rem}
    .intake-sub{color:#aaa;margin-bottom:1.5rem}
    .metric-card{background:#1E1E2E;border-radius:8px;padding:1rem;text-align:center}
    .success-box{background:#0d3321;border:1px solid #1aff7a;border-radius:6px;padding:0.8rem}
    .error-box{background:#3d0d0d;border:1px solid #ff4b4b;border-radius:6px;padding:0.8rem}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<p class="intake-header">📥 Incident Intake</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="intake-sub">Upload JSON, CSV, or Syslog files to ingest security incidents into the pipeline.</p>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def _get_sample_json() -> str:
    return json.dumps(
        [
            {
                "incident_id": "INC-DEMO-001",
                "threat_name": "Cobalt Strike Beacon",
                "severity": "CRITICAL",
                "indicators": ["192.168.1.100", "malware.example.com"],
            },
            {
                "threat_name": "PowerShell Abuse",
                "severity": "HIGH",
                "indicators": ["10.0.0.55"],
            },
        ],
        indent=2,
    )


@st.cache_data(show_spinner=False)
def _get_sample_csv() -> str:
    return (
        "incident_id,threat_name,severity,indicators\n"
        "INC-CSV-001,Ransomware Attack,CRITICAL,192.168.0.5|10.10.10.1\n"
        "INC-CSV-002,Credential Harvesting,HIGH,evil.corp\n"
        "INC-CSV-003,Port Scan,LOW,192.168.1.1\n"
    )


@st.cache_data(show_spinner=False)
def _get_sample_syslog() -> str:
    return (
        "<134>Jun 17 12:00:01 server01 sshd[1234]: Failed password for root from 10.0.0.99 port 22\n"
        "<131>Jun 17 12:00:05 server01 kernel: CRITICAL ransomware detected in /tmp/malware.exe\n"
        "2026-06-17T12:01:00Z server01 nginx: SQL injection attempt from 192.168.100.1\n"
    )


# ---------------------------------------------------------------------------
# Sample file downloads
# ---------------------------------------------------------------------------
with st.expander("📄 Download sample files to test ingestion", expanded=False):
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            "⬇ sample_incidents.json",
            data=_get_sample_json(),
            file_name="sample_incidents.json",
            mime="application/json",
        )
    with c2:
        st.download_button(
            "⬇ sample_incidents.csv",
            data=_get_sample_csv(),
            file_name="sample_incidents.csv",
            mime="text/csv",
        )
    with c3:
        st.download_button(
            "⬇ sample_events.log",
            data=_get_sample_syslog(),
            file_name="sample_events.log",
            mime="text/plain",
        )

# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------
st.subheader("Upload Incident File")
run_pipeline = st.checkbox(
    "Run Mythos pipeline on ingested incidents",
    value=True,
    help="Runs each accepted incident through PlannerAgent → ForensicsAgent → ComplianceAgent",
)

uploaded = st.file_uploader(
    "Choose a file (JSON, CSV, TXT, or LOG)",
    type=["json", "csv", "txt", "log"],
    accept_multiple_files=False,
)

if uploaded is not None:
    with st.spinner(f"Parsing {uploaded.name}…"):
        try:
            from parsers.ingestion_service import IngestionService

            content = uploaded.read()
            service = IngestionService(run_pipeline=run_pipeline)
            result, accepted = service.ingest(content, filename=uploaded.name)
        except Exception as exc:
            st.error(f"Ingestion failed: {exc}")
            st.stop()

    # ── KPI Row ────────────────────────────────────────────────────────────
    st.markdown("---")
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Parsed", result.parsed_count)
    k2.metric("Accepted", result.accepted_count, delta=f"+{result.accepted_count}")
    k3.metric("Duplicates", result.duplicate_count)
    k4.metric("Errors", result.error_count)
    k5.metric("Format", result.format.upper())

    # ── Success / error messages ────────────────────────────────────────────
    if result.accepted_count > 0:
        st.success(
            f"✅ {result.accepted_count} incident(s) accepted and "
            + ("queued through pipeline." if run_pipeline else "stored.")
        )
    if result.duplicate_count > 0:
        st.info(f"ℹ️ {result.duplicate_count} duplicate(s) skipped (already seen).")
    if result.errors:
        with st.expander(f"⚠️ {result.error_count} parse error(s)", expanded=True):
            for err in result.errors:
                st.markdown(f"<div class='error-box'>⚠ {err}</div>", unsafe_allow_html=True)

    # ── Accepted incidents table ────────────────────────────────────────────
    if accepted:
        st.subheader("Accepted Incidents")
        df = pd.DataFrame(
            [
                {
                    "Incident ID": inc.incident_id,
                    "Threat Name": inc.threat_name,
                    "Severity": inc.severity,
                    "Indicators": ", ".join(inc.indicators[:3])
                    + ("…" if len(inc.indicators) > 3 else ""),
                    "Source": inc.source_format.upper(),
                }
                for inc in accepted
            ]
        )

        sev_colors = {
            "CRITICAL": "background-color:#3d0d0d",
            "HIGH": "background-color:#3d2000",
            "MEDIUM": "background-color:#1a1a00",
            "LOW": "background-color:#0d2000",
        }

        def _color_sev(val):
            return sev_colors.get(val, "")

        st.dataframe(
            df.style.map(_color_sev, subset=["Severity"]),
            use_container_width=True,
            hide_index=True,
        )

        col_csv, col_json = st.columns(2)
        with col_csv:
            st.download_button(
                "⬇ Export CSV",
                data=df.to_csv(index=False),
                file_name="ingested_incidents.csv",
                mime="text/csv",
            )
        with col_json:
            st.download_button(
                "⬇ Export JSON",
                data=json.dumps([inc.model_dump(exclude={"raw"}) for inc in accepted], indent=2),
                file_name="ingested_incidents.json",
                mime="application/json",
            )

# ---------------------------------------------------------------------------
# Upload history
# ---------------------------------------------------------------------------
st.markdown("---")
st.subheader("Upload History")

try:
    from parsers.ingestion_service import IngestionService

    history = IngestionService(run_pipeline=False).load_manifest()
except Exception:
    history = []

if history:
    hist_df = pd.DataFrame(history[::-1])  # newest first
    display_cols = [c for c in ["uploaded_at", "filename", "format", "parsed_count",
                                 "accepted_count", "duplicate_count", "error_count"]
                    if c in hist_df.columns]
    st.dataframe(hist_df[display_cols], use_container_width=True, hide_index=True)
else:
    st.info("No uploads yet. Upload a file above to get started.")

# ---------------------------------------------------------------------------
# Format reference
# ---------------------------------------------------------------------------
with st.expander("📚 Supported formats reference", expanded=False):
    st.markdown(
        """
**JSON** — array of objects or single object. Recognised field names:
- `threat_name` / `threat` / `name` / `alert_name` / `title`
- `severity` / `level` / `priority` (mapped to LOW/MEDIUM/HIGH/CRITICAL)
- `indicators` / `iocs` (list or pipe-separated string)
- `incident_id` / `id` / `alert_id` (auto-generated if absent)

**CSV** — header row required. Same column aliases as JSON.
Indicators column: pipe-separated (`|`).

**Syslog / LOG** — RFC 3164, RFC 5424, or ISO-timestamp format.
Threat name is extracted from the message. IPs, hashes, and domains
are automatically identified as indicators.
        """
    )
