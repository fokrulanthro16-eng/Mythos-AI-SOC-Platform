"""reporting/report_builder.py — Mythos SOC PDF incident report generator.

Entry points
------------
build_incident_report(data: dict) -> bytes
    Build a complete PDF report and return raw bytes.

assemble_report_data(incident_id, *, ...) -> dict
    Construct the data dict from individual source records.

get_recommendations(threat_name_or_category, attack_techniques) -> list[str]
    Return contextual remediation recommendations.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from reporting.styles import (
    BLACK,
    DGRAY,
    GRAY,
    LGRAY,
    NAVY,
    RED,
    SEV_COLORS,
    STYLES,
    WHITE,
)

_PAGE_W, _PAGE_H = A4
_MARGIN = 2.0 * cm
_BODY_W = _PAGE_W - 2 * _MARGIN  # usable content width ≈ 17.15 cm

_PROFILES_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_profiles.json"

# ---------------------------------------------------------------------------
# Recommendations database
# ---------------------------------------------------------------------------

_RECS: dict[str, list[str]] = {
    "Ransomware": [
        "Isolate all affected endpoints and network segments immediately.",
        "Initiate offline backup restoration — verify integrity before restoring data.",
        "Deploy EDR across all endpoints with rollback and tamper-protection enabled.",
        "Disable RDP, SMB, and lateral movement protocols at the network perimeter.",
        "Engage your IR retainer and notify legal/compliance of breach reporting obligations.",
        "Hunt for persistence mechanisms: scheduled tasks, registry run keys, WMI subscriptions.",
    ],
    "Phishing": [
        "Quarantine all emails from identified sender domains across the full tenant.",
        "Reset credentials for every account that interacted with the phishing payload.",
        "Enforce DMARC, DKIM, and SPF on all corporate email domains.",
        "Deploy anti-phishing controls with link rewriting and sandbox detonation.",
        "Deliver targeted security awareness training to all affected business units.",
    ],
    "Credential Theft": [
        "Immediately invalidate and rotate all potentially compromised credentials.",
        "Enforce MFA on all privileged and internet-facing accounts without exception.",
        "Audit Active Directory for abnormal last-logon timestamps and source IPs.",
        "Deploy Privileged Access Workstations (PAW) for all administrative activities.",
        "Revoke all OAuth tokens, service account keys, and API secrets issued during the incident window.",
    ],
    "Data Exfiltration": [
        "Quantify and classify all exfiltrated data — initiate breach notification if PII or PHI is involved.",
        "Block all identified exfiltration destinations at DNS, proxy, and firewall levels.",
        "Deploy DLP controls on email gateways, web proxy, and cloud storage integrations.",
        "Enable egress traffic inspection and anomaly detection across all network boundaries.",
        "Apply least-privilege access to all sensitive data repositories.",
    ],
    "Command & Control": [
        "Block all identified C2 infrastructure at every network control point immediately.",
        "Conduct memory forensics and EDR sweep to identify additional implants.",
        "Rotate all credentials accessible from compromised hosts.",
        "Implement DNS sinkholing and filtering to prevent future C2 beaconing.",
        "Review proxy and DNS logs over a 30-day lookback window for additional C2 callbacks.",
    ],
    "Insider Threat": [
        "Preserve all digital evidence immediately — maintain strict chain of custody.",
        "Revoke the subject's access to all systems without prior notice to prevent evidence destruction.",
        "Coordinate response with HR, Legal, and Compliance from the outset.",
        "Deploy UEBA to detect similar data staging patterns across the organisation.",
        "Conduct a full access audit to enumerate all sensitive data accessed by the subject.",
    ],
    "Malware Delivery": [
        "Remove the malware loader from all affected systems using EDR remediation tools.",
        "Block delivery infrastructure (domains, file hashes, email senders) at all control points.",
        "Hunt for payload execution: review process creation events and persistence mechanisms.",
        "Patch all vulnerabilities exploited during the delivery chain.",
        "Enable application allowlisting on high-value and administrative endpoints.",
    ],
    "Lateral Movement": [
        "Apply network micro-segmentation to contain further lateral movement immediately.",
        "Identify and reset all accounts used during the lateral movement chain.",
        "Audit jump-server and administrative access logs to determine full compromise scope.",
        "Enforce just-in-time (JIT) privilege access for all administrative accounts.",
        "Enable Windows Defender Credential Guard and restrict NTLM where possible.",
    ],
}

_DEFAULT_RECS = [
    "Conduct a full forensic investigation to determine the complete scope of compromise.",
    "Preserve all logs and artefacts — do not remediate without forensic preservation.",
    "Notify all relevant stakeholders and regulatory bodies per your organisation's policy.",
    "Review and update incident response playbooks based on lessons learned.",
    "Schedule a post-incident review (PIR) within 72 hours of full containment.",
]

# Maps threat_name → category (mirrors executive_store._THREAT_CATEGORY)
_CATEGORY_MAP: dict[str, str] = {
    "LOCKBIT4-RANSOMWARE":            "Ransomware",
    "BLACKCAT-ALPHV-RANSOMWARE":      "Ransomware",
    "AKIRA-RANSOMWARE":               "Ransomware",
    "PLAY-RANSOMWARE":                "Ransomware",
    "RHYSIDA-RANSOMWARE":             "Ransomware",
    "REVIL-REVIVAL-RANSOMWARE":       "Ransomware",
    "ICEFIRE-LINUX-RANSOMWARE":       "Ransomware",
    "RHYSIDA-EXFIL-PRE-ENCRYPT":      "Ransomware",
    "APT28-SPEARPHISH":               "Phishing",
    "CARBANAK-BANKING-PHISH":         "Phishing",
    "EVILGINX2-AITM-PHISH":           "Phishing",
    "DARKGATE-MALSPAM":               "Phishing",
    "SCATTERED-SPIDER-BEC":           "Credential Theft",
    "SCATTERED-SPIDER-SMS-MFA":       "Credential Theft",
    "MIDNIGHT-BLIZZARD-OAUTH":        "Credential Theft",
    "STORM0558-EXCHANGE-TOKEN":       "Credential Theft",
    "ICEDID-BANKING-MALWARE":         "Credential Theft",
    "CLOP-MOVEIT-STYLE-SQLI":         "Data Exfiltration",
    "TA505-EXFIL-FTP":                "Data Exfiltration",
    "SCATTERED-SPIDER-DATA-THEFT":    "Data Exfiltration",
    "VOLT-TYPHOON-EXFIL":             "Data Exfiltration",
    "APT28-DOCUMENT-EXFIL":           "Data Exfiltration",
    "LAZARUS-CRYPTO-DRAIN":           "Data Exfiltration",
    "MOVEIT-STYLE-SQLI-2026":         "Data Exfiltration",
    "COBALTSTRIKE-BEACON-ENTERPRISE": "Command & Control",
    "BRUTERATEL-C4-IMPLANT":          "Command & Control",
    "SLIVER-C2-FRAMEWORK":            "Command & Control",
    "VOLT-TYPHOON-LOTL":              "Command & Control",
    "LAZARUS-C2-CRYPTO":              "Command & Control",
    "COBALTSTRIKE-VIA-RDP":           "Command & Control",
    "HAVOC-C2-FRAMEWORK":             "Command & Control",
    "MYTHIC-C2-AGENT":                "Command & Control",
    "CITRIX-BLEED-CVE-2023-4966":     "Command & Control",
    "K8S-CRYPTOMINING":               "Command & Control",
    "PAPERCUT-CVE-2023-27350":        "Command & Control",
    "INSIDER-DATA-STAGING":           "Insider Threat",
    "QAKBOT-REVIVAL-PHISH":           "Malware Delivery",
    "BUMBLEBEE-LOADER-EMAIL":         "Malware Delivery",
    "EMOTET-WAVE-2026":               "Malware Delivery",
    "SUPPLY-CHAIN-NPM-PACKAGE":       "Malware Delivery",
    "MIMIKATZ-PASS-THE-HASH":         "Lateral Movement",
    "KERBEROASTING-ATTACK":           "Lateral Movement",
    "RDP-BRUTEFORCE-LATERAL":         "Lateral Movement",
    "WMIC-LATERAL-MOVEMENT":          "Lateral Movement",
    "LOTL-GOVERNMENT-NETWORK":        "Lateral Movement",
}

# ATT&CK tactic IDs → supplemental recommendations
_TACTIC_RECS: dict[str, str] = {
    "credential-access": "Enable credential hardening: enforce MFA, deploy PAM, enable LAPS.",
    "persistence":       "Audit startup locations, scheduled tasks, and registry run keys.",
    "exfiltration":      "Enable data-loss prevention and egress traffic monitoring.",
    "impact":            "Initiate BCP/DR procedures and verify offline backup integrity.",
    "lateral-movement":  "Apply micro-segmentation and enforce JIT privilege for admin accounts.",
    "command-and-control": "Deploy DNS filtering and proxy inspection for C2 beacon detection.",
    "discovery":         "Restrict enumeration rights; alert on LDAP and network scan activity.",
    "defense-evasion":   "Enable script-block logging, AMSI, and cloud-delivered AV protection.",
}


def get_recommendations(
    threat_name_or_category: str,
    attack_techniques: list[dict] | None = None,
) -> list[str]:
    """Return contextual remediation recommendations.

    Accepts either a threat name (e.g. 'LOCKBIT4-RANSOMWARE') or a category
    name directly (e.g. 'Ransomware'). ATT&CK techniques enrich the list.
    """
    # Direct category match first
    if threat_name_or_category in _RECS:
        recs = list(_RECS[threat_name_or_category])
    else:
        category = _CATEGORY_MAP.get(threat_name_or_category, "")
        recs = list(_RECS.get(category, _DEFAULT_RECS))

    # Supplement with ATT&CK tactic-specific recommendations
    if attack_techniques:
        seen = {t.get("tactic_id", "").lower() for t in attack_techniques}
        for tactic_id, rec in _TACTIC_RECS.items():
            if tactic_id in seen and rec not in recs:
                recs.append(rec)

    return recs


# ---------------------------------------------------------------------------
# Low-level flowable helpers
# ---------------------------------------------------------------------------


def _s(name: str) -> ParagraphStyle:
    return STYLES[name]


def _section(title: str) -> list:
    """Return the flowables that form a numbered section header."""
    return [
        Spacer(1, 0.35 * cm),
        Paragraph(f"  {title}", _s("Section")),
        Spacer(1, 0.1 * cm),
    ]


def _hr() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.4, color=GRAY, spaceAfter=4, spaceBefore=2)


def _kv_table(pairs: list[tuple[str, str | None]]) -> Table:
    """Two-column key→value table with zebra shading."""
    col_w  = [4.5 * cm, _BODY_W - 4.5 * cm]
    tdata  = [
        [
            Paragraph(f"<b>{k}</b>", _s("Label")),
            Paragraph(str(v) if v else "—", _s("Body")),
        ]
        for k, v in pairs
    ]
    t = Table(tdata, colWidths=col_w, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, LGRAY]),
        ("GRID",           (0, 0), (-1, -1), 0.4, GRAY),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
    ]))
    return t


def _data_table(
    headers: list[str],
    rows: list[list[str]],
    col_widths: list[float] | None = None,
) -> Table:
    """Multi-column table with a NAVY header row and zebra data rows."""
    col_widths = col_widths or [_BODY_W / len(headers)] * len(headers)
    header_row = [Paragraph(f"<b>{h}</b>", _s("TableHeader")) for h in headers]
    data_rows  = [
        [Paragraph(str(c) if c else "—", _s("Body")) for c in row]
        for row in rows
    ]
    t = Table([header_row] + data_rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGRAY]),
        ("GRID",          (0, 0), (-1, -1), 0.4, GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ]))
    return t


def _severity_badge_table(severity: str) -> Table:
    """Coloured single-cell table used as a severity badge on the cover."""
    sev_color = SEV_COLORS.get(severity, GRAY)
    badge_style = ParagraphStyle(
        "SevBadge",
        parent=STYLES["Body"],
        textColor=WHITE,
        fontName="Helvetica-Bold",
        fontSize=10,
    )
    t = Table(
        [[Paragraph(f"  Severity: {severity}", badge_style)]],
        colWidths=[_BODY_W],
    )
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), sev_color),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return t


def _safe_ts(raw: str, default: str = "—") -> str:
    """Return first 19 chars of ISO timestamp with T→space; or default."""
    if not raw:
        return default
    return str(raw)[:19].replace("T", " ")


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _add_cover(story: list, data: dict) -> None:
    classification = data.get("classification", "CONFIDENTIAL")
    incident_id    = data.get("incident_id", "UNKNOWN")
    threat_name    = (data.get("threat_name", "Unknown Threat") or "").replace("-", " ")
    severity       = data.get("severity", "UNKNOWN")

    story.append(Spacer(1, 1.0 * cm))
    story.append(Paragraph(f"⚠  {classification}  ⚠", _s("Classification")))
    story.append(Spacer(1, 0.5 * cm))

    # Navy cover block
    cover_rows = [
        [Paragraph("MYTHOS SOC PLATFORM", _s("CoverSub"))],
        [Paragraph("INCIDENT INVESTIGATION REPORT", _s("CoverTitle"))],
        [Paragraph(f"Incident ID: {incident_id}", _s("CoverSub"))],
        [Paragraph(threat_name, _s("CoverSub"))],
    ]
    cover_t = Table(cover_rows, colWidths=[_BODY_W])
    cover_t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",   (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 9),
        ("LEFTPADDING",  (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(cover_t)
    story.append(Spacer(1, 0.4 * cm))
    story.append(_severity_badge_table(severity))
    story.append(Spacer(1, 0.8 * cm))

    story.append(_kv_table([
        ("Generated",        _safe_ts(data.get("generated_at", "")) + " UTC"),
        ("Generated By",     data.get("generated_by", "SOC Analyst")),
        ("Campaign",         data.get("campaign_id", "")),
        ("Classification",   classification),
    ]))

    story.append(Spacer(1, 1.2 * cm))
    story.append(Paragraph(
        "This report contains sensitive security information. Handle in accordance with your "
        "organisation's information security policy. Do not distribute without authorisation.",
        _s("Small"),
    ))


def _add_incident_summary(story: list, data: dict) -> None:
    story += _section("1.  INCIDENT SUMMARY")
    story.append(_kv_table([
        ("Incident ID",    data.get("incident_id")),
        ("Threat Name",    (data.get("threat_name") or "").replace("-", " ")),
        ("Severity",       data.get("severity")),
        ("Status",         data.get("status")),
        ("Campaign ID",    data.get("campaign_id")),
        ("Detected At",    _safe_ts(data.get("created_at", "")) + " UTC"),
        ("Confidence",     f"{float(data['confidence_score']):.0%}" if data.get("confidence_score") else None),
        ("Risk Score",     f"{float(data['risk_score']):.4f}"       if data.get("risk_score")       else None),
    ]))
    desc = data.get("description")
    if desc:
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph("<b>Description</b>", _s("SubSection")))
        story.append(Paragraph(str(desc), _s("Body")))


def _add_timeline(story: list, data: dict) -> None:
    story += _section("2.  INCIDENT TIMELINE")
    events: list[dict] = list(data.get("timeline") or [])

    # Build a minimal timeline from available timestamps if none supplied
    if not events:
        if data.get("created_at"):
            events.append({"timestamp": data["created_at"], "event": "Incident detected", "actor": "System"})
        for h in (data.get("case") or {}).get("history", []):
            events.append({
                "timestamp": h.get("timestamp", ""),
                "event":     h.get("content", h.get("action", "")),
                "actor":     h.get("user", "System"),
            })
        for n in (data.get("notes") or []):
            events.append({
                "timestamp": n.get("timestamp", ""),
                "event":     f"Note: {n.get('content', '')[:80]}",
                "actor":     n.get("author", "Analyst"),
            })
        events.sort(key=lambda x: x.get("timestamp") or "")

    if not events:
        story.append(Paragraph("No timeline events recorded.", _s("Body")))
        return

    rows = [
        [
            _safe_ts(ev.get("timestamp", "")),
            str(ev.get("event", ""))[:120],
            str(ev.get("actor", ""))[:28],
        ]
        for ev in events
        if ev.get("timestamp") or ev.get("event")
    ]
    if rows:
        story.append(_data_table(
            ["Timestamp", "Event", "Actor"],
            rows,
            [4.2 * cm, 10.0 * cm, 3.1 * cm],
        ))
    else:
        story.append(Paragraph("No timeline events recorded.", _s("Body")))


def _add_attack_mapping(story: list, data: dict) -> None:
    story += _section("3.  MITRE ATT&CK MAPPING")
    techniques: list[dict] = list(data.get("attack_techniques") or [])

    if not techniques:
        story.append(Paragraph(
            "No MITRE ATT&CK techniques have been mapped to this incident. "
            "Run the analysis pipeline to enrich this incident.",
            _s("Body"),
        ))
        return

    rows = [
        [
            t.get("technique_id", "—"),
            t.get("technique_name") or t.get("display_name", "—"),
            t.get("tactic", "—"),
            (t.get("url", "") or "")[:52],
        ]
        for t in techniques
    ]
    story.append(_data_table(
        ["ID", "Technique", "Tactic", "Reference"],
        rows,
        [2.4 * cm, 5.6 * cm, 3.8 * cm, 5.5 * cm],
    ))


def _add_attribution(story: list, data: dict) -> None:
    story += _section("4.  THREAT ACTOR ATTRIBUTION")
    actor = data.get("suspected_actor") or "UNATTRIBUTED"
    conf  = data.get("attribution_confidence") or 0

    story.append(_kv_table([
        ("Suspected Actor",    actor),
        ("Attribution Conf.",  f"{float(conf):.1%}" if conf else None),
        ("Campaign ID",        data.get("campaign_id")),
    ]))

    profile: dict = data.get("threat_actor_profile") or {}
    if profile:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>Actor Profile</b>", _s("SubSection")))
        story.append(_kv_table([
            ("Aliases",         ", ".join(profile.get("aliases", [])) or None),
            ("Origin",          profile.get("origin")),
            ("Motivation",      profile.get("motivation")),
            ("Target Sectors",  ", ".join(profile.get("target_sectors", [])) or None),
        ]))
        ttps = profile.get("ttps", [])
        if ttps:
            story.append(Spacer(1, 0.1 * cm))
            story.append(Paragraph("<b>Known TTPs</b>", _s("SubSection")))
            for ttp in ttps[:10]:
                story.append(Paragraph(f"• {ttp}", _s("Bullet")))
        tools = profile.get("tools", [])
        if tools:
            story.append(Spacer(1, 0.1 * cm))
            story.append(Paragraph("<b>Known Tools</b>", _s("SubSection")))
            story.append(Paragraph(", ".join(tools[:15]), _s("Body")))


def _add_analyst_notes(story: list, data: dict) -> None:
    story += _section("5.  ANALYST NOTES")
    notes: list[dict] = list(data.get("notes") or [])

    if not notes:
        story.append(Paragraph("No analyst notes recorded for this incident.", _s("Body")))
        return

    for note in notes:
        author  = note.get("author", "Analyst")
        ts      = _safe_ts(note.get("timestamp", ""))
        content = str(note.get("content", ""))
        story.append(Paragraph(
            f"<b>{author}</b>  "
            f"<font color='#6B7280' size='8'>({ts} UTC)</font>",
            _s("SubSection"),
        ))
        story.append(Paragraph(content, _s("Body")))
        story.append(_hr())


def _add_case_status(story: list, data: dict) -> None:
    story += _section("6.  CASE STATUS")
    case: dict = data.get("case") or {}

    if not case:
        story.append(Paragraph("No case record is linked to this incident.", _s("Body")))
        return

    resolved_display = (
        _safe_ts(case.get("resolved_at", "")) + " UTC"
        if case.get("resolved_at") else None
    )
    story.append(_kv_table([
        ("Case Number",      case.get("case_number")),
        ("Status",           case.get("status")),
        ("Priority",         case.get("priority")),
        ("Assigned Analyst", case.get("assigned_analyst") or "Unassigned"),
        ("Created",          _safe_ts(case.get("created_at", "")) + " UTC"),
        ("Last Updated",     _safe_ts(case.get("updated_at", "")) + " UTC"),
        ("Resolved",         resolved_display),
    ]))

    history: list = case.get("history") or []
    if history:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>Case History</b>", _s("SubSection")))
        rows = [
            [
                _safe_ts(h.get("timestamp", "")),
                (h.get("action", "") or "").replace("_", " "),
                str(h.get("content", ""))[:80],
                str(h.get("user", ""))[:22],
            ]
            for h in history[-10:]
        ]
        story.append(_data_table(
            ["Timestamp", "Action", "Details", "User"],
            rows,
            [3.8 * cm, 3.2 * cm, 7.0 * cm, 3.3 * cm],
        ))


def _add_evidence_summary(story: list, data: dict) -> None:
    story += _section("7.  EVIDENCE SUMMARY")
    indicators: list = list(data.get("indicators") or [])

    if not indicators:
        story.append(Paragraph("No indicators of compromise (IOCs) have been recorded.", _s("Body")))
        return

    parsed: list[tuple[str, str]] = []
    for ioc in indicators:
        raw = str(ioc)
        if ":" in raw:
            ioc_type, ioc_val = raw.split(":", 1)
            parsed.append((ioc_type.upper().strip(), ioc_val.strip()))
        else:
            parsed.append(("INDICATOR", raw.strip()))

    rows = [[t, v] for t, v in parsed]
    story.append(_data_table(
        ["IOC Type", "Value / Hash / Domain"],
        rows,
        [3.2 * cm, _BODY_W - 3.2 * cm],
    ))


def _add_recommendations(story: list, data: dict) -> None:
    story += _section("8.  RECOMMENDATIONS")
    threat_name   = data.get("threat_name", "")
    attack_techs  = list(data.get("attack_techniques") or [])
    recs          = get_recommendations(str(threat_name), attack_techs)

    story.append(Paragraph(
        "The following recommendations are based on the identified threat category and MITRE "
        "ATT&CK technique mappings. Prioritise actions in accordance with your current "
        "containment status and organisational risk tolerance.",
        _s("Body"),
    ))
    story.append(Spacer(1, 0.15 * cm))
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"{i}.  {rec}", _s("Bullet")))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def build_incident_report(data: dict) -> bytes:
    """Build a professional SOC PDF incident report.

    Args:
        data: Report data dict. All keys are optional — the builder degrades
              gracefully when individual sections have no data.

    Returns:
        Raw PDF bytes (starts with ``%PDF-``).
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=_MARGIN,
        leftMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=_MARGIN + 0.4 * cm,
        title=f"Mythos SOC Report — {data.get('incident_id', 'Unknown')}",
        author="Mythos SIEM Platform",
        subject=f"Incident Report — {data.get('threat_name', '')}",
    )

    story: list = []
    _add_cover(story, data)
    story.append(PageBreak())
    _add_incident_summary(story, data)
    _add_timeline(story, data)
    _add_attack_mapping(story, data)
    _add_attribution(story, data)
    _add_analyst_notes(story, data)
    _add_case_status(story, data)
    _add_evidence_summary(story, data)
    _add_recommendations(story, data)

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Data assembly helper
# ---------------------------------------------------------------------------


def assemble_report_data(
    incident_id: str,
    *,
    incident_record: dict | None = None,
    case_record: dict | None = None,
    assignment_record: dict | None = None,
    generated_by: str = "SOC Analyst",
    classification: str = "CONFIDENTIAL",
) -> dict:
    """Assemble a report data dict from individual source records.

    Args:
        incident_id:       The incident ID (e.g. ``INC-2026-001``).
        incident_record:   Row from attribution_log.jsonl or sample_incidents.json.
        case_record:       Case dict from case_store.
        assignment_record: Assignment dict from workbench_store.
        generated_by:      Analyst name for the cover page.
        classification:    Classification label (CONFIDENTIAL / RESTRICTED / etc.).

    Returns:
        Flat dict consumed by :func:`build_incident_report`.
    """
    inc  = incident_record or {}
    case = case_record     or {}
    asgn = assignment_record or {}

    # ---- notes ----
    notes: list[dict] = []
    for n in case.get("notes", []):
        notes.append(n)
    for n in asgn.get("notes", []):
        if n not in notes:
            notes.append(n)

    # ---- timeline ----
    timeline: list[dict] = []
    created_at = (
        inc.get("created_at")
        or asgn.get("assigned_at")
        or case.get("created_at")
        or ""
    )
    if created_at:
        timeline.append({"timestamp": created_at, "event": f"Incident {incident_id} detected", "actor": "System"})
    for h in case.get("history", []):
        timeline.append({
            "timestamp": h.get("timestamp", ""),
            "event":     h.get("content", h.get("action", "")),
            "actor":     h.get("user", "System"),
        })
    if asgn.get("assigned_at"):
        timeline.append({
            "timestamp": asgn["assigned_at"],
            "event":     f"Assigned to {asgn.get('analyst', 'Analyst')}",
            "actor":     asgn.get("assigned_by", "SOC Lead"),
        })
    timeline.sort(key=lambda x: x.get("timestamp") or "")

    # ---- indicators — normalise from list or NaN ----
    raw_indicators = inc.get("indicators")
    if not isinstance(raw_indicators, list):
        raw_indicators = []

    # ---- attack_techniques — normalise ----
    raw_techniques = inc.get("attack_techniques")
    if not isinstance(raw_techniques, list):
        raw_techniques = []

    # ---- threat actor profile ----
    threat_actor_profile: dict = {}
    try:
        if _PROFILES_PATH.exists():
            profiles = json.loads(_PROFILES_PATH.read_text(encoding="utf-8"))
            actor    = inc.get("suspected_actor", "")
            if actor:
                threat_actor_profile = profiles.get(actor, {})
    except Exception:
        pass

    confidence_score = inc.get("confidence_score", 0) or 0
    risk_score       = inc.get("risk_score", 0)       or 0
    attr_conf        = inc.get("attribution_confidence", 0) or 0

    return {
        "incident_id":           incident_id,
        "threat_name":           inc.get("threat_name", asgn.get("title", "Unknown Threat")),
        "severity":              inc.get("severity", asgn.get("severity", "UNKNOWN")),
        "status":                inc.get("status", asgn.get("status", "UNKNOWN")),
        "campaign_id":           inc.get("campaign_id", asgn.get("campaign_id", "")),
        "created_at":            created_at,
        "confidence_score":      float(confidence_score),
        "risk_score":            float(risk_score),
        "attribution_confidence":float(attr_conf),
        "suspected_actor":       inc.get("suspected_actor", "UNATTRIBUTED"),
        "indicators":            raw_indicators,
        "attack_techniques":     raw_techniques,
        "threat_actor_profile":  threat_actor_profile,
        "description":           case.get("description", inc.get("threat_summary", "")),
        "notes":                 notes,
        "case":                  case,
        "timeline":              timeline,
        "generated_at":          datetime.now(timezone.utc).isoformat(),
        "generated_by":          generated_by,
        "classification":        classification,
    }
