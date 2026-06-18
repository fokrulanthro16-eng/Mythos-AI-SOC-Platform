"""reporting/executive_report_builder.py — Mythos SOC Executive PDF Report Builder.

Generates a board-level, multi-section PDF covering:
  1. Cover page + Executive Summary KPIs
  2. Incident Summary (severity distribution, top incidents, resolution stats)
  3. MITRE ATT&CK Coverage (most-used techniques, tactic breakdown)
  4. Threat Intelligence (actor attribution, campaign activity, risk summary)

Entry point
-----------
build_executive_report(data: dict) -> bytes
assemble_executive_data(date_from, date_to, severities) -> dict
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
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
_MARGIN  = 2.0 * cm
_BODY_W  = _PAGE_W - 2 * _MARGIN

_EXPORTS_DIR = Path(__file__).resolve().parent.parent / "exports"

# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------


def assemble_executive_data(
    date_from: str | None = None,
    date_to: str | None = None,
    severities: list[str] | None = None,
) -> dict:
    """Pull all executive data from the store and intelligence engine.

    Returns a flat dict consumed by :func:`build_executive_report`.
    """
    from dashboard.executive_store import (
        get_campaign_activity_filtered,
        get_executive_kpis_filtered,
        get_mitre_coverage_filtered,
        get_severity_distribution_filtered,
        get_threat_actor_breakdown_filtered,
        get_threat_category_breakdown_filtered,
    )
    from intelligence.threat_actor_engine import actor_statistics

    kpis       = get_executive_kpis_filtered(date_from, date_to, severities)
    sev_dist   = get_severity_distribution_filtered(date_from, date_to, severities)
    campaigns  = get_campaign_activity_filtered(10, date_from, date_to, severities)
    actor_bkdn = get_threat_actor_breakdown_filtered(date_from, date_to, severities)
    cat_bkdn   = get_threat_category_breakdown_filtered(date_from, date_to, severities)
    mitre_cov  = get_mitre_coverage_filtered(date_from, date_to, severities)
    intel_stats = actor_statistics()

    return {
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date_from":    date_from or "All time",
        "date_to":      date_to   or "Present",
        "severities":   severities or ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "kpis":         kpis,
        "sev_dist":     sev_dist,
        "campaigns":    campaigns,
        "actor_breakdown": actor_bkdn,
        "category_breakdown": cat_bkdn,
        "mitre_coverage": mitre_cov,
        "intel_stats":  intel_stats,
    }


# ---------------------------------------------------------------------------
# PDF construction helpers
# ---------------------------------------------------------------------------


def _hr() -> HRFlowable:
    return HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6, spaceBefore=2)


def _section_header(title: str) -> list:
    return [
        Spacer(1, 0.3 * cm),
        Paragraph(f"  {title}", STYLES["Section"]),
        Spacer(1, 0.2 * cm),
    ]


def _kpi_table(kpis: dict) -> list:
    _K = STYLES["Label"]
    _V_style = __import__("reportlab.lib.styles", fromlist=["ParagraphStyle"]).ParagraphStyle

    from reportlab.lib.styles import ParagraphStyle as PS
    from reportlab.lib.enums import TA_CENTER

    val_style = PS(
        "KpiVal",
        parent=STYLES["Body"],
        fontSize=18,
        fontName="Helvetica-Bold",
        textColor=NAVY,
        alignment=TA_CENTER,
        leading=22,
    )
    lbl_style = PS(
        "KpiLbl",
        parent=STYLES["Small"],
        alignment=TA_CENTER,
        fontSize=7,
    )

    def _cell(label: str, value: Any, highlight: bool = False) -> Table:
        t = Table(
            [[Paragraph(str(value), val_style)], [Paragraph(label, lbl_style)]],
            colWidths=[(_BODY_W - 1.2 * cm) / 4],
        )
        bg = colors.HexColor("#EEF2FF") if highlight else LGRAY
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX",        (0, 0), (-1, -1), 0.5, NAVY),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]))
        return t

    def _fmt_minutes(minutes: float) -> str:
        if not minutes or minutes < 0:
            return "N/A"
        hours = minutes / 60
        if hours < 1:
            return f"{int(minutes)}m"
        return f"{hours:.1f}h"

    row1 = [
        _cell("Total Incidents",   kpis.get("total_incidents", "—"), highlight=True),
        _cell("Critical",          kpis.get("critical_incidents", "—"), highlight=True),
        _cell("Open Cases",        kpis.get("open_cases", "—")),
        _cell("Active Campaigns",  kpis.get("active_campaigns", "—")),
    ]
    row2 = [
        _cell("MTTD",              _fmt_minutes(kpis.get("mttd_minutes", 0))),
        _cell("MTTR",              _fmt_minutes(kpis.get("mttr_minutes", 0))),
        _cell("Analyst Util.",     f"{kpis.get('analyst_utilization', 0)*100:.0f}%"),
        _cell("Avg Attribution",   f"{kpis.get('avg_attribution_confidence', 0)*100:.0f}%"),
    ]

    col_w = (_BODY_W - 0.9 * cm) / 4

    out = []
    for row in [row1, row2]:
        t = Table([row], colWidths=[col_w] * 4, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))
        out.append(t)
    return out


def _sev_table(sev_dist: dict) -> Table:
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    total = sum(sev_dist.values()) or 1

    rows = [[
        Paragraph("Severity",  STYLES["TableHeader"]),
        Paragraph("Count",     STYLES["TableHeader"]),
        Paragraph("% of Total", STYLES["TableHeader"]),
    ]]
    for sev in sev_order:
        count = sev_dist.get(sev, 0)
        pct   = count / total * 100
        rows.append([
            Paragraph(sev, STYLES["Body"]),
            Paragraph(str(count), STYLES["Body"]),
            Paragraph(f"{pct:.1f}%", STYLES["Body"]),
        ])

    col_w = _BODY_W / 3
    t = Table(rows, colWidths=[col_w * 1.5, col_w * 0.75, col_w * 0.75])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRAY, WHITE]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]
    for i, sev in enumerate(sev_order, start=1):
        clr = SEV_COLORS.get(sev, GRAY)
        style.append(("TEXTCOLOR", (0, i), (0, i), clr))
        style.append(("FONTNAME",  (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _campaign_table(campaigns: list[dict]) -> Table:
    rows = [[
        Paragraph(h, STYLES["TableHeader"])
        for h in ["Campaign", "Threat Actor", "Status", "Incidents", "Risk Score"]
    ]]
    for c in campaigns[:10]:
        risk = c.get("risk_score", c.get("avg_risk", 0))
        rows.append([
            Paragraph(str(c.get("name", c.get("campaign_id", "—")))[:40], STYLES["Body"]),
            Paragraph(str(c.get("threat_actor", "—")), STYLES["Body"]),
            Paragraph(str(c.get("status", "—")), STYLES["Body"]),
            Paragraph(str(c.get("incident_count", c.get("count", "—"))), STYLES["Body"]),
            Paragraph(f"{float(risk)*100:.0f}%" if risk else "—", STYLES["Body"]),
        ])

    widths = [_BODY_W * w for w in [0.34, 0.22, 0.14, 0.14, 0.16]]
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRAY, WHITE]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    return t


def _mitre_table(mitre_coverage: list[dict]) -> Table:
    """Build MITRE tactic coverage table.

    Each entry in *mitre_coverage* is expected in the executive_store format:
    ``{"tactic": "<human label>", "tactic_id": "<slug>", "techniques": <int count>}``
    """
    rows = [[
        Paragraph(h, STYLES["TableHeader"])
        for h in ["Tactic", "Tactic ID", "Techniques Observed"]
    ]]
    _TACTIC_ORDER = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "exfiltration", "command-and-control", "impact",
    ]
    ordered = sorted(
        mitre_coverage,
        key=lambda x: (
            _TACTIC_ORDER.index(x.get("tactic_id", ""))
            if x.get("tactic_id") in _TACTIC_ORDER else 99
        ),
    )
    for entry in ordered:
        # techniques may be an int (count) or a list — handle both
        techs_raw = entry.get("techniques", 0)
        if isinstance(techs_raw, list):
            count = len(techs_raw)
        else:
            count = int(techs_raw)
        rows.append([
            Paragraph(str(entry.get("tactic", "—")), STYLES["Body"]),
            Paragraph(str(entry.get("tactic_id", "—")), STYLES["Body"]),
            Paragraph(str(count) if count else "—", STYLES["Body"]),
        ])

    widths = [_BODY_W * w for w in [0.35, 0.35, 0.30]]
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRAY, WHITE]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("FONTNAME",  (2, 1), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (2, 1), (2, -1), NAVY),
    ]))
    return t


def _actor_table(actor_breakdown: dict) -> Table:
    rows = [[
        Paragraph(h, STYLES["TableHeader"])
        for h in ["Threat Actor", "Attributed Incidents", "% Share"]
    ]]
    total = sum(actor_breakdown.values()) or 1
    sorted_actors = sorted(actor_breakdown.items(), key=lambda x: x[1], reverse=True)
    for actor, count in sorted_actors[:10]:
        pct = count / total * 100
        rows.append([
            Paragraph(str(actor), STYLES["Body"]),
            Paragraph(str(count), STYLES["Body"]),
            Paragraph(f"{pct:.1f}%", STYLES["Body"]),
        ])

    widths = [_BODY_W * w for w in [0.50, 0.25, 0.25]]
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRAY, WHITE]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    return t


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


def build_executive_report(data: dict) -> bytes:
    """Build the executive PDF from a pre-assembled *data* dict.

    Returns raw PDF bytes suitable for streaming or file write.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=_MARGIN,
        title="Mythos SOC — Executive Intelligence Report",
        author="Mythos AI SOC Platform",
    )

    story: list = []
    gen_at = data.get("generated_at", "")
    period = f"{data.get('date_from','All time')} — {data.get('date_to','Present')}"

    # -----------------------------------------------------------------------
    # COVER PAGE
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 2.0 * cm))

    cover_box = Table(
        [
            [Paragraph("MYTHOS AI SOC PLATFORM", STYLES["CoverTitle"])],
            [Paragraph("Executive Intelligence Report", STYLES["CoverSub"])],
            [Paragraph(f"Analysis Period: {period}", STYLES["CoverSub"])],
            [Paragraph(f"Generated: {gen_at[:10]} UTC", STYLES["CoverSub"])],
        ],
        colWidths=[_BODY_W],
    )
    cover_box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("BOX",           (0, 0), (-1, -1), 2, RED),
    ]))
    story.append(cover_box)
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("CONFIDENTIAL — FOR AUTHORISED RECIPIENTS ONLY", STYLES["Classification"]))
    story.append(Spacer(1, 1.0 * cm))

    # -----------------------------------------------------------------------
    # SECTION 1 — EXECUTIVE KPIs
    # -----------------------------------------------------------------------
    story += _section_header("1. Executive Summary")
    story.append(Paragraph(
        "This report provides a consolidated view of the organisation's threat landscape, "
        "SOC operational performance, and MITRE ATT&amp;CK coverage over the selected analysis period. "
        "All metrics are derived from the Mythos AI SOC Platform incident management and intelligence pipeline.",
        STYLES["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Key Performance Indicators", STYLES["SubSection"]))
    story += _kpi_table(data.get("kpis", {}))
    story.append(Spacer(1, 0.4 * cm))
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # SECTION 2 — INCIDENT SUMMARY
    # -----------------------------------------------------------------------
    story += _section_header("2. Incident Summary")

    sev_dist = data.get("sev_dist", {})
    if sev_dist:
        story.append(Paragraph("Severity Distribution", STYLES["SubSection"]))
        story.append(_sev_table(sev_dist))
        story.append(Spacer(1, 0.4 * cm))

    cat_bkdn = data.get("category_breakdown", {})
    if cat_bkdn:
        story.append(Paragraph("Threat Category Breakdown", STYLES["SubSection"]))
        cat_rows = [[
            Paragraph(h, STYLES["TableHeader"]) for h in ["Category", "Incidents"]
        ]] + [
            [Paragraph(str(k), STYLES["Body"]), Paragraph(str(v), STYLES["Body"])]
            for k, v in sorted(cat_bkdn.items(), key=lambda x: x[1], reverse=True)[:8]
        ]
        cat_t = Table(cat_rows, colWidths=[_BODY_W * 0.70, _BODY_W * 0.30])
        cat_t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), NAVY),
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRAY, WHITE]),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(cat_t)
        story.append(Spacer(1, 0.4 * cm))

    # Top campaigns
    campaigns = data.get("campaigns", [])
    if campaigns:
        story.append(Paragraph("Active Campaign Summary", STYLES["SubSection"]))
        story.append(_campaign_table(campaigns))
        story.append(Spacer(1, 0.4 * cm))

    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # SECTION 3 — MITRE ATT&CK COVERAGE
    # -----------------------------------------------------------------------
    story += _section_header("3. MITRE ATT&CK Coverage")
    story.append(Paragraph(
        "The following table shows ATT&amp;CK tactics and associated techniques observed across "
        "incidents in the analysis period. Coverage identifies which parts of the kill chain "
        "are actively being exploited against the organisation.",
        STYLES["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    mitre_cov = data.get("mitre_coverage", [])
    if mitre_cov:
        story.append(_mitre_table(mitre_cov))
    else:
        story.append(Paragraph("No MITRE coverage data for the selected period.", STYLES["Small"]))

    story.append(Spacer(1, 0.4 * cm))
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # SECTION 4 — THREAT INTELLIGENCE
    # -----------------------------------------------------------------------
    story += _section_header("4. Threat Intelligence Summary")
    story.append(Paragraph(
        "Attribution data from the Mythos threat actor intelligence engine. "
        "Actor confidence ratings reflect corroborated indicators, TTPs, and campaign overlap.",
        STYLES["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    actor_bkdn = data.get("actor_breakdown", {})
    if actor_bkdn:
        story.append(Paragraph("Incident Attribution by Threat Actor", STYLES["SubSection"]))
        story.append(_actor_table(actor_bkdn))
        story.append(Spacer(1, 0.4 * cm))

    intel_stats = data.get("intel_stats", {})
    if intel_stats:
        story.append(Paragraph("Intelligence Database Summary", STYLES["SubSection"]))
        intel_rows = [
            ["Tracked Threat Actors",   str(intel_stats.get("total_actors", "—"))],
            ["Nations Represented",      str(intel_stats.get("countries_represented", "—"))],
            ["Tracked Campaigns",        str(intel_stats.get("total_campaigns", "—"))],
            ["Unique MITRE Techniques",  str(intel_stats.get("unique_techniques", "—"))],
            ["High-Confidence Actors",   str(intel_stats.get("high_confidence_actors", "—"))],
            ["Avg Attribution Conf.",    f"{intel_stats.get('avg_attribution_conf', 0)*100:.1f}%"],
        ]
        for i, row in enumerate(intel_rows):
            intel_rows[i] = [
                Paragraph(row[0], STYLES["Label"]),
                Paragraph(row[1], STYLES["Body"]),
            ]
        intel_t = Table(intel_rows, colWidths=[_BODY_W * 0.60, _BODY_W * 0.40])
        intel_t.setStyle(TableStyle([
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LGRAY, WHITE]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(intel_t)

    story.append(Spacer(1, 1.0 * cm))
    story.append(_hr())
    story.append(Paragraph(
        f"Mythos AI SOC Platform — Executive Intelligence Report — {gen_at[:10]} — CONFIDENTIAL",
        STYLES["Small"],
    ))

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Convenience: save to exports/ directory
# ---------------------------------------------------------------------------


def save_executive_report(pdf_bytes: bytes, filename: str | None = None) -> Path:
    """Write *pdf_bytes* to exports/ and return the path."""
    _EXPORTS_DIR.mkdir(exist_ok=True)
    if not filename:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"executive_report_{ts}.pdf"
    out = _EXPORTS_DIR / filename
    out.write_bytes(pdf_bytes)
    return out
