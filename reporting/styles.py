"""reporting/styles.py — ReportLab paragraph styles and colour palette for Mythos SOC reports."""

from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

# ---------------------------------------------------------------------------
# Brand colour palette
# ---------------------------------------------------------------------------

NAVY  = colors.HexColor("#1B2A4A")
RED   = colors.HexColor("#CC3333")
GRAY  = colors.HexColor("#6B7280")
LGRAY = colors.HexColor("#F3F4F6")
DGRAY = colors.HexColor("#374151")
WHITE = colors.white
BLACK = colors.black

SEV_COLORS: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#CC3333"),
    "HIGH":     colors.HexColor("#D97706"),
    "MEDIUM":   colors.HexColor("#92400E"),
    "LOW":      colors.HexColor("#065F46"),
}

# ---------------------------------------------------------------------------
# Paragraph styles
# ---------------------------------------------------------------------------

_base = getSampleStyleSheet()

STYLES: dict[str, ParagraphStyle] = {
    "CoverTitle": ParagraphStyle(
        "CoverTitle",
        parent=_base["Normal"],
        fontSize=20,
        textColor=WHITE,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=6,
        leading=26,
    ),
    "CoverSub": ParagraphStyle(
        "CoverSub",
        parent=_base["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#CBD5E1"),
        fontName="Helvetica",
        alignment=TA_CENTER,
        spaceAfter=3,
    ),
    "Section": ParagraphStyle(
        "Section",
        parent=_base["Normal"],
        fontSize=11,
        textColor=WHITE,
        backColor=NAVY,
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=4,
        leftIndent=4,
        leading=18,
    ),
    "SubSection": ParagraphStyle(
        "SubSection",
        parent=_base["Normal"],
        fontSize=9,
        textColor=NAVY,
        fontName="Helvetica-Bold",
        spaceBefore=6,
        spaceAfter=2,
    ),
    "Body": ParagraphStyle(
        "Body",
        parent=_base["Normal"],
        fontSize=9,
        textColor=BLACK,
        fontName="Helvetica",
        spaceAfter=3,
        leading=13,
    ),
    "Bullet": ParagraphStyle(
        "Bullet",
        parent=_base["Normal"],
        fontSize=9,
        textColor=BLACK,
        fontName="Helvetica",
        leftIndent=14,
        bulletIndent=4,
        spaceAfter=3,
        leading=13,
    ),
    "Small": ParagraphStyle(
        "Small",
        parent=_base["Normal"],
        fontSize=8,
        textColor=GRAY,
        fontName="Helvetica",
        spaceAfter=2,
        leading=11,
    ),
    "Classification": ParagraphStyle(
        "Classification",
        parent=_base["Normal"],
        fontSize=10,
        textColor=RED,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    ),
    "Label": ParagraphStyle(
        "Label",
        parent=_base["Normal"],
        fontSize=8,
        textColor=DGRAY,
        fontName="Helvetica-Bold",
        spaceAfter=1,
    ),
    "TableHeader": ParagraphStyle(
        "TableHeader",
        parent=_base["Normal"],
        fontSize=8,
        textColor=WHITE,
        fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    ),
}
