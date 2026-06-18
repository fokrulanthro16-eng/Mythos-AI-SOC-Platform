"""assets/generate_placeholders.py — Generate placeholder screenshot images.

Run this script to create styled placeholder PNGs in assets/screenshots/.
Replace them with real screenshots taken from the live dashboard.

Usage:
    python assets/generate_placeholders.py
"""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

_OUT = Path(__file__).parent / "screenshots"
_OUT.mkdir(exist_ok=True)

_WIDTH  = 1280
_HEIGHT = 720

_BG_COLOR      = (15, 17, 26)        # dark navy
_ACCENT_COLOR  = (255, 75, 75)       # mythos red
_LABEL_COLOR   = (180, 190, 210)     # muted slate
_TITLE_COLOR   = (230, 235, 245)     # near-white
_BORDER_COLOR  = (40, 50, 70)        # subtle border

_SCREENSHOTS = [
    (
        "01_dashboard_overview.png",
        "Incident Overview",
        "KPI row · severity distribution · risk histogram · confidence scatter · incident table",
    ),
    (
        "02_incident_intake.png",
        "Incident Intake",
        "Structured submission form · field validation · campaign link · agent pipeline trigger",
    ),
    (
        "03_case_management.png",
        "Case Management",
        "Full CRUD · OPEN→CLOSED status flow · priority badges · note history · PDF export",
    ),
    (
        "04_mitre_attack.png",
        "MITRE ATT&CK Browser",
        "Tactic selector · technique search · full detail panel · mitigations · sub-techniques",
    ),
    (
        "05_analyst_workbench.png",
        "Analyst Workbench",
        "6-tab action panel · workload distribution · analyst activity feed · PDF export",
    ),
    (
        "06_agent_collaboration.png",
        "Agent Collaboration",
        "Per-agent run inspection · confidence contribution timeline · pipeline duration",
    ),
    (
        "07_executive_reports.png",
        "Executive Reports",
        "Board-level PDF generator · 8 KPIs · MITRE coverage · threat attribution · download",
    ),
    (
        "08_threat_actor_intelligence.png",
        "Threat Actor Intelligence Center",
        "Actor profiles · risk gauges · campaign Gantt · techniques matrix · radar comparison",
    ),
]


def _draw_placeholder(filename: str, title: str, subtitle: str) -> None:
    img  = Image.new("RGB", (_WIDTH, _HEIGHT), _BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Border frame
    draw.rectangle([0, 0, _WIDTH - 1, _HEIGHT - 1], outline=_BORDER_COLOR, width=2)

    # Top accent bar
    draw.rectangle([0, 0, _WIDTH, 6], fill=_ACCENT_COLOR)

    # Header band
    draw.rectangle([0, 6, _WIDTH, 64], fill=(20, 24, 38))

    # Mythos label in header
    try:
        font_header = ImageFont.truetype("arial.ttf", 16)
        font_title  = ImageFont.truetype("arialbd.ttf", 42)
        font_sub    = ImageFont.truetype("arial.ttf", 20)
        font_note   = ImageFont.truetype("arial.ttf", 14)
    except (OSError, IOError):
        font_header = ImageFont.load_default()
        font_title  = font_header
        font_sub    = font_header
        font_note   = font_header

    draw.text((20, 20), "MYTHOS  AI SOC PLATFORM", font=font_header, fill=_LABEL_COLOR)

    # Centre the page title
    bbox = draw.textbbox((0, 0), title, font=font_title)
    tw   = bbox[2] - bbox[0]
    draw.text(((_WIDTH - tw) // 2, 200), title, font=font_title, fill=_TITLE_COLOR)

    # Red underline
    line_y = 260
    draw.rectangle([(_WIDTH - tw) // 2, line_y, (_WIDTH + tw) // 2, line_y + 3], fill=_ACCENT_COLOR)

    # Subtitle
    bbox2 = draw.textbbox((0, 0), subtitle, font=font_sub)
    sw    = bbox2[2] - bbox2[0]
    draw.text(((_WIDTH - sw) // 2, 290), subtitle, font=font_sub, fill=_LABEL_COLOR)

    # Placeholder note
    note = "[ Replace with actual dashboard screenshot ]"
    bbox3 = draw.textbbox((0, 0), note, font=font_note)
    nw    = bbox3[2] - bbox3[0]
    draw.text(((_WIDTH - nw) // 2, _HEIGHT - 80), note, font=font_note, fill=(80, 90, 110))

    # Corner filename label
    draw.text((20, _HEIGHT - 30), filename, font=font_note, fill=(60, 70, 90))

    img.save(_OUT / filename, "PNG", optimize=True)
    print(f"  wrote  screenshots/{filename}")


def _write_minimal_png(filename: str, title: str) -> None:
    """Fallback: write a tiny valid placeholder PNG via raw bytes."""
    import base64, struct, zlib

    def _chunk(name: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + name + data
        return c + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)

    w, h = 16, 16
    raw  = b""
    for _ in range(h):
        raw += b"\x00" + bytes([10, 12, 20] * w)  # dark pixel row

    compressed = zlib.compress(raw)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    png  = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", compressed)
        + _chunk(b"IEND", b"")
    )
    (_OUT / filename).write_bytes(png)
    print(f"  wrote  screenshots/{filename}  (minimal fallback — install Pillow for styled placeholders)")


def main() -> None:
    print(f"Generating {len(_SCREENSHOTS)} placeholder screenshots -> {_OUT}\n")
    for filename, title, subtitle in _SCREENSHOTS:
        if _HAS_PIL:
            _draw_placeholder(filename, title, subtitle)
        else:
            _write_minimal_png(filename, title)

    print(f"\nDone. Replace with real screenshots from: streamlit run dashboard/app.py")
    if not _HAS_PIL:
        print("Tip: pip install Pillow  — for styled placeholder images")


if __name__ == "__main__":
    main()
