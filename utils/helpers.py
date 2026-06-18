"""
utils/helpers.py — Risk scoring engine, attribution confidence engine,
                   and shared utility functions.
"""

from __future__ import annotations

from core.state import ThreatSeverity

# ---------------------------------------------------------------------------
# Risk scoring engine
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[ThreatSeverity, float] = {
    ThreatSeverity.LOW:      0.25,
    ThreatSeverity.MEDIUM:   0.50,
    ThreatSeverity.HIGH:     0.75,
    ThreatSeverity.CRITICAL: 1.00,
}


def compute_risk_score(confidence_score: float, severity: ThreatSeverity) -> float:
    """
    Weighted blend: 70% confidence evidence + 30% severity impact.
    Returns a normalised score in [0.0, 1.0].

    Examples:
        CRITICAL + 0.87 confidence -> 0.9090
        HIGH     + 0.62 confidence -> 0.6590
        MEDIUM   + 0.55 confidence -> 0.5350
        LOW      + 0.40 confidence -> 0.3550
    """
    weight = _SEVERITY_WEIGHTS[severity]
    return round(min((confidence_score * 0.7) + (weight * 0.3), 1.0), 4)


# ---------------------------------------------------------------------------
# Attribution confidence engine (Phase 3)
# ---------------------------------------------------------------------------


def compute_attribution_confidence(
    base_confidence: float,
    ioc_match_count: int,
    total_ioc_patterns: int,
    tactic_overlap: float,
) -> float:
    """
    Three-factor attribution confidence blend:
        40%  base detection / forensic confidence
        35%  IOC match ratio against known actor profile
        25%  tactic/technique overlap with known actor profile

    Returns a value in [0.0, 1.0].

    Examples:
        TA505  base=0.87, ioc_matches=2/4, tactic_overlap=1.0 -> ~0.773
        LOCKBIT base=0.91, ioc_matches=2/3, tactic_overlap=1.0 -> ~0.823
        UNKNWN base=0.45, ioc_matches=0/1, tactic_overlap=0.0  -> ~0.180
    """
    ioc_ratio = min(ioc_match_count / max(total_ioc_patterns, 1), 1.0)
    score = (base_confidence * 0.40) + (ioc_ratio * 0.35) + (tactic_overlap * 0.25)
    return round(min(score, 1.0), 4)


# ---------------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------------


def risk_label(risk_score: float) -> str:
    if risk_score >= 0.80:
        return "CRITICAL"
    if risk_score >= 0.60:
        return "HIGH"
    if risk_score >= 0.40:
        return "MEDIUM"
    return "LOW"


def attribution_label(attribution_confidence: float) -> str:
    if attribution_confidence >= 0.75:
        return "HIGH-CONFIDENCE"
    if attribution_confidence >= 0.50:
        return "MEDIUM-CONFIDENCE"
    if attribution_confidence >= 0.25:
        return "LOW-CONFIDENCE"
    return "UNCONFIRMED"


# ---------------------------------------------------------------------------
# Summary formatter
# ---------------------------------------------------------------------------


def format_summary(state: object) -> str:
    s = state  # type: ignore[assignment]
    return (
        f"  [{s.incident_id}]"
        f"  threat={s.threat_name or 'UNKNOWN':<30}"
        f"  sev={s.severity.value:<8}"
        f"  conf={s.confidence_score:.0%}"
        f"  risk={s.risk_score:.4f}({risk_label(s.risk_score):<8})"
        f"  actor={s.suspected_actor or 'UNKNOWN':<22}"
        f"  attr={s.attribution_confidence:.4f}({attribution_label(s.attribution_confidence):<16})"
        f"  camp={s.campaign_id or 'NONE'}"
    )
