"""tests/test_dashboard_charts.py — Unit tests for dashboard/components/charts.py"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import pytest

from dashboard.components.charts import (
    _empty,
    actor_frequency_chart,
    attribution_confidence_chart,
    campaign_frequency_chart,
    confidence_scatter_chart,
    ioc_type_distribution,
    risk_score_histogram,
    severity_distribution_chart,
    status_progression_chart,
    timeline_scatter_chart,
    transition_heatmap,
)

# ---------------------------------------------------------------------------
# Sample data fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_df() -> pd.DataFrame:
    import numpy as np
    from datetime import datetime, timezone
    rows = [
        {
            "incident_id": f"INC-{i:03d}",
            "status": status,
            "threat_name": threat,
            "severity": sev,
            "confidence_score": conf,
            "risk_score": risk,
            "attribution_confidence": attr,
            "campaign_id": camp,
            "suspected_actor": actor,
            "updated_at": datetime(2026, 6, 17, i, 0, tzinfo=timezone.utc),
        }
        for i, (status, threat, sev, conf, risk, attr, camp, actor) in enumerate([
            ("MITIGATED", "APT-SHADOW-VIPER",         "CRITICAL", 0.87, 0.909, 0.673, "CAMP-TA50-2026-F1DF6A", "TA505"),
            ("MITIGATED", "RANSOMWARE-LOCKBIT3",      "HIGH",     0.91, 0.862, 0.795, "CAMP-LOCK-2026-5939CB", "LOCKBIT"),
            ("MITIGATED", "PHISH-CREDENTIAL-HARVEST", "MEDIUM",   0.68, 0.626, 0.645, "CAMP-FIN7-2026-DC5862", "FIN7"),
            ("MITIGATED", "ADWARE-BUNDLER",           "LOW",      0.45, 0.355, 0.160, "CAMP-UNKN-2026-6EA434", "UNKNOWN-CRIMINAL-RING"),
            ("ANALYZED",  "APT-SHADOW-VIPER",         "CRITICAL", 0.62, 0.734, 0.0,   "",                      ""),
            ("DETECTED",  "RANSOMWARE-LOCKBIT3",      "HIGH",     0.0,  0.0,   0.0,   "",                      ""),
        ])
    ]
    return pd.DataFrame(rows)


@pytest.fixture
def ioc_df() -> pd.DataFrame:
    return pd.DataFrame({
        "incident_id": ["INC-001", "INC-001", "INC-002"],
        "ioc":         ["C2:185.220.101.47", "hash:abc", "mutex:LockBit"],
        "ioc_type":    ["C2_INFRASTRUCTURE", "MALWARE_HASH", "MALWARE_ARTIFACT"],
        "confidence":  [0.88, 0.95, 0.85],
    })


# ---------------------------------------------------------------------------
# _empty helper
# ---------------------------------------------------------------------------


def test_empty_returns_figure():
    fig = _empty("test")
    assert isinstance(fig, go.Figure)


def test_empty_uses_dark_template():
    fig = _empty()
    assert fig.layout.template.layout is not None or fig.layout.template is not None


# ---------------------------------------------------------------------------
# severity_distribution_chart
# ---------------------------------------------------------------------------


def test_severity_chart_returns_figure(sample_df):
    assert isinstance(severity_distribution_chart(sample_df), go.Figure)


def test_severity_chart_empty_df():
    assert isinstance(severity_distribution_chart(pd.DataFrame()), go.Figure)


def test_severity_chart_has_title(sample_df):
    fig = severity_distribution_chart(sample_df)
    assert "Severity" in fig.layout.title.text


# ---------------------------------------------------------------------------
# risk_score_histogram
# ---------------------------------------------------------------------------


def test_risk_histogram_returns_figure(sample_df):
    assert isinstance(risk_score_histogram(sample_df), go.Figure)


def test_risk_histogram_empty_df():
    assert isinstance(risk_score_histogram(pd.DataFrame()), go.Figure)


def test_risk_histogram_has_title(sample_df):
    fig = risk_score_histogram(sample_df)
    assert "Risk" in fig.layout.title.text


# ---------------------------------------------------------------------------
# status_progression_chart
# ---------------------------------------------------------------------------


def test_status_chart_returns_figure(sample_df):
    assert isinstance(status_progression_chart(sample_df), go.Figure)


def test_status_chart_empty_df():
    assert isinstance(status_progression_chart(pd.DataFrame()), go.Figure)


# ---------------------------------------------------------------------------
# confidence_scatter_chart
# ---------------------------------------------------------------------------


def test_confidence_scatter_returns_figure(sample_df):
    assert isinstance(confidence_scatter_chart(sample_df), go.Figure)


def test_confidence_scatter_empty_df():
    assert isinstance(confidence_scatter_chart(pd.DataFrame()), go.Figure)


# ---------------------------------------------------------------------------
# actor_frequency_chart
# ---------------------------------------------------------------------------


def test_actor_chart_returns_figure(sample_df):
    assert isinstance(actor_frequency_chart(sample_df), go.Figure)


def test_actor_chart_empty_df():
    assert isinstance(actor_frequency_chart(pd.DataFrame()), go.Figure)


def test_actor_chart_has_title(sample_df):
    fig = actor_frequency_chart(sample_df)
    assert "Threat Actor" in fig.layout.title.text or "Actor" in fig.layout.title.text


def test_actor_chart_top_n_respected(sample_df):
    fig = actor_frequency_chart(sample_df, top_n=2)
    # Should show at most 2 actors
    data = fig.data
    if data:
        assert len(data[0].y) <= 2


# ---------------------------------------------------------------------------
# campaign_frequency_chart
# ---------------------------------------------------------------------------


def test_campaign_chart_returns_figure(sample_df):
    assert isinstance(campaign_frequency_chart(sample_df), go.Figure)


def test_campaign_chart_empty_df():
    assert isinstance(campaign_frequency_chart(pd.DataFrame()), go.Figure)


# ---------------------------------------------------------------------------
# ioc_type_distribution
# ---------------------------------------------------------------------------


def test_ioc_type_chart_returns_figure(ioc_df):
    assert isinstance(ioc_type_distribution(ioc_df), go.Figure)


def test_ioc_type_chart_empty_df():
    assert isinstance(ioc_type_distribution(pd.DataFrame()), go.Figure)


def test_ioc_type_chart_has_title(ioc_df):
    fig = ioc_type_distribution(ioc_df)
    assert "IOC" in fig.layout.title.text


# ---------------------------------------------------------------------------
# attribution_confidence_chart
# ---------------------------------------------------------------------------


def test_attribution_chart_returns_figure(sample_df):
    assert isinstance(attribution_confidence_chart(sample_df), go.Figure)


def test_attribution_chart_empty_df():
    assert isinstance(attribution_confidence_chart(pd.DataFrame()), go.Figure)


# ---------------------------------------------------------------------------
# timeline_scatter_chart
# ---------------------------------------------------------------------------


def test_timeline_chart_returns_figure(sample_df):
    assert isinstance(timeline_scatter_chart(sample_df), go.Figure)


def test_timeline_chart_empty_df():
    assert isinstance(timeline_scatter_chart(pd.DataFrame()), go.Figure)


def test_timeline_chart_has_title(sample_df):
    fig = timeline_scatter_chart(sample_df)
    assert "Timeline" in fig.layout.title.text


# ---------------------------------------------------------------------------
# transition_heatmap
# ---------------------------------------------------------------------------


def test_heatmap_returns_figure(sample_df):
    assert isinstance(transition_heatmap(sample_df), go.Figure)


def test_heatmap_empty_df():
    assert isinstance(transition_heatmap(pd.DataFrame()), go.Figure)
