"""
dashboard/components/charts.py — Plotly chart builders for the Mythos Command Center.

Every function accepts a DataFrame and returns a go.Figure.
All functions degrade gracefully on empty data.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

_DARK = "plotly_dark"

_SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#FF4B4B",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00CC44",
}

_STATUS_ORDER = ["DETECTED", "ANALYZED", "ENRICHED", "ATTRIBUTED", "MITIGATED"]


# ---------------------------------------------------------------------------
# Incident Overview charts
# ---------------------------------------------------------------------------


def severity_distribution_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty or "severity" not in df.columns:
        return _empty("No severity data")
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    fig = px.pie(
        counts,
        names="severity",
        values="count",
        color="severity",
        color_discrete_map=_SEV_COLORS,
        template=_DARK,
        title="Severity Distribution",
        hole=0.35,
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(showlegend=True, margin=dict(t=50, b=10, l=10, r=10))
    return fig


def risk_score_histogram(df: pd.DataFrame) -> go.Figure:
    if df.empty or "risk_score" not in df.columns:
        return _empty("No risk data")
    fig = px.histogram(
        df,
        x="risk_score",
        nbins=20,
        template=_DARK,
        title="Risk Score Distribution",
        color_discrete_sequence=["#FF4B4B"],
        labels={"risk_score": "Risk Score"},
    )
    fig.update_layout(
        bargap=0.05,
        xaxis=dict(range=[0, 1]),
        yaxis_title="Count",
    )
    return fig


def status_progression_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty or "status" not in df.columns:
        return _empty("No status data")
    counts = (
        df["status"]
        .value_counts()
        .reindex(_STATUS_ORDER, fill_value=0)
        .reset_index()
    )
    counts.columns = ["status", "count"]
    fig = px.bar(
        counts,
        x="status",
        y="count",
        template=_DARK,
        title="Transitions by Status",
        color="status",
        color_discrete_sequence=["#3B4B8C", "#5C6BC0", "#7E57C2", "#AB47BC", "#FF4B4B"],
        category_orders={"status": _STATUS_ORDER},
    )
    fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Transition Count")
    return fig


def confidence_scatter_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return _empty("No data")
    needed = {"confidence_score", "attribution_confidence", "risk_score", "severity"}
    if not needed.issubset(df.columns):
        return _empty("Incomplete columns")
    fig = px.scatter(
        df,
        x="confidence_score",
        y="attribution_confidence",
        color="severity",
        size="risk_score",
        size_max=18,
        hover_data=["incident_id", "threat_name", "suspected_actor"],
        template=_DARK,
        title="Detection Confidence vs Attribution Confidence",
        color_discrete_map=_SEV_COLORS,
        labels={
            "confidence_score":     "Detection Confidence",
            "attribution_confidence": "Attribution Confidence",
        },
    )
    fig.update_layout(xaxis=dict(range=[0, 1]), yaxis=dict(range=[0, 1]))
    return fig


# ---------------------------------------------------------------------------
# Threat Intelligence charts
# ---------------------------------------------------------------------------


def actor_frequency_chart(df: pd.DataFrame, top_n: int = 10) -> go.Figure:
    if df.empty or "suspected_actor" not in df.columns:
        return _empty("No actor data")
    counts = (
        df[df["suspected_actor"].str.strip() != ""]["suspected_actor"]
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    counts.columns = ["actor", "count"]
    if counts.empty:
        return _empty("No actor data")
    fig = px.bar(
        counts,
        x="count",
        y="actor",
        orientation="h",
        template=_DARK,
        title=f"Top {top_n} Threat Actors by Incident Count",
        color="count",
        color_continuous_scale="Reds",
    )
    fig.update_layout(
        yaxis={"categoryorder": "total ascending"},
        coloraxis_showscale=False,
        xaxis_title="Incident Count",
        yaxis_title="",
    )
    return fig


def campaign_frequency_chart(df: pd.DataFrame, top_n: int = 10) -> go.Figure:
    if df.empty or "campaign_id" not in df.columns:
        return _empty("No campaign data")
    counts = (
        df[df["campaign_id"].str.strip() != ""]["campaign_id"]
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    counts.columns = ["campaign", "count"]
    if counts.empty:
        return _empty("No campaign data")
    fig = px.bar(
        counts,
        x="campaign",
        y="count",
        template=_DARK,
        title=f"Top {top_n} Campaigns by Transition Count",
        color="count",
        color_continuous_scale="Blues",
    )
    fig.update_layout(
        coloraxis_showscale=False,
        xaxis_title="Campaign ID",
        yaxis_title="Transition Count",
        xaxis_tickangle=-30,
    )
    return fig


def ioc_type_distribution(ioc_df: pd.DataFrame) -> go.Figure:
    if ioc_df.empty or "ioc_type" not in ioc_df.columns:
        return _empty("No IOC enrichment data")
    counts = ioc_df["ioc_type"].value_counts().reset_index()
    counts.columns = ["ioc_type", "count"]
    fig = px.bar(
        counts,
        x="ioc_type",
        y="count",
        template=_DARK,
        title="IOC Type Distribution",
        color="ioc_type",
        color_discrete_sequence=px.colors.qualitative.Plotly,
    )
    fig.update_layout(showlegend=False, xaxis_title="IOC Type", yaxis_title="Count")
    return fig


def attribution_confidence_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty or "attribution_confidence" not in df.columns:
        return _empty("No attribution data")
    latest = df.groupby("incident_id", as_index=False).last()
    fig = px.bar(
        latest.sort_values("attribution_confidence", ascending=True),
        x="attribution_confidence",
        y="incident_id",
        orientation="h",
        color="attribution_confidence",
        color_continuous_scale="RdYlGn",
        template=_DARK,
        title="Attribution Confidence by Incident",
        range_color=[0, 1],
        labels={"attribution_confidence": "Confidence", "incident_id": "Incident"},
    )
    fig.update_layout(coloraxis_showscale=True, yaxis_title="")
    return fig


# ---------------------------------------------------------------------------
# Timeline charts
# ---------------------------------------------------------------------------


def timeline_scatter_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return _empty("No timeline data")
    needed = {"updated_at", "status", "incident_id"}
    if not needed.issubset(df.columns):
        return _empty("Missing timestamp columns")
    plot_df = df.dropna(subset=["updated_at"]).copy()
    if plot_df.empty:
        return _empty("No timestamp data")
    fig = px.scatter(
        plot_df,
        x="updated_at",
        y="incident_id",
        color="status",
        symbol="status",
        size="risk_score",
        size_max=14,
        hover_data=["threat_name", "suspected_actor", "campaign_id", "risk_score"],
        template=_DARK,
        title="Incident State Transition Timeline",
        category_orders={"status": _STATUS_ORDER},
        color_discrete_sequence=["#3B4B8C", "#5C6BC0", "#7E57C2", "#AB47BC", "#FF4B4B"],
        labels={"updated_at": "Timestamp", "incident_id": "Incident"},
    )
    fig.update_layout(yaxis={"categoryorder": "category ascending"})
    return fig


def transition_heatmap(df: pd.DataFrame) -> go.Figure:
    if df.empty or "status" not in df.columns:
        return _empty("No transition data")
    counts = (
        df.groupby(["incident_id", "status"])
        .size()
        .reset_index(name="count")
    )
    pivot = counts.pivot(index="incident_id", columns="status", values="count").fillna(0)
    # Reorder columns to pipeline order
    cols = [c for c in _STATUS_ORDER if c in pivot.columns]
    pivot = pivot[cols]
    fig = px.imshow(
        pivot,
        template=_DARK,
        title="Status Transition Heatmap (per Incident)",
        color_continuous_scale="Blues",
        aspect="auto",
        labels=dict(x="Status", y="Incident", color="Count"),
    )
    return fig


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _empty(msg: str = "No data available") -> go.Figure:
    fig = go.Figure()
    fig.update_layout(
        template=_DARK,
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        annotations=[{
            "text": msg,
            "showarrow": False,
            "font": {"size": 15, "color": "#8B90A8"},
            "xref": "paper", "yref": "paper",
            "x": 0.5, "y": 0.5,
        }],
    )
    return fig
