"""dashboard/threat_actor_store.py — Threat actor intelligence data layer.

Pure compute functions (no I/O) at the top for unit-testability; file-backed
wrappers at the bottom for use inside Streamlit pages.
"""

from __future__ import annotations

import json
from pathlib import Path

_PROFILES_PATH  = Path(__file__).resolve().parent.parent / "data" / "threat_profiles.json"
_CAMPAIGNS_PATH = Path(__file__).resolve().parent.parent / "data" / "campaigns.json"

# The six actors featured in the Intelligence Center
FEATURED_ACTOR_IDS: list[str] = [
    "LOCKBIT4",
    "TA505",
    "FIN7",
    "APT29",
    "APT41",
    "LAZARUS-GROUP",
]

# ---------------------------------------------------------------------------
# Scoring tables (pure data, no I/O)
# ---------------------------------------------------------------------------

_SOPHISTICATION_SCORE: dict[str, float] = {
    "nation-state": 0.95,
    "advanced":     0.80,
    "intermediate": 0.60,
    "basic":        0.35,
}

_SEVERITY_SCORE: dict[str, float] = {
    "CRITICAL": 1.00,
    "HIGH":     0.75,
    "MEDIUM":   0.50,
    "LOW":      0.25,
}

_ATTRIBUTION_BASE: dict[str, float] = {
    "nation-state": 0.88,
    "advanced":     0.76,
    "intermediate": 0.62,
    "basic":        0.45,
}

# Origin → emoji flag used on KPI cards
ORIGIN_FLAGS: dict[str, str] = {
    "Russia":                     "🇷🇺",
    "China":                      "🇨🇳",
    "North Korea":                "🇰🇵",
    "Iran":                       "🇮🇷",
    "Ukraine":                    "🇺🇦",
    "Ukraine/Russia":             "🇺🇦/🇷🇺",
    "Eastern Europe":             "🌍",
    "English-speaking (US/UK)":   "🇺🇸",
    "Unknown":                    "❓",
    "Unknown (suspected Eastern Europe)": "🌍",
}

# Severity → Streamlit color string for st.markdown badges
SEV_BADGE: dict[str, str] = {
    "CRITICAL": "background:#7d0000;color:#fff",
    "HIGH":     "background:#7d3200;color:#fff",
    "MEDIUM":   "background:#4d4d00;color:#fff",
    "LOW":      "background:#003d00;color:#fff",
}

# ---------------------------------------------------------------------------
# Pure compute functions (no file I/O — injectable for tests)
# ---------------------------------------------------------------------------


def _compute_risk_score(profile: dict) -> float:
    """Return 0–1 risk score from a profile dict.  Weights: soph 45%, sev 40%, ttp-breadth 15%."""
    soph_s = _SOPHISTICATION_SCORE.get(profile.get("sophistication", "basic"), 0.35)
    sev_s  = _SEVERITY_SCORE.get(profile.get("severity", "LOW"), 0.25)
    ttp_s  = min(len(profile.get("ttps", [])) / 10.0, 1.0)
    return round(0.45 * soph_s + 0.40 * sev_s + 0.15 * ttp_s, 4)


def _compute_attribution_confidence(profile: dict, matched_incident_count: int = 0) -> float:
    """Return 0–1 attribution confidence derived from sophistication + incident observation count."""
    base   = _ATTRIBUTION_BASE.get(profile.get("sophistication", "basic"), 0.50)
    boost  = min(matched_incident_count * 0.015, 0.10)
    return round(min(base + boost, 0.98), 4)


def _compute_campaign_stats(campaigns: list[dict]) -> dict:
    """Aggregate stats across a list of campaign dicts."""
    if not campaigns:
        return {"total": 0, "active": 0, "victims": 0, "max_demand_usd": 0, "total_demand_usd": 0}
    return {
        "total":           len(campaigns),
        "active":          sum(1 for c in campaigns if c.get("status") == "ACTIVE"),
        "victims":         sum(c.get("estimated_victims", 0) for c in campaigns),
        "max_demand_usd":  max((c.get("known_ransom_demands_usd") or 0 for c in campaigns), default=0),
        "total_demand_usd":sum((c.get("known_ransom_demands_usd") or 0 for c in campaigns)),
    }


def _enrich_profile(profile: dict, campaigns: list[dict], incident_count: int = 0) -> dict:
    """Return a new dict with derived fields added — does not mutate the input."""
    p = dict(profile)
    p["risk_score"]              = _compute_risk_score(p)
    p["attribution_confidence"]  = _compute_attribution_confidence(p, incident_count)
    p["campaign_stats"]          = _compute_campaign_stats(campaigns)
    p["campaign_list"]           = campaigns
    return p


def _compute_technique_frequency(actors: list[dict]) -> dict[str, int]:
    """Return {technique_id: count} across all actor profiles."""
    freq: dict[str, int] = {}
    for actor in actors:
        for ttp in actor.get("ttps", []):
            freq[ttp] = freq.get(ttp, 0) + 1
    return freq


def _compute_region_matrix(campaigns: list[dict], actor_ids: list[str]) -> dict[str, dict[str, int]]:
    """Return {region: {actor_id: count}} matrix from campaign data."""
    matrix: dict[str, dict[str, int]] = {}
    for c in campaigns:
        actor = c.get("threat_actor", "")
        if actor not in actor_ids:
            continue
        for region in c.get("target_regions", []):
            matrix.setdefault(region, {})
            matrix[region][actor] = matrix[region].get(actor, 0) + 1
    return matrix


def _compute_sector_matrix(campaigns: list[dict], actor_ids: list[str]) -> dict[str, dict[str, int]]:
    """Return {sector: {actor_id: count}} matrix from campaign data."""
    matrix: dict[str, dict[str, int]] = {}
    for c in campaigns:
        actor = c.get("threat_actor", "")
        if actor not in actor_ids:
            continue
        for sector in c.get("target_sectors", []):
            matrix.setdefault(sector, {})
            matrix[sector][actor] = matrix[sector].get(actor, 0) + 1
    return matrix


def _compute_comparison_row(actor: dict) -> dict:
    """Return a flat dict suitable for the actor comparison radar chart."""
    stats = actor.get("campaign_stats", {})
    return {
        "actor_id":               actor.get("actor_id", ""),
        "display_name":           actor.get("actor_id", ""),
        "risk_score":             actor.get("risk_score", 0.0),
        "attribution_confidence": actor.get("attribution_confidence", 0.0),
        "ttp_count":              len(actor.get("ttps", [])),
        "campaign_count":         stats.get("total", 0),
        "active_campaigns":       stats.get("active", 0),
        "victim_count":           stats.get("victims", 0),
        "tool_count":             len(actor.get("known_tools", [])),
        "sophistication":         actor.get("sophistication", "unknown"),
        "origin":                 actor.get("origin", "Unknown"),
        "severity":               actor.get("severity", "UNKNOWN"),
        "total_demand_usd":       stats.get("total_demand_usd", 0),
    }


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def _load_profiles() -> dict[str, dict]:
    try:
        return json.loads(_PROFILES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_campaigns() -> list[dict]:
    try:
        return json.loads(_CAMPAIGNS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def _group_campaigns_by_actor(campaigns: list[dict]) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for c in campaigns:
        aid = c.get("threat_actor", "")
        result.setdefault(aid, []).append(c)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_all_actors() -> list[dict]:
    """Return all actors from threat_profiles.json, enriched with derived stats."""
    profiles   = _load_profiles()
    campaigns  = _load_campaigns()
    by_actor   = _group_campaigns_by_actor(campaigns)
    return [
        _enrich_profile(p, by_actor.get(aid, []), len(by_actor.get(aid, [])) * 3)
        for aid, p in profiles.items()
    ]


def get_actor(actor_id: str) -> dict | None:
    """Return a single enriched actor profile, or None if not found."""
    profiles  = _load_profiles()
    campaigns = _load_campaigns()
    profile   = profiles.get(actor_id)
    if not profile:
        return None
    actor_campaigns = [c for c in campaigns if c.get("threat_actor") == actor_id]
    return _enrich_profile(profile, actor_campaigns, len(actor_campaigns) * 3)


def get_featured_actors() -> list[dict]:
    """Return the 6 featured actors in display order."""
    return [a for aid in FEATURED_ACTOR_IDS if (a := get_actor(aid))]


def get_actor_campaigns(actor_id: str) -> list[dict]:
    return [c for c in _load_campaigns() if c.get("threat_actor") == actor_id]


def search_actors(query: str) -> list[dict]:
    """Full-text search across actor_id, aliases, description, origin, motivation."""
    q = query.lower().strip()
    if not q:
        return get_all_actors()
    result = []
    for actor in get_all_actors():
        blob = " ".join([
            actor.get("actor_id", ""),
            " ".join(actor.get("aliases", [])),
            actor.get("description", ""),
            actor.get("origin", ""),
            " ".join(actor.get("motivation", [])),
            " ".join(actor.get("ttps", [])),
            " ".join(actor.get("known_tools", [])),
        ]).lower()
        if q in blob:
            result.append(actor)
    return result


def filter_actors(
    origins: list[str] | None = None,
    sophistication_levels: list[str] | None = None,
    motivations: list[str] | None = None,
    severities: list[str] | None = None,
) -> list[dict]:
    """Return actors matching all supplied filter criteria (AND logic per field, OR within each field)."""
    actors = get_all_actors()
    if origins:
        actors = [a for a in actors if any(o in a.get("origin", "") for o in origins)]
    if sophistication_levels:
        actors = [a for a in actors if a.get("sophistication") in sophistication_levels]
    if motivations:
        actors = [
            a for a in actors
            if any(m.lower() in mot for mot in a.get("motivation", []) for m in motivations)
        ]
    if severities:
        actors = [a for a in actors if a.get("severity") in severities]
    return actors


def get_comparison_data(actor_ids: list[str]) -> list[dict]:
    """Return comparison-ready rows for the radar chart and comparison table."""
    return [
        _compute_comparison_row(actor)
        for aid in actor_ids
        if (actor := get_actor(aid))
    ]


def get_technique_frequency_for_actors(actor_ids: list[str]) -> dict[str, int]:
    """Return ATT&CK technique frequency across a set of actor IDs."""
    actors = [a for aid in actor_ids if (a := get_actor(aid))]
    return _compute_technique_frequency(actors)


def get_region_matrix(actor_ids: list[str]) -> dict[str, dict[str, int]]:
    return _compute_region_matrix(_load_campaigns(), actor_ids)


def get_sector_matrix(actor_ids: list[str]) -> dict[str, dict[str, int]]:
    return _compute_sector_matrix(_load_campaigns(), actor_ids)
