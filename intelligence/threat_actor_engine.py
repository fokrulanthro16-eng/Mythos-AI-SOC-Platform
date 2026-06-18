"""intelligence/threat_actor_engine.py — Threat Actor Intelligence Engine.

Loads from data/threat_actors.json (10 named actors in the Phase 7.2 format)
and provides lookup, search, statistics, and incident-to-actor mapping.

Public API
----------
load_actor_database(path=None) -> list[dict]
get_actor(name)                -> dict | None
search_actor(query)            -> list[dict]
actor_statistics()             -> dict
actor_campaign_count()         -> dict[str, int]
map_incident_to_actor(incident)-> str | None
"""

from __future__ import annotations

import json
from pathlib import Path

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_actors.json"

# ---------------------------------------------------------------------------
# Threat-category → actor family mappings (for incident attribution)
# ---------------------------------------------------------------------------

_CATEGORY_ACTOR_MAP: dict[str, str] = {
    # Credential-related
    "Credential Harvesting":   "APT29",
    "Credential Theft":        "APT29",
    "Credential Access":       "APT29",
    # PowerShell / banking / phishing
    "PowerShell Abuse":        "FIN7",
    "Financial Fraud":         "FIN7",
    "Banking Phishing":        "FIN7",
    "Business Email Compromise": "FIN7",
    # C2 / data exfiltration
    "Command and Control":     "TA505",
    "C2 Infrastructure":       "TA505",
    "Data Exfiltration":       "TA505",
    # Ransomware
    "Ransomware":              "LockBit",
    "Ransomware Deployment":   "LockBit",
    "Ransomware Encryption":   "LockBit",
    # Lateral movement
    "Lateral Movement":        "BlackCat",
    "Privilege Escalation":    "BlackCat",
    "Internal Propagation":    "BlackCat",
}

# Incident threat-name prefixes / substrings → actor
_THREAT_NAME_ACTOR_MAP: dict[str, str] = {
    "LOCKBIT":         "LockBit",
    "BLACKCAT":        "BlackCat",
    "ALPHV":           "BlackCat",
    "LAZARUS":         "Lazarus",
    "CRYPTO":          "Lazarus",
    "APT29":           "APT29",
    "APT28":           "APT29",
    "MIDNIGHT-BLIZZARD": "APT29",
    "OAUTH":           "APT29",
    "FIN7":            "FIN7",
    "CARBANAK":        "FIN7",
    "DARKGATE":        "FIN7",
    "TA505":           "TA505",
    "CLOP":            "TA505",
    "MOVEIT":          "TA505",
    "VOLT-TYPHOON":    "Volt Typhoon",
    "LOTL":            "Volt Typhoon",
    "MUSTANG":         "Mustang Panda",
    "SCATTER":         "Scattered Spider",
    "OKTA":            "Scattered Spider",
}

# MITRE technique → actor (for technique-level mapping)
_TECHNIQUE_ACTOR_MAP: dict[str, str] = {
    "T1539":  "APT29",   # Steal Web Session Cookie
    "T1528":  "APT29",   # Steal Application Access Token
    "T1098":  "APT29",   # Account Manipulation
    "T1059.001": "FIN7", # PowerShell
    "T1059.005": "FIN7", # Visual Basic
    "T1056":  "FIN7",    # Input Capture
    "T1190":  "TA505",   # Exploit Public-Facing App
    "T1560":  "TA505",   # Archive Collected Data
    "T1567":  "TA505",   # Exfiltration Over Web Service
    "T1486":  "LockBit", # Data Encrypted for Impact
    "T1490":  "LockBit", # Inhibit System Recovery
    "T1550":  "BlackCat",# Use Alternate Authentication Material
    "T1021":  "BlackCat",# Remote Services
    "T1562":  "BlackCat",# Impair Defenses
    "T1047":  "Volt Typhoon",  # WMI
    "T1572":  "Volt Typhoon",  # Protocol Tunneling
    "T1195":  "Lazarus", # Supply Chain Compromise
    "T1078":  "Scattered Spider",  # Valid Accounts
    "T1110":  "Scattered Spider",  # Brute Force
    "T1566":  "Mustang Panda",     # Phishing
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def load_actor_database(path: str | Path | None = None) -> list[dict]:
    """Load all threat actors from JSON. Returns list of actor dicts."""
    target = Path(path) if path else _DEFAULT_PATH
    return json.loads(target.read_text(encoding="utf-8"))


def get_actor(name: str, path: str | Path | None = None) -> dict | None:
    """Return the first actor matching *name* exactly (case-insensitive) by name or alias."""
    actors = load_actor_database(path)
    needle = name.strip().lower()
    for actor in actors:
        if actor.get("name", "").lower() == needle:
            return actor
        if any(a.lower() == needle for a in actor.get("aliases", [])):
            return actor
    return None


def search_actor(query: str, path: str | Path | None = None) -> list[dict]:
    """Full-text search across name, aliases, description, country, type, motivation, known_campaigns.

    Returns all matching actors sorted by name. Empty query returns empty list.
    """
    if not query or not query.strip():
        return []
    actors = load_actor_database(path)
    q = query.strip().lower()

    def _match(actor: dict) -> bool:
        searchable = " ".join([
            actor.get("name", ""),
            actor.get("country", ""),
            actor.get("type", ""),
            actor.get("description", ""),
            " ".join(actor.get("aliases", [])),
            " ".join(actor.get("known_campaigns", [])),
            " ".join(actor.get("motivation", [])),
            " ".join(actor.get("mitre_techniques", [])),
        ]).lower()
        return q in searchable

    return sorted(
        [a for a in actors if _match(a)],
        key=lambda a: a.get("name", ""),
    )


def actor_statistics(path: str | Path | None = None) -> dict:
    """Return summary statistics across the entire actor database.

    Returns:
        total_actors:        int
        by_country:          dict[str, int]
        by_type:             dict[str, int]
        by_sophistication:   dict[str, int]
        total_campaigns:     int
        total_techniques:    int
        unique_techniques:   int
        countries_represented: int
        avg_attribution_conf: float
        high_confidence_actors: int  (attribution >= 0.90)
    """
    actors = load_actor_database(path)

    by_country: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_soph: dict[str, int] = {}
    all_techniques: list[str] = []
    total_campaigns = 0
    total_attribution = 0.0

    for actor in actors:
        c = actor.get("country", "Unknown")
        by_country[c] = by_country.get(c, 0) + 1

        t = actor.get("type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

        s = actor.get("sophistication", "unknown")
        by_soph[s] = by_soph.get(s, 0) + 1

        all_techniques.extend(actor.get("mitre_techniques", []))
        total_campaigns += len(actor.get("known_campaigns", []))
        total_attribution += actor.get("attribution_confidence", 0.0)

    n = len(actors)
    high_conf = sum(
        1 for a in actors if a.get("attribution_confidence", 0) >= 0.90
    )

    return {
        "total_actors":           n,
        "by_country":             by_country,
        "by_type":                by_type,
        "by_sophistication":      by_soph,
        "total_campaigns":        total_campaigns,
        "total_techniques":       len(all_techniques),
        "unique_techniques":      len(set(all_techniques)),
        "countries_represented":  len(by_country),
        "avg_attribution_conf":   round(total_attribution / n, 4) if n else 0.0,
        "high_confidence_actors": high_conf,
    }


def actor_campaign_count(path: str | Path | None = None) -> dict[str, int]:
    """Return {actor_name: known_campaign_count} for every actor in the database."""
    actors = load_actor_database(path)
    return {
        actor["name"]: len(actor.get("known_campaigns", []))
        for actor in actors
    }


def map_incident_to_actor(incident: dict, path: str | Path | None = None) -> str | None:
    """Map an incident record to a likely threat actor.

    Resolution order (first match wins):
      1. ``suspected_actor`` field (if non-empty and != UNKNOWN)
      2. Threat-name prefix table
      3. Threat-category → actor table
      4. MITRE technique match

    Returns the matched actor *name* string, or ``None`` if unmappable.
    """
    actors = load_actor_database(path)
    actor_names = {a["name"] for a in actors}

    # 1. Explicit suspected_actor attribution
    suspected = incident.get("suspected_actor", "")
    if suspected and suspected.upper() not in ("", "UNKNOWN"):
        for name in actor_names:
            if name.lower() == suspected.lower() or name.lower() in suspected.lower():
                return name
        if suspected in actor_names:
            return suspected

    # 2. Threat-name keyword match
    threat_name = incident.get("threat_name", "").upper()
    for keyword, actor_name in _THREAT_NAME_ACTOR_MAP.items():
        if keyword.upper() in threat_name:
            if actor_name in actor_names:
                return actor_name

    # 3. Threat-category mapping
    category = incident.get("threat_category", "") or incident.get("category", "")
    if category:
        mapped = _CATEGORY_ACTOR_MAP.get(category)
        if mapped and mapped in actor_names:
            return mapped

    # 4. MITRE technique match
    techniques = [
        t.get("technique_id", "") for t in incident.get("attack_techniques", [])
    ]
    for tech_id in techniques:
        # Try exact match first, then prefix (e.g. T1059 matches T1059.001)
        for key, actor_name in _TECHNIQUE_ACTOR_MAP.items():
            if tech_id == key or tech_id.startswith(key.split(".")[0]):
                if actor_name in actor_names:
                    return actor_name

    return None
