"""
agents/intelligence_agent.py — IOC enrichment, threat actor profiling, summary generation.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger
from core.state import IncidentStatus, StateObject
from integrations.featherless_client import FeatherlessClient

logger = get_logger("agents.intelligence")

_PROFILES_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_profiles.json"

# Maps internal threat_name to the canonical threat profile key
_THREAT_TO_PROFILE: dict[str, str] = {
    "APT-SHADOW-VIPER":        "TA505",
    "RANSOMWARE-LOCKBIT3":     "LOCKBIT",
    "PHISH-CREDENTIAL-HARVEST":"FIN7",
}


def _load_profiles() -> dict:
    if not _PROFILES_PATH.exists():
        return {}
    with _PROFILES_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


class IntelligenceAgent:
    """
    Transition: ANALYZED -> ENRICHED.

    1. Enriches each IOC with a threat-intelligence classification.
    2. Builds an enrichment_data block from the matching threat profile.
    3. Generates a plain-language threat summary via FeatherlessClient.
    """

    name = "IntelligenceAgent"

    def __init__(self) -> None:
        self._client = FeatherlessClient()
        self._profiles: dict = _load_profiles()

    def run(self, state: StateObject) -> StateObject:
        logger.info("[%s] Enriching intelligence for %s ...", self.name, state.incident_id)

        # 1. IOC enrichment
        state.ioc_enrichments = self._enrich_iocs(state.indicators)

        # 2. Threat actor profiling
        profile_key = _THREAT_TO_PROFILE.get(state.threat_name)
        profile = self._profiles.get(profile_key, {}) if profile_key else {}

        if profile:
            state.enrichment_data = {
                "profile_key":  profile_key,
                "origin":       profile.get("origin", "Unknown"),
                "motivation":   profile.get("motivation", []),
                "ttps":         profile.get("ttps", []),
                "known_tools":  profile.get("known_tools", []),
                "campaigns":    profile.get("campaigns", []),
                "profile_match": True,
            }
        else:
            actor_data = self._client.actor_analysis(state.threat_name)
            state.enrichment_data = {
                "profile_key":   actor_data.get("profile_key"),
                "ttps":          actor_data.get("ttps", []),
                "known_tools":   actor_data.get("tools", []),
                "profile_match": False,
            }

        # 3. Threat summary generation
        state.threat_summary = self._client.generate_summary(
            state.threat_name, state.indicators
        )

        state.status = IncidentStatus.ENRICHED
        state.touch()

        logger.info(
            "[%s] Status -> ENRICHED | profile_match=%s enrichments=%d",
            self.name,
            state.enrichment_data.get("profile_match", False),
            len(state.ioc_enrichments),
        )
        return state

    # ------------------------------------------------------------------

    def _enrich_iocs(self, indicators: list[str]) -> list[str]:
        enrichments: list[str] = []
        for ioc in indicators:
            result = self._client.classify_threat([ioc])
            category = result.get("category", "UNKNOWN")
            confidence = result.get("confidence", 0.0)
            enrichments.append(f"{ioc} [type={category} conf={confidence:.2f}]")
        return enrichments
