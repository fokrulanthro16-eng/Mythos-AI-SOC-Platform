"""
agents/attribution_agent.py — Attribution confidence calculation and campaign clustering.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from core.logger import get_logger
from core.state import IncidentStatus, StateObject
from integrations.bandai_client import BandAIClient
from utils.helpers import compute_attribution_confidence, risk_label

logger = get_logger("agents.attribution")

_PROFILES_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_profiles.json"

# Maps threat_name -> canonical actor key (must match a key in threat_profiles.json or fallback)
_THREAT_TO_ACTOR: dict[str, str] = {
    # Ransomware
    "LOCKBIT4-RANSOMWARE":            "LOCKBIT4",
    "BLACKCAT-ALPHV-RANSOMWARE":      "ALPHV-BLACKCAT",
    "AKIRA-RANSOMWARE":               "AKIRA-GROUP",
    "PLAY-RANSOMWARE":                "PLAY-GROUP",
    "RHYSIDA-RANSOMWARE":             "RHYSIDA-GROUP",
    "REVIL-REVIVAL-RANSOMWARE":       "REVIL-OPERATORS",
    "ICEFIRE-LINUX-RANSOMWARE":       "ICEFIRE-GROUP",
    # Phishing / Credential Theft
    "SCATTERED-SPIDER-BEC":           "UNC3944",
    "SCATTERED-SPIDER-SMS-MFA":       "UNC3944",
    "SCATTERED-SPIDER-DATA-THEFT":    "UNC3944",
    "APT28-SPEARPHISH":               "APT28",
    "APT28-DOCUMENT-EXFIL":           "APT28",
    "BRUTERATEL-C4-IMPLANT":          "APT28",
    "MIDNIGHT-BLIZZARD-OAUTH":        "APT29",
    "CARBANAK-BANKING-PHISH":         "FIN7-SPINOFF",
    "EVILGINX2-AITM-PHISH":           "FIN7-SPINOFF",
    "DARKGATE-MALSPAM":               "DARKGATE-OPERATOR",
    "QAKBOT-REVIVAL-PHISH":           "QAKBOT-OPERATORS",
    "BUMBLEBEE-LOADER-EMAIL":         "EXOTIC-LILY",
    "EMOTET-WAVE-2026":               "MUMMY-SPIDER",
    "ICEDID-BANKING-MALWARE":         "GOLD-SWATHMORE",
    "STORM0558-EXCHANGE-TOKEN":       "STORM-0558",
    # C2 / Beacons
    "VOLT-TYPHOON-LOTL":              "VOLT-TYPHOON",
    "VOLT-TYPHOON-EXFIL":             "VOLT-TYPHOON",
    "WMIC-LATERAL-MOVEMENT":          "VOLT-TYPHOON",
    "LOTL-GOVERNMENT-NETWORK":        "VOLT-TYPHOON",
    "LAZARUS-C2-CRYPTO":              "LAZARUS-GROUP",
    "LAZARUS-CRYPTO-DRAIN":           "LAZARUS-GROUP",
    "SUPPLY-CHAIN-NPM-PACKAGE":       "LAZARUS-GROUP",
    "COBALTSTRIKE-BEACON-ENTERPRISE": "MULTIPLE-ACTORS",
    "COBALTSTRIKE-VIA-RDP":           "MULTIPLE-ACTORS",
    "SLIVER-C2-FRAMEWORK":            "MULTIPLE-ACTORS",
    "HAVOC-C2-FRAMEWORK":             "MULTIPLE-ACTORS",
    "MYTHIC-C2-AGENT":                "MULTIPLE-ACTORS",
    # Data Exfiltration
    "CLOP-MOVEIT-STYLE-SQLI":         "TA505",
    "TA505-EXFIL-FTP":                "TA505",
    "MOVEIT-STYLE-SQLI-2026":         "TA505",
    "RHYSIDA-EXFIL-PRE-ENCRYPT":      "RHYSIDA-GROUP",
    "INSIDER-DATA-STAGING":           "MULTIPLE-ACTORS",
    # Lateral Movement
    "MIMIKATZ-PASS-THE-HASH":         "MULTIPLE-ACTORS",
    "KERBEROASTING-ATTACK":           "MULTIPLE-ACTORS",
    "RDP-BRUTEFORCE-LATERAL":         "MULTIPLE-ACTORS",
    # Exploits / Other
    "CITRIX-BLEED-CVE-2023-4966":     "MULTIPLE-ACTORS",
    "K8S-CRYPTOMINING":               "MULTIPLE-ACTORS",
    "PAPERCUT-CVE-2023-27350":        "MULTIPLE-ACTORS",
    # Legacy (backwards compat)
    "APT-SHADOW-VIPER":               "TA505",
    "RANSOMWARE-LOCKBIT3":            "LOCKBIT4",
    "PHISH-CREDENTIAL-HARVEST":       "FIN7-SPINOFF",
    "ADWARE-BUNDLER":                 "MULTIPLE-ACTORS",
}


def _load_profiles() -> dict:
    if not _PROFILES_PATH.exists():
        return {}
    with _PROFILES_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _count_ioc_matches(indicators: list[str], profile: dict) -> int:
    """Count how many IOCs match at least one known_ioc_pattern in the profile."""
    patterns = profile.get("known_ioc_patterns", [])
    matches = 0
    for ioc in indicators:
        for pattern in patterns:
            if pattern.lower() in ioc.lower():
                matches += 1
                break
    return matches


def cluster_campaign(state: StateObject) -> dict[str, Any]:
    """
    Generate a deterministic campaign cluster from actor + IOC fingerprint.

    Returns:
        campaign_id       — e.g. CAMP-TA50-2026-3FA1C2
        threat_actor      — suspected_actor value
        confidence        — attribution_confidence
        related_incidents — list of incident_ids in this cluster
    """
    actor = state.suspected_actor or "UNKNOWN"
    actor_prefix = actor.replace("-", "")[:4].upper()
    year = state.created_at.year
    ioc_hash = hashlib.md5("|".join(sorted(state.indicators)).encode()).hexdigest()[:6].upper()
    return {
        "campaign_id":        f"CAMP-{actor_prefix}-{year}-{ioc_hash}",
        "threat_actor":        actor,
        "confidence":          state.attribution_confidence,
        "related_incidents":  [state.incident_id],
    }


class AttributionAgent:
    """
    Transition: ENRICHED -> ATTRIBUTED.

    1. Matches threat_name to the closest actor profile.
    2. Computes a three-factor attribution confidence score.
    3. Clusters the incident into a named campaign via IOC fingerprinting.
    4. Logs the attribution task via BandAIClient (mock by default).
    """

    name = "AttributionAgent"

    def __init__(self) -> None:
        self._profiles: dict = _load_profiles()
        self._bandai = BandAIClient()

    def run(self, state: StateObject) -> StateObject:
        logger.info("[%s] Computing attribution for %s ...", self.name, state.incident_id)

        # Log attribution task via BandAI (no-op in mock mode)
        task_id = self._bandai.submit_task(
            self._bandai.forensics_id or "forensics-agent",
            {
                "incident_id": state.incident_id,
                "threat_name": state.threat_name,
                "indicators":  state.indicators,
            },
        )
        self._bandai.get_result(task_id)

        # Resolve threat actor
        state.suspected_actor = _THREAT_TO_ACTOR.get(state.threat_name, "UNATTRIBUTED")
        profile = self._profiles.get(state.suspected_actor, {})

        # Factor 1 — IOC match count against known profile patterns
        ioc_matches = _count_ioc_matches(state.indicators, profile)
        total_patterns = max(len(profile.get("known_ioc_patterns", [])), 1)

        # Factor 2 — tactic/technique overlap with enrichment data
        profile_ttps = set(profile.get("ttps", []))
        enriched_ttps = set(state.enrichment_data.get("ttps", []))
        tactic_overlap = (
            len(profile_ttps & enriched_ttps) / max(len(profile_ttps), 1)
            if profile_ttps else 0.0
        )

        # Compute blended attribution confidence
        state.attribution_confidence = compute_attribution_confidence(
            base_confidence=state.confidence_score,
            ioc_match_count=ioc_matches,
            total_ioc_patterns=total_patterns,
            tactic_overlap=tactic_overlap,
        )

        # Campaign clustering
        cluster = cluster_campaign(state)
        state.campaign_id = cluster["campaign_id"]

        state.status = IncidentStatus.ATTRIBUTED
        state.touch()

        logger.info(
            "[%s] Status -> ATTRIBUTED | actor=%s attr_conf=%.4f campaign=%s risk=%s",
            self.name,
            state.suspected_actor,
            state.attribution_confidence,
            state.campaign_id,
            risk_label(state.risk_score),
        )
        return state
