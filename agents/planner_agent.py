"""
agents/planner_agent.py — Detection analysis and initial IOC population.
"""

from __future__ import annotations

from core.logger import get_logger
from core.state import IncidentStatus, StateObject
from utils.helpers import compute_risk_score

logger = get_logger("agents.planner")

_DEFAULT_INDICATORS = [
    "C2:185.220.101.47",
    "hash:3a4b5c6d7e8f9a0b",
    "domain:exfil-drop.shadow-net.io",
]

_THREAT_CONFIDENCE: dict[str, float] = {
    # Ransomware
    "LOCKBIT4-RANSOMWARE":            0.91,
    "BLACKCAT-ALPHV-RANSOMWARE":      0.88,
    "AKIRA-RANSOMWARE":               0.82,
    "PLAY-RANSOMWARE":                0.79,
    "RHYSIDA-RANSOMWARE":             0.85,
    "REVIL-REVIVAL-RANSOMWARE":       0.83,
    "ICEFIRE-LINUX-RANSOMWARE":       0.71,
    # Phishing / Credential Theft
    "SCATTERED-SPIDER-BEC":           0.87,
    "APT28-SPEARPHISH":               0.78,
    "MIDNIGHT-BLIZZARD-OAUTH":        0.92,
    "CARBANAK-BANKING-PHISH":         0.74,
    "DARKGATE-MALSPAM":               0.65,
    "QAKBOT-REVIVAL-PHISH":           0.68,
    "BUMBLEBEE-LOADER-EMAIL":         0.66,
    "EMOTET-WAVE-2026":               0.72,
    "SCATTERED-SPIDER-SMS-MFA":       0.85,
    "ICEDID-BANKING-MALWARE":         0.69,
    "EVILGINX2-AITM-PHISH":           0.81,
    "STORM0558-EXCHANGE-TOKEN":       0.94,
    # C2 / Beacons
    "COBALTSTRIKE-BEACON-ENTERPRISE": 0.84,
    "BRUTERATEL-C4-IMPLANT":          0.79,
    "SLIVER-C2-FRAMEWORK":            0.67,
    "VOLT-TYPHOON-LOTL":              0.88,
    "LAZARUS-C2-CRYPTO":              0.93,
    "COBALTSTRIKE-VIA-RDP":           0.80,
    "HAVOC-C2-FRAMEWORK":             0.62,
    "MYTHIC-C2-AGENT":                0.61,
    # Data Exfiltration
    "CLOP-MOVEIT-STYLE-SQLI":         0.96,
    "TA505-EXFIL-FTP":                0.89,
    "SCATTERED-SPIDER-DATA-THEFT":    0.84,
    "INSIDER-DATA-STAGING":           0.77,
    "VOLT-TYPHOON-EXFIL":             0.86,
    "APT28-DOCUMENT-EXFIL":           0.82,
    "LAZARUS-CRYPTO-DRAIN":           0.95,
    "RHYSIDA-EXFIL-PRE-ENCRYPT":      0.83,
    # Lateral Movement
    "MIMIKATZ-PASS-THE-HASH":         0.88,
    "KERBEROASTING-ATTACK":           0.75,
    "RDP-BRUTEFORCE-LATERAL":         0.70,
    "WMIC-LATERAL-MOVEMENT":          0.73,
    "LOTL-GOVERNMENT-NETWORK":        0.87,
    # Exploits / Other
    "CITRIX-BLEED-CVE-2023-4966":     0.96,
    "MOVEIT-STYLE-SQLI-2026":         0.91,
    "SUPPLY-CHAIN-NPM-PACKAGE":       0.89,
    "K8S-CRYPTOMINING":               0.55,
    "PAPERCUT-CVE-2023-27350":        0.90,
    # Legacy (backwards compat)
    "APT-SHADOW-VIPER":               0.62,
    "RANSOMWARE-LOCKBIT3":            0.78,
    "PHISH-CREDENTIAL-HARVEST":       0.55,
    "ADWARE-BUNDLER":                 0.40,
}


class PlannerAgent:
    """
    Transition: DETECTED -> ANALYZED.
    Populates IOC list, assigns initial confidence, and computes risk score.
    """

    name = "PlannerAgent"

    def run(self, state: StateObject) -> StateObject:
        logger.info("[%s] Analysing detection signal for %s ...", self.name, state.incident_id)

        if not state.indicators:
            state.indicators = _DEFAULT_INDICATORS.copy()

        if not state.confidence_score:
            state.confidence_score = _THREAT_CONFIDENCE.get(state.threat_name, 0.50)

        state.risk_score = compute_risk_score(state.confidence_score, state.severity)
        state.status = IncidentStatus.ANALYZED
        state.touch()

        logger.info(
            "[%s] Status -> ANALYZED | confidence=%.0f%% risk_score=%.4f iocs=%d",
            self.name,
            state.confidence_score * 100,
            state.risk_score,
            len(state.indicators),
        )
        return state
