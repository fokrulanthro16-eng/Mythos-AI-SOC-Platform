"""
agents/forensics_agent.py — Deep IOC analysis and threat-actor attribution.
"""

from __future__ import annotations

from core.logger import get_logger
from core.state import IncidentStatus, StateObject
from utils.helpers import compute_risk_score

logger = get_logger("agents.forensics")

# threat_name -> (actor, post-attribution confidence)
_ACTOR_MAP: dict[str, tuple[str, float]] = {
    "APT-SHADOW-VIPER": ("TA505-AFFILIATE", 0.87),
    "RANSOMWARE-LOCKBIT3": ("LOCKBIT-GRP", 0.91),
    "PHISH-CREDENTIAL-HARVEST": ("FIN7-SPINOFF", 0.68),
    "ADWARE-BUNDLER": ("UNKNOWN-CRIMINAL-RING", 0.45),
}
_DEFAULT_ATTRIBUTION = ("UNATTRIBUTED", 0.50)

# Lazy singleton — loaded on first agent run to avoid startup cost
_attack_engine = None


def _get_engine():
    global _attack_engine
    if _attack_engine is None:
        try:
            from intelligence.attack_engine import AttackEngine
            _attack_engine = AttackEngine()
        except Exception:
            _attack_engine = None
    return _attack_engine


class ForensicsAgent:
    """
    Transition: ANALYZED -> ATTRIBUTED.
    Identifies suspected threat actor, raises confidence, and maps ATT&CK techniques.
    """

    name = "ForensicsAgent"

    def run(self, state: StateObject) -> StateObject:
        logger.info("[%s] Running attribution for %s ...", self.name, state.incident_id)

        actor, confidence = _ACTOR_MAP.get(state.threat_name, _DEFAULT_ATTRIBUTION)
        state.suspected_actor = actor
        state.confidence_score = confidence
        state.risk_score = compute_risk_score(state.confidence_score, state.severity)
        state.status = IncidentStatus.ATTRIBUTED
        state.touch()

        # ATT&CK mapping — enrich enrichment_data with matched techniques
        engine = _get_engine()
        if engine is not None:
            engine.enrich_state(state)
            techniques = state.enrichment_data.get("attack_techniques", [])
            logger.info(
                "[%s] ATT&CK mapping: %d technique(s) — %s",
                self.name,
                len(techniques),
                ", ".join(t["technique_id"] for t in techniques) if techniques else "none",
            )

        logger.info(
            "[%s] Status -> ATTRIBUTED | actor=%s confidence=%.0f%% risk_score=%.4f",
            self.name,
            state.suspected_actor,
            state.confidence_score * 100,
            state.risk_score,
        )
        return state
