"""
agents/compliance_agent.py — Severity-appropriate mitigation playbook generation.
"""

from __future__ import annotations

from core.logger import get_logger
from core.state import IncidentStatus, StateObject
from utils.helpers import risk_label

logger = get_logger("agents.compliance")

_PLAYBOOKS: dict[str, list[str]] = {
    "APT-SHADOW-VIPER": [
        "Block C2 IP 185.220.101.47 at perimeter firewall",
        "Quarantine hosts matching hash 3a4b5c6d7e8f9a0b",
        "Sinkhole domain exfil-drop.shadow-net.io via DNS RPZ",
        "Rotate credentials for privileged accounts on segment VLAN-10",
        "Submit IOCs to ISAC for threat-sharing",
    ],
    "RANSOMWARE-LOCKBIT3": [
        "Isolate affected endpoints from network immediately",
        "Suspend Active Directory accounts used in lateral movement",
        "Restore from clean backup snapshot pre-encryption",
        "Invoke ransomware playbook P-007 with IR retainer",
        "Notify legal and executive leadership per incident policy",
    ],
    "PHISH-CREDENTIAL-HARVEST": [
        "Force password reset for all targeted accounts",
        "Block phishing domain fake-login.example.com at proxy",
        "Sweep and quarantine phishing emails via EWS",
        "Enforce MFA on all affected user accounts",
        "Report phishing infrastructure to abuse@registrar",
    ],
    "ADWARE-BUNDLER": [
        "Remove adware via EDR remediation task",
        "Purge malicious registry keys under HKCU Software Adware",
        "Block download CDN at web gateway",
        "Issue user awareness notification to affected department",
    ],
}

_DEFAULT_PLAYBOOK = [
    "Isolate affected systems from network",
    "Preserve forensic artefacts (memory, disk images)",
    "Notify SOC leadership and open formal incident ticket",
    "Begin evidence chain-of-custody documentation",
]


class ComplianceAgent:
    """
    Transition: ATTRIBUTED -> MITIGATED.
    Selects the appropriate playbook and records all remediation steps.
    """

    name = "ComplianceAgent"

    def run(self, state: StateObject) -> StateObject:
        logger.info("[%s] Building mitigation playbook for %s ...", self.name, state.incident_id)

        state.mitigation_actions = _PLAYBOOKS.get(
            state.threat_name, _DEFAULT_PLAYBOOK
        ).copy()
        state.status = IncidentStatus.MITIGATED
        state.touch()

        logger.info(
            "[%s] Status -> MITIGATED | actions=%d risk_label=%s",
            self.name,
            len(state.mitigation_actions),
            risk_label(state.risk_score),
        )
        return state
