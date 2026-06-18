"""
integrations/featherless_client.py — Featherless AI client with mock fallback.

Set FEATHERLESS_API_KEY in .env to enable live mode; omit for mock mode.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

_MOCK_SUMMARIES: dict[str, str] = {
    "APT-SHADOW-VIPER": (
        "Sophisticated APT activity consistent with TA505 operations. "
        "IOC analysis confirms active C2 at 185.220.101.47 and exfiltration staging domain. "
        "Tactics align with T1566/T1071 tradecraft. Confidence: HIGH. "
        "Recommend immediate containment and credential rotation."
    ),
    "RANSOMWARE-LOCKBIT3": (
        "LockBit 3.0 ransomware deployment detected with double-extortion indicators. "
        "Lateral movement via compromised credentials observed. "
        "Time-to-full-encryption estimate: under 2 hours. "
        "Recommend immediate network isolation and backup verification."
    ),
    "PHISH-CREDENTIAL-HARVEST": (
        "Credential harvesting phishing campaign targeting enterprise users. "
        "FIN7-linked infrastructure identified. Spoofed HR communications used as lure. "
        "Estimated 15–30 accounts at imminent risk of compromise."
    ),
    "ADWARE-BUNDLER": (
        "Low-sophistication adware bundle with registry persistence. "
        "No lateral movement or data exfiltration indicators. "
        "Financially motivated criminal operation. Standard remediation sufficient."
    ),
}

_MOCK_CLASSIFICATIONS: dict[str, dict] = {
    "C2:":       {"category": "C2_INFRASTRUCTURE",   "confidence": 0.88, "tags": ["malware_c2", "botnet"]},
    "hash:":     {"category": "MALWARE_HASH",         "confidence": 0.95, "tags": ["static_indicator"]},
    "domain:":   {"category": "MALICIOUS_DOMAIN",     "confidence": 0.82, "tags": ["dns_sinkhole_candidate"]},
    "url:":      {"category": "PHISHING_URL",         "confidence": 0.79, "tags": ["phishing", "credential_harvest"]},
    "ip:":       {"category": "THREAT_IP",            "confidence": 0.72, "tags": ["threat_intel_hit"]},
    "registry:": {"category": "PERSISTENCE_KEY",      "confidence": 0.65, "tags": ["registry_autorun"]},
    "mutex:":    {"category": "MALWARE_ARTIFACT",     "confidence": 0.85, "tags": ["mutex_ioc"]},
    "process:":  {"category": "MALICIOUS_PROCESS",    "confidence": 0.70, "tags": ["process_ioc"]},
    "email:":    {"category": "PHISHING_SENDER",      "confidence": 0.75, "tags": ["phishing", "bec_risk"]},
}

_MOCK_ACTOR_ANALYSIS: dict[str, dict] = {
    "APT-SHADOW-VIPER": {
        "profile_key": "TA505",
        "ttps": ["T1566.001", "T1059.001", "T1071.001", "T1486"],
        "tools": ["Clop", "SDBbot", "Get2"],
        "confidence": 0.85,
        "notes": "IOC patterns consistent with TA505 infrastructure fingerprint.",
    },
    "RANSOMWARE-LOCKBIT3": {
        "profile_key": "LOCKBIT",
        "ttps": ["T1486", "T1489", "T1490", "T1078"],
        "tools": ["LockBit 3.0", "Cobalt Strike"],
        "confidence": 0.92,
        "notes": "Mutex and hash patterns match LockBit 3.0 binary family.",
    },
    "PHISH-CREDENTIAL-HARVEST": {
        "profile_key": "FIN7",
        "ttps": ["T1566.001", "T1566.002", "T1071.001"],
        "tools": ["GRIFFON", "BOOSTWRITE"],
        "confidence": 0.77,
        "notes": "Phishing infrastructure overlaps with confirmed FIN7 campaigns.",
    },
    "ADWARE-BUNDLER": {
        "profile_key": None,
        "ttps": ["T1547.001"],
        "tools": ["generic_adware"],
        "confidence": 0.45,
        "notes": "No known APT or organised crime-group attribution.",
    },
}


class FeatherlessClient:
    """
    Featherless AI integration for threat intelligence generation.
    Operates in mock mode when FEATHERLESS_API_KEY is absent.
    """

    def __init__(self) -> None:
        self.api_key: str = os.getenv("FEATHERLESS_API_KEY", "")
        self.base_url: str = os.getenv("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1")
        self.mock_mode: bool = not bool(self.api_key)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_summary(self, threat_name: str, indicators: list[str]) -> str:
        if self.mock_mode:
            return _MOCK_SUMMARIES.get(
                threat_name,
                f"[MOCK] Threat activity detected: {threat_name}. "
                f"{len(indicators)} IOC(s) identified. Manual review recommended.",
            )
        return self._api_generate_summary(threat_name, indicators)

    def classify_threat(self, indicators: list[str]) -> dict:
        if self.mock_mode:
            if not indicators:
                return {"category": "UNKNOWN", "confidence": 0.0, "tags": []}
            ioc = indicators[0]
            for prefix, classification in _MOCK_CLASSIFICATIONS.items():
                if ioc.startswith(prefix):
                    return dict(classification)
            return {"category": "GENERIC_IOC", "confidence": 0.60, "tags": ["unclassified"]}
        return self._api_classify_threat(indicators)

    def actor_analysis(self, threat_name: str) -> dict:
        if self.mock_mode:
            return dict(
                _MOCK_ACTOR_ANALYSIS.get(
                    threat_name,
                    {
                        "profile_key": None,
                        "ttps": [],
                        "tools": [],
                        "confidence": 0.30,
                        "notes": "No known threat profile match.",
                    },
                )
            )
        return self._api_actor_analysis(threat_name)

    # ------------------------------------------------------------------
    # Real API calls (invoked only when api_key is present)
    # ------------------------------------------------------------------

    def _api_post(self, endpoint: str, payload: dict) -> dict:
        url = f"{self.base_url}/{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _api_generate_summary(self, threat_name: str, indicators: list[str]) -> str:
        result = self._api_post("summarize", {"threat_name": threat_name, "indicators": indicators})
        return result.get("summary", "")

    def _api_classify_threat(self, indicators: list[str]) -> dict:
        return self._api_post("classify", {"indicators": indicators})

    def _api_actor_analysis(self, threat_name: str) -> dict:
        return self._api_post("actor-analysis", {"threat_name": threat_name})
