"""intelligence/attack_engine.py — MITRE ATT&CK lookup + threat mapping engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack.json"

_REQUIRED_FIELDS = ("technique_id", "technique_name", "tactic", "url")


class AttackEngine:
    """Load MITRE ATT&CK techniques from JSON and map threats to techniques."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or _DB_PATH
        self._techniques: list[dict] = []
        self._by_id: dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal loader
    # ------------------------------------------------------------------

    def _load(self) -> None:
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self._techniques = [t for t in raw if all(f in t for f in _REQUIRED_FIELDS)]
        except (FileNotFoundError, json.JSONDecodeError):
            self._techniques = []
        self._by_id = {t["technique_id"].upper(): t for t in self._techniques}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def all_techniques(self) -> list[dict]:
        """Return all loaded techniques."""
        return list(self._techniques)

    def lookup(self, technique_id: str) -> dict | None:
        """Return technique by ID (case-insensitive), or None if not found."""
        return self._by_id.get(technique_id.strip().upper())

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """Full-text search across ID, name, tactic, description, and keywords."""
        q = query.strip().lower()
        if not q:
            return list(self._techniques[:limit])

        scored: list[tuple[float, dict]] = []
        for tech in self._techniques:
            score = 0.0

            tid = tech["technique_id"].lower()
            name = tech["technique_name"].lower()
            display = tech.get("display_name", "").lower()
            tactic = tech["tactic"].lower()
            desc = tech.get("description", "").lower()
            kw_blob = " ".join(tech.get("keywords", [])).lower()

            if tid == q:
                score += 100
            elif tid.startswith(q):
                score += 60
            if name == q:
                score += 80
            elif q in name:
                score += 40
            if q in display:
                score += 30
            if q in tactic:
                score += 20
            if q in kw_blob:
                score += 15
            if q in desc:
                score += 5

            if score > 0:
                scored.append((score, tech))

        scored.sort(key=lambda x: -x[0])
        return [t for _, t in scored[:limit]]

    def map_threat(
        self,
        threat_name: str,
        indicators: list[str] | None = None,
    ) -> list[dict]:
        """Map a threat name + optional indicators to ATT&CK techniques.

        Returns up to 5 best-matching techniques ordered by match score.
        """
        text = threat_name.strip().lower()
        ind_text = " ".join(indicators or []).lower()
        combined = f"{text} {ind_text}"

        seen: set[str] = set()
        scored: list[tuple[float, dict]] = []

        for tech in self._techniques:
            score = 0.0
            for kw in tech.get("keywords", []):
                kw_lower = kw.lower()
                if kw_lower in combined:
                    # Longer / multi-word keywords are more specific — weight by word count
                    score += (1 + len(kw_lower.split())) * 0.2

            tid = tech["technique_id"]
            if score > 0 and tid not in seen:
                seen.add(tid)
                scored.append((score, tech))

        scored.sort(key=lambda x: -x[0])
        return [t for _, t in scored[:5]]

    def enrich_state(self, state: Any) -> None:
        """Write ATT&CK mappings into state.enrichment_data['attack_techniques']."""
        techniques = self.map_threat(
            getattr(state, "threat_name", "") or "",
            list(getattr(state, "indicators", []) or []),
        )
        if techniques:
            state.enrichment_data["attack_techniques"] = [
                _slim(t) for t in techniques
            ]

    def stats(self) -> dict:
        """Return aggregate statistics over the loaded technique database."""
        by_tactic: dict[str, int] = {}
        by_tactic_id: dict[str, int] = {}

        for tech in self._techniques:
            tactic = tech.get("tactic", "Unknown")
            tactic_id = tech.get("tactic_id", "")
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
            if tactic_id:
                by_tactic_id[tactic_id] = by_tactic_id.get(tactic_id, 0) + 1

        subtechnique_count = sum(
            len(t.get("subtechniques", [])) for t in self._techniques
        )

        return {
            "total_techniques": len(self._techniques),
            "total_tactics": len(by_tactic),
            "techniques_by_tactic": by_tactic,
            "techniques_by_tactic_id": by_tactic_id,
            "total_subtechniques": subtechnique_count,
        }


def _slim(tech: dict) -> dict:
    """Return the minimal representation stored per incident."""
    return {
        "technique_id": tech["technique_id"],
        "technique_name": tech["technique_name"],
        "display_name": tech.get("display_name", tech["technique_name"]),
        "tactic": tech["tactic"],
        "tactic_id": tech.get("tactic_id", ""),
        "url": tech["url"],
    }
