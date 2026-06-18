"""parsers/dedup.py — File-backed duplicate detection for incident ingestion."""

from __future__ import annotations

import json
from pathlib import Path

_DEFAULT_STORE = Path(__file__).parent.parent / "uploads" / "seen_fingerprints.jsonl"


class DuplicateDetector:
    """Persists seen incident fingerprints to a JSONL file."""

    def __init__(self, store_path: Path | str | None = None) -> None:
        self._path = Path(store_path) if store_path else _DEFAULT_STORE
        self._seen: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                self._seen.add(json.loads(line)["fp"])
            except Exception:
                pass

    def is_duplicate(self, fingerprint: str) -> bool:
        return fingerprint in self._seen

    def mark_seen(self, fingerprint: str, metadata: dict | None = None) -> None:
        if fingerprint in self._seen:
            return
        self._seen.add(fingerprint)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"fp": fingerprint, **(metadata or {})}
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def reset(self) -> None:
        """Clear all fingerprints (use for testing only)."""
        self._seen.clear()
        if self._path.exists():
            self._path.unlink()

    @property
    def seen_count(self) -> int:
        return len(self._seen)
