"""Offline known-bad hash deny-list — an instant malicious verdict
without spending a network quota.

No key, no network. Reads a local file of hex digests (md5 / sha1 /
sha256), one per line, with ``#`` comments allowed; an absent or empty
file means the enricher simply gives no opinion. Point it at a
maintained feed via ``$AVAI_HASH_DENYLIST``.

Because the process / launch-item / setuid / file-scan extractors all
already emit sha256 indicators, this source enriches them with zero
extractor changes — commodity malware gets a verdict locally instead of
burning a VirusTotal lookup.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)


class LocalHashDenylistEnricher(Enricher):
    name = "local_denylist"
    supports_types = frozenset(
        {IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5}
    )
    requires_token: ClassVar[Optional[str]] = None  # keyless, always registered
    ttl_hours = 24 * 365  # purely local; effectively never re-fetch

    def __init__(self, path: Optional[Path] = None):
        # Late import keeps the enrichers package independent of
        # host_monitor at module-load time (it's imported lazily when the
        # chain is built, by which point host_monitor is already loaded).
        from avai.host_monitor import constants

        self._path = Path(path) if path else constants.HASH_DENYLIST_PATH
        self._hashes = self._load(self._path)

    @staticmethod
    def _load(path: Path) -> frozenset[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return frozenset()  # missing file ⇒ no opinions
        out: set[str] = set()
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip().lower()
            if entry:
                out.add(entry)
        return frozenset(out)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        # Indicator hashes are already lowercased at construction.
        if indicator.value not in self._hashes:
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=1.0,
            summary=f"known-bad hash (local deny-list: {self._path.name})",
            details={"denylist": str(self._path)},
        )
