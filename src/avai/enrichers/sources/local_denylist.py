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

from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

# Offline known-bad hash deny-list: one hex digest (md5 / sha1 / sha256)
# per line, '#' comments allowed. An absent file ⇒ the enricher loads
# empty and simply gives no opinion.
DENYLIST_ENV = "AVAI_HASH_DENYLIST"
BUNDLED_DENYLIST = Path(__file__).resolve().parents[2] / "rules" / "hash_denylist.txt"
ONE_YEAR_HOURS = 24 * 365
MALICIOUS_CONFIDENCE = 1.0


class LocalHashDenylistEnricher(Enricher):
    name = "local_denylist"
    supports_types = frozenset(
        {IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5}
    )
    requires_token: ClassVar[str | None] = None  # keyless, always registered
    ttl_hours = ONE_YEAR_HOURS  # purely local; effectively never re-fetch

    def __init__(self, path: Path, hashes: frozenset[str]) -> None:
        self._path = path
        self._hashes = hashes

    @classmethod
    def create(
        cls, http: HttpClient, env: Mapping[str, str]
    ) -> LocalHashDenylistEnricher:
        return cls.from_path(Path(env.get(DENYLIST_ENV) or BUNDLED_DENYLIST))

    @classmethod
    def from_path(cls, path: Path) -> LocalHashDenylistEnricher:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return cls(path, frozenset())  # missing file ⇒ no opinions
        entries = (line.split("#", 1)[0].strip().lower() for line in text.splitlines())
        return cls(path, frozenset(entry for entry in entries if entry))

    def fetch(self, indicator: Indicator) -> Evidence | None:
        # Indicator hashes are already lowercased at construction.
        if indicator.value not in self._hashes:
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"known-bad hash (local deny-list: {self._path.name})",
            details={"denylist": str(self._path)},
        )
