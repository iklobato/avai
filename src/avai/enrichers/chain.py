"""Chain-of-responsibility dispatcher.

Given a list of enrichers and a cache, ``EnrichmentChain.enrich(ind)``
returns every piece of evidence any enabled enricher has — pulling
from cache when fresh, hitting the network when not, swallowing
per-enricher failures so one broken source doesn't break the cycle.

The chain is intentionally dumb: it does not aggregate verdicts, does
not pick a single winner. The judge sees every Evidence entry and
decides. ``worst_hint()`` is provided as a helper for callers that
need a single summary.
"""
from __future__ import annotations

import logging
from typing import Iterable

from avai.enrichers.base import (
    Enricher,
    EnricherError,
    Evidence,
    Indicator,
    RateLimitedError,
)
from avai.enrichers.cache import EvidenceCache

LOG = logging.getLogger("avai.enrichers.chain")


class EnrichmentChain:
    def __init__(self, enrichers: list[Enricher], cache: EvidenceCache):
        self._enrichers = enrichers
        self._cache = cache
        # Tally per-source outcomes for the per-cycle summary log.
        self._stats: dict[str, dict[str, int]] = {}

    @property
    def sources(self) -> list[str]:
        return [e.name for e in self._enrichers]

    def reset_stats(self) -> None:
        self._stats.clear()

    def stats(self) -> dict[str, dict[str, int]]:
        return dict(self._stats)

    def enrich(self, indicator: Indicator) -> list[Evidence]:
        out: list[Evidence] = []
        for enricher in self._enrichers:
            if not enricher.supports(indicator):
                continue
            tally = self._stats.setdefault(
                enricher.name,
                {"hit": 0, "miss": 0, "rate_limited": 0, "error": 0,
                 "none": 0, "cached": 0},
            )
            cached = self._cache.get(enricher, indicator)
            if cached is not None:
                out.append(cached)
                tally["cached"] += 1
                continue
            try:
                evidence = enricher._fetch(indicator)
            except RateLimitedError:
                LOG.warning("enricher=%s rate-limited for %s",
                            enricher.name, indicator.value)
                tally["rate_limited"] += 1
                continue
            except EnricherError as exc:
                LOG.warning("enricher=%s error for %s: %s",
                            enricher.name, indicator.value, exc)
                tally["error"] += 1
                continue
            except Exception as exc:  # noqa: BLE001
                # Last-resort net: a broken source must not bring the
                # cycle down. Log once per cycle would be nice but the
                # surface area here is tiny.
                LOG.warning("enricher=%s unexpected error for %s: %s: %s",
                            enricher.name, indicator.value,
                            type(exc).__name__, exc)
                tally["error"] += 1
                continue
            if evidence is None:
                tally["none"] += 1
                continue
            self._cache.put(evidence)
            out.append(evidence)
            tally["miss"] += 1
            tally["hit"] += 1
        return out

    def enrich_many(self,
                    indicators: Iterable[Indicator]
                    ) -> dict[Indicator, list[Evidence]]:
        """Convenience for the monitor cycle — one call per batch."""
        result: dict[Indicator, list[Evidence]] = {}
        for ind in indicators:
            if ind in result:
                continue
            result[ind] = self.enrich(ind)
        return result
