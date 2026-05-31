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
    IndicatorType,
    RateLimitedError,
)
from avai.enrichers.cache import EvidenceCache

LOG = logging.getLogger("avai.enrichers.chain")


class EnrichmentChain:
    # Cap how many discovered CVE IDs a single indicator forward-chains
    # into CVE lookups — bounds API calls when a package has many advisories.
    _MAX_FORWARD_CVES = 10

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
                {
                    "hit": 0,
                    "miss": 0,
                    "rate_limited": 0,
                    "error": 0,
                    "none": 0,
                    "cached": 0,
                },
            )
            cached = self._cache.get(enricher, indicator)
            if cached is not None:
                out.append(cached)
                tally["cached"] += 1
                continue
            try:
                evidence = enricher._fetch(indicator)
            except RateLimitedError:
                LOG.warning(
                    "enricher=%s rate-limited for %s", enricher.name, indicator.value
                )
                tally["rate_limited"] += 1
                continue
            except EnricherError as exc:
                LOG.warning(
                    "enricher=%s error for %s: %s", enricher.name, indicator.value, exc
                )
                tally["error"] += 1
                continue
            except Exception as exc:  # noqa: BLE001
                # Last-resort net: a broken source must not bring the
                # cycle down. Log once per cycle would be nice but the
                # surface area here is tiny.
                LOG.warning(
                    "enricher=%s unexpected error for %s: %s: %s",
                    enricher.name,
                    indicator.value,
                    type(exc).__name__,
                    exc,
                )
                tally["error"] += 1
                continue
            if evidence is None:
                tally["none"] += 1
                continue
            self._cache.put(evidence)
            out.append(evidence)
            tally["miss"] += 1
            tally["hit"] += 1

        # Forward-chain: a package/OS lookup may report CVE IDs (OSV's
        # ``vuln_ids``). Re-run each discovered CVE through the chain so the
        # CVE-typed sources (NVD CVSS, CISA KEV exploited-status, GitHub
        # Advisory) enrich it. Skip when the indicator is itself a CVE so we
        # never recurse on the same id.
        if indicator.type is not IndicatorType.CVE:
            seen: set[str] = set()
            for ev in list(out):
                for raw in (ev.details or {}).get("vuln_ids", []) or []:
                    cid = str(raw).upper()
                    if not cid.startswith(("CVE-", "GHSA-")) or cid in seen:
                        continue
                    seen.add(cid)
                    if len(seen) > self._MAX_FORWARD_CVES:
                        break
                    out.extend(self.enrich(Indicator(IndicatorType.CVE, cid)))
        return out

    def enrich_many(
        self, indicators: Iterable[Indicator]
    ) -> dict[Indicator, list[Evidence]]:
        """Convenience for the monitor cycle — one call per batch."""
        result: dict[Indicator, list[Evidence]] = {}
        for ind in indicators:
            if ind in result:
                continue
            result[ind] = self.enrich(ind)
        return result
