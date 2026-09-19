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
from itertools import islice
from typing import Iterable, Optional

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

    @property
    def sources(self) -> list[str]:
        return [e.name for e in self._enrichers]

    def enrich(self, indicator: Indicator) -> list[Evidence]:
        out: list[Evidence] = []
        for enricher in self._enrichers:
            if not enricher.supports(indicator):
                continue
            evidence = self._lookup(enricher, indicator)
            if evidence is not None:
                out.append(evidence)
        # A CVE indicator never forward-chains, so a CVE source reporting
        # its own id can't recurse.
        if indicator.type is not IndicatorType.CVE:
            out.extend(self._forward_chain(out))
        return out

    def _lookup(self, enricher: Enricher, indicator: Indicator) -> Optional[Evidence]:
        cached = self._cache.get(enricher, indicator)
        if cached is not None:
            return cached
        evidence = self._fetch(enricher, indicator)
        if evidence is not None:
            self._cache.put(evidence)
        return evidence

    @staticmethod
    def _fetch(enricher: Enricher, indicator: Indicator) -> Optional[Evidence]:
        """Ask the source, swallowing its failures so one broken source
        doesn't break the cycle. None when it failed or had nothing."""
        try:
            evidence = enricher._fetch(indicator)
        except RateLimitedError:
            LOG.warning(
                "enricher=%s rate-limited for %s", enricher.name, indicator.value
            )
            return None
        except EnricherError as exc:
            LOG.warning(
                "enricher=%s error for %s: %s", enricher.name, indicator.value, exc
            )
            return None
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
            return None
        return evidence

    def _forward_chain(self, evidence: list[Evidence]) -> list[Evidence]:
        """A package/OS lookup may report CVE IDs (OSV's ``vuln_ids``).
        Re-run each discovered id through the chain so the CVE-typed sources
        (NVD CVSS, CISA KEV exploited-status, GitHub Advisory) enrich it."""
        ids = islice(_advisory_ids(evidence), self._MAX_FORWARD_CVES)
        return [
            found
            for advisory in ids
            for found in self.enrich(Indicator(IndicatorType.CVE, advisory))
        ]


def _advisory_ids(evidence: list[Evidence]) -> Iterable[str]:
    """The distinct CVE/GHSA ids reported across ``evidence``, upper-cased,
    in the order they appear."""
    seen: set[str] = set()
    for ev in evidence:
        for raw in (ev.details or {}).get("vuln_ids", []) or []:
            advisory = str(raw).upper()
            if advisory.startswith(("CVE-", "GHSA-")) and advisory not in seen:
                seen.add(advisory)
                yield advisory
