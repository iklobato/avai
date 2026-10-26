"""Chain-of-responsibility dispatcher.

Given a list of enrichers and a cache, ``EnrichmentChain.enrich(ind)``
returns every piece of evidence any enabled enricher has — pulling
from cache when fresh, hitting the network when not, swallowing
per-enricher failures so one broken source doesn't break the cycle.

The chain is intentionally dumb: it does not aggregate verdicts, does
not pick a single winner. The judge sees every Evidence entry and
decides. ``VerdictHint.worst()`` is provided as a helper for callers
that need a single summary.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from itertools import islice

import requests

from avai.enrichers.base import (
    Enricher,
    EnricherError,
    Evidence,
    Indicator,
    IndicatorType,
    RateLimitedError,
)
from avai.enrichers.cache import EvidenceCache

# What a source fails with in practice: transport errors, an unexpected
# payload shape (bad JSON, missing key, wrong type), or local I/O. A source
# failing this way must not bring the cycle down; anything else is a bug
# and propagates.
SOURCE_FAILURES = (
    EnricherError,
    requests.RequestException,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    IndexError,
    OSError,
)
ADVISORY_PREFIXES = ("CVE-", "GHSA-")


class EnrichmentChain:
    # Cap how many discovered CVE IDs a single indicator forward-chains
    # into CVE lookups — bounds API calls when a package has many advisories.
    MAX_FORWARD_CVES = 10

    def __init__(
        self, enrichers: list[Enricher], cache: EvidenceCache, logger: logging.Logger
    ) -> None:
        self._enrichers = enrichers
        self._cache = cache
        self._logger = logger

    @property
    def sources(self) -> list[str]:
        return [enricher.name for enricher in self._enrichers]

    def enrich(self, indicator: Indicator) -> list[Evidence]:
        found = [
            evidence
            for enricher in self._enrichers
            if enricher.supports(indicator)
            for evidence in [self._lookup(enricher, indicator)]
            if evidence is not None
        ]
        # A CVE indicator never forward-chains, so a CVE source reporting
        # its own id can't recurse.
        if indicator.type is not IndicatorType.CVE:
            found.extend(self._forward_chain(found))
        return found

    def _lookup(self, enricher: Enricher, indicator: Indicator) -> Evidence | None:
        cached = self._cache.get(enricher, indicator)
        if cached is not None:
            return cached
        evidence = self._fetch(enricher, indicator)
        if evidence is not None:
            self._cache.put(evidence)
        return evidence

    def _fetch(self, enricher: Enricher, indicator: Indicator) -> Evidence | None:
        """Ask the source, swallowing its failures so one broken source
        doesn't break the cycle. None when it failed or had nothing."""
        try:
            return enricher.fetch(indicator)
        except RateLimitedError:
            self._logger.warning(
                "enricher=%s rate-limited for %s", enricher.name, indicator.value
            )
        except SOURCE_FAILURES as exc:
            self._logger.warning(
                "enricher=%s error for %s: %s: %s",
                enricher.name,
                indicator.value,
                type(exc).__name__,
                exc,
            )
        return None

    def _forward_chain(self, evidence: list[Evidence]) -> list[Evidence]:
        """A package/OS lookup may report CVE IDs (OSV's ``vuln_ids``).
        Re-run each discovered id through the chain so the CVE-typed sources
        (NVD CVSS, CISA KEV exploited-status, GitHub Advisory) enrich it."""
        advisories = islice(self._advisory_ids(evidence), self.MAX_FORWARD_CVES)
        return [
            found
            for advisory in advisories
            for found in self.enrich(Indicator(IndicatorType.CVE, advisory))
        ]

    def _advisory_ids(self, evidence: list[Evidence]) -> Iterator[str]:
        """The distinct CVE/GHSA ids reported across ``evidence``, upper-cased,
        in the order they appear."""
        reported = (
            str(raw).upper()
            for item in evidence
            for raw in (item.details or {}).get("vuln_ids", []) or []
        )
        seen: set[str] = set()
        for advisory in reported:
            if advisory.startswith(ADVISORY_PREFIXES) and advisory not in seen:
                seen.add(advisory)
                yield advisory
