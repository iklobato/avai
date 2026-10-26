"""crt.sh — certificate transparency log search by domain.

No key. Free. Useful for detecting recently-issued or unexpectedly-issued
certs against a domain (subdomain enumeration is the opposite use; here
we use it as a freshness/lookback signal). A domain with no CT entries
at all is suspicious; a recently-registered one with brand-new certs
is mildly suspicious.

https://crt.sh/
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://crt.sh/"
TIMEOUT_S = 12.0
LISTED_ISSUERS = 3
NO_CERTS_CONFIDENCE = 0.5
CERTS_CONFIDENCE = 0.4


class CrtShEnricher(Enricher):
    name = "crtsh"
    supports_types = frozenset({IndicatorType.DOMAIN})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 24
    rate_host = "crt.sh"
    # crt.sh is famously slow / overloaded — go gentle.
    rate_per_second = 0.5

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            URL,
            RequestOptions(
                params={"q": indicator.value, "output": "json"}, timeout=TIMEOUT_S
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        try:
            entries = response.json() or []
        except ValueError:
            return None
        if not entries:
            return self._no_certificates(indicator)
        return self._certificates(indicator, entries)

    def _no_certificates(self, indicator: Indicator) -> Evidence:
        # Domain with no CT entries is unusual.
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.SUSPICIOUS,
            confidence=NO_CERTS_CONFIDENCE,
            summary="crt.sh: no certificates found for this domain",
            details={"count": 0},
        )

    def _certificates(
        self, indicator: Indicator, entries: list[Mapping[str, Any]]
    ) -> Evidence:
        oldest = self._earliest_not_before(entries)
        issuers = sorted({entry.get("issuer_name", "") for entry in entries})
        listed = issuers[:LISTED_ISSUERS]
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.UNKNOWN,
            confidence=CERTS_CONFIDENCE,
            summary=f"crt.sh: {len(entries)} cert(s), earliest={oldest}, issuers={listed}",
            details={
                "count": len(entries),
                "earliest_not_before": oldest,
                "issuers": listed,
            },
        )

    def _earliest_not_before(self, entries: list[Mapping[str, Any]]) -> str:
        """Earliest "not_before" across the certs, as a domain-age proxy."""
        not_befores = [
            entry.get("not_before") for entry in entries if entry.get("not_before")
        ]
        return min(not_befores) if not_befores else ""
