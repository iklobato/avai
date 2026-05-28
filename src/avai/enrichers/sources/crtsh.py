"""crt.sh — certificate transparency log search by domain.

No key. Free. Useful for detecting recently-issued or unexpectedly-issued
certs against a domain (subdomain enumeration is the opposite use; here
we use it as a freshness/lookback signal). A domain with no CT entries
at all is suspicious; a recently-registered one with brand-new certs
is mildly suspicious.

https://crt.sh/
"""
from __future__ import annotations

from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_URL = "https://crt.sh/"


class CrtShEnricher(Enricher):
    name           = "crtsh"
    supports_types = frozenset({IndicatorType.DOMAIN})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        # crt.sh is famously slow / overloaded — go gentle.
        self._http.set_rate("crt.sh", 0.5)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(
            _URL,
            params={"q": indicator.value, "output": "json"},
            timeout=12.0,
        )
        if resp.status_code != 200:
            return None
        try:
            entries = resp.json() or []
        except ValueError:
            return None
        count = len(entries)
        if count == 0:
            # Domain with no CT entries is unusual.
            return Evidence(
                source       = self.name,
                indicator    = indicator,
                verdict_hint = VerdictHint.SUSPICIOUS,
                confidence   = 0.5,
                summary      = "crt.sh: no certificates found for this domain",
                details      = {"count": 0},
            )
        # Take earliest "not_before" as a domain-age proxy.
        not_befores = [e.get("not_before") for e in entries if e.get("not_before")]
        oldest = min(not_befores) if not_befores else ""
        issuers = sorted({e.get("issuer_name", "") for e in entries})[:3]
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.UNKNOWN,
            confidence   = 0.4,
            summary      = (f"crt.sh: {count} cert(s), earliest={oldest}, "
                            f"issuers={issuers}"),
            details      = {"count": count,
                            "earliest_not_before": oldest,
                            "issuers": issuers},
        )
