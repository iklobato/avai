"""CIRCL hashlookup — NSRL "known-good" filter.

No key. Free. The NSRL is the National Software Reference Library's
hash database of legitimate vendor binaries. A hit here is a strong
*benign* signal — useful for whitelisting OS-shipped binaries that
would otherwise burn judge tokens.

https://hashlookup.circl.lu/
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

_BASE = "https://hashlookup.circl.lu/lookup"


class CirclHashlookupEnricher(Enricher):
    name           = "circl_hashlookup"
    supports_types = frozenset({IndicatorType.SHA256,
                                IndicatorType.SHA1,
                                IndicatorType.MD5})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24 * 14  # NSRL is slow-moving; cache long.

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("hashlookup.circl.lu", 4.0)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        kind = {
            IndicatorType.SHA256: "sha256",
            IndicatorType.SHA1:   "sha1",
            IndicatorType.MD5:    "md5",
        }[indicator.type]
        resp = self._http.get(
            f"{_BASE}/{kind}/{indicator.value}",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        body = resp.json()
        # "FileName" / "ProductName" are NSRL standard fields.
        product = body.get("ProductName") or body.get("FileName") or "?"
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.BENIGN,
            confidence   = 0.9,
            summary      = f"CIRCL/NSRL: known-good binary ({product})",
            details      = {k: body.get(k) for k in (
                "FileName", "ProductName", "FileSize", "OpSystemCode",
                "trust", "source", "KnownMalicious",
            )},
        )
