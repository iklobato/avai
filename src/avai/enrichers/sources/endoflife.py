"""endoflife.date — EOL status of OSes / runtimes.

No key. Used to flag installed OSes / runtimes past end-of-support.
https://endoflife.date/api
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_BASE = "https://endoflife.date/api"


class EndOfLifeEnricher(Enricher):
    name           = "endoflife"
    supports_types = frozenset({IndicatorType.OS_VERSION})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24 * 7

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("endoflife.date", 4.0)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        # value format: "<product>@<cycle>", e.g. "ubuntu@22.04"
        product, _, cycle = indicator.value.partition("@")
        if not (product and cycle):
            return None
        resp = self._http.get(f"{_BASE}/{product}/{cycle}.json")
        if resp.status_code != 200:
            return None
        body = resp.json()
        eol = body.get("eol")
        # `eol` may be a bool ("EOL: false / true") or an ISO date.
        is_eol = False
        eol_date_str = ""
        if isinstance(eol, bool):
            is_eol = eol
        elif isinstance(eol, str):
            eol_date_str = eol
            try:
                is_eol = datetime.fromisoformat(eol).date() < datetime.utcnow().date()
            except ValueError:
                pass
        if not is_eol:
            return None
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.SUSPICIOUS,
            confidence   = 0.8,
            summary      = f"endoflife.date: {product} {cycle} is past EOL ({eol_date_str})",
            details      = {k: body.get(k) for k in (
                "cycle", "eol", "latest", "support", "releaseDate",
                "extendedSupport", "lts",
            )},
        )
