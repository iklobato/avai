"""endoflife.date — EOL status of OSes / runtimes.

No key. Used to flag installed OSes / runtimes past end-of-support.
https://endoflife.date/api
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from http import HTTPStatus
from typing import Any, ClassVar

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)

BASE_URL = "https://endoflife.date/api"
ONE_WEEK_HOURS = 24 * 7
PAST_EOL_CONFIDENCE = 0.8
DETAIL_FIELDS = (
    "cycle",
    "eol",
    "latest",
    "support",
    "releaseDate",
    "extendedSupport",
    "lts",
)


class EndOfLifeEnricher(Enricher):
    name = "endoflife"
    supports_types = frozenset({IndicatorType.OS_VERSION})
    requires_token: ClassVar[str | None] = None
    ttl_hours = ONE_WEEK_HOURS
    rate_host = "endoflife.date"
    rate_per_second = 4.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        # value format: "<product>@<cycle>", e.g. "ubuntu@22.04"
        product, _, cycle = indicator.value.partition("@")
        if not (product and cycle):
            return None
        response = self._http.get(f"{BASE_URL}/{product}/{cycle}.json")
        if response.status_code != HTTPStatus.OK:
            return None
        body = response.json()
        if not self._is_past_eol(body.get("eol")):
            return None
        return self._evidence(indicator, body)

    def _evidence(self, indicator: Indicator, body: Mapping[str, Any]) -> Evidence:
        product, _, cycle = indicator.value.partition("@")
        eol = body.get("eol")
        eol_date = eol if isinstance(eol, str) else ""
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.SUSPICIOUS,
            confidence=PAST_EOL_CONFIDENCE,
            summary=f"endoflife.date: {product} {cycle} is past EOL ({eol_date})",
            details={field: body.get(field) for field in DETAIL_FIELDS},
        )

    def _is_past_eol(self, eol: object) -> bool:
        """`eol` may be a bool ("EOL: false / true") or an ISO date."""
        if isinstance(eol, bool):
            return eol
        if not isinstance(eol, str):
            return False
        try:
            return datetime.fromisoformat(eol).date() < datetime.utcnow().date()
        except ValueError:
            return False
