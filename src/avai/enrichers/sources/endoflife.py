"""endoflife.date — EOL status of OSes / runtimes.

No key. Used to flag installed OSes / runtimes past end-of-support.
https://endoflife.date/api
"""

from __future__ import annotations

from datetime import datetime
from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import model_validator

from avai.enrichers.reply import ApiReply
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


class ReleaseCycle(ApiReply):
    """One endoflife.date release cycle. ``eol`` is either a bool ("has it
    ended") or an ISO date; it is read into ``eol_flag`` and ``eol_date``."""

    eol_flag: bool = False
    eol_date: str = ""

    @model_validator(mode="before")
    @classmethod
    def _split_eol(cls, raw_cycle: Any) -> Any:
        if not isinstance(raw_cycle, dict):
            return raw_cycle
        eol = raw_cycle.get("eol")
        flag = eol if isinstance(eol, bool) else False
        date = eol if isinstance(eol, str) else ""
        return {**raw_cycle, "eol_flag": flag, "eol_date": date}


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
        release = ReleaseCycle.model_validate(response.json())
        if not self._is_past_eol(release):
            return None
        return self._evidence(indicator, release)

    def _evidence(self, indicator: Indicator, release: ReleaseCycle) -> Evidence:
        product, _, cycle = indicator.value.partition("@")
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.SUSPICIOUS,
            confidence=PAST_EOL_CONFIDENCE,
            summary=(
                f"endoflife.date: {product} {cycle} is past EOL ({release.eol_date})"
            ),
            details=release.given(DETAIL_FIELDS),
        )

    def _is_past_eol(self, release: ReleaseCycle) -> bool:
        if release.eol_flag or not release.eol_date:
            return release.eol_flag
        try:
            ends = datetime.fromisoformat(release.eol_date).date()
        except ValueError:
            return False
        return ends < datetime.utcnow().date()
