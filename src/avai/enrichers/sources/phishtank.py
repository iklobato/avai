"""PhishTank — community-maintained phishing URL DB.

Requires ``PHISHTANK_API_KEY``. Free.
https://phishtank.org/api_info.php
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
    RateLimitedError,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://checkurl.phishtank.com/checkurl/"
# PhishTank's quota response; not in HTTPStatus.
BANDWIDTH_LIMIT_EXCEEDED = 509
MALICIOUS_CONFIDENCE = 0.93
DETAIL_FIELDS = ("phish_id", "phish_detail_page", "verified_at", "submitted_at")


class PhishTankEnricher(Enricher):
    name = "phishtank"
    supports_types = frozenset({IndicatorType.URL})
    requires_token: ClassVar[str | None] = "PHISHTANK_API_KEY"
    ttl_hours = 12
    rate_host = "checkurl.phishtank.com"
    rate_per_second = 2.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        form = {"url": indicator.value, "format": "json", "app_key": self._token}
        response = self._http.post(URL, RequestOptions(form_body=form))
        # PhishTank signals throttling with HTTP 509 (not 429), so the
        # shared client won't catch it — surface it as a rate-limit.
        if response.status_code == BANDWIDTH_LIMIT_EXCEEDED:
            raise RateLimitedError("phishtank returned 509 (rate limited)")
        if response.status_code != HTTPStatus.OK:
            return None
        results = response.json().get("results") or {}
        if not self._is_confirmed_phish(results):
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"PhishTank: known-phishing URL (id={results.get('phish_id')})",
            details={field: results.get(field) for field in DETAIL_FIELDS},
        )

    def _is_confirmed_phish(self, results: Mapping[str, Any]) -> bool:
        return all(
            bool(results.get(flag)) for flag in ("in_database", "verified", "valid")
        )
