"""PhishTank — community-maintained phishing URL DB.

Requires ``PHISHTANK_API_KEY``. Free.
https://phishtank.org/api_info.php
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import field_validator

from avai.enrichers.reply import ApiReply
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


class PhishResult(ApiReply):
    """The ``results`` object of a URL check."""

    in_database: bool = False
    verified: bool = False
    valid: bool = False
    phish_id: object = None

    @field_validator("in_database", "verified", "valid", mode="before")
    @classmethod
    def _truthy(cls, value: Any) -> bool:
        return bool(value)

    def confirmed(self) -> bool:
        return self.in_database and self.verified and self.valid


class PhishReply(ApiReply):
    results: PhishResult = PhishResult()

    @field_validator("results", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or {}


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
        if not self.answered(response):
            return None
        results = PhishReply.model_validate(response.json()).results
        if not results.confirmed():
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"PhishTank: known-phishing URL (id={results.phish_id})",
            details=results.given(DETAIL_FIELDS),
        )
