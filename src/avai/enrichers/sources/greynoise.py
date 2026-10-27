"""GreyNoise Community API — "is this IP internet background noise?"

Requires ``GREYNOISE_API_KEY``. Free Community tier.
https://docs.greynoise.io/reference/get_v3-community-ip
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import field_validator

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    Verdict,
    VerdictHint,
)
from avai.enrichers.reply import ApiReply
from avai.enrichers.http import RequestOptions

BASE_URL = "https://api.greynoise.io/v3/community"
MALICIOUS_CONFIDENCE = 0.85
BENIGN_CONFIDENCE = 0.85
SUSPICIOUS_CONFIDENCE = 0.5
UNKNOWN_CONFIDENCE = 0.3
DETAIL_FIELDS = ("classification", "noise", "riot", "name", "last_seen", "link")


class NoiseRecord(ApiReply):
    """A GreyNoise community lookup."""

    classification: object = None
    noise: bool = False
    riot: bool = False
    name: object = None

    @field_validator("noise", "riot", mode="before")
    @classmethod
    def _truthy(cls, value: Any) -> bool:
        return bool(value)


class GreyNoiseEnricher(Enricher):
    name = "greynoise"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[str | None] = "GREYNOISE_API_KEY"
    ttl_hours = 24
    rate_host = "api.greynoise.io"
    rate_per_second = 1.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            f"{BASE_URL}/{indicator.value}",
            RequestOptions(headers={"key": self._token, "Accept": "application/json"}),
        )
        # 404 = IP not observed: a genuine no-opinion.
        if not self.answered(response):
            return None
        return self._evidence(indicator, NoiseRecord.model_validate(response.json()))

    def _evidence(self, indicator: Indicator, record: NoiseRecord) -> Evidence:
        classification = record.classification or "unknown"
        noise, riot = record.noise, record.riot
        verdict = self._verdict(record)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"GreyNoise: classification={classification} "
                f"noise={noise} riot={riot} name={record.name or ''}"
            ),
            details=record.given(DETAIL_FIELDS),
        )

    def _verdict(self, record: NoiseRecord) -> Verdict:
        if record.classification == "malicious":
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        # RIOT = "known benign service" (Google, Microsoft, etc.)
        if record.riot:
            return Verdict(VerdictHint.BENIGN, BENIGN_CONFIDENCE)
        if record.noise:
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
