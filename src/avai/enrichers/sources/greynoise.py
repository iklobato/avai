"""GreyNoise Community API — "is this IP internet background noise?"

Requires ``GREYNOISE_API_KEY``. Free Community tier.
https://docs.greynoise.io/reference/get_v3-community-ip
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar

from avai.enrichers.base import (
    Enricher,
    EnricherError,
    Evidence,
    Indicator,
    IndicatorType,
    Verdict,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

BASE_URL = "https://api.greynoise.io/v3/community"
MALICIOUS_CONFIDENCE = 0.85
BENIGN_CONFIDENCE = 0.85
SUSPICIOUS_CONFIDENCE = 0.5
UNKNOWN_CONFIDENCE = 0.3
DETAIL_FIELDS = ("classification", "noise", "riot", "name", "last_seen", "link")


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
        # 404 = IP not observed -> genuine no-opinion. Other non-200s
        # (400 bad request, 401/403 bad key) are real errors; raise so the
        # chain logs them instead of silently masking a misconfiguration.
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        if response.status_code != HTTPStatus.OK:
            raise EnricherError(f"greynoise returned {response.status_code}")
        return self._evidence(indicator, response.json())

    def _evidence(self, indicator: Indicator, body: Mapping[str, Any]) -> Evidence:
        classification = body.get("classification") or "unknown"
        noise = bool(body.get("noise"))
        riot = bool(body.get("riot"))
        verdict = self._verdict(body)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"GreyNoise: classification={classification} "
                f"noise={noise} riot={riot} name={body.get('name') or ''}"
            ),
            details={field: body.get(field) for field in DETAIL_FIELDS},
        )

    def _verdict(self, body: Mapping[str, Any]) -> Verdict:
        if body.get("classification") == "malicious":
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        # RIOT = "known benign service" (Google, Microsoft, etc.)
        if body.get("riot"):
            return Verdict(VerdictHint.BENIGN, BENIGN_CONFIDENCE)
        if body.get("noise"):
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
