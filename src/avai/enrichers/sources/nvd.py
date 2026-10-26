"""NIST NVD — CVE detail lookup (description + CVSS).

Optional API key (``NVD_API_KEY``) ups the rate limit from 5 req / 30 s
to 50 req / 30 s.
https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar

from avai.enrichers.base import (
    CVSS_CRITICAL,
    CVSS_HIGH,
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    RateLimitedError,
    VerdictHint,
)
from avai.enrichers.http import HttpClient, RequestOptions

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
TIMEOUT_S = 10.0
DESCRIPTION_WIDTH = 200
ONE_WEEK_HOURS = 24 * 7
CVSS_CONFIDENCE = 0.7
# Slow lane without a key; the key buys a faster rate lane.
KEYED_RATE_PER_SECOND = 1.5
KEYLESS_RATE_PER_SECOND = 0.15


class NvdEnricher(Enricher):
    name = "nvd"
    supports_types = frozenset({IndicatorType.CVE})
    # No required token — but if NVD_API_KEY is set we send it.
    requires_token: ClassVar[str | None] = None
    ttl_hours = ONE_WEEK_HOURS
    rate_host = "services.nvd.nist.gov"

    @classmethod
    def create(cls, http: HttpClient, env: Mapping[str, str]) -> NvdEnricher:
        key = env.get(API_KEY_ENV, "")
        rate = KEYED_RATE_PER_SECOND if key else KEYLESS_RATE_PER_SECOND
        http.set_rate(cls.rate_host, rate)
        return cls(http, key)

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            URL,
            RequestOptions(
                params={"cveId": indicator.value.upper()},
                headers={"apiKey": self._token} if self._token else {},
                timeout=TIMEOUT_S,
            ),
        )
        # NVD returns 403 when the (keyless) rate window is exceeded; treat
        # it as a rate-limit so the chain backs off rather than recording a
        # silent "no opinion" on every CVE under load.
        if response.status_code == HTTPStatus.FORBIDDEN:
            raise RateLimitedError("nvd returned 403 (rate limited / over quota)")
        if response.status_code != HTTPStatus.OK:
            return None
        vulnerabilities = response.json().get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        return self._evidence(indicator, vulnerabilities[0].get("cve") or {})

    def _evidence(self, indicator: Indicator, cve: Mapping[str, Any]) -> Evidence:
        metrics = cve.get("metrics") or {}
        cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData") or {}
        score = cvss31.get("baseScore")
        description = self._english_description(cve)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=self._hint(score),
            confidence=CVSS_CONFIDENCE,
            summary=f"NVD: CVSS={score} {cvss31.get('baseSeverity') or '?'} — {description}",
            details={
                "cvss31": cvss31,
                "description": description,
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
            },
        )

    def _english_description(self, cve: Mapping[str, Any]) -> str:
        descriptions = cve.get("descriptions", [])
        english = (
            entry.get("value") for entry in descriptions if entry.get("lang") == "en"
        )
        return next(english, "")[:DESCRIPTION_WIDTH]

    def _hint(self, score: float | None) -> VerdictHint:
        if score and score >= CVSS_CRITICAL:
            return VerdictHint.MALICIOUS
        if score and score >= CVSS_HIGH:
            return VerdictHint.SUSPICIOUS
        return VerdictHint.UNKNOWN
