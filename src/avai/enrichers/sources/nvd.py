"""NIST NVD — CVE detail lookup (description + CVSS).

Optional API key (``NVD_API_KEY``) ups the rate limit from 5 req / 30 s
to 50 req / 30 s.
https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import Field, field_validator

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
from avai.enrichers.reply import ApiReply
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


class CvssData(ApiReply):
    """CVSS v3.1 numbers."""

    base_score: object = Field(None, alias="baseScore")
    base_severity: object = Field(None, alias="baseSeverity")


class CvssMetric(ApiReply):
    cvss_data: CvssData = Field(default_factory=CvssData, alias="cvssData")

    @field_validator("cvss_data", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or {}


class CveMetrics(ApiReply):
    cvss_v31: list[CvssMetric] = Field([], alias="cvssMetricV31")

    @field_validator("cvss_v31", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or []

    def cvss(self) -> CvssData:
        """The first v3.1 metric's numbers, empty when NVD lists none."""
        return self.cvss_v31[0].cvss_data if self.cvss_v31 else CvssData()


class CveText(ApiReply):
    lang: object = None
    value: object = None


class CveRecord(ApiReply):
    """The ``cve`` object of one NVD vulnerability."""

    published: object = None
    last_modified: object = Field(None, alias="lastModified")
    descriptions: list[CveText] = []
    metrics: CveMetrics = Field(default_factory=CveMetrics)

    @field_validator("metrics", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or {}

    def english_description(self) -> str:
        english = (entry.value for entry in self.descriptions if entry.lang == "en")
        return next(english, "")[:DESCRIPTION_WIDTH]


class NvdVulnerability(ApiReply):
    cve: CveRecord = Field(default_factory=CveRecord)

    @field_validator("cve", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or {}


class NvdReply(ApiReply):
    vulnerabilities: list[NvdVulnerability] = []

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or []


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
        if not self.answered(response):
            return None
        reply = NvdReply.model_validate(response.json())
        if not reply.vulnerabilities:
            return None
        return self._evidence(indicator, reply.vulnerabilities[0].cve)

    def _evidence(self, indicator: Indicator, cve: CveRecord) -> Evidence:
        cvss31 = cve.metrics.cvss()
        score = cvss31.base_score
        description = cve.english_description()
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=self._hint(score),
            confidence=CVSS_CONFIDENCE,
            summary=(
                f"NVD: CVSS={score} {cvss31.base_severity or '?'} — {description}"
            ),
            details={
                "cvss31": cvss31.as_given(),
                "description": description,
                "published": cve.published,
                "modified": cve.last_modified,
            },
        )

    def _hint(self, score: float | None) -> VerdictHint:
        if score and score >= CVSS_CRITICAL:
            return VerdictHint.MALICIOUS
        if score and score >= CVSS_HIGH:
            return VerdictHint.SUSPICIOUS
        return VerdictHint.UNKNOWN
