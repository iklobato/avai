"""AbuseIPDB — IP reputation + abuse-confidence score.

Requires ``ABUSEIPDB_API_KEY``. Free tier: 1000 req/day.
https://docs.abuseipdb.com/
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    Verdict,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90
# abuseConfidenceScore (0-100) and report-count cut-offs for the hint.
MALICIOUS_SCORE = 75
SUSPICIOUS_SCORE = 25
SUSPICIOUS_REPORTS = 5
MALICIOUS_CONFIDENCE = 0.9
SUSPICIOUS_CONFIDENCE = 0.7
UNKNOWN_CONFIDENCE = 0.4
DETAIL_FIELDS = (
    "abuseConfidenceScore",
    "totalReports",
    "lastReportedAt",
    "countryCode",
    "usageType",
    "isp",
    "domain",
    "isWhitelisted",
    "isPublic",
)


class AbuseIpDbReport(BaseModel):
    """The ``data`` object of a check reply; other fields are kept as given."""

    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)

    score: int = Field(0, alias="abuseConfidenceScore")
    reports: int = Field(0, alias="totalReports")
    country: str | None = Field(None, alias="countryCode")
    isp: str | None = None

    def details(self) -> dict[str, Any]:
        given = self.model_dump(by_alias=True)
        return {field: given.get(field) for field in DETAIL_FIELDS}


class AbuseIpDbEnricher(Enricher):
    name = "abuseipdb"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[str | None] = "ABUSEIPDB_API_KEY"
    ttl_hours = 12
    rate_host = "api.abuseipdb.com"
    rate_per_second = 2.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            URL,
            RequestOptions(
                headers={"Key": self._token, "Accept": "application/json"},
                params={
                    "ipAddress": indicator.value,
                    "maxAgeInDays": MAX_AGE_DAYS,
                    "verbose": "false",
                },
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        report = AbuseIpDbReport.model_validate(response.json().get("data", {}))
        return self._evidence(indicator, report)

    def _evidence(self, indicator: Indicator, report: AbuseIpDbReport) -> Evidence:
        score, reports = report.score, report.reports
        verdict = self._verdict(score, reports)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"AbuseIPDB: score={score} reports={reports} "
                f"country={report.country} "
                f"isp={report.isp}"
            ),
            details=report.details(),
        )

    def _verdict(self, score: int, reports: int) -> Verdict:
        if score >= MALICIOUS_SCORE:
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        if score >= SUSPICIOUS_SCORE or reports >= SUSPICIOUS_REPORTS:
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
