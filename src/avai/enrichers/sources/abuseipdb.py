"""AbuseIPDB — IP reputation + abuse-confidence score.

Requires ``ABUSEIPDB_API_KEY``. Free tier: 1000 req/day.
https://docs.abuseipdb.com/
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
        return self._evidence(indicator, response.json().get("data", {}))

    def _evidence(self, indicator: Indicator, report: Mapping[str, Any]) -> Evidence:
        score = int(report.get("abuseConfidenceScore", 0))
        reports = int(report.get("totalReports", 0))
        verdict = self._verdict(score, reports)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"AbuseIPDB: score={score} reports={reports} "
                f"country={report.get('countryCode')} "
                f"isp={report.get('isp')}"
            ),
            details={field: report.get(field) for field in DETAIL_FIELDS},
        )

    def _verdict(self, score: int, reports: int) -> Verdict:
        if score >= MALICIOUS_SCORE:
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        if score >= SUSPICIOUS_SCORE or reports >= SUSPICIOUS_REPORTS:
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
