"""GitHub Advisory Database — curated advisories with CVSS + fix versions.

Requires ``GITHUB_TOKEN`` (any GitHub PAT with public_repo read).
https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, field_validator

from avai.enrichers.base import (
    CVSS_CRITICAL,
    CVSS_HIGH,
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    Verdict,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://api.github.com/advisories"
API_VERSION = "2022-11-28"
SUMMARY_WIDTH = 80
MALICIOUS_CONFIDENCE = 0.9
SUSPICIOUS_CONFIDENCE = 0.7
UNKNOWN_CONFIDENCE = 0.4
DETAIL_FIELDS = (
    "ghsa_id",
    "summary",
    "severity",
    "cvss",
    "vulnerabilities",
    "published_at",
)


class AdvisoryCvss(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")

    score: float | None = None


class Advisory(BaseModel):
    """One GitHub advisory; fields not read here are kept as given."""

    model_config = ConfigDict(frozen=True, extra="allow")

    severity: str = ""
    summary: str | None = None
    cvss: AdvisoryCvss | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, value: Any) -> str:
        return (value or "").lower()

    def score(self) -> float | None:
        return self.cvss.score if self.cvss else None

    def details(self) -> dict[str, Any]:
        given = self.model_dump()
        return {field: given.get(field) for field in DETAIL_FIELDS}


class GitHubAdvisoryEnricher(Enricher):
    name = "github_advisory"
    supports_types = frozenset({IndicatorType.CVE})
    requires_token: ClassVar[str | None] = "GITHUB_TOKEN"
    ttl_hours = 24
    rate_host = "api.github.com"
    rate_per_second = 4.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            URL,
            RequestOptions(
                params={"cve_id": indicator.value.upper()},
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        advisories = response.json() or []
        if not advisories:
            return None
        return self._evidence(indicator, Advisory.model_validate(advisories[0]))

    def _evidence(self, indicator: Indicator, advisory: Advisory) -> Evidence:
        severity, score = advisory.severity, advisory.score()
        verdict = self._verdict(severity, score)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"GH Advisory: severity={severity} score={score} — "
                f"{advisory.summary!s:.{SUMMARY_WIDTH}}"
            ),
            details=advisory.details(),
        )

    def _verdict(self, severity: str, score: float | None) -> Verdict:
        if severity == "critical" or (score and score >= CVSS_CRITICAL):
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        if severity == "high" or (score and score >= CVSS_HIGH):
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
