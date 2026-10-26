"""Google Safe Browsing v4 — phishing / malware URL classifier.

Requires ``GOOGLE_SAFE_BROWSING_API_KEY``. Free tier: 10k req/day.
https://developers.google.com/safe-browsing/v4/lookup-api
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from avai import __version__ as AVAI_VERSION
from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CLIENT_ID = "avai-monitor"
THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)
LISTED_MATCHES = 5
MALICIOUS_CONFIDENCE = 0.95


class SafeBrowsingEnricher(Enricher):
    name = "safe_browsing"
    supports_types = frozenset({IndicatorType.URL})
    requires_token: ClassVar[str | None] = "GOOGLE_SAFE_BROWSING_API_KEY"
    ttl_hours = 12
    rate_host = "safebrowsing.googleapis.com"
    rate_per_second = 4.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.post(
            f"{URL}?key={self._token}",
            RequestOptions(json=self._query(indicator)),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        matches = (response.json() or {}).get("matches") or []
        if not matches:
            return None
        return self._evidence(indicator, matches)

    def _evidence(
        self, indicator: Indicator, matches: list[dict[str, Any]]
    ) -> Evidence:
        threat_types = sorted(
            {match.get("threatType") for match in matches if match.get("threatType")}
        )
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"Google Safe Browsing: matches={threat_types}",
            details={"matches": matches[:LISTED_MATCHES]},
        )

    def _query(self, indicator: Indicator) -> dict[str, Any]:
        return {
            "client": {"clientId": CLIENT_ID, "clientVersion": AVAI_VERSION},
            "threatInfo": {
                "threatTypes": list(THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": indicator.value}],
            },
        }
