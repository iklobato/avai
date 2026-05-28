"""AbuseIPDB — IP reputation + abuse-confidence score.

Requires ``ABUSEIPDB_API_KEY``. Free tier: 1000 req/day.
https://docs.abuseipdb.com/
"""
from __future__ import annotations

import os
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpDbEnricher(Enricher):
    name           = "abuseipdb"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[Optional[str]] = "ABUSEIPDB_API_KEY"
    ttl_hours      = 12

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("api.abuseipdb.com", 2.0)
        self._key = os.environ.get("ABUSEIPDB_API_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(
            _URL,
            headers={"Key": self._key, "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": 90,
                    "verbose": "false"},
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        if score >= 75:
            hint = VerdictHint.MALICIOUS
            conf = 0.9
        elif score >= 25 or reports >= 5:
            hint = VerdictHint.SUSPICIOUS
            conf = 0.7
        else:
            hint = VerdictHint.UNKNOWN
            conf = 0.4
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = hint,
            confidence   = conf,
            summary      = (f"AbuseIPDB: score={score} reports={reports} "
                            f"country={data.get('countryCode')} "
                            f"isp={data.get('isp')}"),
            details      = {k: data.get(k) for k in (
                "abuseConfidenceScore", "totalReports", "lastReportedAt",
                "countryCode", "usageType", "isp", "domain",
                "isWhitelisted", "isPublic",
            )},
        )
