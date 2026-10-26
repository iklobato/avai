"""abuse.ch ThreatFox — mixed IOC search (IP / domain / URL / hash).

Requires ``ABUSE_CH_AUTH_KEY`` (free; same key as MalwareBazaar +
URLhaus). Register at https://auth.abuse.ch/.
https://threatfox-api.abuse.ch/
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
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

URL = "https://threatfox-api.abuse.ch/api/v1/"
MALICIOUS_CONFIDENCE = 0.92
DETAIL_FIELDS = (
    "malware",
    "malware_alias",
    "threat_type",
    "first_seen",
    "last_seen",
    "tags",
    "confidence_level",
)


class ThreatFoxEnricher(Enricher):
    name = "threatfox"
    supports_types = frozenset(
        {
            IndicatorType.IPV4,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.SHA256,
            IndicatorType.SHA1,
            IndicatorType.MD5,
        }
    )
    requires_token: ClassVar[str | None] = "ABUSE_CH_AUTH_KEY"
    ttl_hours = 12
    rate_host = "threatfox-api.abuse.ch"
    rate_per_second = 2.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.post(
            URL,
            RequestOptions(
                json={"query": "search_ioc", "search_term": indicator.value},
                headers={"Auth-Key": self._token},
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        body = response.json()
        if body.get("query_status") != "ok":
            return None
        iocs = body.get("data") or []
        if not iocs:
            return None
        return self._evidence(indicator, iocs[0])

    def _evidence(self, indicator: Indicator, ioc: Mapping[str, Any]) -> Evidence:
        malware = ioc.get("malware") or ioc.get("malware_alias") or "?"
        threat = ioc.get("threat_type") or "?"
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"ThreatFox: known IOC, malware={malware} type={threat}",
            details={field: ioc.get(field) for field in DETAIL_FIELDS},
        )
