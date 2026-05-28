"""abuse.ch ThreatFox — mixed IOC search (IP / domain / URL / hash).

Requires ``ABUSE_CH_AUTH_KEY`` (free; same key as MalwareBazaar +
URLhaus). Register at https://auth.abuse.ch/.
https://threatfox-api.abuse.ch/
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

_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxEnricher(Enricher):
    name           = "threatfox"
    supports_types = frozenset({
        IndicatorType.IPV4, IndicatorType.DOMAIN, IndicatorType.URL,
        IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5,
    })
    requires_token: ClassVar[Optional[str]] = "ABUSE_CH_AUTH_KEY"
    ttl_hours      = 12

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("threatfox-api.abuse.ch", 2.0)
        self._key = os.environ.get("ABUSE_CH_AUTH_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.post(
            _URL,
            json={"query": "search_ioc", "search_term": indicator.value},
            headers={"Auth-Key": self._key},
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
        if body.get("query_status") != "ok":
            return None
        data = body.get("data") or []
        if not data:
            return None
        first = data[0]
        malware = first.get("malware") or first.get("malware_alias") or "?"
        threat  = first.get("threat_type") or "?"
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.92,
            summary      = f"ThreatFox: known IOC, malware={malware} type={threat}",
            details      = {k: first.get(k) for k in (
                "malware", "malware_alias", "threat_type",
                "first_seen", "last_seen", "tags", "confidence_level",
            )},
        )
