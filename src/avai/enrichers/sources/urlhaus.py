"""abuse.ch URLhaus — malware-distribution URLs and domains.

Requires ``ABUSE_CH_AUTH_KEY`` (free; same key as MalwareBazaar +
ThreatFox). Register at https://auth.abuse.ch/.
https://urlhaus-api.abuse.ch/
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

_URL_LOOKUP    = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_LOOKUP   = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausEnricher(Enricher):
    name           = "urlhaus"
    supports_types = frozenset({IndicatorType.URL, IndicatorType.DOMAIN})
    requires_token: ClassVar[Optional[str]] = "ABUSE_CH_AUTH_KEY"
    ttl_hours      = 12

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("urlhaus-api.abuse.ch", 2.0)
        self._key = os.environ.get("ABUSE_CH_AUTH_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        if indicator.type is IndicatorType.URL:
            endpoint = _URL_LOOKUP
            field = "url"
        else:
            endpoint = _HOST_LOOKUP
            field = "host"
        resp = self._http.post(
            endpoint,
            data={field: indicator.value},
            headers={"Auth-Key": self._key},
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
        if body.get("query_status") != "ok":
            return None

        threat = body.get("threat") or body.get("url_status") or "?"
        tags   = body.get("tags") or []
        first  = body.get("date_added") or body.get("firstseen") or ""
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.9,
            summary      = f"URLhaus: known-malicious {field}, threat={threat} tags={tags} first={first}",
            details      = {k: body.get(k) for k in (
                "threat", "url_status", "tags", "date_added",
                "blacklists", "payloads",
            )},
        )
