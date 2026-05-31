"""Google Safe Browsing v4 — phishing / malware URL classifier.

Requires ``GOOGLE_SAFE_BROWSING_API_KEY``. Free tier: 10k req/day.
https://developers.google.com/safe-browsing/v4/lookup-api
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

_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

from avai import __version__ as _AVAI_VERSION

_CLIENT_INFO = {
    "clientId":      "avai-monitor",
    "clientVersion": _AVAI_VERSION,
}
_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class SafeBrowsingEnricher(Enricher):
    name           = "safe_browsing"
    supports_types = frozenset({IndicatorType.URL})
    requires_token: ClassVar[Optional[str]] = "GOOGLE_SAFE_BROWSING_API_KEY"
    ttl_hours      = 12

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("safebrowsing.googleapis.com", 4.0)
        self._key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        payload = {
            "client": _CLIENT_INFO,
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": indicator.value}],
            },
        }
        resp = self._http.post(f"{_URL}?key={self._key}", json=payload)
        if resp.status_code != 200:
            return None
        body = resp.json() or {}
        matches = body.get("matches") or []
        if not matches:
            return None
        types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.95,
            summary      = f"Google Safe Browsing: matches={types}",
            details      = {"matches": matches[:5]},
        )
