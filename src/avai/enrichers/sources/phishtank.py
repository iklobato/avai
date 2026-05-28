"""PhishTank — community-maintained phishing URL DB.

Requires ``PHISHTANK_API_KEY``. Free.
https://phishtank.org/api_info.php
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

_URL = "https://checkurl.phishtank.com/checkurl/"


class PhishTankEnricher(Enricher):
    name           = "phishtank"
    supports_types = frozenset({IndicatorType.URL})
    requires_token: ClassVar[Optional[str]] = "PHISHTANK_API_KEY"
    ttl_hours      = 12

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("checkurl.phishtank.com", 2.0)
        self._key = os.environ.get("PHISHTANK_API_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.post(
            _URL,
            data={"url": indicator.value, "format": "json", "app_key": self._key},
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
        results = (body.get("results") or {})
        in_db   = bool(results.get("in_database"))
        verified = bool(results.get("verified"))
        valid    = bool(results.get("valid"))
        if not (in_db and verified and valid):
            return None
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.93,
            summary      = (f"PhishTank: known-phishing URL "
                            f"(id={results.get('phish_id')})"),
            details      = {k: results.get(k) for k in (
                "phish_id", "phish_detail_page", "verified_at",
                "submitted_at",
            )},
        )
