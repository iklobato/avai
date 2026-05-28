"""GreyNoise Community API — "is this IP internet background noise?"

Requires ``GREYNOISE_API_KEY``. Free Community tier.
https://docs.greynoise.io/reference/get_v3-community-ip
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

_BASE = "https://api.greynoise.io/v3/community"


class GreyNoiseEnricher(Enricher):
    name           = "greynoise"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[Optional[str]] = "GREYNOISE_API_KEY"
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("api.greynoise.io", 1.0)
        self._key = os.environ.get("GREYNOISE_API_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(
            f"{_BASE}/{indicator.value}",
            headers={"key": self._key, "Accept": "application/json"},
        )
        if resp.status_code in (404, 400):
            return None
        if resp.status_code != 200:
            return None
        body = resp.json()
        classification = body.get("classification") or "unknown"
        noise = bool(body.get("noise"))
        riot  = bool(body.get("riot"))
        name  = body.get("name") or ""
        if classification == "malicious":
            hint, conf = VerdictHint.MALICIOUS, 0.85
        elif riot:
            # RIOT = "known benign service" (Google, Microsoft, etc.)
            hint, conf = VerdictHint.BENIGN, 0.85
        elif noise:
            hint, conf = VerdictHint.SUSPICIOUS, 0.5
        else:
            hint, conf = VerdictHint.UNKNOWN, 0.3
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = hint,
            confidence   = conf,
            summary      = (f"GreyNoise: classification={classification} "
                            f"noise={noise} riot={riot} name={name}"),
            details      = {k: body.get(k) for k in (
                "classification", "noise", "riot", "name",
                "last_seen", "link",
            )},
        )
