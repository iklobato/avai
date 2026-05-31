"""VirusTotal v3 — multi-engine reputation for files, URLs, domains, IPs.

Requires ``VT_API_KEY``. Free tier: 4 req/min, 500/day.
https://docs.virustotal.com/reference/files
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

_BASE = "https://www.virustotal.com/api/v3"


def _path_for(indicator: Indicator) -> Optional[str]:
    if indicator.type in (IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5):
        return f"/files/{indicator.value}"
    if indicator.type is IndicatorType.IPV4:
        return f"/ip_addresses/{indicator.value}"
    if indicator.type is IndicatorType.DOMAIN:
        return f"/domains/{indicator.value}"
    if indicator.type is IndicatorType.URL:
        # VT URL endpoint uses base64url-encoded URL as the ID.
        import base64
        url_id = base64.urlsafe_b64encode(
            indicator.value.encode()).rstrip(b"=").decode()
        return f"/urls/{url_id}"
    return None


class VirusTotalEnricher(Enricher):
    name           = "virustotal"
    supports_types = frozenset({
        IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5,
        IndicatorType.IPV4, IndicatorType.DOMAIN, IndicatorType.URL,
    })
    requires_token: ClassVar[Optional[str]] = "VT_API_KEY"
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        # Free tier: 4 req / minute → ~0.066 rps. Pad to 0.06 for safety.
        self._http.set_rate("www.virustotal.com", 0.06)
        self._key = os.environ.get("VT_API_KEY", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        path = _path_for(indicator)
        if path is None:
            return None
        resp = self._http.get(
            f"{_BASE}{path}",
            headers={"x-apikey": self._key, "Accept": "application/json"},
            timeout=12.0,
        )
        if resp.status_code in (404, 400):
            return None
        if resp.status_code != 200:
            return None
        body = resp.json().get("data", {}).get("attributes", {})
        stats = body.get("last_analysis_stats") or {}
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1
        ratio      = (malicious + suspicious) / total
        if malicious >= 5 or ratio >= 0.2:
            hint = VerdictHint.MALICIOUS
            conf = 0.95
        elif malicious >= 1 or suspicious >= 3:
            hint = VerdictHint.SUSPICIOUS
            conf = 0.7
        elif total >= 10 and malicious == 0 and suspicious == 0:
            hint = VerdictHint.BENIGN
            conf = 0.6
        else:
            hint = VerdictHint.UNKNOWN
            conf = 0.3
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = hint,
            confidence   = conf,
            summary      = (f"VirusTotal: {malicious} malicious + "
                            f"{suspicious} suspicious / {total} engines"),
            details      = {"stats": stats,
                            "reputation": body.get("reputation"),
                            "names": (body.get("names") or [])[:5],
                            "type_description": body.get("type_description"),
                            "popular_threat_classification":
                                body.get("popular_threat_classification")},
        )
