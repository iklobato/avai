"""Shodan InternetDB — open ports + CVEs + hostnames for an IP.

No key. No quota (1 rps recommended). Different from the full Shodan
API; this is a free read-only view of their last-scan snapshot.

https://internetdb.shodan.io/
"""
from __future__ import annotations

from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_BASE = "https://internetdb.shodan.io"


class ShodanInternetDBEnricher(Enricher):
    name           = "shodan_internetdb"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("internetdb.shodan.io", 1.0)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(f"{_BASE}/{indicator.value}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        body = resp.json()
        ports = body.get("ports") or []
        cves  = body.get("vulns") or []
        tags  = body.get("tags") or []
        hostnames = body.get("hostnames") or []

        # Heuristic verdict: any known CVE on the IP → suspicious;
        # honeypot/tor/proxy tags → suspicious; otherwise just informational.
        bad_tags = {"honeypot", "tor", "proxy", "compromised", "malware"}
        is_bad = bool(cves) or any(t in bad_tags for t in tags)

        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.SUSPICIOUS if is_bad else VerdictHint.UNKNOWN,
            confidence   = 0.6 if is_bad else 0.3,
            summary      = (
                f"Shodan: ports={ports[:6]} cves={len(cves)} "
                f"tags={tags[:4]} host={hostnames[:1]}"
            ),
            details      = {
                "ports":     ports,
                "vulns":     cves,
                "tags":      tags,
                "hostnames": hostnames,
                "cpes":      body.get("cpes"),
            },
        )
