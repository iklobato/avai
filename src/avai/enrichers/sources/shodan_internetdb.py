"""Shodan InternetDB — open ports + CVEs + hostnames for an IP.

No key. No quota (1 rps recommended). Different from the full Shodan
API; this is a free read-only view of their last-scan snapshot.

https://internetdb.shodan.io/
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
    Verdict,
    VerdictHint,
)

BASE_URL = "https://internetdb.shodan.io"
BAD_TAGS = frozenset({"honeypot", "tor", "proxy", "compromised", "malware"})
SUSPICIOUS_CONFIDENCE = 0.6
UNKNOWN_CONFIDENCE = 0.3
LISTED_PORTS = 6
LISTED_TAGS = 4


class ShodanInternetDBEnricher(Enricher):
    name = "shodan_internetdb"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 24
    rate_host = "internetdb.shodan.io"
    rate_per_second = 1.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(f"{BASE_URL}/{indicator.value}")
        if response.status_code != HTTPStatus.OK:
            return None
        return self._evidence(indicator, response.json())

    def _evidence(self, indicator: Indicator, body: Mapping[str, Any]) -> Evidence:
        details = self._details(body)
        ports, cves, tags = details["ports"], details["vulns"], details["tags"]
        verdict = self._verdict(cves, tags)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"Shodan: ports={ports[:LISTED_PORTS]} cves={len(cves)} "
                f"tags={tags[:LISTED_TAGS]} host={details['hostnames'][:1]}"
            ),
            details=details,
        )

    def _details(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "ports": body.get("ports") or [],
            "vulns": body.get("vulns") or [],
            "tags": body.get("tags") or [],
            "hostnames": body.get("hostnames") or [],
            "cpes": body.get("cpes"),
        }

    def _verdict(self, cves: list[str], tags: list[str]) -> Verdict:
        """Any known CVE on the IP → suspicious; honeypot/tor/proxy tags →
        suspicious; otherwise just informational."""
        if cves or any(tag in BAD_TAGS for tag in tags):
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)
