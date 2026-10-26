"""ipwho.is — free, keyless IP geolocation (country / region / city / ASN).

No API key, HTTPS, no hard quota (we stay polite at 1 rps). This is a
purely *informational* source: it never raises a threat verdict, it
just attaches where a destination IP sits geographically and on the
network so the dashboard can show a location per destination.

https://ipwho.is/
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

BASE_URL = "https://ipwho.is"
ONE_WEEK_HOURS = 24 * 7
INFORMATIONAL_CONFIDENCE = 0.0


class IpwhoisGeoEnricher(Enricher):
    name = "ipwhois_geo"
    supports_types = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})
    requires_token: ClassVar[str | None] = None
    ttl_hours = ONE_WEEK_HOURS  # geolocation is stable — refresh weekly
    rate_host = "ipwho.is"
    rate_per_second = 1.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(f"{BASE_URL}/{indicator.value}")
        if response.status_code != HTTPStatus.OK:
            return None
        body = response.json() or {}
        # ipwho.is answers {"success": false, "message": ...} for bogon /
        # reserved / unroutable addresses — treat as "no opinion".
        if not body.get("success"):
            return None
        return self._evidence(indicator, body)

    def _evidence(self, indicator: Indicator, body: Mapping[str, Any]) -> Evidence:
        details = self._details(body)
        place = (details["city"], details["region"], details["country"])
        where = ", ".join(part for part in place if part)
        asn, org = details["asn"], details["org"]
        network = f" (AS{asn} {org})".rstrip() if (asn or org) else ""
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.UNKNOWN,  # informational, not a threat
            confidence=INFORMATIONAL_CONFIDENCE,
            summary=f"Geo: {where or 'unknown'}{network}",
            details=details,
        )

    def _details(self, body: Mapping[str, Any]) -> dict[str, Any]:
        connection = body.get("connection") or {}
        return {
            "country": body.get("country") or "",
            "country_code": body.get("country_code"),
            "region": body.get("region") or "",
            "city": body.get("city") or "",
            "latitude": body.get("latitude"),
            "longitude": body.get("longitude"),
            "asn": connection.get("asn"),
            "org": connection.get("org") or connection.get("isp") or "",
            "isp": connection.get("isp"),
        }
