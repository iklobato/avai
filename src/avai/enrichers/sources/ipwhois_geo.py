"""ipwho.is — free, keyless IP geolocation (country / region / city / ASN).

No API key, HTTPS, no hard quota (we stay polite at 1 rps). This is a
purely *informational* source: it never raises a threat verdict, it
just attaches where a destination IP sits geographically and on the
network so the dashboard can show a location per destination.

https://ipwho.is/
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import field_validator

from avai.enrichers.reply import ApiReply
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


class GeoConnection(ApiReply):
    asn: object = None
    org: object = None
    isp: object = None


class GeoReply(ApiReply):
    """An ipwho.is lookup; ``success`` is false for bogon/reserved IPs."""

    success: object = False
    country: object = None
    country_code: object = None
    region: object = None
    city: object = None
    latitude: object = None
    longitude: object = None
    connection: GeoConnection | None = None

    @field_validator("connection", mode="before")
    @classmethod
    def _connection(cls, value: Any) -> Any:
        return value or {}

    def details(self) -> dict[str, Any]:
        connection = self.connection or GeoConnection()
        return {
            "country": self.country or "",
            "country_code": self.country_code,
            "region": self.region or "",
            "city": self.city or "",
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": connection.asn,
            "org": connection.org or connection.isp or "",
            "isp": connection.isp,
        }


class IpwhoisGeoEnricher(Enricher):
    name = "ipwhois_geo"
    supports_types = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})
    requires_token: ClassVar[str | None] = None
    ttl_hours = ONE_WEEK_HOURS  # geolocation is stable — refresh weekly
    rate_host = "ipwho.is"
    rate_per_second = 1.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(f"{BASE_URL}/{indicator.value}")
        if not self.answered(response):
            return None
        reply = GeoReply.model_validate(response.json() or {})
        # ipwho.is answers {"success": false, "message": ...} for bogon /
        # reserved / unroutable addresses — treat as "no opinion".
        if not reply.success:
            return None
        return self._evidence(indicator, reply)

    def _evidence(self, indicator: Indicator, reply: GeoReply) -> Evidence:
        details = reply.details()
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
