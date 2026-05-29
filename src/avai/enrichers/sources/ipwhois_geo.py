"""ipwho.is — free, keyless IP geolocation (country / region / city / ASN).

No API key, HTTPS, no hard quota (we stay polite at 1 rps). This is a
purely *informational* source: it never raises a threat verdict, it
just attaches where a destination IP sits geographically and on the
network so the dashboard can show a location per destination.

https://ipwho.is/
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

_BASE = "https://ipwho.is"


class IpwhoisGeoEnricher(Enricher):
    name = "ipwhois_geo"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours = 24 * 7  # geolocation is stable — refresh weekly

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("ipwho.is", 1.0)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(f"{_BASE}/{indicator.value}")
        if resp.status_code != 200:
            return None
        body = resp.json() or {}
        # ipwho.is answers {"success": false, "message": ...} for bogon /
        # reserved / unroutable addresses — treat as "no opinion".
        if not body.get("success"):
            return None
        conn = body.get("connection") or {}
        country = body.get("country") or ""
        city = body.get("city") or ""
        region = body.get("region") or ""
        org = conn.get("org") or conn.get("isp") or ""
        asn = conn.get("asn")
        where = ", ".join(p for p in (city, region, country) if p)
        net = f" (AS{asn} {org})".rstrip() if (asn or org) else ""
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.UNKNOWN,  # informational, not a threat
            confidence=0.0,
            summary=f"Geo: {where or 'unknown'}{net}",
            details={
                "country": country,
                "country_code": body.get("country_code"),
                "region": region,
                "city": city,
                "latitude": body.get("latitude"),
                "longitude": body.get("longitude"),
                "asn": asn,
                "org": org,
                "isp": conn.get("isp"),
            },
        )
