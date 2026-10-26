"""Geo and host details from the IP enrichment table, merged into rows."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from avai.enrichers import IndicatorType
from avai.enrichers.cache import EnrichmentSchema
from avai.host_monitor import Base

from .panel_reads import SchemaProbe, StoredJson


class IpDetails:
    """One evidence row's details about an IP, read across each source's own
    key names."""

    def __init__(self, details: dict[str, Any]) -> None:
        self._details = details

    def geo(self) -> dict[str, Any] | None:
        """A normalised geolocation: ipwho.is (country/city/region/asn/org),
        AbuseIPDB (countryCode/isp), Feodo (country/as_name/as_number). None
        when the row carries no geo at all."""
        details = self._details
        code = details.get("country_code") or details.get("countryCode")
        org = details.get("org") or details.get("as_name") or details.get("isp")
        asn = details.get("asn") or details.get("as_number")
        geo = {
            "country": details.get("country") or code,
            "cc": code,
            "city": details.get("city"),
            "region": details.get("region"),
            "org": org,
            "asn": asn,
        }
        named = (geo["country"], geo["city"], org, asn)
        return geo if any(named) else None

    def host(self) -> str | None:
        """A hostname / domain for the IP: Shodan InternetDB's reverse-DNS
        ``hostnames`` or AbuseIPDB's registered ``domain``."""
        hostnames = self._details.get("hostnames")
        names = hostnames if isinstance(hostnames, list) else []
        named = [name for name in names if isinstance(name, str) and name]
        if named:
            return named[0]
        domain = self._details.get("domain")
        return domain if isinstance(domain, str) and domain else None


class IpEnrichment:
    """Fills each flow row's ``geo`` (the richest geolocation across sources)
    and ``hostname`` (a reverse-DNS name, if any source resolved one) from
    the cached enrichment evidence. Both stay None without evidence."""

    GEO_FIELDS = ("city", "region", "country", "org", "asn")

    def __init__(self, session: Session) -> None:
        self._session = session

    def attach(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row["geo"] = None
            row["hostname"] = None
        ips = [row["dst_ip"] for row in rows if row.get("dst_ip")]
        if not ips or "enrichment_evidence" not in SchemaProbe(self._session).tables():
            return
        geo_by_ip, hosts_by_ip = self._evidence(ips)
        for row in rows:
            row["geo"] = geo_by_ip.get(row["dst_ip"])
            hosts = hosts_by_ip.get(row["dst_ip"])
            # Deterministic pick when several sources name different hosts.
            row["hostname"] = sorted(hosts)[0] if hosts else None

    def _evidence(
        self, ips: list[str]
    ) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
        geo_by_ip: dict[str, dict[str, Any]] = {}
        hosts_by_ip: dict[str, set[str]] = {}
        for ip, details_json in self._rows(ips):
            details = IpDetails(StoredJson().as_dict(details_json))
            geo, host = details.geo(), details.host()
            if geo is not None and self._richness(geo) > self._richness(
                geo_by_ip.get(ip)
            ):
                geo_by_ip[ip] = geo
            if host:
                hosts_by_ip.setdefault(ip, set()).add(host)
        return geo_by_ip, hosts_by_ip

    def _rows(self, ips: list[str]) -> list[Any]:
        # Registering the model is idempotent (the monitor's startup usually
        # did it), so the cache is read through the ORM, not raw SQL.
        model = EnrichmentSchema(Base).model()
        address_types = [str(IndicatorType.IPV4), str(IndicatorType.IPV6)]
        statement = select(model.indicator_value, model.details_json).where(
            model.indicator_type.in_(address_types), model.indicator_value.in_(ips)
        )
        return list(self._session.execute(statement).all())

    def _richness(self, geo: dict[str, Any] | None) -> int:
        """How many fields a geo candidate fills; the most detailed wins."""
        if geo is None:
            return -1
        return sum(1 for name in self.GEO_FIELDS if geo[name])
