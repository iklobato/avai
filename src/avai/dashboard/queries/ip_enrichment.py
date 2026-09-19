"""Geo and host details from the IP enrichment table, merged into rows."""

from __future__ import annotations

import json

from sqlalchemy import (
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Base,
)

from .common import _existing_tables


def _geo_from_details(details: dict) -> dict | None:
    """Extract a normalised geolocation from one evidence row's details,
    tolerating each source's own key names: ipwho.is
    (country/city/region/asn/org), AbuseIPDB (countryCode/isp), Feodo
    (country/as_name/as_number). Returns ``None`` when the row carries no
    geo at all."""
    cc = details.get("country_code") or details.get("countryCode")
    country = details.get("country") or cc
    city = details.get("city")
    region = details.get("region")
    org = details.get("org") or details.get("as_name") or details.get("isp")
    asn = details.get("asn") or details.get("as_number")
    if not any((country, city, org, asn)):
        return None
    return {
        "country": country,
        "cc": cc,
        "city": city,
        "region": region,
        "org": org,
        "asn": asn,
    }


def _geo_richness(g: dict) -> int:
    """Count how many fields a geo candidate fills — used to keep the
    most detailed geolocation when several sources disagree."""
    return sum(
        1 for v in (g["city"], g["region"], g["country"], g["org"], g["asn"]) if v
    )


def _host_from_details(details: dict) -> str | None:
    """Pull a hostname / domain for the IP out of one evidence row's
    details: Shodan InternetDB carries reverse-DNS ``hostnames`` (keyless,
    on by default), AbuseIPDB carries a registered ``domain``. ``None``
    when the row names no host."""
    hostnames = details.get("hostnames")
    if isinstance(hostnames, list):
        for h in hostnames:
            if isinstance(h, str) and h:
                return h
    dom = details.get("domain")
    if isinstance(dom, str) and dom:
        return dom
    return None


def _attach_ip_enrichment(session: Session, rows: list[dict]) -> None:
    """Populate each flow row from the cached enrichment evidence for its
    destination IP:

    - ``geo``:      the richest geolocation (country / city / region /
      org / ASN) across any source — ipwho.is primarily, with AbuseIPDB /
      Feodo as fallbacks.
    - ``hostname``: a reverse-DNS hostname / domain for the IP, if any
      source resolved one (Shodan ``hostnames``, AbuseIPDB ``domain``).

    Both default to ``None``. No-op if the enrichment cache table doesn't
    exist or there are no rows.
    """
    for r in rows:
        r["geo"] = None
        r["hostname"] = None
    if not rows or "enrichment_evidence" not in _existing_tables(session):
        return
    ips = [r["dst_ip"] for r in rows if r.get("dst_ip")]
    if not ips:
        return
    # Register the enrichment ORM model against the dashboard's Base
    # (idempotent — no-op if the monitor's startup already did it) so we
    # can query the cache through the ORM rather than raw SQL.
    from avai.enrichers import IndicatorType
    from avai.enrichers.cache import register_schema

    model = register_schema(Base)
    stmt = select(
        model.indicator_value,
        model.details_json,
    ).where(
        model.indicator_type.in_([str(IndicatorType.IPV4), str(IndicatorType.IPV6)]),
        model.indicator_value.in_(ips),
    )
    geo_by_ip: dict[str, dict] = {}
    host_by_ip: dict[str, set] = {}
    for ip, details_json in session.execute(stmt).all():
        try:
            details = json.loads(details_json) if details_json else {}
        except (TypeError, ValueError):
            details = {}
        geo = _geo_from_details(details)
        if geo is not None:
            best = geo_by_ip.get(ip)
            if best is None or _geo_richness(geo) > _geo_richness(best):
                geo_by_ip[ip] = geo
        host = _host_from_details(details)
        if host:
            host_by_ip.setdefault(ip, set()).add(host)
    for r in rows:
        r["geo"] = geo_by_ip.get(r["dst_ip"])
        hosts = host_by_ip.get(r["dst_ip"])
        # Deterministic pick when several sources name different hosts.
        r["hostname"] = sorted(hosts)[0] if hosts else None
