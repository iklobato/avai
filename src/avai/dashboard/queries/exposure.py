"""The network topology and exposure panels."""

from __future__ import annotations

from sqlalchemy.orm import Session

from avai.host_monitor import (
    ArpEntryRow,
    DnsResolverRow,
    LoginSessionRow,
    NdpNeighborRow,
    NetworkShareRow,
    PromiscuousInterfaceRow,
    ProxyConfigRow,
    RouteRow,
)

from .common import _collector_rows_with_verdict


def network_topology(
    session: Session,
    run_id: str,
    limit: int = 500,
    verdict: str = "",
    q: str = "",
):
    """Network neighborhood & topology for ``run_id``: configured DNS
    resolvers, the ARP (IPv4) and NDP (IPv6) neighbor caches, and the
    routing table — each row annotated with its LLM verdict. These are the
    DNS-hijack / ARP-spoof / route-redirection surfaces. Each table is
    small and bounded, so the section shows all rows (capped at ``limit``)
    behind a shared verdict + search filter rather than paginating."""
    resolvers = _collector_rows_with_verdict(
        session,
        run_id,
        DnsResolverRow,
        "dns_resolvers",
        ("server", "scope", "search", "interface"),
        limit,
    )
    arp = _collector_rows_with_verdict(
        session,
        run_id,
        ArpEntryRow,
        "arp_table",
        ("ip", "mac", "interface", "flags"),
        limit,
    )
    ndp = _collector_rows_with_verdict(
        session,
        run_id,
        NdpNeighborRow,
        "ndp_neighbors",
        ("ip", "mac", "interface", "state"),
        limit,
    )
    routes = _collector_rows_with_verdict(
        session,
        run_id,
        RouteRow,
        "routes",
        ("destination", "gateway", "interface", "flags"),
        limit,
    )

    def _filter(rs, fields):
        if verdict:
            rs = [r for r in rs if r.get("verdict") == verdict]
        if q:
            ql = q.lower()
            rs = [
                r for r in rs if any(ql in str(r.get(f) or "").lower() for f in fields)
            ]
        return rs

    resolvers = _filter(resolvers, ("server", "scope", "search", "interface"))
    arp = _filter(arp, ("ip", "mac", "interface"))
    ndp = _filter(ndp, ("ip", "mac", "interface", "state"))
    routes = _filter(routes, ("destination", "gateway", "interface"))

    def _counts(rs: list[dict]) -> dict:
        return {
            "total": len(rs),
            "malicious": sum(1 for r in rs if r["verdict"] == "malicious"),
            "suspicious": sum(1 for r in rs if r["verdict"] == "suspicious"),
        }

    return {
        "resolvers": resolvers,
        "arp": arp,
        "ndp": ndp,
        "routes": routes,
        "counts": {
            "resolvers": _counts(resolvers),
            "arp": _counts(arp),
            "ndp": _counts(ndp),
            "routes": _counts(routes),
        },
        "verdict": verdict,
        "q": q,
        "any": bool(resolvers or arp or ndp or routes),
    }


def network_exposure(
    session: Session,
    run_id: str,
    limit: int = 500,
    verdict: str = "",
    q: str = "",
):
    """Network exposure & MITM surface for ``run_id``: configured proxies,
    mounted network shares, active login sessions, and promiscuous-mode
    interfaces — each row annotated with its LLM verdict. These are the
    silent-proxy / lateral-movement / live-operator / packet-sniffer
    surfaces. Small bounded tables, so all rows show behind a shared
    verdict + search filter (no pagination), mirroring network_topology."""
    proxies = _collector_rows_with_verdict(
        session,
        run_id,
        ProxyConfigRow,
        "proxy_config",
        ("scope", "host", "port", "pac_url"),
        limit,
    )
    shares = _collector_rows_with_verdict(
        session,
        run_id,
        NetworkShareRow,
        "network_shares",
        ("remote", "mountpoint", "fstype", "options"),
        limit,
    )
    sessions = _collector_rows_with_verdict(
        session,
        run_id,
        LoginSessionRow,
        "login_sessions",
        ("user", "tty", "source", "login_at"),
        limit,
    )
    promisc = _collector_rows_with_verdict(
        session,
        run_id,
        PromiscuousInterfaceRow,
        "promiscuous_ifaces",
        ("interface", "promiscuous", "flags"),
        limit,
    )

    def _filter(rs, fields):
        if verdict:
            rs = [r for r in rs if r.get("verdict") == verdict]
        if q:
            ql = q.lower()
            rs = [
                r for r in rs if any(ql in str(r.get(f) or "").lower() for f in fields)
            ]
        return rs

    proxies = _filter(proxies, ("scope", "host", "pac_url"))
    shares = _filter(shares, ("remote", "mountpoint", "fstype"))
    sessions = _filter(sessions, ("user", "tty", "source"))
    promisc = _filter(promisc, ("interface", "flags"))

    def _counts(rs: list[dict]) -> dict:
        return {
            "total": len(rs),
            "malicious": sum(1 for r in rs if r["verdict"] == "malicious"),
            "suspicious": sum(1 for r in rs if r["verdict"] == "suspicious"),
        }

    return {
        "proxies": proxies,
        "shares": shares,
        "sessions": sessions,
        "promisc": promisc,
        "counts": {
            "proxies": _counts(proxies),
            "shares": _counts(shares),
            "sessions": _counts(sessions),
            "promisc": _counts(promisc),
        },
        "verdict": verdict,
        "q": q,
        "any": bool(proxies or shares or sessions or promisc),
    }
