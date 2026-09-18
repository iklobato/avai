"""The network topology and exposure panels."""

from __future__ import annotations

from sqlalchemy.orm import Session

from .common import RowFilter, VerdictTable, _verdict_tables

# Resolvers, neighbor caches and routes: the DNS-hijack / ARP-spoof /
# route-redirection surfaces.
_TOPOLOGY_TABLES = {
    "resolvers": VerdictTable(
        "dns_resolvers",
        ("server", "scope", "search", "interface"),
        search=("server", "scope", "search", "interface"),
    ),
    "arp": VerdictTable(
        "arp_table",
        ("ip", "mac", "interface", "flags"),
        search=("ip", "mac", "interface"),
    ),
    "ndp": VerdictTable(
        "ndp_neighbors",
        ("ip", "mac", "interface", "state"),
        search=("ip", "mac", "interface", "state"),
    ),
    "routes": VerdictTable(
        "routes",
        ("destination", "gateway", "interface", "flags"),
        search=("destination", "gateway", "interface"),
    ),
}


def network_topology(session: Session, run_id: str, filters: RowFilter = RowFilter()):
    """Network neighborhood & topology for ``run_id``: configured DNS
    resolvers, the ARP (IPv4) and NDP (IPv6) neighbor caches, and the
    routing table, each row annotated with its LLM verdict. Each table is
    small and bounded, so the section shows all rows behind a shared
    verdict + search filter rather than paginating."""
    return _verdict_tables(session, run_id, _TOPOLOGY_TABLES, filters)


# Proxies, network mounts, logins and sniffing interfaces: the silent-proxy /
# lateral-movement / live-operator / packet-sniffer surfaces.
_EXPOSURE_TABLES = {
    "proxies": VerdictTable(
        "proxy_config",
        ("scope", "host", "port", "pac_url"),
        search=("scope", "host", "pac_url"),
    ),
    "shares": VerdictTable(
        "network_shares",
        ("remote", "mountpoint", "fstype", "options"),
        search=("remote", "mountpoint", "fstype"),
    ),
    "sessions": VerdictTable(
        "login_sessions",
        ("user", "tty", "source", "login_at"),
        search=("user", "tty", "source"),
    ),
    "promisc": VerdictTable(
        "promiscuous_ifaces",
        ("interface", "promiscuous", "flags"),
        search=("interface", "flags"),
    ),
}


def network_exposure(session: Session, run_id: str, filters: RowFilter = RowFilter()):
    """Network exposure & MITM surface for ``run_id``: configured proxies,
    mounted network shares, active login sessions, and promiscuous-mode
    interfaces, each row annotated with its LLM verdict. Small bounded
    tables, so all rows show behind a shared verdict + search filter (no
    pagination), mirroring network_topology."""
    return _verdict_tables(session, run_id, _EXPOSURE_TABLES, filters)
