"""The network topology and exposure panels."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .panel_reads import RowFilter, VerdictPanel, VerdictTable

# Resolvers, neighbor caches and routes: the DNS-hijack / ARP-spoof /
# route-redirection surfaces.
TOPOLOGY_TABLES = (
    (
        "resolvers",
        VerdictTable(
            "dns_resolvers",
            ("server", "scope", "search", "interface"),
            search=("server", "scope", "search", "interface"),
        ),
    ),
    (
        "arp",
        VerdictTable(
            "arp_table",
            ("ip", "mac", "interface", "flags"),
            search=("ip", "mac", "interface"),
        ),
    ),
    (
        "ndp",
        VerdictTable(
            "ndp_neighbors",
            ("ip", "mac", "interface", "state"),
            search=("ip", "mac", "interface", "state"),
        ),
    ),
    (
        "routes",
        VerdictTable(
            "routes",
            ("destination", "gateway", "interface", "flags"),
            search=("destination", "gateway", "interface"),
        ),
    ),
)

# Proxies, network mounts, logins and sniffing interfaces: the silent-proxy /
# lateral-movement / live-operator / packet-sniffer surfaces.
EXPOSURE_TABLES = (
    (
        "proxies",
        VerdictTable(
            "proxy_config",
            ("scope", "host", "port", "pac_url"),
            search=("scope", "host", "pac_url"),
        ),
    ),
    (
        "shares",
        VerdictTable(
            "network_shares",
            ("remote", "mountpoint", "fstype", "options"),
            search=("remote", "mountpoint", "fstype"),
        ),
    ),
    (
        "sessions",
        VerdictTable(
            "login_sessions",
            ("user", "tty", "source", "login_at"),
            search=("user", "tty", "source"),
        ),
    ),
    (
        "promisc",
        VerdictTable(
            "promiscuous_ifaces",
            ("interface", "promiscuous", "flags"),
            search=("interface", "flags"),
        ),
    ),
)


class NetworkPanels:
    """Small bounded tables, each row annotated with its LLM verdict, shown
    whole behind a shared verdict + search filter rather than paginated."""

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def topology(self, filters: RowFilter) -> dict[str, Any]:
        """Configured DNS resolvers, the ARP (IPv4) and NDP (IPv6) neighbor
        caches, and the routing table."""
        panel = VerdictPanel(self._session, self._run_id)
        return panel.tables(dict(TOPOLOGY_TABLES), filters)

    def exposure(self, filters: RowFilter) -> dict[str, Any]:
        """Configured proxies, mounted network shares, active login sessions
        and promiscuous-mode interfaces."""
        panel = VerdictPanel(self._session, self._run_id)
        return panel.tables(dict(EXPOSURE_TABLES), filters)
