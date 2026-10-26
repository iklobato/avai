"""Network neighborhood & topology collectors (Tier 1).

Each collector is an OS-agnostic contract (name / model / judge_fields)
that delegates gathering to an injected :class:`RowSource`; the per-OS
``RowParser`` strategies below are pure ``text -> rows`` transforms,
unit-tested without a subprocess. The host wires the OS-specific
``(command, parser)`` pair (see ``hosts/{macos,linux,windows}.py``).

macOS parsers are validated against real output from this platform;
Linux (``ip``/``resolv.conf``) and Windows (PowerShell ``ConvertTo-Json``)
parsers are written to the documented formats and unit-tested against
representative samples.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from . import slices
from .collectors import SnapshotCollector
from .runtime import RowSource


class PsJson:
    """PowerShell ``ConvertTo-Json`` emits a bare object for one result, an
    array for many and nothing for none; normalise all three to a list of
    objects."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        stripped = text.strip()
        if not stripped:
            return []
        try:
            return self.objects(json.loads(stripped))
        except json.JSONDecodeError:
            return []

    def objects(self, payload: Any) -> list[dict[str, Any]]:
        if payload is None:
            return []
        items = payload if isinstance(payload, list) else [payload]
        return [item for item in items if isinstance(item, dict)]


class KeywordTokens:
    """The whitespace-split words of one command-output line."""

    def __init__(self, words: list[str]) -> None:
        self._words = words

    def after(self, keyword: str) -> str | None:
        """The word that follows ``keyword``, or None when it is absent."""
        if keyword not in self._words:
            return None
        return self._words[self._words.index(keyword) + 1]


# ---------------------------------------------------------------------------
# Collectors (thin contracts over an injected RowSource)
# ---------------------------------------------------------------------------


class SourceSnapshotCollector(SnapshotCollector):
    """A snapshot collector whose rows come from an injected RowSource."""

    def __init__(self, source: RowSource, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._source = source

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from self._source.rows()


class ArpTableCollector(SourceSnapshotCollector):
    slice = slices.ARP_TABLE
    judge_fields = ("ip", "mac", "interface", "flags")


class NdpNeighborsCollector(SourceSnapshotCollector):
    slice = slices.NDP_NEIGHBORS
    judge_fields = ("ip", "mac", "interface", "state")


class RoutesCollector(SourceSnapshotCollector):
    slice = slices.ROUTES
    judge_fields = ("destination", "gateway", "interface", "flags")


class DnsResolversCollector(SourceSnapshotCollector):
    slice = slices.DNS_RESOLVERS
    judge_fields = ("server", "scope", "search", "interface")


# ---------------------------------------------------------------------------
# macOS parsers (validated against real output)
# ---------------------------------------------------------------------------

INCOMPLETE_MAC = "(incomplete)"


class MacosArpParser:
    """``arp -an`` -> ``? (IP) at MAC on IFACE [flags] [ethernet]``."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        tokens = line.split()
        if "at" not in tokens or "on" not in tokens:
            return None
        addresses = (token for token in tokens if self._wrapped(token, "()"))
        ip = next((token[1:-1] for token in addresses), None)
        if not ip:
            return None
        mac = tokens[tokens.index("at") + 1]
        iface_at = tokens.index("on") + 1
        trailing = tokens[iface_at + 1 :]
        flags = [token for token in trailing if not self._wrapped(token, "[]")]
        return {
            "ip": ip,
            "mac": None if mac == INCOMPLETE_MAC else mac,
            "interface": tokens[iface_at] if iface_at < len(tokens) else None,
            "flags": " ".join(flags) or None,
            "raw_json": json.dumps(line.strip()),
        }

    def _wrapped(self, token: str, brackets: str) -> bool:
        opening, closing = brackets
        return token.startswith(opening) and token.endswith(closing)


class MacosNdpParser:
    """``ndp -an`` columns: Neighbor LinklayerAddr Netif Expire St ..."""

    MIN_COLUMNS = 3  # Neighbor LinklayerAddr Netif
    EXPIRE, STATE = 3, 4

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        cols = line.split()
        if line.startswith("Neighbor") or len(cols) < self.MIN_COLUMNS:
            return None
        ip, mac, iface = cols[: self.MIN_COLUMNS]
        states = (
            cols[index] for index in (self.STATE, self.EXPIRE) if len(cols) > index
        )
        return {
            "ip": ip,
            "mac": None if mac == INCOMPLETE_MAC else mac,
            "interface": iface,
            "state": next(states, None),
            "raw_json": json.dumps(line.strip()),
        }


class MacosRouteParser:
    """``netstat -rn``: keep default routes and IP-next-hop routes; drop
    link# and MAC-gateway (neighbor) rows already covered by ARP."""

    MIN_COLUMNS = 4  # Destination Gateway Flags Netif
    MAC_ADDRESS = re.compile(r"^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$")

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [row for section in self._sections(text) for row in self._table(section)]

    def _sections(self, text: str) -> list[list[str]]:
        """Blank-line-separated blocks; each routing table is one block."""
        sections: list[list[str]] = [[]]
        for line in text.splitlines():
            if not line.strip():
                sections.append([])
                continue
            sections[-1].append(line.rstrip())
        return sections

    def _table(self, lines: list[str]) -> list[dict[str, Any]]:
        headers = (index for index, line in enumerate(lines) if self._header(line))
        start = next(headers, None)
        if start is None:
            return []
        rows = (self._row(line) for line in lines[start + 1 :])
        return [row for row in rows if row is not None]

    def _header(self, line: str) -> bool:
        return line.startswith("Destination") and "Gateway" in line

    def _row(self, line: str) -> dict[str, Any] | None:
        cols = line.split()
        if len(cols) < self.MIN_COLUMNS:
            return None
        destination, gateway, flags, netif = cols[: self.MIN_COLUMNS]
        if not self._is_route(destination, gateway):
            return None
        return {
            "destination": destination,
            "gateway": gateway,
            "interface": netif,
            "flags": flags,
            "raw_json": json.dumps(line.strip()),
        }

    def _is_route(self, destination: str, gateway: str) -> bool:
        if destination == "default":
            return True
        if gateway.startswith("link#") or self.MAC_ADDRESS.match(gateway):
            return False
        return ("." in gateway) or (":" in gateway)


class MacosDnsParser:
    """``scutil --dns``: one row per nameserver per resolver block."""

    RESOLVER = "resolver #"

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [row for block in self._blocks(text) for row in self._block_rows(block)]

    def _blocks(self, text: str) -> list[list[str]]:
        blocks: list[list[str]] = [[]]
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(self.RESOLVER):
                blocks.append([])
            blocks[-1].append(stripped)
        return blocks

    def _block_rows(self, lines: list[str]) -> list[dict[str, Any]]:
        scope = lines[0] if lines and lines[0].startswith(self.RESOLVER) else None
        searches = self._values(lines, ("search domain[", "domain "))
        return [
            {
                "server": server,
                "scope": scope,
                "search": " ".join(searches) or None,
                "interface": self._interface(lines),
                "raw_json": json.dumps({"resolver": scope, "search": searches}),
            }
            for server in self._values(lines, ("nameserver[",))
        ]

    def _values(self, lines: list[str], prefixes: tuple[str, ...]) -> list[str]:
        return [
            line.split(":", 1)[1].strip() for line in lines if line.startswith(prefixes)
        ]

    def _interface(self, lines: list[str]) -> str | None:
        values = self._values(lines, ("if_index",))
        names = [value.split("(", 1)[1].rstrip(")") for value in values if "(" in value]
        return names[-1] if names else None


# ---------------------------------------------------------------------------
# Linux parsers (iproute2 + resolv.conf)
# ---------------------------------------------------------------------------


class IpNeighParser:
    """``ip neigh`` / ``ip -6 neigh``:
    ``IP dev IFACE lladdr MAC STATE`` (lladdr absent for FAILED/INCOMPLETE).

    ``state_key`` is the model field for the trailing state token: ``flags``
    for the ARP table, ``state`` for the NDP table."""

    MIN_COLUMNS = 3  # ip, then dev/lladdr pairs

    def __init__(self, state_key: str) -> None:
        self._state_key = state_key

    def parse(self, text: str) -> list[dict[str, Any]]:
        lines = text.splitlines()
        return [
            self._row(line) for line in lines if len(line.split()) >= self.MIN_COLUMNS
        ]

    def _row(self, line: str) -> dict[str, Any]:
        cols = line.split()
        tokens = KeywordTokens(cols)
        return {
            "ip": cols[0],
            "mac": tokens.after("lladdr"),
            "interface": tokens.after("dev"),
            self._state_key: cols[-1],
            "raw_json": json.dumps(line.strip()),
        }


class IpRouteParser:
    """``ip route``: ``default via GW dev IFACE proto P`` /
    ``PREFIX dev IFACE proto kernel ...``. Keep default + via routes."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines() if line.split())
        return [
            row for row in rows if row["destination"] == "default" or row["gateway"]
        ]

    def _row(self, line: str) -> dict[str, Any]:
        cols = line.split()
        tokens = KeywordTokens(cols)
        return {
            "destination": cols[0],
            "gateway": tokens.after("via"),
            "interface": tokens.after("dev"),
            "flags": tokens.after("proto"),
            "raw_json": json.dumps(line.strip()),
        }


class ResolvConfParser:
    """``/etc/resolv.conf`` nameserver/search lines."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        stripped = (line.strip() for line in text.splitlines())
        live = [line.split() for line in stripped if line and not line.startswith("#")]
        servers = [
            words[1]
            for words in live
            if words[0].startswith("nameserver") and len(words) > 1
        ]
        searches = [
            word
            for words in live
            if words[0].startswith(("search", "domain"))
            for word in words[1:]
        ]
        return [self._row(server, searches) for server in servers]

    def _row(self, server: str, searches: list[str]) -> dict[str, Any]:
        return {
            "server": server,
            "scope": "resolv.conf",
            "search": " ".join(searches) or None,
            "interface": None,
            "raw_json": json.dumps({"nameserver": server}),
        }


# ---------------------------------------------------------------------------
# Windows parsers (PowerShell ConvertTo-Json)
# ---------------------------------------------------------------------------


class PsNeighborParser:
    """``Get-NetNeighbor ... | ConvertTo-Json`` objects."""

    def __init__(self, state_key: str) -> None:
        self._state_key = state_key

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [
            {
                "ip": neighbor.get("IPAddress"),
                "mac": neighbor.get("LinkLayerAddress") or None,
                "interface": neighbor.get("InterfaceAlias"),
                self._state_key: str(neighbor.get("State")),
                "raw_json": json.dumps(neighbor),
            }
            for neighbor in PsJson().parse(text)
        ]


class PsRouteParser:
    """``Get-NetRoute | ConvertTo-Json``. Keep default + real next-hop."""

    DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")
    UNSPECIFIED = ("0.0.0.0", "::")

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [
            {
                "destination": route.get("DestinationPrefix"),
                "gateway": route.get("NextHop"),
                "interface": route.get("InterfaceAlias"),
                "flags": str(route.get("RouteMetric")),
                "raw_json": json.dumps(route),
            }
            for route in PsJson().parse(text)
            if self._kept(route)
        ]

    def _kept(self, route: dict[str, Any]) -> bool:
        next_hop = route.get("NextHop")
        real_hop = bool(next_hop) and next_hop not in self.UNSPECIFIED
        return route.get("DestinationPrefix") in self.DEFAULT_ROUTES or real_hop


class PsDnsParser:
    """``Get-DnsClientServerAddress | ConvertTo-Json``: one row per server."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [
            {
                "server": server,
                "scope": "dns-client",
                "search": None,
                "interface": client.get("InterfaceAlias"),
                "raw_json": json.dumps(client),
            }
            for client in PsJson().parse(text)
            for server in client.get("ServerAddresses") or []
        ]
