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

from .collectors import SnapshotCollector
from .models import ArpEntryRow, DnsResolverRow, NdpNeighborRow, RouteRow
from .runtime import RowSource

_MAC_RE = re.compile(r"^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$")


def _load_ps_json(text: str) -> list:
    """Normalise PowerShell ``ConvertTo-Json`` output (bare object for one
    result, array for many, empty for none) into a list of dicts."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


# ---------------------------------------------------------------------------
# Collectors (thin contracts over an injected RowSource)
# ---------------------------------------------------------------------------


class _SourceSnapshotCollector(SnapshotCollector):
    """A snapshot collector whose rows come from an injected RowSource."""

    def __init__(self, source: RowSource, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self._source = source

    def collect(self):
        yield from self._source.rows()


class ArpTableCollector(_SourceSnapshotCollector):
    name = "arp_table"
    model = ArpEntryRow
    judge_fields = ("ip", "mac", "interface", "flags")


class NdpNeighborsCollector(_SourceSnapshotCollector):
    name = "ndp_neighbors"
    model = NdpNeighborRow
    judge_fields = ("ip", "mac", "interface", "state")


class RoutesCollector(_SourceSnapshotCollector):
    name = "routes"
    model = RouteRow
    judge_fields = ("destination", "gateway", "interface", "flags")


class DnsResolversCollector(_SourceSnapshotCollector):
    name = "dns_resolvers"
    model = DnsResolverRow
    judge_fields = ("server", "scope", "search", "interface")


# ---------------------------------------------------------------------------
# macOS parsers (validated against real output)
# ---------------------------------------------------------------------------


class MacosArpParser:
    """``arp -an`` → ``? (IP) at MAC on IFACE [flags] [ethernet]``."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            toks = line.split()
            if "at" not in toks or "on" not in toks:
                continue
            ip = next(
                (t[1:-1] for t in toks if t.startswith("(") and t.endswith(")")), None
            )
            if not ip:
                continue
            ai, oi = toks.index("at"), toks.index("on")
            mac = toks[ai + 1]
            if mac == "(incomplete)":
                mac = None
            iface = toks[oi + 1] if oi + 1 < len(toks) else None
            flags = (
                " ".join(
                    t
                    for t in toks[oi + 2 :]
                    if not (t.startswith("[") and t.endswith("]"))
                )
                or None
            )
            rows.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "interface": iface,
                    "flags": flags,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class MacosNdpParser:
    """``ndp -an`` columns: Neighbor LinklayerAddr Netif Expire St ..."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            if not line.strip() or line.startswith("Neighbor"):
                continue
            cols = line.split()
            if len(cols) < 3:
                continue
            mac = cols[1] if cols[1] != "(incomplete)" else None
            state = cols[4] if len(cols) > 4 else (cols[3] if len(cols) > 3 else None)
            rows.append(
                {
                    "ip": cols[0],
                    "mac": mac,
                    "interface": cols[2],
                    "state": state,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class MacosRouteParser:
    """``netstat -rn`` — keep default routes and IP-next-hop routes; drop
    link# and MAC-gateway (neighbor) rows already covered by ARP."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        in_table = False
        for line in text.splitlines():
            s = line.rstrip()
            if not s.strip():
                in_table = False
                continue
            if s.startswith("Destination") and "Gateway" in s:
                in_table = True
                continue
            if not in_table:
                continue
            cols = s.split()
            if len(cols) < 4:
                continue
            dest, gw, flags, netif = cols[0], cols[1], cols[2], cols[3]
            if not self._is_route(dest, gw):
                continue
            rows.append(
                {
                    "destination": dest,
                    "gateway": gw,
                    "interface": netif,
                    "flags": flags,
                    "raw_json": json.dumps(s.strip()),
                }
            )
        return rows

    @staticmethod
    def _is_route(dest: str, gw: str) -> bool:
        if dest == "default":
            return True
        if gw.startswith("link#") or _MAC_RE.match(gw):
            return False
        return ("." in gw) or (":" in gw)


class MacosDnsParser:
    """``scutil --dns`` — one row per nameserver per resolver block."""

    def parse(self, text: str) -> list[dict]:
        rows: list[dict] = []
        scope = None
        searches: list[str] = []
        iface = None
        servers: list[str] = []

        def flush():
            for srv in servers:
                rows.append(
                    {
                        "server": srv,
                        "scope": scope,
                        "search": " ".join(searches) or None,
                        "interface": iface,
                        "raw_json": json.dumps({"resolver": scope, "search": searches}),
                    }
                )

        for line in text.splitlines():
            s = line.strip()
            if s.startswith("resolver #"):
                flush()
                scope, searches, iface, servers = s, [], None, []
            elif s.startswith("nameserver["):
                servers.append(s.split(":", 1)[1].strip())
            elif s.startswith("search domain[") or s.startswith("domain "):
                searches.append(s.split(":", 1)[1].strip())
            elif s.startswith("if_index"):
                val = s.split(":", 1)[1].strip()
                if "(" in val:
                    iface = val.split("(", 1)[1].rstrip(")")
        flush()
        return rows


# ---------------------------------------------------------------------------
# Linux parsers (iproute2 + resolv.conf)
# ---------------------------------------------------------------------------


class IpNeighParser:
    """``ip neigh`` / ``ip -6 neigh``:
    ``IP dev IFACE lladdr MAC STATE`` (lladdr absent for FAILED/INCOMPLETE).

    ``state_key`` is the model field for the trailing state token: ``flags``
    for the ARP table, ``state`` for the NDP table."""

    def __init__(self, state_key: str):
        self._state_key = state_key

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            cols = line.split()
            if len(cols) < 3:
                continue
            iface = cols[cols.index("dev") + 1] if "dev" in cols else None
            mac = cols[cols.index("lladdr") + 1] if "lladdr" in cols else None
            rows.append(
                {
                    "ip": cols[0],
                    "mac": mac,
                    "interface": iface,
                    self._state_key: cols[-1],
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class IpRouteParser:
    """``ip route``: ``default via GW dev IFACE proto P`` /
    ``PREFIX dev IFACE proto kernel ...``. Keep default + via routes."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            cols = line.split()
            if not cols:
                continue
            dest = cols[0]
            gw = cols[cols.index("via") + 1] if "via" in cols else None
            iface = cols[cols.index("dev") + 1] if "dev" in cols else None
            flags = cols[cols.index("proto") + 1] if "proto" in cols else None
            if dest == "default" or gw:
                rows.append(
                    {
                        "destination": dest,
                        "gateway": gw,
                        "interface": iface,
                        "flags": flags,
                        "raw_json": json.dumps(line.strip()),
                    }
                )
        return rows


class ResolvConfParser:
    """``/etc/resolv.conf`` nameserver/search lines."""

    def parse(self, text: str) -> list[dict]:
        servers: list[str] = []
        searches: list[str] = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("nameserver"):
                parts = s.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
            elif s.startswith(("search", "domain")):
                searches += s.split()[1:]
        return [
            {
                "server": srv,
                "scope": "resolv.conf",
                "search": " ".join(searches) or None,
                "interface": None,
                "raw_json": json.dumps({"nameserver": srv}),
            }
            for srv in servers
        ]


# ---------------------------------------------------------------------------
# Windows parsers (PowerShell ConvertTo-Json)
# ---------------------------------------------------------------------------


class PsNeighborParser:
    """``Get-NetNeighbor ... | ConvertTo-Json`` objects."""

    def __init__(self, state_key: str):
        self._state_key = state_key

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            rows.append(
                {
                    "ip": o.get("IPAddress"),
                    "mac": o.get("LinkLayerAddress") or None,
                    "interface": o.get("InterfaceAlias"),
                    self._state_key: str(o.get("State")),
                    "raw_json": json.dumps(o),
                }
            )
        return rows


class PsRouteParser:
    """``Get-NetRoute | ConvertTo-Json``. Keep default + real next-hop."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            dest = o.get("DestinationPrefix")
            nh = o.get("NextHop")
            if dest in ("0.0.0.0/0", "::/0") or (nh and nh not in ("0.0.0.0", "::")):
                rows.append(
                    {
                        "destination": dest,
                        "gateway": nh,
                        "interface": o.get("InterfaceAlias"),
                        "flags": str(o.get("RouteMetric")),
                        "raw_json": json.dumps(o),
                    }
                )
        return rows


class PsDnsParser:
    """``Get-DnsClientServerAddress | ConvertTo-Json`` — one row per server."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            for srv in o.get("ServerAddresses") or []:
                rows.append(
                    {
                        "server": srv,
                        "scope": "dns-client",
                        "search": None,
                        "interface": o.get("InterfaceAlias"),
                        "raw_json": json.dumps(o),
                    }
                )
        return rows
