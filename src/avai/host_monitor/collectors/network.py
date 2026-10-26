from __future__ import annotations

import json
import socket
from collections.abc import Iterator, Mapping
from typing import Any, NamedTuple

from ..slices import Slices
from ..runtime import Clock, CommandRunner, PsutilConnections, SystemMetrics
from ..runtime.row_source import MissingToolError
from .base import SnapshotCollector

DNS_PORT = 53
DOH_PORT = 443
NO_PAYLOAD = 0
# Well-known DoH resolver endpoints. Plaintext DNS (53) is visible to us;
# DoH (TLS/443) isn't — so a host talking to one of these on 443 is
# resolving names out of our sight.
DOH_RESOLVERS = (
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("9.9.9.9", "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("2606:4700:4700::1111", "Cloudflare"),
    ("2001:4860:4860::8888", "Google"),
)
IP_TOKENS = ("IP", "IP6")
# Token offsets after tcpdump's ">": the destination, then the protocol /
# DNS payload.
DESTINATION_OFFSET = 1
PROTO_OFFSET = 2
SERVICE_PROTOCOLS = frozenset({"tcp", "udp"})
INTERFACE_STAT_FIELDS = ("mtu",)
IO_COUNTER_FIELDS = (
    "bytes_sent",
    "bytes_recv",
    "packets_sent",
    "packets_recv",
    "errin",
    "errout",
    "dropin",
    "dropout",
)

Owners = Mapping[tuple[str, int], tuple[str, int]]


class PacketFlow(NamedTuple):
    iface: str | None
    proto: str
    dst_ip: str
    dst_port: int
    nbytes: int


class DnsQuestion(NamedTuple):
    iface: str | None
    qname: str
    qtype: str | None
    server_ip: str


class CapturedPackets(NamedTuple):
    stdout: str
    default_iface: str | None


class PayloadSize:
    """The payload length tcpdump prints for one packet (so flows can report
    data volume, not just a packet count): TCP shows it as the trailing token
    (``tcp 1380``), UDP/ICMP as ``length <n>``. 0 when absent or unparseable."""

    def __init__(self, parts: list[str]) -> None:
        self._parts = parts

    def bytes(self) -> int:
        if "length" in self._parts:
            index = self._parts.index("length") + 1
            token = self._parts[index] if index < len(self._parts) else ""
            return self._number(token)
        return self._number(self._parts[-1] if self._parts else "")

    def _number(self, token: str) -> int:
        cleaned = token.rstrip(".,")
        return int(cleaned) if cleaned.isdigit() else NO_PAYLOAD


class TcpdumpLine:
    """One ``tcpdump -n -t`` packet line.

    Parsing is split-based (no regex): tcpdump prints one line per packet
    as ``IP src.port > dst.port: proto len``. If "IP" isn't the first token,
    the leading token is the interface — Linux '-i any' prefixes
    "<iface> In/Out IP …", macOS '-k I' prefixes "(<iface>) IP …".

        macOS '-k I':   ``(en6) IP src.port > dst.port: tcp 1380``
        Linux -i any:   ``eth0 Out IP6 src.port > dst.port: UDP, length 45``
    """

    def __init__(self, parts: list[str]) -> None:
        self._parts = parts

    @classmethod
    def of(cls, line: str) -> TcpdumpLine:
        return cls(line.split())

    def flow(self) -> PacketFlow | None:
        """(iface, proto, dst_ip, dst_port, nbytes) of a TCP/UDP packet.
        IPv4 and IPv6 both append the port after a final ``.``, so the
        trailing ``.<port>`` splits off the destination address."""
        destination = self._destination()
        if destination is None:
            return None
        ip, _, port = destination.rpartition(".")
        if not ip or not port.isdigit():
            return None
        after = self._after_arrow(PROTO_OFFSET)
        proto = after.rstrip(",").lower() if after else "ip"
        size = PayloadSize(self._parts).bytes()
        return PacketFlow(self._iface(), proto, ip, int(port), size)

    def dns_question(self) -> DnsQuestion | None:
        """(iface, qname, qtype, server_ip) of an outbound DNS question.
        Only questions *to* port 53 are kept (a response has src port 53
        and no ``A?``-style token)."""
        destination = self._destination()
        if destination is None:
            return None
        server_ip, _, server_port = destination.rpartition(".")
        if server_port != str(DNS_PORT) or not server_ip:
            return None
        qtype, qname = self._question()
        if not qname:
            return None
        return DnsQuestion(self._iface(), qname, qtype, server_ip)

    def _destination(self) -> str | None:
        has_ip = any(token in self._parts for token in IP_TOKENS)
        if ">" not in self._parts or not has_ip:
            return None
        target = self._after_arrow(DESTINATION_OFFSET)
        return target.rstrip(":") if target else None

    def _after_arrow(self, offset: int) -> str | None:
        index = self._parts.index(">") + offset
        return self._parts[index] if index < len(self._parts) else None

    def _iface(self) -> str | None:
        ip_index = min(
            self._parts.index(token) for token in IP_TOKENS if token in self._parts
        )
        return self._parts[0].strip("()") if ip_index >= 1 else None

    def _question(self) -> tuple[str | None, str | None]:
        """The question type is the token ending in '?' (A?, AAAA?, PTR?, …);
        the queried name is the token right after it."""
        payload = self._parts[self._parts.index(">") + PROTO_OFFSET :]
        for index, token in enumerate(payload):
            if len(token) > 1 and token.endswith("?"):
                name = (
                    payload[index + 1].rstrip(".") if index + 1 < len(payload) else None
                )
                return token[:-1], name
        return None, None


class TcpdumpBanner:
    """tcpdump's stderr banner: 'listening on en0, link-type ...'."""

    def __init__(self, stderr: str) -> None:
        self._stderr = stderr

    def listening_iface(self) -> str | None:
        for line in self._stderr.splitlines():
            if "listening on" in line:
                rest = line.split("listening on", 1)[1].strip()
                return rest.split(",", 1)[0].strip() or None
        return None

    def default_iface(self) -> str | None:
        """The banner interface, dropping the macOS 'pktap' pseudo-device:
        pktap0 / pktap aren't real interfaces — they're the aggregating tap
        macOS captures through. With '-k I' each line carries its real
        interface, so a pktap banner falls back to 'unknown' rather than
        mislabel every flow 'pktap'."""
        iface = self.listening_iface()
        if iface and iface.startswith("pktap"):
            return None
        return iface


class TcpdumpCapture:
    """One bounded tcpdump capture. ``iface_args`` are the host's interface
    flags: Linux '-i any' prefixes each line with the interface + direction;
    macOS '-k I' prints the real per-packet interface (otherwise every flow
    is labelled with the 'pktap' aggregating pseudo-device)."""

    def __init__(self, runner: CommandRunner, iface_args: tuple[str, ...]) -> None:
        self._runner = runner
        self._iface_args = iface_args

    def record(
        self, flags: list[str], bpf_filter: list[str], timeout: int
    ) -> CapturedPackets:
        """Hitting the time cap before the packet cap is normal on a slow
        link, so the partial output is kept. The default interface is the
        one tcpdump reported listening on (used when a line carries no
        per-packet interface)."""
        if not self._runner.exists("tcpdump"):
            raise MissingToolError("tcpdump not found on PATH")
        cmd = ["tcpdump", *flags, *self._iface_args, *bpf_filter]
        output = self._runner.capture(cmd, timeout)
        return CapturedPackets(
            output.stdout, TcpdumpBanner(output.stderr).default_iface()
        )


class PortService:
    """The well-known service name of a port, from the system services db."""

    def name(self, port: int, proto: str) -> str | None:
        lookup_proto = proto if proto in SERVICE_PROTOCOLS else "tcp"
        try:
            return socket.getservbyport(port, lookup_proto)
        except (OSError, OverflowError, TypeError):
            return None


class ProcessConnectionResolver:
    """Resolves which local process owns a socket to a remote endpoint by
    snapshotting the kernel connection table (psutil).

    Injected into :class:`NetworkFlowsCollector` (and reused by the DNS
    collector) so it's swappable in tests. tcpdump sees packets but not
    the owning PID, so we correlate each flow's ``(dst_ip, dst_port)``
    against the live connection table to name the process behind it.
    Best-effort: a short-lived connection may already be gone by snapshot
    time, in which case the flow simply carries no process.
    """

    def __init__(self, connections: PsutilConnections) -> None:
        self._connections = connections

    def snapshot(self) -> dict[tuple[str, int], tuple[str, int]]:
        """Map remote ``(ip, port)`` → ``(process_name, pid)`` for every
        inet socket that has a remote peer and a resolvable owner."""
        try:
            conns = self._connections.inet()
        except OSError:
            return {}
        owners: dict[tuple[str, int], tuple[str, int]] = {}
        for conn in conns:
            if not conn.raddr or conn.pid is None:
                continue
            key = (conn.raddr.ip, conn.raddr.port)
            if key not in owners:
                owners[key] = (self._process_name(conn.pid), conn.pid)
        return owners

    def _process_name(self, pid: int) -> str:
        name = self._connections.process_name(pid)
        return f"pid {pid}" if name is None else name


class FlowTable:
    """Packets aggregated into distinct ``(iface, proto, dst_ip, dst_port)``
    flows with packet and byte counts."""

    def aggregate(
        self, output: str, default_iface: str | None
    ) -> dict[tuple[Any, ...], dict[str, Any]]:
        now = Clock().now_iso()
        flows: dict[tuple[Any, ...], dict[str, Any]] = {}
        packets = (TcpdumpLine.of(line).flow() for line in output.splitlines())
        for packet in (packet for packet in packets if packet is not None):
            iface = packet.iface or default_iface
            key = (iface, packet.proto, packet.dst_ip, packet.dst_port)
            if key not in flows:
                flows[key] = self._new_flow(packet, iface, now)
            flow = flows[key]
            flow["packets"] += 1
            flow["byte_count"] += packet.nbytes
            flow["last_seen"] = now
        return flows

    def _new_flow(
        self, packet: PacketFlow, iface: str | None, now: str
    ) -> dict[str, Any]:
        return {
            "iface": iface,
            "proto": packet.proto,
            "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port,
            "service": PortService().name(packet.dst_port, packet.proto),
            "packets": 0,
            "byte_count": 0,
            "first_seen": now,
            "last_seen": now,
        }


class QueryTable:
    """DNS questions aggregated by ``(qname, qtype, resolver)`` with a count."""

    def aggregate(
        self, output: str, default_iface: str | None, owners: Owners
    ) -> dict[tuple[Any, ...], dict[str, Any]]:
        now = Clock().now_iso()
        queries: dict[tuple[Any, ...], dict[str, Any]] = {}
        parsed = (TcpdumpLine.of(line).dns_question() for line in output.splitlines())
        for question in (question for question in parsed if question is not None):
            key = (question.qname, question.qtype, question.server_ip)
            if key not in queries:
                located = question._replace(iface=question.iface or default_iface)
                owner = owners.get((question.server_ip, DNS_PORT))
                queries[key] = self._new_query(located, owner, now)
                continue
            queries[key]["count"] += 1
            queries[key]["last_seen"] = now
        return queries

    def _new_query(
        self, question: DnsQuestion, owner: tuple[str, int] | None, now: str
    ) -> dict[str, Any]:
        return {
            "iface": question.iface,
            "qname": question.qname,
            "qtype": question.qtype,
            "server_ip": question.server_ip,
            "process": owner[0] if owner else None,
            "count": 1,
            "first_seen": now,
            "last_seen": now,
        }


class NetworkConnectionsCollector(SnapshotCollector):
    slice = Slices.NETWORK_CONNECTIONS
    # Judged on the remote-endpoint identity. Dedup over (remote ip, port,
    # status) collapses the many sockets to one verdict per peer (judged once
    # ever via content_hash), and threat-intel for the remote IP is attached
    # by enrichment. tcpdump `network_flows` cover active outbound traffic;
    # this catches established/idle remote peers a capture window can miss.
    # Private/loopback/no-remote rows collapse to a single benign entry.
    judge_fields = ("raddr_ip", "raddr_port", "status")

    def __init__(self, connections: PsutilConnections, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._connections = connections

    def collect(self) -> Iterator[dict[str, Any]]:
        for conn in self._connections.inet():
            yield {
                "pid": conn.pid,
                "family": conn.family.name,
                "type": conn.type.name,
                "laddr_ip": conn.laddr.ip if conn.laddr else None,
                "laddr_port": conn.laddr.port if conn.laddr else None,
                "raddr_ip": conn.raddr.ip if conn.raddr else None,
                "raddr_port": conn.raddr.port if conn.raddr else None,
                "status": conn.status,
            }


class ListeningPortsCollector(SnapshotCollector):
    slice = Slices.LISTENING_PORTS
    judge_fields = ("process_name", "family", "type", "laddr_ip", "laddr_port")

    def __init__(self, connections: PsutilConnections, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._connections = connections

    def collect(self) -> Iterator[dict[str, Any]]:
        names: dict[int, str | None] = {}
        for conn in self._connections.listening():
            if conn.pid is not None and conn.pid not in names:
                names[conn.pid] = self._connections.process_name(conn.pid)
            yield {
                "pid": conn.pid,
                "process_name": names.get(conn.pid) if conn.pid else None,
                "family": conn.family.name,
                "type": conn.type.name,
                "laddr_ip": conn.laddr.ip if conn.laddr else None,
                "laddr_port": conn.laddr.port if conn.laddr else None,
            }


class NetworkFlowsCollector(SnapshotCollector):
    """tcpdump-based flow aggregator.

    Each cycle, captures live packets for a bounded window and
    aggregates them into distinct ``(proto, dst_ip, dst_port)`` flows
    with a packet count — the "top talkers" your host is sending to.
    Each new public-destination flow is enriched against the threat-
    intel sources (Feodo Tracker, AbuseIPDB, GreyNoise, Shodan, …) and
    then judged by the LLM, so malicious requests — C2 beacons,
    exfiltration, connections to known-bad IPs — surface as findings.

    On Linux we capture with ``-i any``, which prefixes each line with the
    interface + direction (``eth0 Out IP …``) — that's where the per-flow
    interface comes from. On macOS ``-i any`` isn't supported, so we
    capture the default interface and read its name from tcpdump's
    "listening on <iface>" banner on stderr. Requires root to capture —
    the monitor already runs as root.
    """

    slice = Slices.NETWORK_FLOWS
    judge_fields = ("iface", "proto", "dst_ip", "dst_port")

    CAPTURE_SECONDS = 8  # wall-clock cap per cycle
    MAX_PACKETS = 2000  # stop after this many packets
    MAX_FLOWS = 200  # emit only the top-N flows by packet count

    def __init__(
        self,
        capture: TcpdumpCapture,
        resolver: ProcessConnectionResolver,
        judge_hints: str = "",
    ) -> None:
        super().__init__(judge_hints)
        self._capture = capture
        self._resolver = resolver

    def capture(self) -> CapturedPackets:
        # -t drops timestamps (we stamp our own); TCP/UDP (v4 + v6) only.
        flags = ["-n", "-q", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        return self._capture.record(flags, ["tcp", "or", "udp"], self.CAPTURE_SECONDS)

    def collect(self) -> Iterator[dict[str, Any]]:
        packets = self.capture()
        flows = FlowTable().aggregate(packets.stdout, packets.default_iface)
        owners = self._resolver.snapshot()
        ranked = sorted(flows.values(), key=lambda flow: flow["packets"], reverse=True)
        for flow in ranked[: self.MAX_FLOWS]:
            owner = owners.get((flow["dst_ip"], flow["dst_port"]))
            # Set both unconditionally (None when unresolved) so every
            # emitted row carries the same keys — Sink.write does a
            # uniform-column executemany insert.
            flow["process"] = owner[0] if owner else None
            flow["pid"] = owner[1] if owner else None
            yield flow


class DnsQueriesCollector(SnapshotCollector):
    """tcpdump-based DNS visibility.

    Captures plaintext DNS questions (port 53) for a bounded window and
    aggregates them by ``(qname, qtype, resolver)`` with a count. Each
    queried domain is enriched against the domain threat feeds
    (PhishTank, URLhaus, …) and judged by the LLM, so lookups of
    known-bad / DGA / typosquat domains surface as findings.

    DoH (DNS-over-HTTPS) deliberately *can't* be seen on the wire, so we
    also flag connections to well-known DoH resolver endpoints on :443 —
    a host using those is bypassing local DNS visibility.

    Without ``-q`` tcpdump decodes the DNS payload as
    ``… 1234+ A? example.com. (29)``. Requires root to capture.
    """

    slice = Slices.DNS_QUERIES
    judge_fields = ("qname", "qtype", "server_ip")

    CAPTURE_SECONDS = 8
    MAX_PACKETS = 2000
    MAX_QUERIES = 200

    def __init__(
        self,
        capture: TcpdumpCapture,
        resolver: ProcessConnectionResolver,
        judge_hints: str = "",
    ) -> None:
        super().__init__(judge_hints)
        self._capture = capture
        self._resolver = resolver

    def capture(self) -> CapturedPackets:
        """Capture port-53 traffic *without* ``-q`` so tcpdump decodes the
        DNS question."""
        flags = ["-n", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        bpf_filter = ["udp", "port", "53", "or", "tcp", "port", "53"]
        return self._capture.record(flags, bpf_filter, self.CAPTURE_SECONDS)

    def collect(self) -> Iterator[dict[str, Any]]:
        packets = self.capture()
        owners = self._resolver.snapshot()
        queries = QueryTable().aggregate(packets.stdout, packets.default_iface, owners)
        # DoH: connections to known DoH endpoints on :443 bypass plaintext
        # DNS visibility entirely — surface them alongside the queries.
        for key, row in self._doh_rows(owners):
            queries.setdefault(key, row)
        ranked = sorted(
            queries.values(), key=lambda query: query["count"], reverse=True
        )
        yield from ranked[: self.MAX_QUERIES]

    def _doh_rows(
        self, owners: Owners
    ) -> Iterator[tuple[tuple[Any, ...], dict[str, Any]]]:
        resolvers = dict(DOH_RESOLVERS)
        now = Clock().now_iso()
        for (ip, port), (process, _pid) in owners.items():
            if port != DOH_PORT or ip not in resolvers:
                continue
            provider = resolvers[ip]
            yield (provider, "DoH", ip), {
                "iface": None,
                "qname": provider,
                "qtype": "DoH",
                "server_ip": ip,
                "process": process,
                "count": 1,
                "first_seen": now,
                "last_seen": now,
            }


class NetworkInterfacesCollector(SnapshotCollector):
    slice = Slices.NETWORK_INTERFACES
    judge_enabled = False  # counters need behavioural analysis

    def __init__(self, metrics: SystemMetrics, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._metrics = metrics

    def collect(self) -> Iterator[dict[str, Any]]:
        stats = self._metrics.net_if_stats()
        counters = self._metrics.net_io_counters()
        for name, addresses in self._metrics.net_if_addrs().items():
            stat, counter = stats.get(name), counters.get(name)
            yield {
                "name": name,
                "is_up": int(stat.isup) if stat else None,
                "speed_mbps": stat.speed if stat else None,
                **{
                    field: getattr(stat, field, None) for field in INTERFACE_STAT_FIELDS
                },
                **{field: getattr(counter, field, None) for field in IO_COUNTER_FIELDS},
                "addresses_json": json.dumps(
                    [self._address(address) for address in addresses]
                ),
            }

    def _address(self, address: Any) -> dict[str, Any]:
        return {
            "family": address.family.name,
            "address": address.address,
            "netmask": address.netmask,
            "broadcast": address.broadcast,
        }
