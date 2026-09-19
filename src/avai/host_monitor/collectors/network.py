"""Sockets and traffic: connections, listeners, tcpdump flows and DNS, interfaces."""

from __future__ import annotations

import json
import socket
from typing import Optional

from .. import slices
from ..runtime import (
    Clock,
    CommandRunner,
    PsutilConnections,
    SystemMetrics,
)
from .base import SnapshotCollector


class NetworkConnectionsCollector(SnapshotCollector):
    slice = slices.NETWORK_CONNECTIONS
    # Judged on the remote-endpoint identity. Dedup over (remote ip, port,
    # status) collapses the many sockets to one verdict per peer (judged once
    # ever via content_hash), and threat-intel for the remote IP is attached
    # by enrichment. tcpdump `network_flows` cover active outbound traffic;
    # this catches established/idle remote peers a capture window can miss.
    # Private/loopback/no-remote rows collapse to a single benign entry.
    judge_fields = ("raddr_ip", "raddr_port", "status")

    def collect(self):
        for c in PsutilConnections.inet():
            yield {
                "pid": c.pid,
                "family": c.family.name,
                "type": c.type.name,
                "laddr_ip": c.laddr.ip if c.laddr else None,
                "laddr_port": c.laddr.port if c.laddr else None,
                "raddr_ip": c.raddr.ip if c.raddr else None,
                "raddr_port": c.raddr.port if c.raddr else None,
                "status": c.status,
            }


class ListeningPortsCollector(SnapshotCollector):
    slice = slices.LISTENING_PORTS
    judge_fields = ("process_name", "family", "type", "laddr_ip", "laddr_port")

    def __init__(
        self,
        judge_hints: str = "",
        connections: Optional[PsutilConnections] = None,
    ) -> None:
        super().__init__(judge_hints)
        self._connections = connections or PsutilConnections()

    def collect(self):
        names: dict[int, Optional[str]] = {}
        for c in self._connections.listening():
            if c.pid is not None and c.pid not in names:
                names[c.pid] = self._connections.process_name(c.pid)
            yield {
                "pid": c.pid,
                "process_name": names.get(c.pid) if c.pid else None,
                "family": c.family.name,
                "type": c.type.name,
                "laddr_ip": c.laddr.ip if c.laddr else None,
                "laddr_port": c.laddr.port if c.laddr else None,
            }


def _payload_bytes(parts: list[str]) -> int:
    """Pull the payload length tcpdump prints for one packet (so flows
    can report data volume, not just a packet count): TCP shows it as the
    trailing token (``tcp 1380``), UDP/ICMP as ``length <n>``. Returns 0
    when absent or unparseable."""
    if "length" in parts:
        i = parts.index("length")
        if i + 1 < len(parts):
            tok = parts[i + 1].rstrip(".,")
            if tok.isdigit():
                return int(tok)
        return 0
    tail = parts[-1].rstrip(".,") if parts else ""
    return int(tail) if tail.isdigit() else 0


def _run_tcpdump(
    runner: CommandRunner, cmd: list[str], timeout: int
) -> tuple[str, Optional[str]]:
    """Return (stdout, default_iface) of one bounded tcpdump capture.
    default_iface is the interface tcpdump reported listening on (used
    when a line carries no per-packet interface, i.e. not the Linux
    '-i any' path). Hitting the time cap before the packet cap is normal
    on a slow link, so the partial output is kept."""
    if not runner.exists("tcpdump"):
        raise RuntimeError("tcpdump not found on PATH")
    out = runner.capture(cmd, timeout)
    iface = NetworkFlowsCollector._iface_from_banner(out.stderr)
    return out.stdout, NetworkFlowsCollector._normalize_default_iface(iface)


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

    def __init__(self, connections: Optional[PsutilConnections] = None) -> None:
        self._connections = connections or PsutilConnections()

    def snapshot(self) -> dict[tuple[str, int], tuple[str, int]]:
        """Map remote ``(ip, port)`` → ``(process_name, pid)`` for every
        inet socket that has a remote peer and a resolvable owner."""
        out: dict[tuple[str, int], tuple[str, int]] = {}
        try:
            conns = self._connections.inet()
        except OSError:
            return out
        for c in conns:
            raddr = c.raddr
            if not raddr or c.pid is None:
                continue
            key = (raddr.ip, raddr.port)
            if key in out:
                continue
            out[key] = (self._proc_name(c.pid), c.pid)
        return out

    def _proc_name(self, pid: int) -> str:
        name = self._connections.process_name(pid)
        return f"pid {pid}" if name is None else name


class NetworkFlowsCollector(SnapshotCollector):
    """tcpdump-based flow aggregator.

    Each cycle, captures live packets for a bounded window and
    aggregates them into distinct ``(proto, dst_ip, dst_port)`` flows
    with a packet count — the "top talkers" your host is sending to.
    Each new public-destination flow is enriched against the threat-
    intel sources (Feodo Tracker, AbuseIPDB, GreyNoise, Shodan, …) and
    then judged by the LLM, so malicious requests — C2 beacons,
    exfiltration, connections to known-bad IPs — surface as findings.

    Parsing is split-based (no regex): with ``-t -n -q`` tcpdump prints
    one line per packet as ``IP src.port > dst.port: proto len``. On
    Linux we capture with ``-i any``, which prefixes each line with the
    interface + direction (``eth0 Out IP …``) — that's where the
    per-flow interface comes from. On macOS ``-i any`` isn't supported,
    so we capture the default interface and read its name from
    tcpdump's "listening on <iface>" banner on stderr.
    Requires root to capture — the monitor already runs as root.
    """

    slice = slices.NETWORK_FLOWS
    judge_fields = ("iface", "proto", "dst_ip", "dst_port")

    CAPTURE_SECONDS = 8  # wall-clock cap per cycle
    MAX_PACKETS = 2000  # stop after this many packets
    MAX_FLOWS = 200  # emit only the top-N flows by packet count

    def __init__(
        self,
        judge_hints: str = "",
        resolver: Optional["ProcessConnectionResolver"] = None,
        iface_args: Optional[list[str]] = None,
        runner: Optional[CommandRunner] = None,
    ):
        super().__init__(judge_hints)
        self._resolver = resolver or ProcessConnectionResolver()
        self._runner = runner or CommandRunner()
        # tcpdump flags that make each line carry its interface name;
        # supplied by the host (Linux '-i any' vs macOS '-k I').
        self._iface_args = list(iface_args or [])

    def collect(self):
        stdout, default_iface = self._capture()
        flows = self._aggregate(stdout, default_iface)
        proc_map = self._resolver.snapshot()
        ranked = sorted(flows.values(), key=lambda f: f["packets"], reverse=True)
        for f in ranked[: self.MAX_FLOWS]:
            owner = proc_map.get((f["dst_ip"], f["dst_port"]))
            # Set both unconditionally (None when unresolved) so every
            # emitted row carries the same keys — Sink.write does a
            # uniform-column executemany insert.
            f["process"] = owner[0] if owner else None
            f["pid"] = owner[1] if owner else None
            yield f

    def _capture(self) -> tuple[str, Optional[str]]:
        # -t drops timestamps (we stamp our own); TCP/UDP (v4 + v6) only.
        cmd = ["tcpdump", "-n", "-q", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        # Interface flags supplied by the host: Linux '-i any' prefixes
        # each line with the interface + direction; macOS '-k I' prints
        # the real per-packet interface (otherwise every flow is labelled
        # with the 'pktap' aggregating pseudo-device). Both yield the
        # leading-interface-token shape that _parse_line expects.
        cmd += self._iface_args
        cmd += ["tcp", "or", "udp"]
        return _run_tcpdump(self._runner, cmd, self.CAPTURE_SECONDS)

    @staticmethod
    def _iface_from_banner(stderr: str) -> Optional[str]:
        """tcpdump prints 'listening on en0, link-type ...' to stderr."""
        for line in stderr.splitlines():
            if "listening on" in line:
                rest = line.split("listening on", 1)[1].strip()
                return rest.split(",", 1)[0].strip() or None
        return None

    @staticmethod
    def _normalize_default_iface(iface: Optional[str]) -> Optional[str]:
        """Drop the macOS 'pktap' pseudo-device as a default interface.

        pktap0 / pktap aren't real interfaces — they're the aggregating
        tap macOS captures through. With '-k I' each line carries its
        real interface, so a pktap banner should fall back to 'unknown'
        rather than mislabel every flow 'pktap'."""
        if iface and iface.startswith("pktap"):
            return None
        return iface

    def _aggregate(self, output: str, default_iface: Optional[str]) -> dict:
        now = Clock().now_iso()
        flows: dict[tuple, dict] = {}
        for line in output.splitlines():
            parsed = self._parse_line(line)
            if parsed is None:
                continue
            iface, proto, dst_ip, dst_port, nbytes = parsed
            iface = iface or default_iface
            key = (iface, proto, dst_ip, dst_port)
            f = flows.get(key)
            if f is None:
                flows[key] = {
                    "iface": iface,
                    "proto": proto,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "service": self._service(dst_port, proto),
                    "packets": 1,
                    "byte_count": nbytes,
                    "first_seen": now,
                    "last_seen": now,
                }
            else:
                f["packets"] += 1
                f["byte_count"] += nbytes
                f["last_seen"] = now
        return flows

    @staticmethod
    def _parse_line(line: str):
        """Return (iface, proto, dst_ip, dst_port, nbytes) from one tcpdump
        -t -q line, or None if it isn't a parseable TCP/UDP packet.
        ``nbytes`` is the payload length tcpdump prints (0 when absent).

        Handles both IPv4 (``IP``) and IPv6 (``IP6``) — tcpdump appends
        the port after a final ``.`` for both families, so the trailing
        ``.<port>`` splits off the destination address either way.

        macOS '-k I':   ``(en6) IP src.port > dst.port: tcp 1380``
        Linux -i any:   ``eth0 Out IP6 src.port > dst.port: UDP, length 45``
        """
        parts = line.split()
        if ">" not in parts:
            return None
        if "IP" in parts:
            ip_idx = parts.index("IP")
        elif "IP6" in parts:
            ip_idx = parts.index("IP6")
        else:
            return None
        # If "IP" isn't the first token, the leading token is the
        # interface — Linux '-i any' prefixes "<iface> In/Out IP …",
        # macOS '-k I' prefixes "<iface> IP …". Strip any decoration.
        iface = parts[0].strip("()") if ip_idx >= 1 else None
        gt = parts.index(">")
        if gt + 1 >= len(parts):
            return None
        dst = parts[gt + 1].rstrip(":")  # e.g. 142.250.80.46.443
        ip, _, port_s = dst.rpartition(".")  # ip=142.250.80.46 port=443
        if not ip or not port_s.isdigit():
            return None
        proto = "ip"
        if gt + 2 < len(parts):
            proto = parts[gt + 2].rstrip(",").lower()
        return iface, proto, ip, int(port_s), _payload_bytes(parts)

    @staticmethod
    def _service(port: int, proto: str):
        try:
            return socket.getservbyport(
                port, proto if proto in ("tcp", "udp") else "tcp"
            )
        except (OSError, OverflowError, TypeError):
            return None


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

    Parsing is split-based (no regex): without ``-q`` tcpdump decodes the
    DNS payload as ``… 1234+ A? example.com. (29)`` — we pull the qtype
    (the token ending in ``?``) and the qname (the token after it).
    Requires root to capture.
    """

    slice = slices.DNS_QUERIES
    judge_fields = ("qname", "qtype", "server_ip")

    CAPTURE_SECONDS = 8
    MAX_PACKETS = 2000
    MAX_QUERIES = 200

    # Well-known DoH resolver endpoints. Plaintext DNS (53) is visible to
    # us; DoH (TLS/443) isn't — so a host talking to one of these on 443
    # is resolving names out of our sight.
    _DOH_PORT = 443
    _DOH_IPS = {
        "1.1.1.1": "Cloudflare",
        "1.0.0.1": "Cloudflare",
        "8.8.8.8": "Google",
        "8.8.4.4": "Google",
        "9.9.9.9": "Quad9",
        "149.112.112.112": "Quad9",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
        "2606:4700:4700::1111": "Cloudflare",
        "2001:4860:4860::8888": "Google",
    }

    def __init__(
        self,
        judge_hints: str = "",
        resolver: Optional["ProcessConnectionResolver"] = None,
        iface_args: Optional[list[str]] = None,
        runner: Optional[CommandRunner] = None,
    ):
        super().__init__(judge_hints)
        self._resolver = resolver or ProcessConnectionResolver()
        self._runner = runner or CommandRunner()
        self._iface_args = list(iface_args or [])

    def collect(self):
        stdout, default_iface = self._capture()
        proc_map = self._resolver.snapshot()
        queries = self._aggregate(stdout, default_iface, proc_map)
        # DoH: connections to known DoH endpoints on :443 bypass plaintext
        # DNS visibility entirely — surface them alongside the queries.
        for (ip, port), (name, _pid) in proc_map.items():
            if port != self._DOH_PORT or ip not in self._DOH_IPS:
                continue
            provider = self._DOH_IPS[ip]
            key = (provider, "DoH", ip)
            if key not in queries:
                now = Clock().now_iso()
                queries[key] = {
                    "iface": None,
                    "qname": provider,
                    "qtype": "DoH",
                    "server_ip": ip,
                    "process": name,
                    "count": 1,
                    "first_seen": now,
                    "last_seen": now,
                }
        ranked = sorted(queries.values(), key=lambda q: q["count"], reverse=True)
        yield from ranked[: self.MAX_QUERIES]

    def _capture(self) -> tuple[str, Optional[str]]:
        """Capture port-53 traffic *without* ``-q`` so tcpdump decodes the
        DNS question."""
        cmd = ["tcpdump", "-n", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        cmd += self._iface_args
        cmd += ["udp", "port", "53", "or", "tcp", "port", "53"]
        return _run_tcpdump(self._runner, cmd, self.CAPTURE_SECONDS)

    def _aggregate(self, output: str, default_iface: Optional[str], proc_map: dict):
        now = Clock().now_iso()
        queries: dict[tuple, dict] = {}
        for line in output.splitlines():
            parsed = self._parse_dns_line(line)
            if parsed is None:
                continue
            iface, qname, qtype, server_ip = parsed
            iface = iface or default_iface
            key = (qname, qtype, server_ip)
            g = queries.get(key)
            if g is None:
                owner = proc_map.get((server_ip, 53))
                queries[key] = {
                    "iface": iface,
                    "qname": qname,
                    "qtype": qtype,
                    "server_ip": server_ip,
                    "process": owner[0] if owner else None,
                    "count": 1,
                    "first_seen": now,
                    "last_seen": now,
                }
            else:
                g["count"] += 1
                g["last_seen"] = now
        return queries

    @staticmethod
    def _parse_dns_line(line: str):
        """Return (iface, qname, qtype, server_ip) from one decoded
        tcpdump DNS line, or None if it isn't an outbound query.

        Example (macOS '-k I'):
            ``(en6) IP 10.0.0.5.51000 > 8.8.8.8.53: 1234+ A? example.com. (29)``
        Only questions *to* port 53 are kept (a response has src port 53
        and no ``A?``-style token).
        """
        parts = line.split()
        if ">" not in parts:
            return None
        if "IP" in parts:
            ip_idx = parts.index("IP")
        elif "IP6" in parts:
            ip_idx = parts.index("IP6")
        else:
            return None
        iface = parts[0].strip("()") if ip_idx >= 1 else None
        gt = parts.index(">")
        if gt + 1 >= len(parts):
            return None
        server = parts[gt + 1].rstrip(":")
        server_ip, _, server_port = server.rpartition(".")
        if server_port != "53" or not server_ip:
            return None
        qtype = qname = None
        payload = parts[gt + 2 :]
        for i, tok in enumerate(payload):
            # The question type is the token ending in '?' (A?, AAAA?,
            # PTR?, …); the queried name is the token right after it.
            if len(tok) > 1 and tok.endswith("?"):
                qtype = tok[:-1]
                if i + 1 < len(payload):
                    qname = payload[i + 1].rstrip(".")
                break
        if not qname:
            return None
        return iface, qname, qtype, server_ip


class NetworkInterfacesCollector(SnapshotCollector):
    slice = slices.NETWORK_INTERFACES
    judge_enabled = False  # counters need behavioural analysis

    def __init__(
        self, judge_hints: str = "", metrics: Optional[SystemMetrics] = None
    ) -> None:
        super().__init__(judge_hints)
        self._metrics = metrics or SystemMetrics()

    def collect(self):
        addrs = self._metrics.net_if_addrs()
        stats = self._metrics.net_if_stats()
        counters = self._metrics.net_io_counters()
        for name, addr_list in addrs.items():
            s, c = stats.get(name), counters.get(name)
            yield {
                "name": name,
                "is_up": int(s.isup) if s else None,
                "speed_mbps": s.speed if s else None,
                "mtu": s.mtu if s else None,
                "bytes_sent": c.bytes_sent if c else None,
                "bytes_recv": c.bytes_recv if c else None,
                "packets_sent": c.packets_sent if c else None,
                "packets_recv": c.packets_recv if c else None,
                "errin": c.errin if c else None,
                "errout": c.errout if c else None,
                "dropin": c.dropin if c else None,
                "dropout": c.dropout if c else None,
                "addresses_json": json.dumps(
                    [
                        {
                            "family": a.family.name,
                            "address": a.address,
                            "netmask": a.netmask,
                            "broadcast": a.broadcast,
                        }
                        for a in addr_list
                    ]
                ),
            }
