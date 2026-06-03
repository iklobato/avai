"""Snapshot + streaming collectors and their platform builders."""

from __future__ import annotations

import configparser
import json
import shlex
import shutil
import socket
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Iterable, Optional

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

from . import constants
from .constants import (
    APP_INFO_KEYS,
    AUTH_LOG_PREDICATE,
    BROWSER_PROFILES,
    BROWSER_PROFILES_LINUX,
    IS_LINUX,
    LAUNCH_DIRS,
    WATCHED_FILES,
    WATCHED_FILES_LINUX,
)
from .enums import Browser, LaunchScope
from .models import (
    AuthEventRow,
    BluetoothDeviceRow,
    BrowserExtensionRow,
    DnsQueryRow,
    FileIntegrityRow,
    HostsFileRow,
    InstalledAppRow,
    KernelExtensionRow,
    LaunchItemRow,
    ListeningPortRow,
    MdmProfileRow,
    MountRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    NetworkInterfaceRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    ProcessRow,
    QuarantineEventRow,
    SetuidFileRow,
    SshAuthorizedKeyRow,
    SystemExtensionRow,
    SystemIntegrityRow,
    UsbDeviceRow,
    WifiStateRow,
    _RowBase,
)
from .prompts import Prompts
from .runtime import JsonLineStreamSource
from .shell import (
    _read_sysfs,
    _ssh_fingerprint,
    exit_code,
    expand,
    external_sqlite_rows,
    host_path,
    host_paths_for_home,
    jsonable,
    process_running,
    read_plist,
    run_json,
    safe_psutil_connections,
    sha256_file,
    utcnow,
)


class Collector(ABC):
    """Common base for any host-state collector. Subclass
    :class:`SnapshotCollector` (pull, per-cycle) or
    :class:`StreamingCollector` (push, long-lived) — not this directly.

    Free-form text used to steer the LLM judge is injected per-instance
    via ``judge_hints`` (sourced from the external prompts TOML file).
    """

    name: ClassVar[str]
    model: ClassVar[type[_RowBase]]
    judge_enabled: ClassVar[bool] = True
    judge_fields: ClassVar[tuple[str, ...]] = ()

    def __init__(self, judge_hints: str = ""):
        self.judge_hints = judge_hints

    @property
    def table(self) -> str:
        return self.model.__tablename__


class SnapshotCollector(Collector):
    """Pull model — the Runner calls :meth:`collect` once per cycle and
    materializes the result as a batch insert."""

    @abstractmethod
    def collect(self) -> Iterable[dict]:
        """Yield row dicts for ``self.model``.

        ``run_id``, ``collected_at`` and ``content_hash`` are injected
        by the Runner — do not include them here.
        """


class StreamingCollector(Collector):
    """Push model — the Runner starts :meth:`stream` once in a dedicated
    worker thread; the iterator yields rows as events arrive and only
    stops when ``stop_event`` is set or the stream ends.

    Streaming sources are time-series events (not state), so the default
    ``judge_enabled`` is ``False``; aggregate analysis is the right tool.
    """

    judge_enabled: ClassVar[bool] = False

    @abstractmethod
    def stream(self, stop_event: threading.Event) -> Iterable[dict]:
        """Yield row dicts continuously until ``stop_event`` is set.

        Implementations are responsible for terminating their underlying
        data source (subprocess, socket, filesystem watcher) when the
        event fires.
        """


class BrowserExtensionReader(ABC):
    @abstractmethod
    def read(self, base: Path, browser: Browser) -> Iterable[dict]: ...


class ChromiumExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        try:
            profile_dirs = list(base.iterdir())
        except OSError:
            return
        for profile_dir in profile_dirs:
            ext_root = profile_dir / "Extensions"
            if not ext_root.is_dir():
                continue
            for ext_id_dir in ext_root.iterdir():
                if not ext_id_dir.is_dir():
                    continue
                for version_dir in ext_id_dir.iterdir():
                    manifest = version_dir / "manifest.json"
                    if not manifest.is_file():
                        continue
                    try:
                        m = json.loads(
                            manifest.read_text(encoding="utf-8", errors="replace")
                        )
                    except (json.JSONDecodeError, OSError):
                        continue
                    yield {
                        "browser": str(browser),
                        "profile": profile_dir.name,
                        "extension_id": ext_id_dir.name,
                        "name": m.get("name"),
                        "version": m.get("version"),
                        "permissions_json": json.dumps(m.get("permissions") or []),
                        "host_permissions_json": json.dumps(
                            m.get("host_permissions") or m.get("matches") or []
                        ),
                        "path": str(version_dir),
                        "manifest_json": json.dumps(m),
                    }


class FirefoxExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        profiles_dir = base / "Profiles"
        if not profiles_dir.is_dir():
            return
        for profile_dir in profiles_dir.iterdir():
            ext_file = profile_dir / "extensions.json"
            if not ext_file.is_file():
                continue
            try:
                data = json.loads(
                    ext_file.read_text(encoding="utf-8", errors="replace")
                )
            except (json.JSONDecodeError, OSError):
                continue
            for addon in data.get("addons", []) or []:
                up = addon.get("userPermissions") or {}
                dl = addon.get("defaultLocale") or {}
                yield {
                    "browser": str(browser),
                    "profile": profile_dir.name,
                    "extension_id": addon.get("id"),
                    "name": dl.get("name"),
                    "version": addon.get("version"),
                    "permissions_json": json.dumps(up.get("permissions") or []),
                    "host_permissions_json": json.dumps(up.get("origins") or []),
                    "path": addon.get("path"),
                    "manifest_json": json.dumps(addon),
                }


class ProcessCollector(SnapshotCollector):
    name = "processes"
    model = ProcessRow
    judge_fields = ("name", "exe", "cmdline_json", "username")
    _ATTRS = [
        "pid",
        "ppid",
        "name",
        "exe",
        "cmdline",
        "username",
        "uids",
        "status",
        "create_time",
        "cpu_percent",
        "memory_info",
        "num_fds",
        "num_threads",
    ]

    def collect(self):
        for p in psutil.process_iter(self._ATTRS, ad_value=None):
            info = p.info
            mem, uids = info.get("memory_info"), info.get("uids")
            yield {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline_json": json.dumps(info.get("cmdline") or []),
                "username": info.get("username"),
                "uid": uids[0] if uids else None,
                "status": info.get("status"),
                "create_time": info.get("create_time"),
                "cpu_percent": info.get("cpu_percent"),
                "memory_rss": mem.rss if mem else None,
                "num_fds": info.get("num_fds"),
                "num_threads": info.get("num_threads"),
            }


class NetworkConnectionsCollector(SnapshotCollector):
    name = "network_connections"
    model = NetworkConnectionRow
    judge_enabled = False  # too high churn; aggregate behaviourally instead

    def collect(self):
        for c in safe_psutil_connections():
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
    name = "listening_ports"
    model = ListeningPortRow
    judge_fields = ("process_name", "family", "type", "laddr_ip", "laddr_port")

    def collect(self):
        names: dict[int, Optional[str]] = {}
        for c in safe_psutil_connections():
            if c.status != psutil.CONN_LISTEN:
                continue
            if c.pid is not None and c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[c.pid] = None
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

    def snapshot(self) -> dict[tuple[str, int], tuple[str, int]]:
        """Map remote ``(ip, port)`` → ``(process_name, pid)`` for every
        inet socket that has a remote peer and a resolvable owner."""
        out: dict[tuple[str, int], tuple[str, int]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
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

    @staticmethod
    def _proc_name(pid: int) -> str:
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return f"pid {pid}"


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

    name = "network_flows"
    model = NetworkFlowRow
    judge_fields = ("iface", "proto", "dst_ip", "dst_port")

    CAPTURE_SECONDS = 8  # wall-clock cap per cycle
    MAX_PACKETS = 2000  # stop after this many packets
    MAX_FLOWS = 200  # emit only the top-N flows by packet count

    def __init__(
        self,
        judge_hints: str = "",
        resolver: Optional["ProcessConnectionResolver"] = None,
    ):
        super().__init__(judge_hints)
        self._resolver = resolver or ProcessConnectionResolver()

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
        """Return (stdout, default_iface). default_iface is the interface
        tcpdump reported listening on (used when a line carries no
        per-packet interface, i.e. not the Linux '-i any' path)."""
        if shutil.which("tcpdump") is None:
            raise RuntimeError("tcpdump not found on PATH")
        # -t drops timestamps (we stamp our own); TCP/UDP (v4 + v6) only.
        cmd = ["tcpdump", "-n", "-q", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        if IS_LINUX:
            # 'any' prefixes each line with the interface + direction.
            cmd += ["-i", "any"]
        else:
            # macOS auto-selects the 'pktap' pseudo-device, which aggregates
            # every interface — so without this every flow is labelled
            # 'pktap'. '-k I' prints the real per-packet interface name as
            # the leading token (same shape as Linux '-i any'), which
            # _parse_line already picks up.
            cmd += ["-k", "I"]
        cmd += ["tcp", "or", "udp"]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.CAPTURE_SECONDS
            )
            stdout, stderr = r.stdout or "", r.stderr or ""
        except subprocess.TimeoutExpired as e:
            # Slow link: hit the time cap before MAX_PACKETS — keep partial.
            def _txt(b):
                return (
                    b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")
                )

            stdout, stderr = _txt(e.stdout), _txt(e.stderr)
        return stdout, self._normalize_default_iface(self._iface_from_banner(stderr))

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
        now = utcnow()
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

    name = "dns_queries"
    model = DnsQueryRow
    judge_fields = ("qname", "qtype", "server_ip")

    CAPTURE_SECONDS = 8
    MAX_PACKETS = 2000
    MAX_QUERIES = 200

    # Well-known DoH resolver endpoints. Plaintext DNS (53) is visible to
    # us; DoH (TLS/443) isn't — so a host talking to one of these on 443
    # is resolving names out of our sight.
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
    ):
        super().__init__(judge_hints)
        self._resolver = resolver or ProcessConnectionResolver()

    def collect(self):
        stdout, default_iface = self._capture()
        proc_map = self._resolver.snapshot()
        queries = self._aggregate(stdout, default_iface, proc_map)
        # DoH: connections to known DoH endpoints on :443 bypass plaintext
        # DNS visibility entirely — surface them alongside the queries.
        for (ip, port), (name, _pid) in proc_map.items():
            if port != 443 or ip not in self._DOH_IPS:
                continue
            provider = self._DOH_IPS[ip]
            key = (provider, "DoH", ip)
            if key not in queries:
                now = utcnow()
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
        DNS question. Reuses the flow collector's interface helpers."""
        if shutil.which("tcpdump") is None:
            raise RuntimeError("tcpdump not found on PATH")
        cmd = ["tcpdump", "-n", "-l", "-t", "-c", str(self.MAX_PACKETS)]
        if IS_LINUX:
            cmd += ["-i", "any"]
        else:
            cmd += ["-k", "I"]
        cmd += ["udp", "port", "53", "or", "tcp", "port", "53"]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.CAPTURE_SECONDS
            )
            stdout, stderr = r.stdout or "", r.stderr or ""
        except subprocess.TimeoutExpired as e:

            def _txt(b):
                return (
                    b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")
                )

            stdout, stderr = _txt(e.stdout), _txt(e.stderr)
        iface = NetworkFlowsCollector._normalize_default_iface(
            NetworkFlowsCollector._iface_from_banner(stderr)
        )
        return stdout, iface

    def _aggregate(self, output: str, default_iface: Optional[str], proc_map: dict):
        now = utcnow()
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
    name = "network_interfaces"
    model = NetworkInterfaceRow
    judge_enabled = False  # counters need behavioural analysis

    def collect(self):
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True)
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


class UsbDevicesCollector(SnapshotCollector):
    name = "usb_devices"
    model = UsbDeviceRow
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPUSBDataType"], timeout=30)
        root = data.get("SPUSBDataType", []) if isinstance(data, dict) else (data or [])
        yield from self._walk(root, None)

    def _walk(self, items, parent_location):
        for item in items or []:
            loc = item.get("location_id") or parent_location
            yield {
                "name": item.get("_name"),
                "vendor_id": item.get("vendor_id"),
                "product_id": item.get("product_id"),
                "serial_number": item.get("serial_num"),
                "manufacturer": item.get("manufacturer"),
                "location_id": loc,
                "speed": item.get("device_speed"),
                "raw_json": json.dumps(
                    {k: jsonable(v) for k, v in item.items() if k != "_items"}
                ),
            }
            yield from self._walk(item.get("_items"), loc)


class BluetoothCollector(SnapshotCollector):
    name = "bluetooth_devices"
    model = BluetoothDeviceRow
    judge_fields = ("name", "address", "minor_type")
    _GROUPS = (
        "device_connected",
        "device_not_connected",
        "device_paired",
        "devices_list",
    )
    _PAIRED_GROUPS = {"device_connected", "device_not_connected", "device_paired"}

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPBluetoothDataType"], timeout=30)
        sections = (
            data.get("SPBluetoothDataType", [])
            if isinstance(data, dict)
            else (data or [])
        )
        for section in sections:
            for group in self._GROUPS:
                for entry in section.get(group, []) or []:
                    if not isinstance(entry, dict):
                        continue
                    for dev_name, dev in entry.items():
                        if not isinstance(dev, dict):
                            continue
                        yield {
                            "name": dev_name,
                            "address": dev.get("device_address"),
                            "connected": int(group == "device_connected"),
                            "paired": int(group in self._PAIRED_GROUPS),
                            "minor_type": dev.get("device_minorType"),
                            "raw_json": json.dumps(jsonable(dev)),
                        }


class WifiCollector(SnapshotCollector):
    name = "wifi_state"
    model = WifiStateRow
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPAirPortDataType"], timeout=30)
        sections = (
            data.get("SPAirPortDataType", [])
            if isinstance(data, dict)
            else (data or [])
        )
        for entry in sections:
            for iface in entry.get("spairport_airport_interfaces", []) or []:
                cur = iface.get("spairport_current_network_information") or {}
                channel = cur.get("spairport_network_channel")
                yield {
                    "interface": iface.get("_name"),
                    "ssid": cur.get("_name"),
                    "bssid": cur.get("spairport_network_bssid"),
                    "channel": str(channel) if channel is not None else None,
                    "security": cur.get("spairport_security_mode"),
                    "raw_json": json.dumps(jsonable(cur)),
                }


class LaunchItemsCollector(SnapshotCollector):
    name = "launch_items"
    model = LaunchItemRow
    judge_fields = (
        "scope",
        "label",
        "program",
        "program_arguments_json",
        "user_name",
        "run_at_load",
        "keep_alive",
    )

    def collect(self):
        for scope, dir_str in LAUNCH_DIRS:
            d = expand(dir_str)
            if not d.is_dir():
                continue
            try:
                plists = list(d.glob("*.plist"))
            except PermissionError:
                continue
            for path in plists:
                row = self._row(scope, path)
                if row is not None:
                    yield row

    @staticmethod
    def _row(scope: LaunchScope, path: Path):
        data = read_plist(path)
        if data is None:
            return None
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        sci = data.get("StartCalendarInterval")
        return {
            "scope": str(scope),
            "path": str(path),
            "label": data.get("Label"),
            "program": data.get("Program"),
            "program_arguments_json": json.dumps(
                jsonable(data.get("ProgramArguments") or [])
            ),
            "run_at_load": int(bool(data.get("RunAtLoad"))),
            "keep_alive": int(bool(data.get("KeepAlive"))),
            "start_interval": data.get("StartInterval"),
            "start_calendar_interval_json": (
                json.dumps(jsonable(sci)) if sci is not None else None
            ),
            "user_name": data.get("UserName"),
            "group_name": data.get("GroupName"),
            "sha256": sha256_file(path),
            "mtime": mtime,
            "raw_json": json.dumps(jsonable(data)),
        }


class QuarantineCollector(SnapshotCollector):
    name = "quarantine_events"
    model = QuarantineEventRow
    judge_fields = ("agent_bundle_id", "agent_name", "origin_url", "data_url")
    _COLUMN_MAP = {
        "LSQuarantineEventIdentifier": "event_id",
        "LSQuarantineTimeStamp": "timestamp",
        "LSQuarantineAgentBundleIdentifier": "agent_bundle_id",
        "LSQuarantineAgentName": "agent_name",
        "LSQuarantineOriginURLString": "origin_url",
        "LSQuarantineDataURLString": "data_url",
        "LSQuarantineSenderName": "sender_name",
        "LSQuarantineTypeNumber": "type_number",
    }

    def collect(self):
        path = expand(
            "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        )
        if not path.exists():
            return
        for row in external_sqlite_rows(
            path, "LSQuarantineEvent", list(self._COLUMN_MAP.keys())
        ):
            yield {self._COLUMN_MAP[k]: v for k, v in row.items()}


class BrowserExtensionsCollector(SnapshotCollector):
    name = "browser_extensions"
    model = BrowserExtensionRow
    judge_fields = (
        "browser",
        "extension_id",
        "name",
        "permissions_json",
        "host_permissions_json",
    )

    def __init__(
        self,
        readers: Optional[dict[Browser, BrowserExtensionReader]] = None,
        default_reader: Optional[BrowserExtensionReader] = None,
        judge_hints: str = "",
        profiles: Optional[dict[Browser, list[str]]] = None,
    ):
        super().__init__(judge_hints=judge_hints)
        self.readers = readers or {Browser.FIREFOX: FirefoxExtensionReader()}
        self.default_reader = default_reader or ChromiumExtensionReader()
        # Per-platform search roots — caller supplies BROWSER_PROFILES
        # or BROWSER_PROFILES_LINUX. Defaults to the macOS layout.
        self.profiles = profiles or BROWSER_PROFILES

    def collect(self):
        for browser, profiles in self.profiles.items():
            reader = self.readers.get(browser, self.default_reader)
            for base_str in profiles:
                base = expand(base_str)
                if not base.is_dir():
                    continue
                yield from reader.read(base, browser)


class SystemIntegrityCollector(SnapshotCollector):
    name = "system_integrity"
    model = SystemIntegrityRow
    judge_fields = (
        "filevault_active",
        "firewall_global_state",
        "firewall_stealth",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    def collect(self):
        fv = exit_code(["fdesetup", "isactive"])
        alf = read_plist(Path("/Library/Preferences/com.apple.alf.plist")) or {}
        # spctl --status always exits 0; the state is in its stdout text.
        try:
            _gk = subprocess.run(
                ["spctl", "--status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            _gk_out = (_gk.stdout + _gk.stderr).lower()
            if "assessments enabled" in _gk_out:
                gk: Optional[int] = 1
            elif "assessments disabled" in _gk_out:
                gk = 0
            else:
                gk = None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            gk = None
        yield {
            "filevault_active": None if fv is None else int(fv == 0),
            "firewall_global_state": alf.get("globalstate"),
            "firewall_stealth": int(bool(alf.get("stealthenabled"))) if alf else None,
            "firewall_logging": int(bool(alf.get("loggingenabled"))) if alf else None,
            "gatekeeper_assessments_enabled": gk,
            # launchctl list only covers the user domain; sshd/screensharingd/
            # ARDAgent are system-domain services — use pgrep instead.
            "remote_login_enabled": process_running("sshd"),
            "screen_sharing_enabled": process_running("screensharingd"),
            "remote_management_enabled": process_running("ARDAgent"),
            "raw_json": json.dumps({"alf": jsonable(alf)}),
        }


class UnifiedLogAuthParser:
    """Strategy: macOS ``log stream --style ndjson`` event → auth row."""

    def parse(self, event: dict) -> dict:
        return {
            "event_timestamp": event.get("timestamp"),
            "process": event.get("processImagePath"),
            "subsystem": event.get("subsystem"),
            "category": event.get("category"),
            "event_type": event.get("eventType"),
            "event_message": event.get("eventMessage"),
            "pid": event.get("processID"),
            "raw_json": json.dumps(event),
        }


class AuthEventsCollector(StreamingCollector):
    """Tails the macOS unified log forever via ``log stream``. Each
    matching event is yielded as it arrives — no polling gaps."""

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    def __init__(self, predicate: str = AUTH_LOG_PREDICATE, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.predicate = predicate

    def stream(self, stop_event: threading.Event):
        cmd = [
            "log",
            "stream",
            "--style",
            "ndjson",
            "--info",
            "--predicate",
            self.predicate,
        ]
        source = JsonLineStreamSource(
            cmd, UnifiedLogAuthParser(), killer_name="log-stream-killer"
        )
        yield from source.stream(stop_event)


class FileIntegrityCollector(SnapshotCollector):
    name = "file_integrity"
    model = FileIntegrityRow
    judge_fields = ("path", "sha256", "exists_flag")

    def __init__(self, watched: Iterable[str] = WATCHED_FILES, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.watched = list(watched)

    def collect(self):
        for path_str in self.watched:
            p = expand(path_str)
            try:
                st = p.lstat()
            except FileNotFoundError:
                yield self._missing(p)
                continue
            except PermissionError:
                continue
            yield {
                "path": str(p),
                "sha256": sha256_file(p) if p.is_file() else None,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "exists_flag": 1,
            }

    @staticmethod
    def _missing(p):
        return {
            "path": str(p),
            "sha256": None,
            "size": None,
            "mtime": None,
            "mode": None,
            "uid": None,
            "gid": None,
            "exists_flag": 0,
        }


class InstalledAppsCollector(SnapshotCollector):
    name = "installed_apps"
    model = InstalledAppRow
    judge_fields = ("bundle_id", "name", "path")

    def collect(self):
        for app_dir in (Path("/Applications"), expand("~/Applications")):
            if not app_dir.is_dir():
                continue
            try:
                apps = list(app_dir.glob("*.app"))
            except PermissionError:
                continue
            for app in apps:
                info = read_plist(app / "Contents" / "Info.plist") or {}
                yield {
                    "path": str(app),
                    "bundle_id": info.get("CFBundleIdentifier"),
                    "name": info.get("CFBundleName") or info.get("CFBundleDisplayName"),
                    "version": info.get("CFBundleShortVersionString"),
                    "raw_json": json.dumps(
                        jsonable(
                            {
                                k: info.get(k)
                                for k in APP_INFO_KEYS
                                if info.get(k) is not None
                            }
                        )
                    ),
                }


class LinuxInstalledAppsCollector(SnapshotCollector):
    """Linux equivalent of :class:`InstalledAppsCollector`. Sources:

    - ``dpkg -l`` (Debian / Ubuntu / derivatives): installed binary
      packages. Each yields one row tagged ``source='dpkg'``.
    - ``/usr/share/applications/*.desktop`` (XDG, universal): GUI app
      menu entries. Each yields one row tagged ``source='desktop'``.

    The ``bundle_id`` column holds the package name (dpkg) or the
    ``.desktop`` filename's stem (XDG), so the judge dedupes via a
    stable identifier in either case.
    """

    name = "installed_apps"
    model = InstalledAppRow
    judge_fields = ("bundle_id", "name", "path")

    _DPKG_FIELDS = ("Status", "Package", "Version", "Architecture", "Description")

    def collect(self):
        yield from self._dpkg_rows()
        yield from self._desktop_rows()

    def _dpkg_rows(self):
        if not shutil.which("dpkg-query"):
            return
        # Tab-separated fixed-field output: no parsing of dpkg -l's
        # column-aligned text. dpkg-query -W -f gives us structured
        # output with a chosen delimiter.
        fmt = (
            "${db:Status-Status}\t${Package}\t${Version}\t"
            "${Architecture}\t${binary:Summary}\n"
        )
        cmd = ["dpkg-query", "-W", "-f", fmt]
        # When containerised, --admindir points dpkg-query at the host's
        # package database rather than the container's.
        host_admindir = host_path("/var/lib/dpkg")
        if constants.HOST_PREFIX and host_admindir.is_dir():
            cmd[1:1] = ["--admindir", str(host_admindir)]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            status, name, version, arch, summary = (
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                parts[4],
            )
            if status != "installed":
                continue
            yield {
                "path": f"dpkg:{name}",
                "bundle_id": name,
                "name": name,
                "version": version,
                "raw_json": json.dumps(
                    {
                        "source": "dpkg",
                        "status": status,
                        "architecture": arch,
                        "summary": summary,
                    }
                ),
            }

    def _desktop_rows(self):
        # XDG desktop entries are simple INI files; configparser
        # handles them. We extract [Desktop Entry] Name / Exec /
        # Comment / Categories.
        roots: list[Path] = [
            host_path("/usr/share/applications"),
            host_path("/usr/local/share/applications"),
            host_path("/var/lib/flatpak/exports/share/applications"),
        ]
        roots.extend(host_paths_for_home("~/.local/share/applications"))
        roots.extend(
            host_paths_for_home("~/.local/share/flatpak/exports/share/applications")
        )
        for root in roots:
            if not root.is_dir():
                continue
            try:
                entries = list(root.glob("*.desktop"))
            except PermissionError:
                continue
            for entry in entries:
                cp = configparser.ConfigParser(
                    interpolation=None,
                    strict=False,
                )
                # .desktop keys are CamelCase (Name, Exec, Version,
                # Type). Preserve case — the default lowercasing made
                # every sec.get("Name")/("Exec") miss.
                cp.optionxform = str
                try:
                    cp.read(entry, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                if "Desktop Entry" not in cp:
                    continue
                sec = cp["Desktop Entry"]
                yield {
                    "path": str(entry),
                    "bundle_id": entry.stem,
                    "name": sec.get("Name"),
                    "version": sec.get("Version"),
                    "raw_json": json.dumps(
                        {
                            "source": "desktop",
                            "exec": sec.get("Exec"),
                            "comment": sec.get("Comment"),
                            "categories": sec.get("Categories"),
                            "type": sec.get("Type"),
                            "no_display": sec.get("NoDisplay") == "true",
                        }
                    ),
                }


class LinuxLaunchItemsCollector(SnapshotCollector):
    """Linux equivalent of :class:`LaunchItemsCollector`.

    Sources, all parsed structurally (no regex):

    - **systemd unit files** in (in this precedence order, first wins
      for duplicate names) ``/etc/systemd/system``,
      ``/run/systemd/system``, ``/lib/systemd/system``,
      ``/usr/lib/systemd/system``, ``~/.config/systemd/user``. Both
      ``.service`` and ``.timer`` units are read. INI format parsed
      via :mod:`configparser`. The ``[Unit] / [Service] / [Install] /
      [Timer]`` sections are captured verbatim in ``raw_json``;
      key fields land in the existing ``launch_items`` columns.

    - **cron entries** from ``/etc/crontab``, drop-in files in
      ``/etc/cron.d/*``, and per-user crontabs in ``/var/spool/cron``
      and ``/var/spool/cron/crontabs`` (root-readable). System-wide
      crontabs carry a user column (field 6); user crontabs don't.

    The ``scope`` column distinguishes sources:
    ``system_service`` / ``user_service`` / ``system_timer`` /
    ``user_timer`` / ``system_crontab`` / ``system_crontab_d`` /
    ``user_crontab``.
    """

    name = "launch_items"
    model = LaunchItemRow
    judge_fields = (
        "scope",
        "label",
        "program",
        "program_arguments_json",
        "user_name",
        "run_at_load",
        "keep_alive",
    )

    # (scope, directory, glob). Directories searched in this order;
    # later occurrences of the same unit filename are ignored (systemd
    # itself layers these dirs with /etc winning over /lib).
    _UNIT_DIRS = [
        ("system_service", "/etc/systemd/system", "*.service"),
        ("system_service", "/run/systemd/system", "*.service"),
        ("system_service", "/lib/systemd/system", "*.service"),
        ("system_service", "/usr/lib/systemd/system", "*.service"),
        ("user_service", "~/.config/systemd/user", "*.service"),
        ("system_timer", "/etc/systemd/system", "*.timer"),
        ("system_timer", "/lib/systemd/system", "*.timer"),
        ("system_timer", "/usr/lib/systemd/system", "*.timer"),
        ("user_timer", "~/.config/systemd/user", "*.timer"),
    ]

    _CRON_FILE = ("system_crontab", Path("/etc/crontab"))
    _CRON_DROP_INS = [
        ("system_crontab_d", Path("/etc/cron.d")),
    ]
    _USER_CRONS = [
        ("user_crontab", Path("/var/spool/cron")),
        ("user_crontab", Path("/var/spool/cron/crontabs")),
    ]

    _ALWAYS_RESTART = {
        "always",
        "on-failure",
        "on-success",
        "on-abnormal",
        "on-abort",
        "on-watchdog",
    }

    def collect(self):
        # systemd units. Path translation honours HOST_PREFIX so the
        # container reads the host's /etc/systemd/system rather than
        # its own (empty) one.
        seen_units: set[str] = set()
        for scope, dir_str, pattern in self._UNIT_DIRS:
            # host_paths_for_home expands a ~/... template into 0..N real
            # dirs (one per user home in container mode), or exactly one
            # for an absolute path. It can return [] — e.g. container
            # mode with no /host/home and no /host/root mounted — so we
            # iterate rather than index [0] (which raised IndexError and
            # killed the whole collector).
            for d in host_paths_for_home(dir_str):
                if not d.is_dir():
                    continue
                try:
                    paths = list(d.glob(pattern))
                except PermissionError:
                    continue
                for path in paths:
                    # Dedup by name preserves systemd's first-wins
                    # precedence across the system unit dirs.
                    if path.name in seen_units:
                        continue
                    seen_units.add(path.name)
                    row = self._unit_row(scope, path)
                    if row is not None:
                        yield row

        # /etc/crontab — single file, has-user-column form
        scope, p = self._CRON_FILE
        p = host_path(p)
        if p.is_file():
            yield from self._cron_rows(scope, p, has_user_col=True)

        # /etc/cron.d/* — drop-in files, has-user-column form
        for scope, d in self._CRON_DROP_INS:
            d = host_path(d)
            if not d.is_dir():
                continue
            try:
                files = list(d.iterdir())
            except PermissionError:
                continue
            for f in files:
                if not f.is_file() or f.name.startswith("."):
                    continue
                yield from self._cron_rows(scope, f, has_user_col=True)

        # /var/spool/cron* — per-user crontabs (no user column inside).
        # The filename IS the username.
        for scope, d in self._USER_CRONS:
            d = host_path(d)
            if not d.is_dir():
                continue
            try:
                files = list(d.iterdir())
            except PermissionError:
                continue
            for f in files:
                if not f.is_file() or f.name.startswith("."):
                    continue
                yield from self._cron_rows(
                    scope, f, has_user_col=False, default_user=f.name
                )

    @staticmethod
    def _unit_row(scope: str, path: Path):
        cp = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            inline_comment_prefixes=("#", ";"),
            comment_prefixes=("#", ";"),
        )
        # systemd directive keys are CamelCase (ExecStart, OnCalendar,
        # WantedBy, Restart, User…). ConfigParser lowercases keys by
        # default, which made every `.get("ExecStart")` below silently
        # miss — so every unit row landed with program/keep_alive/
        # user_name = None/0, starving the judge of the persistence
        # data it most needs. Preserve the original key case.
        cp.optionxform = str
        try:
            cp.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        unit_sec = dict(cp["Unit"]) if cp.has_section("Unit") else {}
        service_sec = dict(cp["Service"]) if cp.has_section("Service") else {}
        install_sec = dict(cp["Install"]) if cp.has_section("Install") else {}
        timer_sec = dict(cp["Timer"]) if cp.has_section("Timer") else {}

        exec_start = service_sec.get("ExecStart") or ""
        on_calendar = timer_sec.get("OnCalendar")

        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None

        try:
            args = shlex.split(exec_start) if exec_start else []
        except ValueError:
            args = [exec_start]

        return {
            "scope": scope,
            "path": str(path),
            "label": path.stem,
            "program": exec_start or on_calendar,
            "program_arguments_json": json.dumps(args),
            "run_at_load": int(bool(install_sec.get("WantedBy"))),
            "keep_alive": int(
                service_sec.get("Restart", "no").strip()
                in LinuxLaunchItemsCollector._ALWAYS_RESTART
            ),
            "start_interval": None,
            "start_calendar_interval_json": (
                json.dumps(on_calendar) if on_calendar else None
            ),
            "user_name": service_sec.get("User"),
            "group_name": service_sec.get("Group"),
            "sha256": sha256_file(path),
            "mtime": mtime,
            "raw_json": json.dumps(
                {
                    "unit": unit_sec,
                    "service": service_sec,
                    "install": install_sec,
                    "timer": timer_sec,
                }
            ),
        }

    @staticmethod
    def _cron_rows(
        scope: str, path: Path, has_user_col: bool, default_user: Optional[str] = None
    ):
        """Yield one row per executable crontab line.

        crontab(5) format:
          - 5 schedule fields + [user] + command  (system: /etc/crontab,
            /etc/cron.d)
          - 5 schedule fields + command           (user crontabs)
          - or a @keyword (e.g. ``@reboot``) replacing the schedule.
        Lines starting with ``#`` and blank lines are skipped.
        Environment-assignment lines (``KEY=value``) are also skipped —
        they're not jobs.
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        digest = sha256_file(path)

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # KEY=VALUE assignments aren't jobs.
            if "=" in line.split(None, 1)[0]:
                continue

            if line.startswith("@"):
                tokens = line.split(None, 2 if has_user_col else 1)
                need = 3 if has_user_col else 2
                if len(tokens) < need:
                    continue
                schedule = tokens[0]
                user = tokens[1] if has_user_col else default_user
                command = tokens[-1]
            else:
                # 5 schedule fields + optional user + command (which may
                # contain whitespace — preserve via maxsplit).
                need = 7 if has_user_col else 6
                tokens = line.split(None, need - 1)
                if len(tokens) < need:
                    continue
                schedule = " ".join(tokens[:5])
                user = tokens[5] if has_user_col else default_user
                command = tokens[-1]

            try:
                args = shlex.split(command)
            except ValueError:
                args = [command]

            yield {
                "scope": scope,
                "path": f"{path}:{lineno}",
                "label": f"cron:{path.name}:{lineno}",
                "program": command,
                "program_arguments_json": json.dumps(args),
                "run_at_load": int(schedule == "@reboot"),
                "keep_alive": 0,
                "start_interval": None,
                "start_calendar_interval_json": json.dumps({"schedule": schedule}),
                "user_name": user,
                "group_name": None,
                "sha256": digest,
                "mtime": mtime,
                "raw_json": json.dumps(
                    {
                        "source": "cron",
                        "schedule": schedule,
                        "user": user,
                        "command": command,
                        "line": lineno,
                    }
                ),
            }


class LinuxAuthEventsCollector(StreamingCollector):
    """Linux equivalent of :class:`AuthEventsCollector` — tails
    ``journalctl -f --output=json`` filtered to security-relevant
    sources (auth+authpriv syslog facilities, sshd, systemd-logind,
    sudo, su, polkitd). Yields rows in the same shape as the macOS
    streaming collector so the dashboard treats them identically.

    The OR semantics across different journalctl matchers require
    inserting ``+`` between AND-groups; same-field matchers within a
    group OR by default.
    """

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    _MATCH_GROUPS = [
        ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"],  # auth + authpriv
        ["_SYSTEMD_UNIT=sshd.service"],
        ["_SYSTEMD_UNIT=systemd-logind.service"],
        ["_COMM=sudo"],
        ["_COMM=su"],
        ["_COMM=polkitd"],
        ["_COMM=login"],
    ]

    def __init__(self, judge_hints: str = "", priority: str = "info"):
        super().__init__(judge_hints=judge_hints)
        self.priority = priority

    def _cmd(self) -> list[str]:
        cmd = [
            "journalctl",
            "-f",
            "--output=json",
            "--no-pager",
            f"--priority={self.priority}",
        ]
        # In container mode, point journalctl at the host's journal
        # directory rather than the container's empty one.
        if constants.HOST_PREFIX:
            host_journal = host_path("/var/log/journal")
            if host_journal.is_dir():
                cmd.extend(["--directory", str(host_journal)])
        for i, group in enumerate(self._MATCH_GROUPS):
            if i > 0:
                cmd.append("+")
            cmd.extend(group)
        return cmd

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), JournalAuthParser(), killer_name="journalctl-killer"
        )
        yield from source.stream(stop_event)


class JournalAuthParser:
    """Strategy: ``journalctl --output=json`` event → auth row."""

    def parse(self, event: dict) -> dict:
        # journalctl --output=json gives __REALTIME_TIMESTAMP in
        # microseconds since the epoch (as a string).
        ts_us = event.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass

        try:
            pid = int(event["_PID"]) if event.get("_PID") else None
        except (TypeError, ValueError):
            pid = None

        return {
            "event_timestamp": ts,
            "process": event.get("_EXE") or event.get("_COMM"),
            "subsystem": event.get("_SYSTEMD_UNIT") or "syslog",
            "category": str(event.get("SYSLOG_FACILITY") or ""),
            "event_type": f"priority={event.get('PRIORITY', '?')}",
            "event_message": event.get("MESSAGE"),
            "pid": pid,
            "raw_json": json.dumps(event),
        }


class LinuxUsbDevicesCollector(SnapshotCollector):
    """Linux equivalent of :class:`UsbDevicesCollector`.

    Walks ``/sys/bus/usb/devices`` and reads attribute files (kernel
    exposes the USB descriptors as plain-text files — no parsing
    needed, just :func:`Path.read_text`). Interface sub-nodes (those
    with a ``:`` in their name like ``1-1:1.0``) are skipped — we
    only want device-level entries.
    """

    name = "usb_devices"
    model = UsbDeviceRow
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    _ATTRS = (
        "idVendor",
        "idProduct",
        "manufacturer",
        "product",
        "serial",
        "speed",
        "bDeviceClass",
        "bDeviceProtocol",
        "bMaxPower",
        "version",
        "busnum",
        "devnum",
    )

    def collect(self):
        root = host_path("/sys/bus/usb/devices")
        if not root.is_dir():
            return
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for dev in entries:
            # USB device nodes are named like "1-1", "2-1.2", "usb1".
            # Interfaces (which carry a colon) are sub-descriptors of
            # devices — skip them.
            if ":" in dev.name:
                continue
            if not dev.is_dir():
                continue
            attrs = {a: _read_sysfs(dev / a) for a in self._ATTRS}
            attrs = {k: v for k, v in attrs.items() if v is not None}
            if not attrs.get("idVendor") and not attrs.get("product"):
                # Empty entry (e.g. root hubs without descriptors).
                continue
            yield {
                "name": attrs.get("product"),
                "vendor_id": attrs.get("idVendor"),
                "product_id": attrs.get("idProduct"),
                "serial_number": attrs.get("serial"),
                "manufacturer": attrs.get("manufacturer"),
                "location_id": dev.name,
                "speed": attrs.get("speed"),
                "raw_json": json.dumps(attrs),
            }


class LinuxBluetoothCollector(SnapshotCollector):
    """Linux equivalent of :class:`BluetoothCollector`.

    Walks ``/var/lib/bluetooth/<adapter_mac>/<device_mac>/info`` — the
    persistent state files BlueZ writes for every paired device. Each
    file is an INI document parsed by :mod:`configparser`. Presence
    in this directory means the device is paired; live connectivity
    requires D-Bus (deferred to a future phase) so ``connected`` is
    left as 0.

    Requires read access to ``/var/lib/bluetooth`` which is normally
    root-only — the monitor container runs as root.
    """

    name = "bluetooth_devices"
    model = BluetoothDeviceRow
    judge_fields = ("name", "address", "minor_type")

    def collect(self):
        root = host_path("/var/lib/bluetooth")
        if not root.is_dir():
            return
        try:
            adapters = list(root.iterdir())
        except PermissionError:
            return
        for adapter in adapters:
            if not adapter.is_dir():
                continue
            try:
                devices = list(adapter.iterdir())
            except PermissionError:
                continue
            for dev in devices:
                if not dev.is_dir():
                    continue
                info_file = dev / "info"
                if not info_file.is_file():
                    continue
                cp = configparser.ConfigParser(
                    interpolation=None,
                    strict=False,
                    inline_comment_prefixes=("#", ";"),
                )
                # BlueZ info keys are CamelCase (Alias, Name, Class).
                # Preserve case — default lowercasing blanked the
                # device name + class.
                cp.optionxform = str
                try:
                    cp.read(info_file, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                general = dict(cp["General"]) if cp.has_section("General") else {}
                # BlueZ stores the MAC with underscores; restore colons.
                mac = dev.name.replace("_", ":")
                full = {sec: dict(cp[sec]) for sec in cp.sections()}
                yield {
                    "name": general.get("Alias") or general.get("Name"),
                    "address": mac,
                    "connected": 0,
                    "paired": 1,
                    "minor_type": general.get("Class"),
                    "raw_json": json.dumps(full),
                }


class LinuxWifiCollector(SnapshotCollector):
    """Linux equivalent of :class:`WifiCollector`.

    Discovers wireless interfaces from sysfs (any net interface that
    has a ``wireless/`` subdirectory in ``/sys/class/net``). For each,
    asks ``iw dev <iface> link`` for the current connection details
    (SSID, BSSID, freq) — parsed line-by-line using ``key: value``
    structure, not regex. If ``iw`` isn't installed the interface is
    still emitted with empty fields so the dashboard can see it
    exists.
    """

    name = "wifi_state"
    model = WifiStateRow
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        # sysfs discovery via HOST_PREFIX; iw queries via netlink which
        # the host-network namespace (network_mode: host) already
        # exposes to the container.
        net = host_path("/sys/class/net")
        if not net.is_dir():
            return
        try:
            ifaces = list(net.iterdir())
        except OSError:
            return
        iw_available = shutil.which("iw") is not None
        for iface_dir in ifaces:
            if not (iface_dir / "wireless").is_dir():
                continue
            iface = iface_dir.name
            link = self._iw_link(iface) if iw_available else {}
            yield {
                "interface": iface,
                "ssid": link.get("SSID"),
                "bssid": link.get("BSSID"),
                "channel": link.get("freq"),
                "security": link.get("type"),
                "raw_json": json.dumps(link),
            }

    @staticmethod
    def _iw_link(iface: str) -> dict:
        try:
            r = subprocess.run(
                ["iw", "dev", iface, "link"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}
        if r.returncode != 0 or not r.stdout:
            return {}
        out: dict = {}
        for raw in r.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Connected to"):
                tokens = line.split()
                if len(tokens) >= 3:
                    out["BSSID"] = tokens[2]
                continue
            if line.startswith("Not connected"):
                out["connected"] = "no"
                continue
            key, sep, value = line.partition(":")
            if sep:
                out[key.strip()] = value.strip()
        return out


class LinuxSystemIntegrityCollector(SnapshotCollector):
    """Linux equivalent of :class:`SystemIntegrityCollector`.

    Maps Linux security posture into the existing ``system_integrity``
    row, preserving the macOS-shaped column names so the dashboard
    keeps rendering them:

    - ``filevault_active``          → any active dm-crypt (LUKS) mapping.
    - ``firewall_global_state``    → ``ufw`` OR ``firewalld`` active.
    - ``firewall_stealth``         → reserved (no clean Linux analog).
    - ``firewall_logging``         → reserved.
    - ``gatekeeper_assessments_*`` → SELinux in *Enforcing* mode OR
                                     AppArmor enabled.
    - ``remote_login_enabled``     → ``ssh.service`` / ``sshd.service``
                                     active.
    - ``screen_sharing_enabled``   → ``x11vnc`` / ``vncserver`` active.
    - ``remote_management_enabled``→ same as screen_sharing (no Linux
                                     equivalent to Apple Remote Desktop).

    Raw posture details (SELinux mode string, AppArmor enabled/loaded
    profiles, ufw / firewalld active flags, dm-crypt count, sshd /
    vnc systemd status) live in ``raw_json`` for the LLM judge.
    """

    name = "system_integrity"
    model = SystemIntegrityRow
    judge_fields = (
        "filevault_active",
        "firewall_global_state",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    def collect(self):
        selinux = self._selinux_state()
        apparmor = self._apparmor_state()
        ufw = self._ufw_active()
        fwd = self._service_active("firewalld")
        sshd = self._service_active("ssh") or self._service_active("sshd")
        vnc = (
            self._service_active("x11vnc")
            or self._service_active("vncserver")
            or self._service_active("xrdp")
        )
        luks_n = self._luks_count()

        raw = {
            "selinux": selinux,
            "apparmor": apparmor,
            "ufw_active": ufw,
            "firewalld_active": fwd,
            "sshd_active": sshd,
            "vnc_active": vnc,
            "luks_mappings": luks_n,
        }

        yield {
            "filevault_active": int(luks_n > 0),
            "firewall_global_state": int(ufw or fwd),
            "firewall_stealth": None,
            "firewall_logging": None,
            "gatekeeper_assessments_enabled": int(
                selinux == "Enforcing" or apparmor.get("enabled") is True
            ),
            "remote_login_enabled": int(sshd),
            "screen_sharing_enabled": int(vnc),
            "remote_management_enabled": int(vnc),
            "raw_json": json.dumps(raw),
        }

    # ---- helpers ----------------------------------------------------

    @staticmethod
    def _selinux_state() -> Optional[str]:
        """Returns 'Enforcing' / 'Permissive' / None (not present)."""
        flag = _read_sysfs(host_path("/sys/fs/selinux/enforce"))
        if flag is None:
            return None
        return {"0": "Permissive", "1": "Enforcing"}.get(flag, "Unknown")

    @staticmethod
    def _apparmor_state() -> dict:
        enabled = _read_sysfs(host_path("/sys/module/apparmor/parameters/enabled"))
        return (
            {"enabled": enabled == "Y"} if enabled is not None else {"enabled": False}
        )

    @staticmethod
    def _ufw_active() -> bool:
        # /etc/ufw/ufw.conf is the canonical persistent state.
        conf = _read_sysfs(host_path("/etc/ufw/ufw.conf"))
        if conf is None:
            return False
        for line in conf.splitlines():
            if line.lstrip().startswith("ENABLED"):
                key, _, value = line.partition("=")
                if key.strip() == "ENABLED":
                    return value.strip().strip('"').lower() == "yes"
        return False

    @staticmethod
    def _service_active(unit: str) -> bool:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return r.stdout.strip() == "active"

    @staticmethod
    def _luks_count() -> int:
        if not shutil.which("dmsetup"):
            return 0
        try:
            r = subprocess.run(
                ["dmsetup", "ls", "--target", "crypt"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return 0
        if r.returncode != 0 or "No devices found" in r.stdout:
            return 0
        return sum(1 for line in r.stdout.splitlines() if line.strip())


class MountsCollector(SnapshotCollector):
    """Cross-platform mount-table snapshot via ``psutil.disk_partitions``.

    Detects new mounts (an attacker shadowing ``/etc/passwd`` with a
    tmpfs is a classic rootkit move) and persistent device →
    mountpoint mappings. ``all=True`` keeps pseudo-filesystems
    (``proc``, ``sys``, ``tmpfs``, ``cgroup``, …) in the result —
    those are exactly what we want to watch for surprises.
    """

    name = "mounts"
    model = MountRow
    judge_fields = ("device", "mountpoint", "fstype", "opts")

    def collect(self):
        try:
            partitions = psutil.disk_partitions(all=True)
        except (psutil.AccessDenied, PermissionError):
            return
        for p in partitions:
            yield {
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "opts": p.opts,
                "raw_json": json.dumps(
                    {
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                        "maxfile": getattr(p, "maxfile", None),
                        "maxpath": getattr(p, "maxpath", None),
                    }
                ),
            }


class SetuidFilesCollector(SnapshotCollector):
    """Enumerate setuid / setgid files in common executable directories.

    A *new* setuid binary on a system is one of the loudest signals
    of privilege-escalation persistence — and is invisible to most
    of the other collectors. The walk is bounded to typical bin /
    sbin / libexec dirs to keep cycle time short; a full ``/`` walk
    takes minutes on a populated host.

    Honors ``HOST_PREFIX`` on Linux so a container monitor walks the
    host's ``/usr/bin`` rather than its own.
    """

    name = "setuid_files"
    model = SetuidFileRow
    judge_fields = ("path", "uid", "setuid", "setgid")

    _BIN_DIRS_MACOS = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
    )
    _BIN_DIRS_LINUX = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
        "/opt",
    )

    def collect(self):
        bin_dirs = self._BIN_DIRS_LINUX if IS_LINUX else self._BIN_DIRS_MACOS
        for d in bin_dirs:
            base = host_path(d) if IS_LINUX else Path(d)
            if not base.is_dir():
                continue
            try:
                paths = list(base.rglob("*"))
            except (PermissionError, OSError):
                continue
            for path in paths:
                try:
                    if not path.is_file():
                        continue
                    st = path.lstat()
                except (PermissionError, OSError):
                    continue
                mode = st.st_mode
                setuid = bool(mode & 0o4000)
                setgid = bool(mode & 0o2000)
                if not (setuid or setgid):
                    continue
                yield {
                    "path": str(path),
                    "mode": mode,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "sha256": sha256_file(path),
                    "setuid": int(setuid),
                    "setgid": int(setgid),
                    "raw_json": json.dumps(
                        {
                            "path": str(path),
                            "mode": oct(mode),
                            "setuid": setuid,
                            "setgid": setgid,
                        }
                    ),
                }


class SshAuthorizedKeysCollector(SnapshotCollector):
    """Enumerate every key in every user's ``authorized_keys`` — each one
    is a credential that grants SSH login. A *new* key (especially with a
    permissive ``from=``/forced-command, or an unfamiliar comment) is a
    classic, quiet persistence backdoor invisible to process/network
    collectors."""

    name = "ssh_authorized_keys"
    model = SshAuthorizedKeyRow
    judge_fields = ("path", "owner", "key_type", "fingerprint")

    _KEY_TYPES = frozenset(
        {
            "ssh-rsa",
            "ssh-dss",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    )

    def collect(self):
        for home in self._home_dirs():
            owner = home.name
            for fname in ("authorized_keys", "authorized_keys2"):
                path = home / ".ssh" / fname
                try:
                    content = path.read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                for row in self._parse_authorized_keys(content, str(path), owner):
                    yield row

    def _home_dirs(self) -> list[Path]:
        homes: list[Path] = []
        if IS_LINUX:
            base = host_path("/home")
            if base.is_dir():
                try:
                    homes += [d for d in base.iterdir() if d.is_dir()]
                except OSError:
                    pass
            root = host_path("/root")
            if root.is_dir():
                homes.append(root)
        else:
            users = Path("/Users")
            if users.is_dir():
                try:
                    homes += [
                        d
                        for d in users.iterdir()
                        if d.is_dir() and not d.name.startswith(".")
                    ]
                except OSError:
                    pass
            root = Path("/var/root")
            if root.is_dir():
                homes.append(root)
        return homes

    @classmethod
    def _parse_authorized_keys(cls, content: str, path: str, owner: str):
        """Pure parser: one row dict per key line. Tolerates leading
        option fields (``from=...,command=...``) before the key type."""
        rows = []
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            idx = next((i for i, t in enumerate(parts) if t in cls._KEY_TYPES), None)
            if idx is None or idx + 1 >= len(parts):
                continue
            rows.append(
                {
                    "path": path,
                    "owner": owner,
                    "key_type": parts[idx],
                    "fingerprint": _ssh_fingerprint(parts[idx + 1]),
                    "comment": " ".join(parts[idx + 2 :]) or None,
                    "options": " ".join(parts[:idx]) or None,
                }
            )
        return rows


class HostsFileCollector(SnapshotCollector):
    """Snapshot ``/etc/hosts``. A mapping that points a real domain at an
    attacker IP (phishing / update hijack) or sinkholes a security domain
    to 0.0.0.0 is a cheap, high-impact tamper that nothing else catches."""

    name = "hosts_file"
    model = HostsFileRow
    judge_fields = ("ip", "hostnames")

    def collect(self):
        path = host_path("/etc/hosts") if IS_LINUX else Path("/etc/hosts")
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from self._parse_hosts(content, str(path))

    @staticmethod
    def _parse_hosts(content: str, path: str):
        """Pure parser: one row per ``<ip> <name...>`` mapping."""
        rows = []
        for line in content.splitlines():
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) < 2:
                continue
            rows.append(
                {
                    "source_path": path,
                    "ip": parts[0],
                    "hostnames": " ".join(parts[1:]),
                }
            )
        return rows


class PrivilegeConfigCollector(SnapshotCollector):
    """Enumerate the host's privilege-granting configuration: sudoers
    rules, members of the admin/wheel/sudo groups, and UID-0 accounts.
    New entries here are privilege-escalation persistence."""

    name = "privilege_config"
    model = PrivilegeConfigRow
    judge_fields = ("kind", "subject", "detail")

    _PRIV_GROUPS = frozenset({"sudo", "wheel", "admin"})

    def collect(self):
        yield from self._sudoers()
        yield from self._priv_groups()
        yield from self._uid0_accounts()

    # -- sudoers (both platforms) ----------------------------------------

    def _sudoers(self):
        files = [host_path("/etc/sudoers") if IS_LINUX else Path("/etc/sudoers")]
        sudoers_d = host_path("/etc/sudoers.d") if IS_LINUX else Path("/etc/sudoers.d")
        if sudoers_d.is_dir():
            try:
                files += sorted(p for p in sudoers_d.iterdir() if p.is_file())
            except OSError:
                pass
        for path in files:
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            yield from self._parse_sudoers(content, str(path))

    @staticmethod
    def _parse_sudoers(content: str, path: str):
        """Pure parser: keep privilege-granting rules, drop Defaults /
        includes / comments."""
        rows = []
        for line in content.splitlines():
            s = line.split("#", 1)[0].strip()
            if not s or s.startswith(("Defaults", "@includedir", "@include")):
                continue
            rows.append(
                {
                    "kind": "sudoers",
                    "subject": s.split()[0],
                    "detail": s,
                    "source_path": path,
                }
            )
        return rows

    # -- privileged group membership -------------------------------------

    def _priv_groups(self):
        if IS_LINUX:
            path = host_path("/etc/group")
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                return
            yield from self._parse_groups(content, str(path), self._PRIV_GROUPS)
        else:
            for gname in ("admin", "wheel"):
                out = self._dscl(["-read", f"/Groups/{gname}", "GroupMembership"])
                members = out.split(":", 1)[1].strip() if ":" in out else out.strip()
                if members:
                    yield {
                        "kind": "group",
                        "subject": gname,
                        "detail": members,
                        "source_path": "dscl:/Groups",
                    }

    @staticmethod
    def _parse_groups(content: str, path: str, priv_groups):
        """Pure parser for /etc/group: members of privileged groups."""
        rows = []
        for line in content.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue
            gname, members = parts[0], parts[3]
            if gname in priv_groups and members:
                rows.append(
                    {
                        "kind": "group",
                        "subject": gname,
                        "detail": members,
                        "source_path": path,
                    }
                )
        return rows

    # -- UID-0 accounts --------------------------------------------------

    def _uid0_accounts(self):
        if IS_LINUX:
            path = host_path("/etc/passwd")
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                return
            yield from self._parse_passwd_uid0(content, str(path))
        else:
            out = self._dscl(["-list", "/Users", "UniqueID"])
            for line in out.splitlines():
                cols = line.split()
                if len(cols) >= 2 and cols[-1] == "0":
                    yield {
                        "kind": "account",
                        "subject": cols[0],
                        "detail": "uid=0",
                        "source_path": "dscl:/Users",
                    }

    @staticmethod
    def _parse_passwd_uid0(content: str, path: str):
        """Pure parser for /etc/passwd: accounts with uid 0."""
        rows = []
        for line in content.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            user, uid, shell = parts[0], parts[2], parts[6]
            if uid == "0":
                rows.append(
                    {
                        "kind": "account",
                        "subject": user,
                        "detail": f"uid=0 shell={shell}",
                        "source_path": path,
                    }
                )
        return rows

    @staticmethod
    def _dscl(args: list[str]) -> str:
        try:
            r = subprocess.run(
                ["dscl", ".", *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return r.stdout or "" if r.returncode == 0 else ""
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""


class MdmProfilesCollector(SnapshotCollector):
    """macOS configuration profiles (MDM payloads). Unauthorized MDM
    enrollment is a major compromise vector — a malicious profile
    can install root CAs, push launch agents, configure VPNs, or
    restrict settings system-wide. ``system_profiler
    SPConfigurationProfileDataType`` gives us a structured (JSON)
    view of every installed profile."""

    name = "mdm_profiles"
    model = MdmProfileRow
    judge_fields = ("identifier", "display_name", "organization", "profile_scope")

    def collect(self):
        try:
            data = run_json(
                ["system_profiler", "-json", "SPConfigurationProfileDataType"],
                timeout=30,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        profiles = data.get("SPConfigurationProfileDataType", []) or []
        # The output structure is "list of nested groups, with profile
        # records under either _items or directly at the top level."
        for entry in self._walk(profiles):
            yield {
                "identifier": entry.get("spconfigprofile_profile_identifier"),
                "display_name": entry.get("_name")
                or entry.get("spconfigprofile_profile_display_name"),
                "organization": entry.get("spconfigprofile_profile_organization"),
                "description": entry.get("spconfigprofile_profile_description"),
                "install_date": entry.get("spconfigprofile_install_date"),
                "profile_scope": entry.get("spconfigprofile_profile_scope"),
                "is_supervised": None,
                "raw_json": json.dumps(jsonable(entry)),
            }

    @classmethod
    def _walk(cls, items):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            # A node is a profile if it has an identifier field, else
            # descend into _items.
            if item.get("spconfigprofile_profile_identifier"):
                yield item
            if "_items" in item:
                yield from cls._walk(item.get("_items"))


class KernelExtensionsCollector(SnapshotCollector):
    """macOS kernel extensions (kexts). Apple has deprecated them in
    favour of System Extensions, but third-party kexts can still
    load on older macOS or via legacy paths. Anything in ring 0 has
    full machine access — every loaded kext is high-signal.

    ``system_profiler -json SPExtensionsDataType`` is the structured
    source. It enumerates every installed kext (loaded or not),
    including the signing chain and notarisation state. The judge
    naturally ignores Apple-signed kexts and focuses on third-party
    ones via the prompt hints.
    """

    name = "kernel_extensions"
    model = KernelExtensionRow
    judge_fields = ("bundle_id", "name", "team_id")

    def collect(self):
        try:
            data = run_json(
                ["system_profiler", "-json", "SPExtensionsDataType"],
                timeout=60,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        for kext in data.get("SPExtensionsDataType", []) or []:
            if not isinstance(kext, dict):
                continue
            yield {
                "bundle_id": kext.get("spext_bundleid"),
                "name": kext.get("_name"),
                "version": kext.get("spext_version"),
                "path": kext.get("spext_path"),
                "team_id": None,
                "signing_id": kext.get("spext_signed_by"),
                "raw_json": json.dumps(
                    jsonable(
                        {
                            k: v
                            for k, v in kext.items()
                            if k
                            in (
                                "_name",
                                "spext_bundleid",
                                "spext_version",
                                "spext_path",
                                "spext_signed_by",
                                "spext_obtained_from",
                                "spext_notarized",
                                "spext_loaded",
                                "spext_loadable",
                                "spext_lastModified",
                                "spext_hasAllDependencies",
                            )
                        }
                    )
                ),
            }


class SystemExtensionsCollector(SnapshotCollector):
    """macOS System Extensions — the post-Catalina replacement for
    kexts. Used by network filters (NEFilter), DriverKit
    (USB/serial), and endpoint-security extensions (ES).

    Source: ``/Library/SystemExtensions/db.plist`` — the LaunchServices
    plist that records every installed extension and its enabled /
    active state. Parsed via :mod:`plistlib`; no text scraping of
    ``systemextensionsctl list`` output.
    """

    name = "system_extensions"
    model = SystemExtensionRow
    judge_fields = ("bundle_id", "team_id")

    def collect(self):
        db = Path("/Library/SystemExtensions/db.plist")
        data = read_plist(db)
        if not data:
            return
        # The plist is a top-level dict with 'extensions' as the list
        # of every installed System Extension (one entry per ext,
        # regardless of activation state). 'bundleVersion' is a
        # nested dict carrying both CFBundleShortVersionString and
        # CFBundleVersion. 'categories' is a list of extension-point
        # identifiers (network_extension, endpoint_security, …).
        for ext in data.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            version = ext.get("bundleVersion")
            if isinstance(version, dict):
                version = version.get("CFBundleShortVersionString") or version.get(
                    "CFBundleVersion"
                )
            categories = ext.get("categories") or []
            yield {
                "bundle_id": ext.get("identifier"),
                "team_id": ext.get("teamID"),
                "version": version,
                "state": ext.get("state"),
                "categories": ",".join(categories) if categories else None,
                "raw_json": json.dumps(jsonable(ext)),
            }


class MacosProcessExecCollector(StreamingCollector):
    """Tails ``eslogger exec`` — Apple's Endpoint-Security CLI, shipped
    since macOS Ventura. Each ``exec(2)`` on the host emits one JSON
    object with the executing binary, args, parent, and signing
    information. Requires root (the binary itself enforces this).

    judge_enabled is True so the LLM evaluates each *unique*
    (exe_path, args, user, parent_path) combination — content_hash
    dedupe means a busy machine costs O(unique-binaries-run) LLM
    calls, not O(every-exec).
    """

    name = "process_exec_events"
    model = ProcessExecRow
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    _EVENTS = ("exec",)

    def stream(self, stop_event: threading.Event):
        cmd = ["eslogger", *self._EVENTS]
        source = JsonLineStreamSource(
            cmd, EsloggerExecParser(), killer_name="eslogger-killer"
        )
        yield from source.stream(stop_event)


class EsloggerExecParser:
    """Strategy: macOS ``eslogger exec`` Endpoint-Security event → exec row."""

    def parse(self, event: dict) -> dict:
        # eslogger emits ES events: { time, action_type, event,
        # process, ... } where event.exec.{target, args, ...}
        event_obj = event.get("event") or {}
        exec_evt = event_obj.get("exec") or {}
        target = exec_evt.get("target") or {}
        target_exe = (target.get("executable") or {}).get("path")
        args = exec_evt.get("args") or []
        parent = event.get("process") or {}
        parent_path = (parent.get("executable") or {}).get("path")
        target_token = target.get("audit_token") or {}
        parent_token = parent.get("audit_token") or {}
        return {
            "event_timestamp": event.get("time"),
            "event_type": "exec",
            "pid": target_token.get("pid"),
            "ppid": parent_token.get("pid"),
            "uid": target_token.get("ruid"),
            "username": None,
            "exe_path": target_exe,
            "exe_args_json": json.dumps(args),
            "parent_path": parent_path,
            "signing_id": target.get("signing_id"),
            "raw_json": json.dumps(event),
        }


class LinuxProcessExecCollector(StreamingCollector):
    """Tails the Linux audit subsystem for ``execve`` events via
    ``journalctl -f --output=json`` matchers on the audit type names.

    Requires ``auditd`` running on the host with the execve rule
    installed, e.g.::

        auditctl -a always,exit -F arch=b64 -S execve

    (most distros ship ``audit`` enabled by default for SECCOMP /
    PAM events; the execve rule is the additional configuration.)
    """

    name = "process_exec_events"
    model = ProcessExecRow
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    def _cmd(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager"]
        if constants.HOST_PREFIX:
            host_journal = host_path("/var/log/journal")
            if host_journal.is_dir():
                cmd.extend(["--directory", str(host_journal)])
        cmd.extend(["_AUDIT_TYPE_NAME=EXECVE", "+", "_AUDIT_TYPE_NAME=SYSCALL"])
        return cmd

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), AuditExecParser(), killer_name="journalctl-audit-killer"
        )
        yield from source.stream(stop_event)


class AuditExecParser:
    """Strategy: Linux audit ``journalctl --output=json`` event → exec row."""

    def parse(self, event: dict) -> dict:
        ts_us = event.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass
        try:
            pid = int(event["_PID"]) if event.get("_PID") else None
        except (TypeError, ValueError):
            pid = None
        try:
            uid = int(event["_UID"]) if event.get("_UID") else None
        except (TypeError, ValueError):
            uid = None
        # audit EXECVE messages carry the args as separate fields a0,
        # a1, ... in the structured message; SYSCALL records have
        # the exe= path and comm= name. The combined-record view is
        # typically captured under MESSAGE; we surface what's
        # available and dump the full event into raw_json so the
        # judge sees everything.
        return {
            "event_timestamp": ts,
            "event_type": event.get("_AUDIT_TYPE_NAME") or "AUDIT",
            "pid": pid,
            "ppid": None,
            "uid": uid,
            "username": None,
            "exe_path": event.get("EXE") or event.get("_EXE"),
            "exe_args_json": None,
            "parent_path": None,
            "signing_id": None,
            "raw_json": json.dumps(event),
        }


def _build_macos_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
    h = prompts.hint_for
    return [
        ProcessCollector(judge_hints=h("processes")),
        NetworkConnectionsCollector(judge_hints=h("network_connections")),
        ListeningPortsCollector(judge_hints=h("listening_ports")),
        NetworkFlowsCollector(judge_hints=h("network_flows")),
        DnsQueriesCollector(judge_hints=h("dns_queries")),
        NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
        UsbDevicesCollector(judge_hints=h("usb_devices")),
        BluetoothCollector(judge_hints=h("bluetooth_devices")),
        WifiCollector(judge_hints=h("wifi_state")),
        LaunchItemsCollector(judge_hints=h("launch_items")),
        QuarantineCollector(judge_hints=h("quarantine_events")),
        BrowserExtensionsCollector(judge_hints=h("browser_extensions")),
        SystemIntegrityCollector(judge_hints=h("system_integrity")),
        FileIntegrityCollector(judge_hints=h("file_integrity")),
        InstalledAppsCollector(judge_hints=h("installed_apps")),
        # Phase 4 additions
        MountsCollector(judge_hints=h("mounts")),
        SetuidFilesCollector(judge_hints=h("setuid_files")),
        MdmProfilesCollector(judge_hints=h("mdm_profiles")),
        KernelExtensionsCollector(judge_hints=h("kernel_extensions")),
        SystemExtensionsCollector(judge_hints=h("system_extensions")),
        # Persistence & tampering
        SshAuthorizedKeysCollector(judge_hints=h("ssh_authorized_keys")),
        HostsFileCollector(judge_hints=h("hosts_file")),
        PrivilegeConfigCollector(judge_hints=h("privilege_config")),
    ]


def _build_linux_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
    """Linux snapshot collector set — full parity with the macOS set
    minus the two slices that have no Linux equivalent.

    Cross-platform via psutil: processes, network connections, listening
    ports, network interfaces.

    Same collector classes, Linux paths: file_integrity (WATCHED_FILES_LINUX),
    browser_extensions (BROWSER_PROFILES_LINUX).

    Linux-specific implementations:
      Phase 1 — installed_apps (dpkg-query + XDG .desktop)
      Phase 2 — launch_items (systemd unit files + cron entries)
      Phase 3 — usb_devices (sysfs walk), bluetooth_devices
                (/var/lib/bluetooth INI files), wifi_state (sysfs +
                `iw dev link`), system_integrity (SELinux + AppArmor
                + ufw / firewalld + sshd + vnc + LUKS).

    Dropped on Linux: quarantine_events (a macOS-only concept with no Linux
    analog).
    """
    h = prompts.hint_for

    # Expand watched-file templates through host_paths_for_home so that
    # ~/-prefixed entries become one path per user home found under
    # the container's bind-mounted /host/home (or the literal
    # expanduser path on a native install). Absolute /etc paths
    # become /host/etc paths automatically.
    watched: list[str] = []
    for tmpl in WATCHED_FILES_LINUX:
        for p in host_paths_for_home(tmpl):
            watched.append(str(p))

    # Same treatment for browser profile roots — one entry per
    # user_home/.config/<browser>.
    expanded_browser_profiles: dict[Browser, list[str]] = {}
    for browser, templates in BROWSER_PROFILES_LINUX.items():
        out: list[str] = []
        for tmpl in templates:
            for p in host_paths_for_home(tmpl):
                out.append(str(p))
        expanded_browser_profiles[browser] = out

    return [
        ProcessCollector(judge_hints=h("processes")),
        NetworkConnectionsCollector(judge_hints=h("network_connections")),
        ListeningPortsCollector(judge_hints=h("listening_ports")),
        NetworkFlowsCollector(judge_hints=h("network_flows")),
        DnsQueriesCollector(judge_hints=h("dns_queries")),
        NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
        LinuxUsbDevicesCollector(judge_hints=h("usb_devices")),
        LinuxBluetoothCollector(judge_hints=h("bluetooth_devices")),
        LinuxWifiCollector(judge_hints=h("wifi_state")),
        LinuxLaunchItemsCollector(judge_hints=h("launch_items")),
        BrowserExtensionsCollector(
            judge_hints=h("browser_extensions"),
            profiles=expanded_browser_profiles,
        ),
        LinuxSystemIntegrityCollector(judge_hints=h("system_integrity")),
        FileIntegrityCollector(
            judge_hints=h("file_integrity"),
            watched=watched,
        ),
        LinuxInstalledAppsCollector(judge_hints=h("installed_apps")),
        # Phase 4 additions — cross-platform
        MountsCollector(judge_hints=h("mounts")),
        SetuidFilesCollector(judge_hints=h("setuid_files")),
        # Persistence & tampering
        SshAuthorizedKeysCollector(judge_hints=h("ssh_authorized_keys")),
        HostsFileCollector(judge_hints=h("hosts_file")),
        PrivilegeConfigCollector(judge_hints=h("privilege_config")),
    ]


def build_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
    if IS_LINUX:
        return _build_linux_snapshot_collectors(prompts)
    return _build_macos_snapshot_collectors(prompts)


def build_streaming_collectors(prompts: Prompts) -> list[StreamingCollector]:
    h = prompts.hint_for
    if IS_LINUX:
        return [
            LinuxAuthEventsCollector(judge_hints=h("auth_events")),
            LinuxProcessExecCollector(judge_hints=h("process_exec_events")),
        ]
    return [
        AuthEventsCollector(judge_hints=h("auth_events")),
        MacosProcessExecCollector(judge_hints=h("process_exec_events")),
    ]
