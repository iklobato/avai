"""Per-collector indicator extraction (Strategy pattern).

Each :class:`IndicatorExtractor` looks at one collector's row dict and
yields ``Indicator`` values for the threat-intel chain to enrich.
Registered in :data:`EXTRACTORS` keyed by collector name; the public
:func:`extract_indicators` dispatches.

New collectors land by either:
  1. Registering a new ``IndicatorExtractor`` here, or
  2. Doing nothing — the collector then contributes no enrichments
     but everything else keeps working.

What we deliberately don't do:
  - Hash files on disk during extraction. Hashing is the collector's
    job (cheap row-time op) — we read the precomputed value.
  - Re-validate inputs. The collector emitted it; we trust the shape.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Mapping, Optional
from urllib.parse import urlparse

from avai.enrichers.base import Indicator, IndicatorType

LOG = logging.getLogger("avai.enrichers.indicators")

# ---------------------------------------------------------------------------
# Helpers — small, defensive parsers used by multiple extractors.
# ---------------------------------------------------------------------------

_SHA256_HEX_LEN = 64
_ANY_HOST = (IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN)

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def _is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_ipv6(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_domain(s: str) -> bool:
    # An IPv4 literal matches the regex (all-digit labels separated by
    # dots) but isn't a domain — classify it as IPv4 instead.
    return bool(_DOMAIN_RE.match(s)) and "." in s and not _is_ipv4(s)


def _public_host_type(host: str) -> Optional[IndicatorType]:
    """IPV4, IPV6 or DOMAIN for a host worth sending to threat-intel. None
    for private/local addresses (no intel, and they map the LAN to a third
    party) and for anything that isn't a host."""
    if _is_private_ip(host):
        return None
    if _is_ipv4(host):
        return IndicatorType.IPV4
    if _is_ipv6(host):
        return IndicatorType.IPV6
    if _is_domain(host):
        return IndicatorType.DOMAIN
    return None


def _host_indicators(
    host: object, *kinds: IndicatorType, context: Mapping[str, str] | None = None
) -> Iterable[Indicator]:
    """The host as an indicator when it's public and one of ``kinds``."""
    if not isinstance(host, str):
        return
    kind = _public_host_type(host)
    if kind in kinds:
        yield Indicator(kind, host, context=context or {})


def _file_hash_indicators(path: str, context: Mapping[str, str]) -> Iterable[Indicator]:
    digest = _sha256_of_file(path)
    if digest:
        yield Indicator(IndicatorType.SHA256, digest, context=context)


def _safe_loads(s: object) -> object:
    if not isinstance(s, str) or not s:
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None


def _sha256_of_file(path: str) -> str | None:
    p = Path(path)
    try:
        if not p.is_file():
            return None
        # Cap at 16 MB to avoid stalling on huge binaries.
        if p.stat().st_size > 16 * 1024 * 1024:
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Strategy base + concrete extractors.
# ---------------------------------------------------------------------------


class IndicatorExtractor(ABC):
    @abstractmethod
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]: ...


class ProcessExtractor(IndicatorExtractor):
    def extract(self, row):
        exe = row.get("exe")
        if isinstance(exe, str) and exe:
            yield from _file_hash_indicators(exe, {"binary_path": exe})


class NetworkConnectionExtractor(IndicatorExtractor):
    def extract(self, row):
        # The collector emits raddr_ip/raddr_port; older/synthetic rows may
        # carry a combined "ip:port" raddr string — support both. IPv4-only
        # by design (bracketed-IPv6 raddr strings parse to a non-IPv4 host
        # and are skipped).
        host = row.get("raddr_ip")
        if not host:
            raddr = row.get("raddr")
            if isinstance(raddr, str) and ":" in raddr:
                host = raddr.rsplit(":", 1)[0]
        yield from _host_indicators(
            host, IndicatorType.IPV4, context={"raddr_ip": str(host)}
        )


class NetworkFlowExtractor(IndicatorExtractor):
    """tcpdump-aggregator flows — enrich the public destination IP
    (IPv4 or IPv6) so the judge / dashboard sees threat-intel and
    geolocation for the destination."""

    def extract(self, row):
        yield from _host_indicators(
            row.get("dst_ip"),
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            context={"dst_port": str(row.get("dst_port") or "")},
        )


class DnsQueryExtractor(IndicatorExtractor):
    """DNS questions — enrich the queried domain so the judge sees
    PhishTank / URLhaus / threat-feed verdicts before deciding. DoH rows
    carry a provider name (not a domain) and are skipped here."""

    def extract(self, row):
        qname = row.get("qname")
        if isinstance(qname, str) and _is_domain(qname):
            yield Indicator(
                IndicatorType.DOMAIN,
                qname,
                context={"qtype": str(row.get("qtype") or "")},
            )


class HostsFileExtractor(IndicatorExtractor):
    """/etc/hosts mappings — enrich the target IP (if public) and each
    real domain on the line, so a hijack entry (e.g. a bank domain
    pointed at an attacker IP) gets threat-intel."""

    def extract(self, row):
        yield from _host_indicators(
            row.get("ip"), IndicatorType.IPV4, IndicatorType.IPV6
        )
        names = row.get("hostnames")
        if isinstance(names, str):
            for host in names.split():
                yield from _host_indicators(host, IndicatorType.DOMAIN)


class ListeningPortExtractor(IndicatorExtractor):
    def extract(self, row):
        # listening_ports has laddr (bind ip) — only flag publicly bound.
        laddr = row.get("laddr")
        if isinstance(laddr, str) and ":" in laddr:
            yield from _host_indicators(
                laddr.rsplit(":", 1)[0], IndicatorType.IPV4, context={"laddr": laddr}
            )


class LaunchItemExtractor(IndicatorExtractor):
    def extract(self, row):
        # Try the program first; fall back to the first argv element.
        target = row.get("program") or row.get("exec_start")
        if isinstance(target, str) and target.startswith("/"):
            yield from _file_hash_indicators(target.split()[0], {"target": target})


class SetuidFileExtractor(IndicatorExtractor):
    def extract(self, row):
        path = row.get("path")
        if isinstance(path, str):
            yield from _file_hash_indicators(path, {"path": path})


class QuarantineExtractor(IndicatorExtractor):
    """macOS quarantine_events — `origin_url` is what the LLM judge
    cares most about. Enrich both the URL and its host."""

    def extract(self, row):
        url = row.get("origin_url") or row.get("data_url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            yield Indicator(IndicatorType.URL, url)
            yield from _host_indicators(
                urlparse(url).hostname, IndicatorType.DOMAIN, IndicatorType.IPV4
            )


class BrowserExtensionExtractor(IndicatorExtractor):
    """Pull host_permissions out of extension manifests and emit them
    as domain indicators. Extensions targeting known-malicious hosts
    are a strong signal."""

    def extract(self, row):
        hp = _safe_loads(row.get("host_permissions_json"))
        if not isinstance(hp, list):
            return
        for pattern in hp:
            if not isinstance(pattern, str):
                continue
            # Patterns are "<scheme>://<host>/..."; strip wildcards.
            host = pattern.split("://", 1)[-1].split("/", 1)[0]
            host = host.replace("*.", "").replace("*", "")
            if _is_domain(host):
                yield Indicator(IndicatorType.DOMAIN, host)


class InstalledAppExtractor(IndicatorExtractor):
    def extract(self, row):
        name = row.get("name") or row.get("package")
        version = row.get("version") or ""
        if not isinstance(name, str) or not name:
            return
        value = f"{name}@{version}" if version else name
        yield Indicator(
            IndicatorType.PACKAGE,
            value,
            context={"name": name, "version": str(version)},
        )


class SystemIntegrityExtractor(IndicatorExtractor):
    def extract(self, row):
        product = row.get("os_name") or row.get("distro")
        cycle = row.get("os_version") or row.get("version")
        if isinstance(product, str) and isinstance(cycle, str) and product and cycle:
            yield Indicator(
                IndicatorType.OS_VERSION,
                f"{product.lower()}@{cycle}",
                context={"product": product, "cycle": cycle},
            )


class ProcessExecEventExtractor(IndicatorExtractor):
    def extract(self, row):
        exe = row.get("exe") or row.get("path")
        if isinstance(exe, str):
            yield from _file_hash_indicators(exe.split()[0], {"exe": exe})


class RecordedDigestExtractor(IndicatorExtractor):
    """Rows that already carry the file's sha256 (file_integrity, and the
    YARA-matched files of file_scan), so a finding converges with hash
    threat-intel (VirusTotal / MalwareBazaar / CIRCL / the local deny-list)
    without hashing the file again."""

    def extract(self, row):
        digest = row.get("sha256")
        if isinstance(digest, str) and len(digest) == _SHA256_HEX_LEN:
            yield Indicator(
                IndicatorType.SHA256,
                digest,
                context={"path": str(row.get("path") or "")},
            )


def _share_server(remote: str) -> str | None:
    """Pull the server host out of a share path: ``//server/share``,
    ``\\\\server\\share`` (SMB) or ``server:/export`` (NFS)."""
    r = remote.strip()
    if r.startswith(("//", "\\\\")):
        head = r.replace("\\", "/").lstrip("/").split("/", 1)[0]
    elif ":" in r and not r.startswith("/"):
        head = r.split(":", 1)[0]
    else:
        return None
    if "@" in head:
        head = head.split("@", 1)[1]
    return head or None


class ProxyConfigExtractor(IndicatorExtractor):
    """Enrich a configured proxy host (public IP/domain) and PAC URL."""

    def extract(self, row):
        yield from _host_indicators(row.get("host"), *_ANY_HOST)
        pac = row.get("pac_url")
        if isinstance(pac, str) and pac.startswith(("http://", "https://")):
            yield Indicator(IndicatorType.URL, pac)


class NetworkShareExtractor(IndicatorExtractor):
    """Enrich the server of a mounted network share."""

    def extract(self, row):
        remote = row.get("remote")
        if isinstance(remote, str):
            yield from _host_indicators(
                _share_server(remote), IndicatorType.IPV4, IndicatorType.DOMAIN
            )


class LoginSessionExtractor(IndicatorExtractor):
    """Enrich a remote login source when it's a public IP/domain."""

    def extract(self, row):
        # A console login's source is "local", which isn't a host.
        yield from _host_indicators(row.get("source"), *_ANY_HOST)


class DnsResolverExtractor(IndicatorExtractor):
    """Enrich the configured nameserver when it's a *public* IP — a
    resolver pointed at an attacker-controlled box is the DNS-hijack
    signal. LAN/private resolvers (your router) carry no threat-intel
    value and are skipped."""

    def extract(self, row):
        yield from _host_indicators(
            row.get("server"), IndicatorType.IPV4, IndicatorType.IPV6
        )


class _NoOp(IndicatorExtractor):
    """Sink for collectors we deliberately don't enrich yet."""

    def extract(self, row):
        return ()


# ---------------------------------------------------------------------------
# Public dispatch.
# ---------------------------------------------------------------------------

EXTRACTORS: dict[str, IndicatorExtractor] = {
    "processes": ProcessExtractor(),
    "network_connections": NetworkConnectionExtractor(),
    "network_flows": NetworkFlowExtractor(),
    "dns_queries": DnsQueryExtractor(),
    "hosts_file": HostsFileExtractor(),
    "listening_ports": ListeningPortExtractor(),
    "launch_items": LaunchItemExtractor(),
    "setuid_files": SetuidFileExtractor(),
    "quarantine_events": QuarantineExtractor(),
    "browser_extensions": BrowserExtensionExtractor(),
    "installed_apps": InstalledAppExtractor(),
    "system_integrity": SystemIntegrityExtractor(),
    "process_exec_events": ProcessExecEventExtractor(),
    "file_integrity": RecordedDigestExtractor(),
    "file_scan": RecordedDigestExtractor(),
    "dns_resolvers": DnsResolverExtractor(),
    "proxy_config": ProxyConfigExtractor(),
    "network_shares": NetworkShareExtractor(),
    "login_sessions": LoginSessionExtractor(),
}

_NOOP = _NoOp()


def extract_indicators(collector: str, row: Mapping[str, object]) -> list[Indicator]:
    """One row in, list of indicators out. Deduped within the row."""
    extractor = EXTRACTORS.get(collector, _NOOP)
    seen: set[tuple[str, str]] = set()
    out: list[Indicator] = []
    for ind in extractor.extract(row):
        key = (str(ind.type), ind.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(ind)
    return out
