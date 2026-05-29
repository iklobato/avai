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
from typing import Iterable, Mapping
from urllib.parse import urlparse

from avai.enrichers.base import Indicator, IndicatorType

LOG = logging.getLogger("avai.enrichers.indicators")

# ---------------------------------------------------------------------------
# Helpers — small, defensive parsers used by multiple extractors.
# ---------------------------------------------------------------------------

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
            digest = _sha256_of_file(exe)
            if digest:
                yield Indicator(
                    IndicatorType.SHA256, digest, context={"binary_path": exe}
                )


class NetworkConnectionExtractor(IndicatorExtractor):
    def extract(self, row):
        raddr = row.get("raddr")
        if isinstance(raddr, str) and ":" in raddr:
            host = raddr.rsplit(":", 1)[0]
            if _is_ipv4(host) and not _is_private_ip(host):
                yield Indicator(IndicatorType.IPV4, host, context={"raddr": raddr})


class NetworkFlowExtractor(IndicatorExtractor):
    """tcpdump-aggregator flows — enrich the public destination IP
    (IPv4 or IPv6) so the judge / dashboard sees threat-intel and
    geolocation for the destination."""

    def extract(self, row):
        ip = row.get("dst_ip")
        if not isinstance(ip, str) or _is_private_ip(ip):
            return
        if _is_ipv4(ip):
            itype = IndicatorType.IPV4
        elif _is_ipv6(ip):
            itype = IndicatorType.IPV6
        else:
            return
        yield Indicator(
            itype,
            ip,
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
        ip = row.get("ip")
        if isinstance(ip, str) and not _is_private_ip(ip):
            if _is_ipv4(ip):
                yield Indicator(IndicatorType.IPV4, ip)
            elif _is_ipv6(ip):
                yield Indicator(IndicatorType.IPV6, ip)
        names = row.get("hostnames")
        if isinstance(names, str):
            for host in names.split():
                if _is_domain(host):
                    yield Indicator(IndicatorType.DOMAIN, host)


class ListeningPortExtractor(IndicatorExtractor):
    def extract(self, row):
        # listening_ports has laddr (bind ip) — only flag publicly bound.
        laddr = row.get("laddr")
        if isinstance(laddr, str) and ":" in laddr:
            host = laddr.rsplit(":", 1)[0]
            if _is_ipv4(host) and not _is_private_ip(host):
                yield Indicator(IndicatorType.IPV4, host, context={"laddr": laddr})


class LaunchItemExtractor(IndicatorExtractor):
    def extract(self, row):
        # Try the program first; fall back to the first argv element.
        target = row.get("program") or row.get("exec_start")
        if isinstance(target, str) and target.startswith("/"):
            digest = _sha256_of_file(target.split()[0])
            if digest:
                yield Indicator(
                    IndicatorType.SHA256, digest, context={"target": target}
                )


class SetuidFileExtractor(IndicatorExtractor):
    def extract(self, row):
        path = row.get("path")
        if isinstance(path, str):
            digest = _sha256_of_file(path)
            if digest:
                yield Indicator(IndicatorType.SHA256, digest, context={"path": path})


class QuarantineExtractor(IndicatorExtractor):
    """macOS quarantine_events — `origin_url` is what the LLM judge
    cares most about. Enrich both the URL and its host."""

    def extract(self, row):
        url = row.get("origin_url") or row.get("data_url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            yield Indicator(IndicatorType.URL, url)
            host = urlparse(url).hostname or ""
            if _is_domain(host):
                yield Indicator(IndicatorType.DOMAIN, host)
            elif _is_ipv4(host):
                yield Indicator(IndicatorType.IPV4, host)


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
            digest = _sha256_of_file(exe.split()[0])
            if digest:
                yield Indicator(IndicatorType.SHA256, digest, context={"exe": exe})


class FileIntegrityExtractor(IndicatorExtractor):
    def extract(self, row):
        # avai already records sha256 — use it directly.
        digest = row.get("sha256")
        path = row.get("path")
        if isinstance(digest, str) and len(digest) == 64:
            yield Indicator(
                IndicatorType.SHA256, digest, context={"path": str(path or "")}
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
    "file_integrity": FileIntegrityExtractor(),
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
