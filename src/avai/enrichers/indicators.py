"""Per-collector indicator extraction (Strategy pattern).

Each :class:`IndicatorExtractor` looks at one collector's row dict and
yields ``Indicator`` values for the threat-intel chain to enrich.
:class:`IndicatorExtraction` holds them keyed by collector name and
dispatches.

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
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from urllib.parse import urlparse

from avai.enrichers.base import Indicator, IndicatorType

SHA256_HEX_LEN = 64
# Files above this are not hashed, to avoid stalling on huge binaries.
MAX_HASHED_FILE_BYTES = 16 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024
WEB_SCHEMES = ("http://", "https://")
SHARE_PREFIXES = ("//", "\\\\")

ANY_HOST = frozenset({IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN})
IP_HOST = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})
IPV4_HOST = frozenset({IndicatorType.IPV4})
DOMAIN_HOST = frozenset({IndicatorType.DOMAIN})
NAMED_HOST = frozenset({IndicatorType.IPV4, IndicatorType.DOMAIN})

DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


class HostClassifier:
    """Classifies a host string as a public IPv4, IPv6 or domain."""

    def is_ipv4(self, host: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
        except ValueError:
            return False

    def is_ipv6(self, host: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
        except ValueError:
            return False

    def is_private_ip(self, host: str) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    def is_domain(self, host: str) -> bool:
        # An IPv4 literal matches the regex (all-digit labels separated by
        # dots) but isn't a domain — classify it as IPv4 instead.
        return (
            bool(DOMAIN_PATTERN.match(host)) and "." in host and not self.is_ipv4(host)
        )

    def public_type(self, host: str) -> IndicatorType | None:
        """IPV4, IPV6 or DOMAIN for a host worth sending to threat-intel.
        None for private/local addresses (no intel, and they map the LAN to
        a third party) and for anything that isn't a host."""
        if self.is_private_ip(host):
            return None
        checks = (
            (self.is_ipv4, IndicatorType.IPV4),
            (self.is_ipv6, IndicatorType.IPV6),
            (self.is_domain, IndicatorType.DOMAIN),
        )
        return next((kind for check, kind in checks if check(host)), None)

    def indicators(
        self, host: object, kinds: frozenset[IndicatorType]
    ) -> Iterator[Indicator]:
        """The host as an indicator when it's public and one of ``kinds``."""
        if not isinstance(host, str):
            return
        kind = self.public_type(host)
        if kind in kinds:
            yield Indicator(kind, host)


class FileHasher:
    """sha256 of a regular file on disk, skipped for huge or missing files."""

    def sha256(self, path: str) -> str | None:
        file_path = Path(path)
        try:
            if not file_path.is_file():
                return None
            if file_path.stat().st_size > MAX_HASHED_FILE_BYTES:
                return None
            return self._digest(file_path)
        except OSError:
            return None

    def indicators(self, path: str) -> Iterator[Indicator]:
        digest = self.sha256(path)
        if digest:
            yield Indicator(IndicatorType.SHA256, digest)

    def _digest(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
        return digest.hexdigest()


class IndicatorExtractor(ABC):
    def __init__(self, hosts: HostClassifier, files: FileHasher) -> None:
        self._hosts = hosts
        self._files = files

    @abstractmethod
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]: ...


class ProcessExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        exe = row.get("exe")
        if isinstance(exe, str) and exe:
            yield from self._files.indicators(exe)


class NetworkConnectionExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        # The collector emits raddr_ip/raddr_port; older/synthetic rows may
        # carry a combined "ip:port" raddr string — support both. IPv4-only
        # by design (bracketed-IPv6 raddr strings parse to a non-IPv4 host
        # and are skipped).
        host = row.get("raddr_ip") or self._combined_host(row.get("raddr"))
        yield from self._hosts.indicators(host, IPV4_HOST)

    def _combined_host(self, raddr: object) -> str | None:
        if isinstance(raddr, str) and ":" in raddr:
            return raddr.rsplit(":", 1)[0]
        return None


class NetworkFlowExtractor(IndicatorExtractor):
    """tcpdump-aggregator flows — enrich the public destination IP
    (IPv4 or IPv6) so the judge / dashboard sees threat-intel and
    geolocation for the destination."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        yield from self._hosts.indicators(row.get("dst_ip"), IP_HOST)


class DnsQueryExtractor(IndicatorExtractor):
    """DNS questions — enrich the queried domain so the judge sees
    PhishTank / URLhaus / threat-feed verdicts before deciding. DoH rows
    carry a provider name (not a domain) and are skipped here."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        qname = row.get("qname")
        if isinstance(qname, str) and self._hosts.is_domain(qname):
            yield Indicator(IndicatorType.DOMAIN, qname)


class HostsFileExtractor(IndicatorExtractor):
    """/etc/hosts mappings — enrich the target IP (if public) and each
    real domain on the line, so a hijack entry (e.g. a bank domain
    pointed at an attacker IP) gets threat-intel."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        yield from self._hosts.indicators(row.get("ip"), IP_HOST)
        names = row.get("hostnames")
        if isinstance(names, str):
            for host in names.split():
                yield from self._hosts.indicators(host, DOMAIN_HOST)


class ListeningPortExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        # listening_ports has laddr (bind ip) — only flag publicly bound.
        laddr = row.get("laddr")
        if isinstance(laddr, str) and ":" in laddr:
            yield from self._hosts.indicators(laddr.rsplit(":", 1)[0], IPV4_HOST)


class LaunchItemExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        # Try the program first; fall back to the first argv element.
        target = row.get("program") or row.get("exec_start")
        if isinstance(target, str) and target.startswith("/"):
            yield from self._files.indicators(target.split()[0])


class SetuidFileExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        path = row.get("path")
        if isinstance(path, str):
            yield from self._files.indicators(path)


class QuarantineExtractor(IndicatorExtractor):
    """macOS quarantine_events — `origin_url` is what the LLM judge
    cares most about. Enrich both the URL and its host."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        url = row.get("origin_url") or row.get("data_url")
        if isinstance(url, str) and url.startswith(WEB_SCHEMES):
            yield Indicator(IndicatorType.URL, url)
            yield from self._hosts.indicators(urlparse(url).hostname, NAMED_HOST)


class BrowserExtensionExtractor(IndicatorExtractor):
    """Pull host_permissions out of extension manifests and emit them
    as domain indicators. Extensions targeting known-malicious hosts
    are a strong signal."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        patterns = self.permissions(row.get("host_permissions_json"))
        for pattern in patterns:
            host = self._pattern_host(pattern)
            if self._hosts.is_domain(host):
                yield Indicator(IndicatorType.DOMAIN, host)

    def permissions(self, raw: object) -> list[str]:
        """The manifest's host_permissions; empty when it isn't a JSON list."""
        if not isinstance(raw, str) or not raw:
            return []
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        if not isinstance(parsed, list):
            return []
        return [pattern for pattern in parsed if isinstance(pattern, str)]

    def _pattern_host(self, pattern: str) -> str:
        # Patterns are "<scheme>://<host>/..."; strip wildcards.
        host = pattern.split("://", 1)[-1].split("/", 1)[0]
        return host.replace("*.", "").replace("*", "")


class InstalledAppExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        name = row.get("name") or row.get("package")
        version = row.get("version") or ""
        if not isinstance(name, str) or not name:
            return
        value = f"{name}@{version}" if version else name
        yield Indicator(IndicatorType.PACKAGE, value)


class SystemIntegrityExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        product = row.get("os_name") or row.get("distro")
        cycle = row.get("os_version") or row.get("version")
        if isinstance(product, str) and isinstance(cycle, str) and product and cycle:
            yield Indicator(IndicatorType.OS_VERSION, f"{product.lower()}@{cycle}")


class ProcessExecEventExtractor(IndicatorExtractor):
    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        exe = row.get("exe") or row.get("path")
        if isinstance(exe, str):
            yield from self._files.indicators(exe.split()[0])


class RecordedDigestExtractor(IndicatorExtractor):
    """Rows that already carry the file's sha256 (file_integrity, and the
    YARA-matched files of file_scan), so a finding converges with hash
    threat-intel (VirusTotal / MalwareBazaar / CIRCL / the local deny-list)
    without hashing the file again."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        digest = row.get("sha256")
        if isinstance(digest, str) and len(digest) == SHA256_HEX_LEN:
            yield Indicator(IndicatorType.SHA256, digest)


class ProxyConfigExtractor(IndicatorExtractor):
    """Enrich a configured proxy host (public IP/domain) and PAC URL."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        yield from self._hosts.indicators(row.get("host"), ANY_HOST)
        pac = row.get("pac_url")
        if isinstance(pac, str) and pac.startswith(WEB_SCHEMES):
            yield Indicator(IndicatorType.URL, pac)


class NetworkShareExtractor(IndicatorExtractor):
    """Enrich the server of a mounted network share."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        remote = row.get("remote")
        if isinstance(remote, str):
            yield from self._hosts.indicators(self.server(remote), NAMED_HOST)

    def server(self, remote: str) -> str | None:
        """Pull the server host out of a share path: ``//server/share``,
        ``\\\\server\\share`` (SMB) or ``server:/export`` (NFS)."""
        head = self._share_head(remote.strip())
        if head is None:
            return None
        if "@" in head:
            head = head.split("@", 1)[1]
        return head or None

    def _share_head(self, remote: str) -> str | None:
        if remote.startswith(SHARE_PREFIXES):
            return remote.replace("\\", "/").lstrip("/").split("/", 1)[0]
        if ":" in remote and not remote.startswith("/"):
            return remote.split(":", 1)[0]
        return None


class LoginSessionExtractor(IndicatorExtractor):
    """Enrich a remote login source when it's a public IP/domain."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        # A console login's source is "local", which isn't a host.
        yield from self._hosts.indicators(row.get("source"), ANY_HOST)


class DnsResolverExtractor(IndicatorExtractor):
    """Enrich the configured nameserver when it's a *public* IP — a
    resolver pointed at an attacker-controlled box is the DNS-hijack
    signal. LAN/private resolvers (your router) carry no threat-intel
    value and are skipped."""

    def extract(self, row: Mapping[str, object]) -> Iterable[Indicator]:
        yield from self._hosts.indicators(row.get("server"), IP_HOST)


EXTRACTOR_TYPES: tuple[tuple[str, type[IndicatorExtractor]], ...] = (
    ("processes", ProcessExtractor),
    ("network_connections", NetworkConnectionExtractor),
    ("network_flows", NetworkFlowExtractor),
    ("dns_queries", DnsQueryExtractor),
    ("hosts_file", HostsFileExtractor),
    ("listening_ports", ListeningPortExtractor),
    ("launch_items", LaunchItemExtractor),
    ("setuid_files", SetuidFileExtractor),
    ("quarantine_events", QuarantineExtractor),
    ("browser_extensions", BrowserExtensionExtractor),
    ("installed_apps", InstalledAppExtractor),
    ("system_integrity", SystemIntegrityExtractor),
    ("process_exec_events", ProcessExecEventExtractor),
    ("file_integrity", RecordedDigestExtractor),
    ("file_scan", RecordedDigestExtractor),
    ("dns_resolvers", DnsResolverExtractor),
    ("proxy_config", ProxyConfigExtractor),
    ("network_shares", NetworkShareExtractor),
    ("login_sessions", LoginSessionExtractor),
)


class IndicatorExtraction:
    """Dispatches a collector's row to that collector's extractor. A
    collector with no extractor contributes no indicators."""

    def __init__(self, extractors: Mapping[str, IndicatorExtractor]) -> None:
        self._extractors = extractors

    @classmethod
    def default(cls) -> IndicatorExtraction:
        hosts, files = HostClassifier(), FileHasher()
        return cls(
            {
                collector: extractor_type(hosts, files)
                for collector, extractor_type in EXTRACTOR_TYPES
            }
        )

    @property
    def collectors(self) -> frozenset[str]:
        return frozenset(self._extractors)

    def extract(self, collector: str, row: Mapping[str, object]) -> list[Indicator]:
        """One row in, list of indicators out. Deduped within the row."""
        extractor = self._extractors.get(collector)
        if extractor is None:
            return []
        seen: set[tuple[str, str]] = set()
        unique: list[Indicator] = []
        for indicator in extractor.extract(row):
            key = (str(indicator.type), indicator.value)
            if key not in seen:
                seen.add(key)
                unique.append(indicator)
        return unique
