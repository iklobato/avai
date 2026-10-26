"""Network exposure & MITM-surface collectors (Tier 2).

Same shape as Tier 1: thin OS-agnostic collector contracts over an
injected RowSource, with per-OS RowParser strategies. macOS parsers are
validated against real output from this platform; Linux/Windows parsers
are written to the documented formats.
"""

from __future__ import annotations

import json
from typing import Any

from . import slices
from .net_collectors import PsJson, SourceSnapshotCollector

NET_FILESYSTEMS = frozenset({"smbfs", "nfs", "nfs4", "afpfs", "webdav", "cifs", "ftp"})


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


class ProxyConfigCollector(SourceSnapshotCollector):
    slice = slices.PROXY_CONFIG
    judge_fields = ("scope", "host", "port", "pac_url")


class LoginSessionsCollector(SourceSnapshotCollector):
    slice = slices.LOGIN_SESSIONS
    judge_fields = ("user", "tty", "source")


class NetworkSharesCollector(SourceSnapshotCollector):
    slice = slices.NETWORK_SHARES
    judge_fields = ("remote", "mountpoint", "fstype")


class PromiscuousInterfacesCollector(SourceSnapshotCollector):
    slice = slices.PROMISCUOUS_IFACES
    judge_fields = ("interface", "promiscuous", "flags")


class TrustedRootsCollector(SourceSnapshotCollector):
    slice = slices.TRUSTED_ROOTS
    judge_fields = ("subject", "fingerprint")


# ---------------------------------------------------------------------------
# Cross-platform parsers (who is the same on macOS + Linux)
# ---------------------------------------------------------------------------


class WhoParser:
    """``who`` -> user / tty / source / login time. A trailing ``(host)`` is
    a remote session source."""

    MIN_COLUMNS = 2  # user tty

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines() if line.strip())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        body, source = self._split_source(line.rstrip())
        cols = body.split()
        if len(cols) < self.MIN_COLUMNS:
            return None
        user, tty, *login = cols
        return {
            "user": user,
            "tty": tty,
            "source": source,
            "login_at": " ".join(login) or None,
            "raw_json": json.dumps(line.strip()),
        }

    def _split_source(self, line: str) -> tuple[str, str]:
        if not (line.endswith(")") and "(" in line):
            return line, "local"
        cut = line.rfind("(")
        return line[:cut].rstrip(), line[cut + 1 : -1]


# ---------------------------------------------------------------------------
# macOS parsers (validated)
# ---------------------------------------------------------------------------


class MacosProxyParser:
    """``scutil --proxy`` key/value dump -> one row per *enabled* proxy."""

    TYPES = (
        ("HTTP", "HTTPProxy", "HTTPPort"),
        ("HTTPS", "HTTPSProxy", "HTTPSPort"),
        ("FTP", "FTPProxy", "FTPPort"),
        ("SOCKS", "SOCKSProxy", "SOCKSPort"),
    )

    def parse(self, text: str) -> list[dict[str, Any]]:
        settings = self._settings(text)
        enabled = (
            kind for kind in self.TYPES if settings.get(kind[0] + "Enable") == "1"
        )
        rows = [self._proxy_row(settings, kind) for kind in enabled]
        if settings.get("ProxyAutoConfigEnable") == "1":
            rows.append(self._pac_row(settings.get("ProxyAutoConfigURLString")))
        return rows

    def _settings(self, text: str) -> dict[str, str]:
        pairs = (line.split(":", 1) for line in text.splitlines() if ":" in line)
        stripped = ((key.strip(), value.strip()) for key, value in pairs)
        return {
            key: value
            for key, value in stripped
            if key and not key.isdigit() and not value.startswith("<")
        }

    def _proxy_row(
        self, settings: dict[str, str], kind: tuple[str, str, str]
    ) -> dict[str, Any]:
        name, host_key, port_key = kind
        return {
            "scope": name.lower(),
            "host": settings.get(host_key),
            "port": settings.get(port_key),
            "pac_url": None,
            "raw_json": json.dumps({host_key: settings.get(host_key)}),
        }

    def _pac_row(self, url: str | None) -> dict[str, Any]:
        return {
            "scope": "pac",
            "host": None,
            "port": None,
            "pac_url": url,
            "raw_json": json.dumps({"pac": url}),
        }


class MacosMountSharesParser:
    """``mount`` -> network mounts only (``REMOTE on MOUNT (fstype, ...)``)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        if " on " not in line or "(" not in line:
            return None
        remote, rest = line.split(" on ", 1)
        mount, _, paren = rest.partition(" (")
        options = paren.rstrip(")").split(", ")
        fstype = options[0] if options else None
        if fstype not in NET_FILESYSTEMS:
            return None
        return {
            "remote": remote.strip(),
            "mountpoint": mount.strip(),
            "fstype": fstype,
            "options": ", ".join(options[1:]) or None,
            "raw_json": json.dumps(line.strip()),
        }


class MacosPromiscParser:
    """``ifconfig`` flag lines -> promiscuous bit per interface."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        headers = (
            line
            for line in text.splitlines()
            if "flags=" in line and not line.startswith((" ", "\t"))
        )
        return [self._row(line) for line in headers]

    def _row(self, line: str) -> dict[str, Any]:
        flags = line[line.index("<") + 1 : line.index(">")] if "<" in line else ""
        return {
            "interface": line.split(":", 1)[0].strip(),
            "promiscuous": 1 if "PROMISC" in flags else 0,
            "flags": flags,
            "raw_json": json.dumps(line.strip()),
        }


class MacosCertParser:
    """``security find-certificate -a -Z`` -> (subject, sha256) per cert."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        fingerprint = None
        for line in (raw.strip() for raw in text.splitlines()):
            if line.startswith("SHA-256 hash:"):
                fingerprint = line.split(":", 1)[1].strip()
                continue
            if not (line.startswith('"labl"') and fingerprint):
                continue
            rows.append(self._row(line, fingerprint))
            fingerprint = None
        return rows

    def _row(self, line: str, fingerprint: str) -> dict[str, Any]:
        subject = line.split("=", 1)[1].strip().strip('"') if "=" in line else None
        return {
            "subject": subject,
            "fingerprint": fingerprint,
            "source": "System.keychain",
            "raw_json": json.dumps({"subject": subject, "sha256": fingerprint}),
        }


# ---------------------------------------------------------------------------
# Linux parsers
# ---------------------------------------------------------------------------


class LinuxProxyEnvParser:
    """``/etc/environment`` proxy variables."""

    VARIABLES = frozenset({"http_proxy", "https_proxy", "ftp_proxy", "all_proxy"})

    def parse(self, text: str) -> list[dict[str, Any]]:
        lines = (line.strip() for line in text.splitlines())
        assignments = (line.split("=", 1) for line in lines if self._assignment(line))
        pairs = (
            (name.strip().lower(), value.strip().strip('"').strip("'"))
            for name, value in assignments
        )
        return [
            self._row(name, value)
            for name, value in pairs
            if name in self.VARIABLES and value
        ]

    def _assignment(self, line: str) -> bool:
        return "=" in line and not line.startswith("#")

    def _row(self, name: str, value: str) -> dict[str, Any]:
        return {
            "scope": name.replace("_proxy", ""),
            "host": value,
            "port": None,
            "pac_url": None,
            "raw_json": json.dumps({name: value}),
        }


class ProcMountsSharesParser:
    """``/proc/mounts`` -> network mounts only."""

    MIN_COLUMNS = 3  # device mountpoint fstype, then options

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        cols = line.split()
        if len(cols) < self.MIN_COLUMNS:
            return None
        device, mountpoint, fstype, *rest = cols
        if fstype not in NET_FILESYSTEMS:
            return None
        return {
            "remote": device,
            "mountpoint": mountpoint,
            "fstype": fstype,
            "options": rest[0] if rest else None,
            "raw_json": json.dumps(line.strip()),
        }


class LinuxPromiscParser:
    """``ip link`` -> promiscuous bit per interface (PROMISC in flags)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        if "<" not in line or ">" not in line:
            return None
        index, sep, rest = line.partition(":")
        if not sep or not index.strip().isdigit():
            return None
        flags = line[line.index("<") + 1 : line.index(">")]
        return {
            "interface": rest.split(":", 1)[0].strip(),
            "promiscuous": 1 if "PROMISC" in flags else 0,
            "flags": flags,
            "raw_json": json.dumps(line.strip()),
        }


class LinuxTrustListParser:
    """``trust list`` (p11-kit) -> one row per anchor label."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        lines = (line.strip() for line in text.splitlines())
        labels = (
            line.split(":", 1)[1].strip() for line in lines if line.startswith("label:")
        )
        return [
            {
                "subject": subject,
                "fingerprint": None,
                "source": "trust",
                "raw_json": json.dumps({"label": subject}),
            }
            for subject in labels
        ]


# ---------------------------------------------------------------------------
# Windows parsers (PowerShell ConvertTo-Json)
# ---------------------------------------------------------------------------


class WindowsProxyParser:
    """Internet Settings registry: ProxyEnable / ProxyServer / AutoConfigURL."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(settings) for settings in PsJson().parse(text))
        return [row for row in rows if row is not None]

    def _row(self, settings: dict[str, Any]) -> dict[str, Any] | None:
        if settings.get("ProxyEnable"):
            host, _, port = (settings.get("ProxyServer") or "").partition(":")
            return self._shaped("winhttp", (host or None, port or None), settings)
        if settings.get("AutoConfigURL"):
            return self._shaped("pac", (None, None), settings)
        return None

    def _shaped(
        self,
        scope: str,
        endpoint: tuple[str | None, str | None],
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        host, port = endpoint
        return {
            "scope": scope,
            "host": host,
            "port": port,
            "pac_url": settings.get("AutoConfigURL"),
            "raw_json": json.dumps(settings),
        }


class WindowsSessionParser:
    """``query user`` columns (best-effort; layout is whitespace-aligned)."""

    MIN_COLUMNS = 2  # user session
    LOGIN_AT_COLUMNS = 3  # the date, time and meridiem that end the line

    def parse(self, text: str) -> list[dict[str, Any]]:
        rows = (self._row(line.rstrip()) for line in text.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str) -> dict[str, Any] | None:
        if not line.strip() or line.lstrip().upper().startswith("USERNAME"):
            return None
        cols = line.replace(">", " ").split()
        if len(cols) < self.MIN_COLUMNS:
            return None
        login = cols[-self.LOGIN_AT_COLUMNS :]
        return {
            "user": cols[0],
            "tty": cols[1],
            "source": "local",
            "login_at": " ".join(login) if len(cols) >= self.LOGIN_AT_COLUMNS else None,
            "raw_json": json.dumps(line.strip()),
        }


class WindowsSharesParser:
    """``Get-SmbConnection | ConvertTo-Json``."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [
            {
                "remote": f"\\\\{share.get('ServerName')}\\{share.get('ShareName')}",
                "mountpoint": share.get("ShareName"),
                "fstype": "smb",
                "options": str(share.get("Dialect")),
                "raw_json": json.dumps(share),
            }
            for share in PsJson().parse(text)
        ]


class WindowsCertParser:
    """``Get-ChildItem Cert:\\LocalMachine\\Root | ConvertTo-Json``."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        return [
            {
                "subject": cert.get("Subject"),
                "fingerprint": cert.get("Thumbprint"),
                "source": "LocalMachine/Root",
                "raw_json": json.dumps(cert),
            }
            for cert in PsJson().parse(text)
        ]
