"""Network exposure & MITM-surface collectors (Tier 2).

Same shape as Tier 1: thin OS-agnostic collector contracts over an
injected RowSource, with per-OS RowParser strategies. macOS parsers are
validated against real output from this platform; Linux/Windows parsers
are written to the documented formats.
"""

from __future__ import annotations

import json

from .models import (
    LoginSessionRow,
    NetworkShareRow,
    PromiscuousInterfaceRow,
    ProxyConfigRow,
    TrustedRootRow,
)
from .net_collectors import _load_ps_json, _SourceSnapshotCollector

_NET_FS = {"smbfs", "nfs", "nfs4", "afpfs", "webdav", "cifs", "ftp"}


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


class ProxyConfigCollector(_SourceSnapshotCollector):
    name = "proxy_config"
    model = ProxyConfigRow
    judge_fields = ("scope", "host", "port", "pac_url")


class LoginSessionsCollector(_SourceSnapshotCollector):
    name = "login_sessions"
    model = LoginSessionRow
    judge_fields = ("user", "tty", "source")


class NetworkSharesCollector(_SourceSnapshotCollector):
    name = "network_shares"
    model = NetworkShareRow
    judge_fields = ("remote", "mountpoint", "fstype")


class PromiscuousInterfacesCollector(_SourceSnapshotCollector):
    name = "promiscuous_ifaces"
    model = PromiscuousInterfaceRow
    judge_fields = ("interface", "promiscuous", "flags")


class TrustedRootsCollector(_SourceSnapshotCollector):
    name = "trusted_roots"
    model = TrustedRootRow
    judge_fields = ("subject", "fingerprint")


# ---------------------------------------------------------------------------
# Cross-platform parsers (who is the same on macOS + Linux)
# ---------------------------------------------------------------------------


class WhoParser:
    """``who`` → user / tty / source / login time. A trailing ``(host)`` is
    a remote session source."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            s = line.rstrip()
            if not s.strip():
                continue
            source = "local"
            if s.endswith(")") and "(" in s:
                source = s[s.rfind("(") + 1 : -1]
                s = s[: s.rfind("(")].rstrip()
            cols = s.split()
            if len(cols) < 2:
                continue
            rows.append(
                {
                    "user": cols[0],
                    "tty": cols[1],
                    "source": source,
                    "login_at": " ".join(cols[2:]) or None,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


# ---------------------------------------------------------------------------
# macOS parsers (validated)
# ---------------------------------------------------------------------------


class MacosProxyParser:
    """``scutil --proxy`` key/value dump → one row per *enabled* proxy."""

    _TYPES = [
        ("HTTP", "HTTPProxy", "HTTPPort"),
        ("HTTPS", "HTTPSProxy", "HTTPSPort"),
        ("FTP", "FTPProxy", "FTPPort"),
        ("SOCKS", "SOCKSProxy", "SOCKSPort"),
    ]

    def parse(self, text: str) -> list[dict]:
        kv: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if not k or k.isdigit() or v.startswith("<"):
                continue
            kv[k] = v
        rows = []
        for name, hostk, portk in self._TYPES:
            if kv.get(name + "Enable") == "1":
                rows.append(
                    {
                        "scope": name.lower(),
                        "host": kv.get(hostk),
                        "port": kv.get(portk),
                        "pac_url": None,
                        "raw_json": json.dumps({hostk: kv.get(hostk)}),
                    }
                )
        if kv.get("ProxyAutoConfigEnable") == "1":
            rows.append(
                {
                    "scope": "pac",
                    "host": None,
                    "port": None,
                    "pac_url": kv.get("ProxyAutoConfigURLString"),
                    "raw_json": json.dumps({"pac": kv.get("ProxyAutoConfigURLString")}),
                }
            )
        return rows


class MacosMountSharesParser:
    """``mount`` → network mounts only (``REMOTE on MOUNT (fstype, ...)``)."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            if " on " not in line or "(" not in line:
                continue
            remote, rest = line.split(" on ", 1)
            mount, _, paren = rest.partition(" (")
            opts = paren.rstrip(")").split(", ")
            fstype = opts[0] if opts else None
            if fstype not in _NET_FS:
                continue
            rows.append(
                {
                    "remote": remote.strip(),
                    "mountpoint": mount.strip(),
                    "fstype": fstype,
                    "options": ", ".join(opts[1:]) or None,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class MacosPromiscParser:
    """``ifconfig`` flag lines → promiscuous bit per interface."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            if "flags=" not in line or line.startswith((" ", "\t")):
                continue
            iface = line.split(":", 1)[0].strip()
            flags = line[line.index("<") + 1 : line.index(">")] if "<" in line else ""
            rows.append(
                {
                    "interface": iface,
                    "promiscuous": 1 if "PROMISC" in flags else 0,
                    "flags": flags,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class MacosCertParser:
    """``security find-certificate -a -Z`` → (subject, sha256) per cert."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        fp = None
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("SHA-256 hash:"):
                fp = s.split(":", 1)[1].strip()
            elif s.startswith('"labl"') and fp:
                subj = s.split("=", 1)[1].strip().strip('"') if "=" in s else None
                rows.append(
                    {
                        "subject": subj,
                        "fingerprint": fp,
                        "source": "System.keychain",
                        "raw_json": json.dumps({"subject": subj, "sha256": fp}),
                    }
                )
                fp = None
        return rows


# ---------------------------------------------------------------------------
# Linux parsers
# ---------------------------------------------------------------------------


class LinuxProxyEnvParser:
    """``/etc/environment`` proxy variables."""

    _VARS = {"http_proxy", "https_proxy", "ftp_proxy", "all_proxy"}

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            s = line.strip()
            if "=" not in s or s.startswith("#"):
                continue
            k, v = s.split("=", 1)
            k = k.strip().lower()
            v = v.strip().strip('"').strip("'")
            if k in self._VARS and v:
                rows.append(
                    {
                        "scope": k.replace("_proxy", ""),
                        "host": v,
                        "port": None,
                        "pac_url": None,
                        "raw_json": json.dumps({k: v}),
                    }
                )
        return rows


class ProcMountsSharesParser:
    """``/proc/mounts`` → network mounts only."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            cols = line.split()
            if len(cols) < 3 or cols[2] not in _NET_FS:
                continue
            rows.append(
                {
                    "remote": cols[0],
                    "mountpoint": cols[1],
                    "fstype": cols[2],
                    "options": cols[3] if len(cols) > 3 else None,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class LinuxPromiscParser:
    """``ip link`` → promiscuous bit per interface (PROMISC in flags)."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            if "<" not in line or ">" not in line:
                continue
            head = line.split(":", 2)
            if len(head) < 2 or not head[0].strip().isdigit():
                continue
            iface = head[1].strip()
            flags = line[line.index("<") + 1 : line.index(">")]
            rows.append(
                {
                    "interface": iface,
                    "promiscuous": 1 if "PROMISC" in flags else 0,
                    "flags": flags,
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class LinuxTrustListParser:
    """``trust list`` (p11-kit) → one row per anchor label."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("label:"):
                subj = s.split(":", 1)[1].strip()
                rows.append(
                    {
                        "subject": subj,
                        "fingerprint": None,
                        "source": "trust",
                        "raw_json": json.dumps({"label": subj}),
                    }
                )
        return rows


# ---------------------------------------------------------------------------
# Windows parsers (PowerShell ConvertTo-Json)
# ---------------------------------------------------------------------------


class WindowsProxyParser:
    """Internet Settings registry: ProxyEnable / ProxyServer / AutoConfigURL."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            if o.get("ProxyEnable"):
                host, _, port = (o.get("ProxyServer") or "").partition(":")
                rows.append(
                    {
                        "scope": "winhttp",
                        "host": host or None,
                        "port": port or None,
                        "pac_url": o.get("AutoConfigURL"),
                        "raw_json": json.dumps(o),
                    }
                )
            elif o.get("AutoConfigURL"):
                rows.append(
                    {
                        "scope": "pac",
                        "host": None,
                        "port": None,
                        "pac_url": o.get("AutoConfigURL"),
                        "raw_json": json.dumps(o),
                    }
                )
        return rows


class WindowsSessionParser:
    """``query user`` columns (best-effort; layout is whitespace-aligned)."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            s = line.rstrip()
            if not s.strip() or s.lstrip().upper().startswith("USERNAME"):
                continue
            cols = s.replace(">", " ").split()
            if len(cols) < 2:
                continue
            rows.append(
                {
                    "user": cols[0],
                    "tty": cols[1],
                    "source": "local",
                    "login_at": " ".join(cols[-3:]) if len(cols) >= 3 else None,
                    "raw_json": json.dumps(s.strip()),
                }
            )
        return rows


class WindowsSharesParser:
    """``Get-SmbConnection | ConvertTo-Json``."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            server, share = o.get("ServerName"), o.get("ShareName")
            rows.append(
                {
                    "remote": f"\\\\{server}\\{share}",
                    "mountpoint": share,
                    "fstype": "smb",
                    "options": str(o.get("Dialect")),
                    "raw_json": json.dumps(o),
                }
            )
        return rows


class WindowsCertParser:
    """``Get-ChildItem Cert:\\LocalMachine\\Root | ConvertTo-Json``."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            rows.append(
                {
                    "subject": o.get("Subject"),
                    "fingerprint": o.get("Thumbprint"),
                    "source": "LocalMachine/Root",
                    "raw_json": json.dumps(o),
                }
            )
        return rows
