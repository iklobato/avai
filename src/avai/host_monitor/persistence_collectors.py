"""Host persistence / injection collectors (Tier 3).

injection_env and kernel_modules follow the RowSource pattern;
ssh_known_hosts mirrors SshAuthorizedKeysCollector (it walks per-user home
directories via the injected FilesystemLayout, so it isn't a single
RowSource). macOS composes out kernel_modules — the kexts collector
already covers loaded kernel code there.
"""

from __future__ import annotations

import csv
import io
import json
from typing import TYPE_CHECKING

from .collectors import SnapshotCollector
from .models import InjectionEnvRow, KernelModuleRow, SshKnownHostRow
from .net_collectors import _load_ps_json, _SourceSnapshotCollector
from .runtime import Digest

if TYPE_CHECKING:
    from .hosts.capabilities import FilesystemLayout

_KNOWN_HOST_KEY_TYPES = frozenset(
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


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


class InjectionEnvCollector(_SourceSnapshotCollector):
    name = "injection_env"
    model = InjectionEnvRow
    judge_fields = ("scope", "variable", "value")


class KernelModulesCollector(_SourceSnapshotCollector):
    name = "kernel_modules"
    model = KernelModuleRow
    judge_fields = ("name", "size", "used_by")


class SshKnownHostsCollector(SnapshotCollector):
    """Enumerate every host pinned in each user's ``known_hosts``. Walks the
    per-user homes the FilesystemLayout reports (same shape as
    ssh_authorized_keys)."""

    name = "ssh_known_hosts"
    model = SshKnownHostRow
    judge_fields = ("host", "key_type", "fingerprint")

    def __init__(self, judge_hints: str = "", fs: "FilesystemLayout" = None):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self):
        for home in self._fs.home_dirs():
            path = home / ".ssh" / "known_hosts"
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            yield from self._parse_known_hosts(content, str(path))

    @classmethod
    def _parse_known_hosts(cls, content: str, path: str) -> list[dict]:
        """Pure parser: ``host[,host2] keytype base64 [comment]``; tolerates
        a leading ``@cert-authority``/``@revoked`` marker. Hashed hostnames
        (``|1|...``) are kept verbatim as the host token."""
        rows = []
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if parts[0].startswith("@"):
                parts = parts[1:]
            if len(parts) < 3 or parts[1] not in _KNOWN_HOST_KEY_TYPES:
                continue
            rows.append(
                {
                    "host": parts[0],
                    "key_type": parts[1],
                    "fingerprint": Digest.ssh_fingerprint(parts[2]),
                    "source_path": path,
                    "raw_json": json.dumps({"host": parts[0], "key_type": parts[1]}),
                }
            )
        return rows


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class EnvValueParser:
    """A single env var's value (e.g. ``launchctl getenv X``) → one row when
    it's set."""

    def __init__(self, variable: str, scope: str):
        self._variable = variable
        self._scope = scope

    def parse(self, text: str) -> list[dict]:
        val = text.strip()
        if not val:
            return []
        return [
            {
                "scope": self._scope,
                "variable": self._variable,
                "value": val,
                "raw_json": json.dumps({self._variable: val}),
            }
        ]


class LdSoPreloadParser:
    """``/etc/ld.so.preload`` — each listed library is force-preloaded."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            for lib in s.split():
                rows.append(
                    {
                        "scope": "ld.so.preload",
                        "variable": "LD_PRELOAD",
                        "value": lib,
                        "raw_json": json.dumps({"ld.so.preload": lib}),
                    }
                )
        return rows


class WindowsAppInitParser:
    """Registry ``AppInit_DLLs`` value (injected into every GUI process)."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for o in _load_ps_json(text):
            if not isinstance(o, dict):
                continue
            dlls = o.get("AppInit_DLLs")
            if dlls and str(dlls).strip():
                rows.append(
                    {
                        "scope": "AppInit_DLLs",
                        "variable": "AppInit_DLLs",
                        "value": str(dlls).strip(),
                        "raw_json": json.dumps(o),
                    }
                )
        return rows


class ProcModulesParser:
    """``/proc/modules`` — ``name size refcount used_by state addr``."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for line in text.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            rows.append(
                {
                    "name": cols[0],
                    "size": cols[1],
                    "used_by": None if cols[3] == "-" else cols[3],
                    "raw_json": json.dumps(line.strip()),
                }
            )
        return rows


class WindowsDriverParser:
    """``driverquery /fo csv`` — Module Name, Display Name, Driver Type."""

    def parse(self, text: str) -> list[dict]:
        rows = []
        for cols in csv.reader(io.StringIO(text)):
            if len(cols) < 2 or cols[0].strip().lower() == "module name":
                continue
            rows.append(
                {
                    "name": cols[0].strip(),
                    "size": None,
                    "used_by": cols[1].strip() if len(cols) > 1 else None,
                    "raw_json": json.dumps(cols),
                }
            )
        return rows
