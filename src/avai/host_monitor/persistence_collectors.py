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
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from .slices import Slices
from .collectors import SnapshotCollector
from .net_collectors import PsJson, SourceSnapshotCollector
from .runtime import Digest

if TYPE_CHECKING:
    from .hosts.capabilities import FilesystemLayout

KNOWN_HOST_KEY_TYPES = frozenset(
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


class InjectionEnvCollector(SourceSnapshotCollector):
    slice = Slices.INJECTION_ENV
    judge_fields = ("scope", "variable", "value")


class KernelModulesCollector(SourceSnapshotCollector):
    slice = Slices.KERNEL_MODULES
    judge_fields = ("name", "size", "used_by")


class KnownHostsParser:
    """``host[,host2] keytype base64 [comment]``; tolerates a leading
    ``@cert-authority``/``@revoked`` marker. Hashed hostnames (``|1|...``)
    are kept verbatim as the host token."""

    MIN_COLUMNS = 3  # host keytype key

    def rows(self, content: str, path: str) -> list[dict[str, Any]]:
        lines = (line.strip() for line in content.splitlines())
        entries = (self._fields(line) for line in lines if self._entry(line))
        return [
            self._row(fields, path)
            for fields in entries
            if len(fields) >= self.MIN_COLUMNS and fields[1] in KNOWN_HOST_KEY_TYPES
        ]

    def _entry(self, line: str) -> bool:
        return bool(line) and not line.startswith("#")

    def _fields(self, line: str) -> list[str]:
        fields = line.split()
        return fields[1:] if fields[0].startswith("@") else fields

    def _row(self, fields: list[str], path: str) -> dict[str, Any]:
        host, key_type, key, *_comment = fields
        return {
            "host": host,
            "key_type": key_type,
            "fingerprint": Digest().ssh_fingerprint(key),
            "source_path": path,
            "raw_json": json.dumps({"host": host, "key_type": key_type}),
        }


class SshKnownHostsCollector(SnapshotCollector):
    """Enumerate every host pinned in each user's ``known_hosts``. Walks the
    per-user homes the FilesystemLayout reports (same shape as
    ssh_authorized_keys)."""

    slice = Slices.SSH_KNOWN_HOSTS
    judge_fields = ("host", "key_type", "fingerprint")

    def __init__(self, fs: FilesystemLayout, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self) -> Iterator[dict[str, Any]]:
        for home in self._fs.home_dirs():
            path = home / ".ssh" / "known_hosts"
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            yield from KnownHostsParser().rows(content, str(path))


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class EnvValueParser:
    """A single env var's value (e.g. ``launchctl getenv X``) -> one row when
    it's set."""

    def __init__(self, variable: str, scope: str) -> None:
        self._variable = variable
        self._scope = scope

    def parse(self, text: str) -> list[dict[str, Any]]:
        value = text.strip()
        if not value:
            return []
        return [
            {
                "scope": self._scope,
                "variable": self._variable,
                "value": value,
                "raw_json": json.dumps({self._variable: value}),
            }
        ]


class LdSoPreloadParser:
    """``/etc/ld.so.preload``: each listed library is force-preloaded."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        lines = (line.strip() for line in text.splitlines())
        live = (line for line in lines if line and not line.startswith("#"))
        return [
            {
                "scope": "ld.so.preload",
                "variable": "LD_PRELOAD",
                "value": library,
                "raw_json": json.dumps({"ld.so.preload": library}),
            }
            for line in live
            for library in line.split()
        ]


class WindowsAppInitParser:
    """Registry ``AppInit_DLLs`` value (injected into every GUI process)."""

    def parse(self, text: str) -> list[dict[str, Any]]:
        settings = PsJson().parse(text)
        return [
            {
                "scope": "AppInit_DLLs",
                "variable": "AppInit_DLLs",
                "value": str(entry.get("AppInit_DLLs")).strip(),
                "raw_json": json.dumps(entry),
            }
            for entry in settings
            if entry.get("AppInit_DLLs") and str(entry.get("AppInit_DLLs")).strip()
        ]


class ProcModulesParser:
    """``/proc/modules``: ``name size refcount used_by state addr``."""

    MIN_COLUMNS = 4  # name size refcount used_by

    def parse(self, text: str) -> list[dict[str, Any]]:
        lines = text.splitlines()
        return [
            self._row(line) for line in lines if len(line.split()) >= self.MIN_COLUMNS
        ]

    def _row(self, line: str) -> dict[str, Any]:
        name, size, _refcount, used_by, *_rest = line.split()
        return {
            "name": name,
            "size": size,
            "used_by": None if used_by == "-" else used_by,
            "raw_json": json.dumps(line.strip()),
        }


class WindowsDriverParser:
    """``driverquery /fo csv``: Module Name, Display Name, Driver Type."""

    MIN_COLUMNS = 2  # module name, display name

    def parse(self, text: str) -> list[dict[str, Any]]:
        records = csv.reader(io.StringIO(text))
        return [
            {
                "name": cols[0].strip(),
                "size": None,
                "used_by": cols[1].strip(),
                "raw_json": json.dumps(cols),
            }
            for cols in records
            if len(cols) >= self.MIN_COLUMNS
            and cols[0].strip().lower() != "module name"
        ]
