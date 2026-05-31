"""Subprocess / filesystem / hashing helpers used by collectors."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import plistlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy import MetaData, Table, create_engine, select

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

from . import constants


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def host_path(p) -> Path:
    """Translate an absolute host path to its in-container location
    when HOST_PREFIX is set. Relative paths and the empty-prefix case
    are passthroughs."""
    p = p if isinstance(p, Path) else Path(p)
    if not constants.HOST_PREFIX or not p.is_absolute():
        return p
    return Path(constants.HOST_PREFIX + str(p))


def host_paths_for_home(template: str) -> list[Path]:
    """Expand a ``~/<rest>`` template into actual paths.

    Without HOST_PREFIX:
        ~/<rest> → [Path(os.path.expanduser(template))]

    With HOST_PREFIX (container mode):
        ~/<rest> → one entry per user home found under <prefix>/home/*
                   plus <prefix>/root for the rest.

    Absolute paths pass through ``host_path`` unchanged in count
    (always one path) so callers can flatten freely.
    """
    if not template.startswith("~/"):
        return [host_path(template)]
    rest = template[2:]
    if not constants.HOST_PREFIX:
        return [Path(os.path.expanduser(template))]
    out: list[Path] = []
    home_root = Path(constants.HOST_PREFIX) / "home"
    if home_root.is_dir():
        try:
            for user_dir in home_root.iterdir():
                if user_dir.is_dir():
                    out.append(user_dir / rest)
        except OSError:
            pass
    root_home = Path(constants.HOST_PREFIX) / "root"
    if root_home.is_dir():
        out.append(root_home / rest)
    return out


def run_json(cmd: list[str], timeout: int = 60) -> Any:
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} rc={r.returncode}: " f"{r.stderr.decode(errors='replace')[:200]}"
        )
    return json.loads(r.stdout) if r.stdout else None


def run_ndjson(cmd: list[str], timeout: int = 180) -> Iterable[dict]:
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} rc={r.returncode}: " f"{r.stderr.decode(errors='replace')[:200]}"
        )
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def exit_code(cmd: list[str], timeout: int = 10) -> Optional[int]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        return r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def service_loaded(label: str) -> Optional[int]:
    code = exit_code(["launchctl", "list", label])
    return None if code is None else int(code == 0)


def process_running(name: str) -> Optional[int]:
    """Return 1 if a process named *name* is running, 0 if not, None on error.

    Uses pgrep -x (exact match) so it works for system-domain services
    (sshd, screensharingd, ARDAgent) that launchctl list misses from the
    user session.
    """
    code = exit_code(["pgrep", "-x", name])
    return None if code is None else int(code == 0)


def sha256_file(path: Path, chunk: int = 65536) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def read_plist(path: Path) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    return data if isinstance(data, dict) else None


def jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def external_sqlite_rows(
    path: Path, table_name: str, columns: list[str]
) -> Iterable[dict]:
    """Reflect an external SQLite table and yield row dicts. No raw SQL."""
    url = f"sqlite:///file:{path}?mode=ro&uri=true"
    engine = create_engine(url)
    try:
        meta = MetaData()
        table = Table(table_name, meta, autoload_with=engine)
        stmt = select(*(table.c[c] for c in columns))
        with engine.connect() as conn:
            for row in conn.execute(stmt):
                yield dict(row._mapping)
    finally:
        engine.dispose()


def safe_psutil_connections() -> list:
    try:
        return psutil.net_connections(kind="inet")
    except psutil.AccessDenied as e:
        raise PermissionError(
            "psutil.net_connections requires root for full visibility"
        ) from e


def content_hash(row: dict, fields: Iterable[str]) -> Optional[str]:
    """Stable SHA-256 over the declared judgeable fields of a row."""
    keys = list(fields)
    if not keys:
        return None
    canonical = json.dumps(
        [row.get(k) for k in keys],
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def coerce_enum(value: Any, enum_cls, default):
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default


def _read_sysfs(path: Path, encoding: str = "utf-8") -> Optional[str]:
    """Read a sysfs/procfs attribute file. Returns the stripped string or
    None if unreadable. Doesn't raise on permission errors."""
    try:
        return path.read_text(encoding=encoding, errors="replace").strip()
    except (OSError, UnicodeError):
        return None


def _ssh_fingerprint(b64key: str) -> Optional[str]:
    """SHA256 fingerprint of an SSH public key blob, OpenSSH-style
    (``SHA256:<base64 of sha256(raw key), unpadded>``)."""
    try:
        raw = base64.b64decode(b64key, validate=True)
    except (ValueError, binascii.Error):
        return None
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
