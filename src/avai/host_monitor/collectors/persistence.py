"""Ways back in: launch items, systemd units and cron, SSH keys, the hosts
file, sudoers."""

from __future__ import annotations

import configparser
import json
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout, PrivilegedAccounts

from .. import slices
from ..constants import (
    LAUNCH_DIRS,
)
from ..enums import LaunchScope
from ..runtime import (
    Coerce,
    Digest,
    HostPaths,
)
from .base import SnapshotCollector


class LaunchItemsCollector(SnapshotCollector):
    slice = slices.LAUNCH_ITEMS
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
            d = HostPaths.expand(dir_str)
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
        data = HostPaths.read_plist(path)
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
                Coerce.jsonable(data.get("ProgramArguments") or [])
            ),
            "run_at_load": int(bool(data.get("RunAtLoad"))),
            "keep_alive": int(bool(data.get("KeepAlive"))),
            "start_interval": data.get("StartInterval"),
            "start_calendar_interval_json": (
                json.dumps(Coerce.jsonable(sci)) if sci is not None else None
            ),
            "user_name": data.get("UserName"),
            "group_name": data.get("GroupName"),
            "sha256": Digest.sha256_file(path),
            "mtime": mtime,
            "raw_json": json.dumps(Coerce.jsonable(data)),
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

    slice = slices.LAUNCH_ITEMS
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
            for d in HostPaths.for_home(dir_str):
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
        p = HostPaths.translate(p)
        if p.is_file():
            yield from self._cron_rows(scope, p, has_user_col=True)

        # /etc/cron.d/* — drop-in files, has-user-column form
        for scope, d in self._CRON_DROP_INS:
            d = HostPaths.translate(d)
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
            d = HostPaths.translate(d)
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
            "sha256": Digest.sha256_file(path),
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
        digest = Digest.sha256_file(path)

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


class SshAuthorizedKeysCollector(SnapshotCollector):
    """Enumerate every key in every user's ``authorized_keys`` — each one
    is a credential that grants SSH login. A *new* key (especially with a
    permissive ``from=``/forced-command, or an unfamiliar comment) is a
    classic, quiet persistence backdoor invisible to process/network
    collectors."""

    slice = slices.SSH_AUTHORIZED_KEYS
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

    def __init__(self, judge_hints: str = "", fs: "FilesystemLayout" = None):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self):
        for home in self._fs.home_dirs():
            owner = home.name
            for fname in ("authorized_keys", "authorized_keys2"):
                path = home / ".ssh" / fname
                try:
                    content = path.read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                for row in self._parse_authorized_keys(content, str(path), owner):
                    yield row

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
                    "fingerprint": Digest.ssh_fingerprint(parts[idx + 1]),
                    "comment": " ".join(parts[idx + 2 :]) or None,
                    "options": " ".join(parts[:idx]) or None,
                }
            )
        return rows


class HostsFileCollector(SnapshotCollector):
    """Snapshot ``/etc/hosts``. A mapping that points a real domain at an
    attacker IP (phishing / update hijack) or sinkholes a security domain
    to 0.0.0.0 is a cheap, high-impact tamper that nothing else catches."""

    slice = slices.HOSTS_FILE
    judge_fields = ("ip", "hostnames")

    def __init__(self, judge_hints: str = "", fs: "FilesystemLayout" = None):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self):
        path = self._fs.hosts_file()
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

    slice = slices.PRIVILEGE_CONFIG
    judge_fields = ("kind", "subject", "detail")

    def __init__(
        self,
        judge_hints: str = "",
        fs: "FilesystemLayout" = None,
        accounts: "PrivilegedAccounts" = None,
    ):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs
        self._accounts = accounts

    def collect(self):
        yield from self._sudoers()
        yield from self._accounts.privileged_group_members()
        yield from self._accounts.uid0_accounts()

    def _sudoers(self):
        """Sudoers parsing is identical across platforms; only the file
        locations differ, supplied by the FilesystemLayout."""
        files = [self._fs.sudoers_file()]
        sudoers_d = self._fs.sudoers_dir()
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
