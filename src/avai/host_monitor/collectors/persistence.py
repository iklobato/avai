from __future__ import annotations

import configparser
import json
import shlex
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout, PrivilegedAccounts

from .. import slices
from ..constants import LAUNCH_DIRS
from ..enums import LaunchScope
from ..runtime import Coerce, Digest, HostPaths
from .base import SnapshotCollector

# minute hour day-of-month month day-of-week
CRON_SCHEDULE_FIELDS = 5
CRON_KEYWORD_FIELDS = 1
FIRST_LINE = 1
# The key comment starts two tokens after the key type (type, blob, comment).
COMMENT_OFFSET = 2
LAUNCH_JUDGE_FIELDS = (
    "scope",
    "label",
    "program",
    "program_arguments_json",
    "user_name",
    "run_at_load",
    "keep_alive",
)
SYSTEMD_SECTIONS = ("Unit", "Service", "Install", "Timer")
SYSTEMD_ACCOUNT_KEYS = (("user_name", "User"), ("group_name", "Group"))
SUDOERS_SKIPPED_PREFIXES = ("Defaults", "@includedir", "@include")
AUTHORIZED_KEY_FILES = ("authorized_keys", "authorized_keys2")
SSH_KEY_TYPES = frozenset(
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


class FileFacts:
    """Facts about one file on disk that may vanish or be unreadable."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def mtime(self) -> float | None:
        try:
            return self._path.stat().st_mtime
        except OSError:
            return None

    def text(self) -> str | None:
        try:
            return self._path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return None


class ShellArgs:
    """A command line split the way a shell would; the raw command as one
    argument when it isn't valid shell syntax."""

    def __init__(self, command: str) -> None:
        self._command = command

    def json(self) -> str:
        try:
            args = shlex.split(self._command) if self._command else []
        except ValueError:
            args = [self._command]
        return json.dumps(args)


class VisibleFiles:
    """The regular, non-dot files directly in a directory; [] when it is
    missing or unreadable."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def files(self) -> list[Path]:
        if not self._directory.is_dir():
            return []
        try:
            entries = list(self._directory.iterdir())
        except PermissionError:
            return []
        return [
            entry
            for entry in entries
            if entry.is_file() and not entry.name.startswith(".")
        ]


class LaunchPlist:
    """One launchd job plist as a launch_items row."""

    def __init__(self, scope: LaunchScope, path: Path) -> None:
        self._scope = scope
        self._path = path

    def row(self) -> dict[str, Any] | None:
        job = HostPaths().read_plist(self._path)
        if job is None:
            return None
        coerce = Coerce()
        return {
            "scope": str(self._scope),
            "path": str(self._path),
            "label": job.get("Label"),
            "program": job.get("Program"),
            "program_arguments_json": json.dumps(
                coerce.jsonable(job.get("ProgramArguments") or [])
            ),
            **self._schedule(job),
            "user_name": job.get("UserName"),
            "group_name": job.get("GroupName"),
            "sha256": Digest().sha256_file(self._path),
            "mtime": FileFacts(self._path).mtime(),
            "raw_json": json.dumps(coerce.jsonable(job)),
        }

    def _schedule(self, job: Mapping[str, Any]) -> dict[str, Any]:
        calendar = job.get("StartCalendarInterval")
        return {
            "run_at_load": int(bool(job.get("RunAtLoad"))),
            "keep_alive": int(bool(job.get("KeepAlive"))),
            "start_interval": job.get("StartInterval"),
            "start_calendar_interval_json": (
                json.dumps(Coerce().jsonable(calendar))
                if calendar is not None
                else None
            ),
        }


class LaunchItemsCollector(SnapshotCollector):
    slice = slices.LAUNCH_ITEMS
    judge_fields = LAUNCH_JUDGE_FIELDS

    def collect(self) -> Iterator[dict[str, Any]]:
        rows = (
            LaunchPlist(scope, path).row()
            for scope, dir_str in LAUNCH_DIRS
            for path in self._plists(HostPaths().expand(dir_str))
        )
        yield from (row for row in rows if row is not None)

    def _plists(self, directory: Path) -> list[Path]:
        if not directory.is_dir():
            return []
        try:
            return list(directory.glob("*.plist"))
        except PermissionError:
            return []


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
    judge_fields = LAUNCH_JUDGE_FIELDS

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from SystemdUnitReader().rows()
        yield from CrontabReader().rows()


class SystemdUnit:
    """One systemd unit file, parsed as INI."""

    ALWAYS_RESTART = frozenset(
        {"always", "on-failure", "on-success", "on-abnormal", "on-abort", "on-watchdog"}
    )

    def __init__(self, scope: str, path: Path) -> None:
        self._scope = scope
        self._path = path

    def row(self) -> dict[str, Any] | None:
        sections = self._sections()
        if sections is None:
            return None
        service = sections["Service"]
        exec_start = service.get("ExecStart") or ""
        return {
            "scope": self._scope,
            "path": str(self._path),
            "label": self._path.stem,
            "program": exec_start or sections["Timer"].get("OnCalendar"),
            "program_arguments_json": ShellArgs(exec_start).json(),
            **self._schedule(sections),
            **{column: service.get(key) for column, key in SYSTEMD_ACCOUNT_KEYS},
            "sha256": Digest().sha256_file(self._path),
            "mtime": FileFacts(self._path).mtime(),
            "raw_json": json.dumps(
                {name.lower(): section for name, section in sections.items()}
            ),
        }

    def _schedule(self, sections: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
        on_calendar = sections["Timer"].get("OnCalendar")
        restart = sections["Service"].get("Restart", "no").strip()
        return {
            "run_at_load": int(bool(sections["Install"].get("WantedBy"))),
            "keep_alive": int(restart in self.ALWAYS_RESTART),
            "start_interval": None,
            "start_calendar_interval_json": (
                json.dumps(on_calendar) if on_calendar else None
            ),
        }

    def _sections(self) -> dict[str, dict[str, str]] | None:
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            inline_comment_prefixes=("#", ";"),
            comment_prefixes=("#", ";"),
        )
        # systemd directive keys are CamelCase (ExecStart, WantedBy, …);
        # ConfigParser's default lowercasing made every lookup miss.
        parser.optionxform = str
        try:
            parser.read(self._path, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        return {
            name: dict(parser[name]) if parser.has_section(name) else {}
            for name in SYSTEMD_SECTIONS
        }


class SystemdUnitReader:
    """Launch-item rows for the systemd ``.service`` and ``.timer`` units.
    Path translation honours HOST_PREFIX so the container reads the host's
    /etc/systemd/system rather than its own (empty) one."""

    # (scope, directory, glob). Directories searched in this order;
    # later occurrences of the same unit filename are ignored (systemd
    # itself layers these dirs with /etc winning over /lib).
    UNIT_DIRS = (
        ("system_service", "/etc/systemd/system", "*.service"),
        ("system_service", "/run/systemd/system", "*.service"),
        ("system_service", "/lib/systemd/system", "*.service"),
        ("system_service", "/usr/lib/systemd/system", "*.service"),
        ("user_service", "~/.config/systemd/user", "*.service"),
        ("system_timer", "/etc/systemd/system", "*.timer"),
        ("system_timer", "/lib/systemd/system", "*.timer"),
        ("system_timer", "/usr/lib/systemd/system", "*.timer"),
        ("user_timer", "~/.config/systemd/user", "*.timer"),
    )

    def rows(self) -> Iterator[dict[str, Any]]:
        seen_units: set[str] = set()
        candidates = (
            (scope, path)
            for scope, dir_str, pattern in self.UNIT_DIRS
            for path in self._unit_files(dir_str, pattern)
        )
        for scope, path in candidates:
            # Dedup by name preserves systemd's first-wins precedence across
            # the system unit dirs.
            if path.name in seen_units:
                continue
            seen_units.add(path.name)
            row = self.unit_row(scope, path)
            if row is not None:
                yield row

    def unit_row(self, scope: str, path: Path) -> dict[str, Any] | None:
        return SystemdUnit(scope, path).row()

    def _unit_files(self, dir_str: str, pattern: str) -> Iterator[Path]:
        # HostPaths().for_home expands a ~/... template into 0..N real dirs
        # (one per user home in container mode), or exactly one for an
        # absolute path. It can return [] (container mode with no /host/home
        # and no /host/root mounted), so iterate rather than index [0],
        # which raised IndexError and killed the collector.
        directories = [path for path in HostPaths().for_home(dir_str) if path.is_dir()]
        for directory in directories:
            try:
                yield from list(directory.glob(pattern))
            except PermissionError:
                continue


class CronJob(NamedTuple):
    schedule: str
    user: str | None
    command: str

    @classmethod
    def parse(cls, line: str, owner: str | None) -> CronJob | None:
        """One crontab(5) line: 5 schedule fields (or ``@reboot``-style
        keyword), the user only when the file has no ``owner``, then the
        command. Comments, ``KEY=value`` and truncated lines give None."""
        line = line.strip()
        if not line or line.startswith("#") or "=" in line.split(None, 1)[0]:
            return None
        keyword = line.startswith("@")
        schedule_fields = CRON_KEYWORD_FIELDS if keyword else CRON_SCHEDULE_FIELDS
        has_user_col = owner is None
        need = schedule_fields + int(has_user_col) + 1
        tokens = line.split(None, need - 1)
        if len(tokens) < need:
            return None
        return cls(
            schedule=" ".join(tokens[:schedule_fields]),
            user=tokens[schedule_fields] if has_user_col else owner,
            command=tokens[-1],
        )

    def fields(self, lineno: int) -> dict[str, Any]:
        return {
            "program": self.command,
            "program_arguments_json": ShellArgs(self.command).json(),
            "run_at_load": int(self.schedule == "@reboot"),
            "keep_alive": 0,
            "start_interval": None,
            "start_calendar_interval_json": json.dumps({"schedule": self.schedule}),
            "user_name": self.user,
            "group_name": None,
            "raw_json": json.dumps(
                {
                    "source": "cron",
                    "schedule": self.schedule,
                    "user": self.user,
                    "command": self.command,
                    "line": lineno,
                }
            ),
        }


class CrontabReader:
    """Launch-item rows for cron: ``/etc/crontab``, the drop-ins in
    ``/etc/cron.d`` and the per-user crontabs in ``/var/spool/cron*``."""

    CRON_FILE = ("system_crontab", "/etc/crontab")
    CRON_DROP_INS = (("system_crontab_d", "/etc/cron.d"),)
    USER_CRONS = (
        ("user_crontab", "/var/spool/cron"),
        ("user_crontab", "/var/spool/cron/crontabs"),
    )

    def rows(self) -> Iterator[dict[str, Any]]:
        paths = HostPaths()
        scope, crontab_path = self.CRON_FILE
        crontab = paths.translate(crontab_path)
        if crontab.is_file():
            yield from self.file_rows(scope, crontab)
        for scope, directory in self.CRON_DROP_INS:
            for path in VisibleFiles(paths.translate(directory)).files():
                yield from self.file_rows(scope, path)
        # Per-user crontabs: the filename IS the username.
        for scope, directory in self.USER_CRONS:
            for path in VisibleFiles(paths.translate(directory)).files():
                yield from self.file_rows(scope, path, owner=path.name)

    def file_rows(
        self, scope: str, path: Path, owner: str | None = None
    ) -> Iterator[dict[str, Any]]:
        """Yield one row per job line of the crontab at ``path``. A file
        with an ``owner`` is a per-user crontab, whose lines carry no user
        column; without one each line names its user (system crontabs)."""
        text = FileFacts(path).text()
        if text is None:
            return
        stamp = {"sha256": Digest().sha256_file(path), "mtime": FileFacts(path).mtime()}
        jobs = (
            (lineno, CronJob.parse(raw, owner))
            for lineno, raw in enumerate(text.splitlines(), FIRST_LINE)
        )
        for lineno, job in ((lineno, job) for lineno, job in jobs if job is not None):
            where = {"path": f"{path}:{lineno}", "label": f"cron:{path.name}:{lineno}"}
            yield {"scope": scope, **where, **job.fields(lineno), **stamp}


class AuthorizedKeysParser:
    """Pure parser for an ``authorized_keys`` file: one row per key line.
    Tolerates leading option fields (``from=...,command=...``) before the
    key type."""

    def parse(self, content: str, path: str, owner: str) -> list[dict[str, Any]]:
        rows = (self._row(line.strip(), path, owner) for line in content.splitlines())
        return [row for row in rows if row is not None]

    def _row(self, line: str, path: str, owner: str) -> dict[str, Any] | None:
        if not line or line.startswith("#"):
            return None
        parts = line.split()
        key_index = next(
            (index for index, token in enumerate(parts) if token in SSH_KEY_TYPES), None
        )
        if key_index is None or key_index + 1 >= len(parts):
            return None
        return {
            "path": path,
            "owner": owner,
            "key_type": parts[key_index],
            "fingerprint": Digest().ssh_fingerprint(parts[key_index + 1]),
            "comment": " ".join(parts[key_index + COMMENT_OFFSET :]) or None,
            "options": " ".join(parts[:key_index]) or None,
        }


class SshAuthorizedKeysCollector(SnapshotCollector):
    """Enumerate every key in every user's ``authorized_keys`` — each one
    is a credential that grants SSH login. A *new* key (especially with a
    permissive ``from=``/forced-command, or an unfamiliar comment) is a
    classic, quiet persistence backdoor invisible to process/network
    collectors."""

    slice = slices.SSH_AUTHORIZED_KEYS
    judge_fields = ("path", "owner", "key_type", "fingerprint")

    def __init__(self, fs: FilesystemLayout, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self) -> Iterator[dict[str, Any]]:
        parser = AuthorizedKeysParser()
        key_files = (
            (home.name, home / ".ssh" / name)
            for home in self._fs.home_dirs()
            for name in AUTHORIZED_KEY_FILES
        )
        for owner, path in key_files:
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            yield from parser.parse(content, str(path), owner)


class HostsFileParser:
    """Pure parser for ``/etc/hosts``: one row per ``<ip> <name...>``."""

    def parse(self, content: str, path: str) -> list[dict[str, Any]]:
        mappings = (line.split("#", 1)[0].split() for line in content.splitlines())
        return [
            {"source_path": path, "ip": fields[0], "hostnames": " ".join(fields[1:])}
            for fields in mappings
            if len(fields) > 1
        ]


class HostsFileCollector(SnapshotCollector):
    """Snapshot ``/etc/hosts``. A mapping that points a real domain at an
    attacker IP (phishing / update hijack) or sinkholes a security domain
    to 0.0.0.0 is a cheap, high-impact tamper that nothing else catches."""

    slice = slices.HOSTS_FILE
    judge_fields = ("ip", "hostnames")

    def __init__(self, fs: FilesystemLayout, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self) -> Iterator[dict[str, Any]]:
        path = self._fs.hosts_file()
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from HostsFileParser().parse(content, str(path))


class SudoersParser:
    """Pure parser: keep privilege-granting rules, drop Defaults / includes /
    comments."""

    def parse(self, content: str, path: str) -> list[dict[str, Any]]:
        rules = (line.split("#", 1)[0].strip() for line in content.splitlines())
        return [
            {
                "kind": "sudoers",
                "subject": rule.split()[0],
                "detail": rule,
                "source_path": path,
            }
            for rule in rules
            if rule and not rule.startswith(SUDOERS_SKIPPED_PREFIXES)
        ]


class PrivilegeConfigCollector(SnapshotCollector):
    """Enumerate the host's privilege-granting configuration: sudoers
    rules, members of the admin/wheel/sudo groups, and UID-0 accounts.
    New entries here are privilege-escalation persistence."""

    slice = slices.PRIVILEGE_CONFIG
    judge_fields = ("kind", "subject", "detail")

    def __init__(
        self, fs: FilesystemLayout, accounts: PrivilegedAccounts, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._fs = fs
        self._accounts = accounts

    def collect(self) -> Iterator[Mapping[str, Any]]:
        yield from self._sudoers()
        yield from self._accounts.privileged_group_members()
        yield from self._accounts.uid0_accounts()

    def _sudoers(self) -> Iterator[dict[str, Any]]:
        """Sudoers parsing is identical across platforms; only the file
        locations differ, supplied by the FilesystemLayout."""
        parser = SudoersParser()
        for path in [self._fs.sudoers_file(), *self._sudoers_drop_ins()]:
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            yield from parser.parse(content, str(path))

    def _sudoers_drop_ins(self) -> list[Path]:
        sudoers_d = self._fs.sudoers_dir()
        if not sudoers_d.is_dir():
            return []
        try:
            return sorted(path for path in sudoers_d.iterdir() if path.is_file())
        except OSError:
            return []
