from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout

from ..slices import Slices
from ..constants import WATCHED_FILES
from ..runtime import (
    Coerce,
    CommandRunner,
    Digest,
    HostPaths,
    LaunchdServiceSupervisor,
    PsutilConnections,
    PsutilPortInspector,
    PsutilProcessInspector,
    SystemdServiceSupervisor,
    TriState,
)
from ..security_controls import ServiceProbes, ServiceSpec
from .base import SnapshotCollector

SPCTL_TIMEOUT_S = 10
SYSTEMCTL_TIMEOUT_S = 5
SELINUX_MODES = (("0", "Permissive"), ("1", "Enforcing"))
VNC_UNITS = ("x11vnc", "vncserver", "xrdp")
VNC_PORT = 5900
FILE_STAT_FIELDS = ("size", "mtime", "mode", "uid", "gid")


class SystemIntegrityCollector(SnapshotCollector):
    slice = Slices.SYSTEM_INTEGRITY
    judge_fields = (
        "filevault_active",
        "firewall_global_state",
        "firewall_stealth",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    # macOS network-service topics (label, port, process). enabled = launchd
    # job enabled OR port listening — so an idle-but-enabled daemon (whose
    # process hasn't been spawned yet by launchd) is never reported "off".
    SERVICES = (
        ServiceSpec("remote_login", "com.openssh.sshd", 22, "sshd"),
        ServiceSpec(
            "screen_sharing", "com.apple.screensharing", 5900, "screensharingd"
        ),
        ServiceSpec(
            "remote_management", "com.apple.RemoteDesktop.agent", 3283, "ARDAgent"
        ),
    )
    ALF_PLIST = Path("/Library/Preferences/com.apple.alf.plist")

    def __init__(
        self, runner: CommandRunner, probes: ServiceProbes, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._runner = runner
        self._probes = probes

    @classmethod
    def create(
        cls, runner: CommandRunner, judge_hints: str = ""
    ) -> SystemIntegrityCollector:
        probes = ServiceProbes(
            LaunchdServiceSupervisor(runner),
            PsutilPortInspector(PsutilConnections()),
            PsutilProcessInspector(),
        )
        return cls(runner, probes, judge_hints)

    def collect(self) -> Iterator[dict[str, Any]]:
        filevault = self._runner.exit_code(["fdesetup", "isactive"])
        alf = HostPaths().read_plist(self.ALF_PLIST) or {}
        # Enabled goes to the columns; the live-session signal stays in raw_json.
        signals = self._service_signals()
        yield {
            "filevault_active": None if filevault is None else int(filevault == 0),
            **self._firewall(alf),
            "gatekeeper_assessments_enabled": self._gatekeeper_state(),
            **{
                f"{topic}_enabled": signal["enabled"]
                for topic, signal in signals.items()
            },
            "raw_json": json.dumps(
                {"alf": Coerce().jsonable(alf), "services": signals}
            ),
        }

    def _service_signals(self) -> dict[str, dict[str, int | None]]:
        findings = {
            spec.topic: self._probes.control(spec).inspect() for spec in self.SERVICES
        }
        return {
            topic: {"enabled": finding.enabled, "active": finding.active}
            for topic, finding in findings.items()
        }

    def _firewall(self, alf: dict[str, Any]) -> dict[str, Any]:
        return {
            "firewall_global_state": alf.get("globalstate"),
            "firewall_stealth": int(bool(alf.get("stealthenabled"))) if alf else None,
            "firewall_logging": int(bool(alf.get("loggingenabled"))) if alf else None,
        }

    def _gatekeeper_state(self) -> int | None:
        # spctl --status always exits 0; the state is in its text output.
        try:
            output = self._runner.capture(
                ["spctl", "--status"], timeout=SPCTL_TIMEOUT_S
            )
        except FileNotFoundError:
            return None
        status = (output.stdout + output.stderr).lower()
        if "assessments enabled" in status:
            return 1
        if "assessments disabled" in status:
            return 0
        return None


class FileIntegrityCollector(SnapshotCollector):
    slice = Slices.FILE_INTEGRITY
    judge_fields = ("path", "sha256", "exists_flag")

    def __init__(
        self, watched: Iterable[str] = WATCHED_FILES, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._watched = watched

    def collect(self) -> Iterator[dict[str, Any]]:
        for path_str in self._watched:
            path = HostPaths().expand(path_str)
            try:
                file_stat = path.lstat()
            except FileNotFoundError:
                yield self._missing(path)
                continue
            except PermissionError:
                continue
            yield {
                "path": str(path),
                "sha256": Digest().sha256_file(path) if path.is_file() else None,
                **{
                    field: getattr(file_stat, f"st_{field}")
                    for field in FILE_STAT_FIELDS
                },
                "exists_flag": 1,
            }

    def _missing(self, path: Path) -> dict[str, Any]:
        return {
            "path": str(path),
            "sha256": None,
            **dict.fromkeys(FILE_STAT_FIELDS),
            "exists_flag": 0,
        }


class LinuxSecurityPosture:
    """Linux security controls read from sysfs, config files and systemd."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def selinux_state(self) -> str | None:
        """Returns 'Enforcing' / 'Permissive' / None (not present)."""
        paths = HostPaths()
        flag = paths.read_sysfs(paths.translate("/sys/fs/selinux/enforce"))
        if flag is None:
            return None
        return dict(SELINUX_MODES).get(flag, "Unknown")

    def apparmor_state(self) -> dict[str, bool]:
        paths = HostPaths()
        enabled = paths.read_sysfs(
            paths.translate("/sys/module/apparmor/parameters/enabled")
        )
        return {"enabled": enabled == "Y"}

    def ufw_active(self) -> bool:
        # /etc/ufw/ufw.conf is the canonical persistent state.
        paths = HostPaths()
        conf = paths.read_sysfs(paths.translate("/etc/ufw/ufw.conf"))
        settings = (line.partition("=") for line in (conf or "").splitlines())
        enabled = next(
            (value for key, sep, value in settings if sep and key.strip() == "ENABLED"),
            None,
        )
        return enabled is not None and enabled.strip().strip('"').lower() == "yes"

    def service_active(self, unit: str) -> bool:
        state = self._runner.text(
            ["systemctl", "is-active", unit], timeout=SYSTEMCTL_TIMEOUT_S
        )
        return state.strip() == "active"

    def luks_count(self) -> int:
        if not self._runner.exists("dmsetup"):
            return 0
        mappings = self._runner.text(
            ["dmsetup", "ls", "--target", "crypt"], timeout=SYSTEMCTL_TIMEOUT_S
        )
        if "No devices found" in mappings:
            return 0
        return sum(1 for line in mappings.splitlines() if line.strip())


class LinuxSystemIntegrityCollector(SnapshotCollector):
    """Linux equivalent of :class:`SystemIntegrityCollector`.

    Maps Linux security posture into the existing ``system_integrity``
    row, preserving the macOS-shaped column names so the dashboard
    keeps rendering them:

    - ``filevault_active``          → any active dm-crypt (LUKS) mapping.
    - ``firewall_global_state``    → ``ufw`` OR ``firewalld`` active.
    - ``firewall_stealth``         → reserved (no clean Linux analog).
    - ``firewall_logging``         → reserved.
    - ``gatekeeper_assessments_*`` → SELinux in *Enforcing* mode OR
                                     AppArmor enabled.
    - ``remote_login_enabled``     → ``ssh.service`` / ``sshd.service``
                                     active.
    - ``screen_sharing_enabled``   → ``x11vnc`` / ``vncserver`` active.
    - ``remote_management_enabled``→ same as screen_sharing (no Linux
                                     equivalent to Apple Remote Desktop).

    Raw posture details (SELinux mode string, AppArmor enabled/loaded
    profiles, ufw / firewalld active flags, dm-crypt count, sshd /
    vnc systemd status) live in ``raw_json`` for the LLM judge.
    """

    slice = Slices.SYSTEM_INTEGRITY
    judge_fields = (
        "filevault_active",
        "firewall_global_state",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    # SSH goes through the shared control (systemd-enabled OR port 22
    # listening); VNC stays multi-server (x11vnc/vncserver/xrdp) but gains
    # the port-5900 robustness + an active signal.
    SSH = ServiceSpec("remote_login", "ssh.service", 22, "sshd")

    def __init__(
        self, runner: CommandRunner, probes: ServiceProbes, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._runner = runner
        self._probes = probes

    @classmethod
    def create(
        cls, runner: CommandRunner, judge_hints: str = ""
    ) -> LinuxSystemIntegrityCollector:
        probes = ServiceProbes(
            SystemdServiceSupervisor(runner),
            PsutilPortInspector(PsutilConnections()),
            PsutilProcessInspector(),
        )
        return cls(runner, probes, judge_hints)

    def collect(self) -> Iterator[dict[str, Any]]:
        posture = LinuxSecurityPosture(self._runner)
        raw = self._raw(posture)
        ssh, vnc = raw["services"]["remote_login"], raw["services"]["screen_sharing"]
        yield {
            "filevault_active": int(raw["luks_mappings"] > 0),
            "firewall_global_state": int(raw["ufw_active"] or raw["firewalld_active"]),
            "firewall_stealth": None,
            "firewall_logging": None,
            "gatekeeper_assessments_enabled": int(
                raw["selinux"] == "Enforcing" or raw["apparmor"].get("enabled") is True
            ),
            "remote_login_enabled": ssh["enabled"],
            "screen_sharing_enabled": vnc["enabled"],
            "remote_management_enabled": vnc["enabled"],
            "raw_json": json.dumps(raw),
        }

    def _raw(self, posture: LinuxSecurityPosture) -> dict[str, Any]:
        ssh = self._probes.control(self.SSH).inspect()
        vnc = self._vnc(posture)
        return {
            "selinux": posture.selinux_state(),
            "apparmor": posture.apparmor_state(),
            "ufw_active": posture.ufw_active(),
            "firewalld_active": posture.service_active("firewalld"),
            # posture (enabled) drives the dashboard badge; behaviour lives
            # under "services" for the "active" pill.
            "sshd_active": ssh.enabled,
            "vnc_active": vnc["enabled"],
            "luks_mappings": posture.luks_count(),
            "services": {
                "remote_login": {"enabled": ssh.enabled, "active": ssh.active},
                "screen_sharing": vnc,
                "remote_management": vnc,
            },
        }

    def _vnc(self, posture: LinuxSecurityPosture) -> dict[str, int | None]:
        running = int(any(posture.service_active(unit) for unit in VNC_UNITS))
        signals = TriState()
        ports = self._probes.ports
        return {
            "enabled": signals.any_on((running, ports.listening(VNC_PORT))),
            "active": signals.any_on((running, ports.established(VNC_PORT))),
        }


class SetuidFilesCollector(SnapshotCollector):
    """Enumerate setuid / setgid files in common executable directories.

    A *new* setuid binary on a system is one of the loudest signals
    of privilege-escalation persistence — and is invisible to most
    of the other collectors. The walk is bounded to typical bin /
    sbin / libexec dirs to keep cycle time short; a full ``/`` walk
    takes minutes on a populated host.

    Honors ``HOST_PREFIX`` on Linux so a container monitor walks the
    host's ``/usr/bin`` rather than its own.
    """

    slice = Slices.SETUID_FILES
    judge_fields = ("path", "uid", "setuid", "setgid")

    def __init__(self, fs: FilesystemLayout, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self) -> Iterator[dict[str, Any]]:
        paths = (
            path for base in self._fs.privileged_bin_dirs() for path in self._tree(base)
        )
        rows = (self._row(path) for path in paths)
        yield from (row for row in rows if row is not None)

    def _tree(self, base: Path) -> list[Path]:
        if not base.is_dir():
            return []
        try:
            return list(base.rglob("*"))
        except OSError:
            return []

    def _row(self, path: Path) -> dict[str, Any] | None:
        try:
            if not path.is_file():
                return None
            file_stat = path.lstat()
        except OSError:
            return None
        setuid = bool(file_stat.st_mode & stat.S_ISUID)
        setgid = bool(file_stat.st_mode & stat.S_ISGID)
        if not (setuid or setgid):
            return None
        return self._privileged_row(path, file_stat, (setuid, setgid))

    def _privileged_row(
        self, path: Path, file_stat: os.stat_result, flags: tuple[bool, bool]
    ) -> dict[str, Any]:
        setuid, setgid = flags
        details = {"path": str(path), "mode": oct(file_stat.st_mode)}
        return {
            "path": str(path),
            **{field: getattr(file_stat, f"st_{field}") for field in FILE_STAT_FIELDS},
            "sha256": Digest().sha256_file(path),
            "setuid": int(setuid),
            "setgid": int(setgid),
            "raw_json": json.dumps({**details, "setuid": setuid, "setgid": setgid}),
        }
