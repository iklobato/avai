"""Security posture: system integrity settings, watched files and setuid binaries."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Optional

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout

from .. import slices
from ..constants import (
    WATCHED_FILES,
)
from ..runtime import (
    Coerce,
    CommandRunner,
    Digest,
    HostPaths,
    LaunchdServiceManager,
    PortInspector,
    ProcessInspector,
    PsutilPortInspector,
    PsutilProcessInspector,
    ServiceManager,
    SystemdServiceManager,
    tri_or,
)
from ..security_controls import NetworkServiceControl, ServiceSpec
from .base import SnapshotCollector


class SystemIntegrityCollector(SnapshotCollector):
    slice = slices.SYSTEM_INTEGRITY
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
    _SERVICES = (
        ServiceSpec("remote_login", "com.openssh.sshd", 22, "sshd"),
        ServiceSpec(
            "screen_sharing", "com.apple.screensharing", 5900, "screensharingd"
        ),
        ServiceSpec(
            "remote_management", "com.apple.RemoteDesktop.agent", 3283, "ARDAgent"
        ),
    )

    def __init__(
        self,
        judge_hints: str = "",
        services: Optional[ServiceManager] = None,
        ports: Optional[PortInspector] = None,
        processes: Optional[ProcessInspector] = None,
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        svc = services or LaunchdServiceManager()
        ports = ports or PsutilPortInspector()
        processes = processes or PsutilProcessInspector()
        self._controls = {
            s.topic: NetworkServiceControl(s, svc, ports, processes)
            for s in self._SERVICES
        }

    def collect(self):
        fv = CommandRunner().exit_code(["fdesetup", "isactive"])
        alf = (
            HostPaths.read_plist(Path("/Library/Preferences/com.apple.alf.plist")) or {}
        )
        # spctl --status always exits 0; the state is in its stdout text.
        try:
            _gk = subprocess.run(
                ["spctl", "--status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            _gk_out = (_gk.stdout + _gk.stderr).lower()
            if "assessments enabled" in _gk_out:
                gk: Optional[int] = 1
            elif "assessments disabled" in _gk_out:
                gk = 0
            else:
                gk = None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            gk = None
        # Posture (enabled) + behaviour (active) for the network services,
        # via the injected controls. Persisting enabled into the existing
        # columns; the live-session signal is kept in raw_json for the judge.
        svc = {t: c.inspect() for t, c in self._controls.items()}
        yield {
            "filevault_active": None if fv is None else int(fv == 0),
            "firewall_global_state": alf.get("globalstate"),
            "firewall_stealth": int(bool(alf.get("stealthenabled"))) if alf else None,
            "firewall_logging": int(bool(alf.get("loggingenabled"))) if alf else None,
            "gatekeeper_assessments_enabled": gk,
            "remote_login_enabled": svc["remote_login"].enabled,
            "screen_sharing_enabled": svc["screen_sharing"].enabled,
            "remote_management_enabled": svc["remote_management"].enabled,
            "raw_json": json.dumps(
                {
                    "alf": Coerce.jsonable(alf),
                    "services": {
                        t: {"enabled": f.enabled, "active": f.active}
                        for t, f in svc.items()
                    },
                }
            ),
        }


class FileIntegrityCollector(SnapshotCollector):
    slice = slices.FILE_INTEGRITY
    judge_fields = ("path", "sha256", "exists_flag")

    def __init__(self, watched: Iterable[str] = WATCHED_FILES, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.watched = list(watched)

    def collect(self):
        for path_str in self.watched:
            p = HostPaths.expand(path_str)
            try:
                st = p.lstat()
            except FileNotFoundError:
                yield self._missing(p)
                continue
            except PermissionError:
                continue
            yield {
                "path": str(p),
                "sha256": Digest.sha256_file(p) if p.is_file() else None,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "exists_flag": 1,
            }

    @staticmethod
    def _missing(p):
        return {
            "path": str(p),
            "sha256": None,
            "size": None,
            "mtime": None,
            "mode": None,
            "uid": None,
            "gid": None,
            "exists_flag": 0,
        }


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

    slice = slices.SYSTEM_INTEGRITY
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
    _SSH = ServiceSpec("remote_login", "ssh.service", 22, "sshd")
    _VNC_PORT = 5900

    def __init__(
        self,
        judge_hints: str = "",
        services: Optional[ServiceManager] = None,
        ports: Optional[PortInspector] = None,
        processes: Optional[ProcessInspector] = None,
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._ports = ports or PsutilPortInspector()
        self._ssh = NetworkServiceControl(
            self._SSH,
            services or SystemdServiceManager(),
            self._ports,
            processes or PsutilProcessInspector(),
        )

    def collect(self):
        selinux = self._selinux_state()
        apparmor = self._apparmor_state()
        ufw = self._ufw_active()
        fwd = self._service_active("firewalld")
        vnc = (
            self._service_active("x11vnc")
            or self._service_active("vncserver")
            or self._service_active("xrdp")
        )
        luks_n = self._luks_count()

        ssh = self._ssh.inspect()
        vnc_enabled = tri_or(int(vnc), self._ports.listening(self._VNC_PORT))
        vnc_active = tri_or(int(vnc), self._ports.established(self._VNC_PORT))

        raw = {
            "selinux": selinux,
            "apparmor": apparmor,
            "ufw_active": ufw,
            "firewalld_active": fwd,
            # posture (enabled) drives the dashboard badge; behaviour lives
            # under "services" for the "active" pill.
            "sshd_active": ssh.enabled,
            "vnc_active": vnc_enabled,
            "luks_mappings": luks_n,
            "services": {
                "remote_login": {"enabled": ssh.enabled, "active": ssh.active},
                "screen_sharing": {"enabled": vnc_enabled, "active": vnc_active},
                "remote_management": {"enabled": vnc_enabled, "active": vnc_active},
            },
        }

        yield {
            "filevault_active": int(luks_n > 0),
            "firewall_global_state": int(ufw or fwd),
            "firewall_stealth": None,
            "firewall_logging": None,
            "gatekeeper_assessments_enabled": int(
                selinux == "Enforcing" or apparmor.get("enabled") is True
            ),
            "remote_login_enabled": ssh.enabled,
            "screen_sharing_enabled": vnc_enabled,
            "remote_management_enabled": vnc_enabled,
            "raw_json": json.dumps(raw),
        }

    # ---- helpers ----------------------------------------------------

    @staticmethod
    def _selinux_state() -> Optional[str]:
        """Returns 'Enforcing' / 'Permissive' / None (not present)."""
        flag = HostPaths.read_sysfs(HostPaths.translate("/sys/fs/selinux/enforce"))
        if flag is None:
            return None
        return {"0": "Permissive", "1": "Enforcing"}.get(flag, "Unknown")

    @staticmethod
    def _apparmor_state() -> dict:
        enabled = HostPaths.read_sysfs(
            HostPaths.translate("/sys/module/apparmor/parameters/enabled")
        )
        return (
            {"enabled": enabled == "Y"} if enabled is not None else {"enabled": False}
        )

    @staticmethod
    def _ufw_active() -> bool:
        # /etc/ufw/ufw.conf is the canonical persistent state.
        conf = HostPaths.read_sysfs(HostPaths.translate("/etc/ufw/ufw.conf"))
        if conf is None:
            return False
        for line in conf.splitlines():
            if line.lstrip().startswith("ENABLED"):
                key, _, value = line.partition("=")
                if key.strip() == "ENABLED":
                    return value.strip().strip('"').lower() == "yes"
        return False

    @staticmethod
    def _service_active(unit: str) -> bool:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return r.stdout.strip() == "active"

    @staticmethod
    def _luks_count() -> int:
        if not shutil.which("dmsetup"):
            return 0
        try:
            r = subprocess.run(
                ["dmsetup", "ls", "--target", "crypt"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return 0
        if r.returncode != 0 or "No devices found" in r.stdout:
            return 0
        return sum(1 for line in r.stdout.splitlines() if line.strip())


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

    slice = slices.SETUID_FILES
    judge_fields = ("path", "uid", "setuid", "setgid")

    def __init__(self, judge_hints: str = "", fs: "FilesystemLayout" = None):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs

    def collect(self):
        for base in self._fs.privileged_bin_dirs():
            if not base.is_dir():
                continue
            try:
                paths = list(base.rglob("*"))
            except (PermissionError, OSError):
                continue
            for path in paths:
                try:
                    if not path.is_file():
                        continue
                    st = path.lstat()
                except (PermissionError, OSError):
                    continue
                mode = st.st_mode
                setuid = bool(mode & 0o4000)
                setgid = bool(mode & 0o2000)
                if not (setuid or setgid):
                    continue
                yield {
                    "path": str(path),
                    "mode": mode,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "sha256": Digest.sha256_file(path),
                    "setuid": int(setuid),
                    "setgid": int(setgid),
                    "raw_json": json.dumps(
                        {
                            "path": str(path),
                            "mode": oct(mode),
                            "setuid": setuid,
                            "setgid": setgid,
                        }
                    ),
                }
