"""Linux host: capability adapters + collector set.

This host owns the ``HOST_PREFIX`` container-path translation (via
``host_path``); the macOS/Windows hosts never see it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Iterable

from .. import constants
from ..collectors import (
    BrowserExtensionsCollector,
    DnsQueriesCollector,
    FileIntegrityCollector,
    FileScanCollector,
    LinuxAuthEventsCollector,
    LinuxBluetoothCollector,
    LinuxInstalledAppsCollector,
    LinuxLaunchItemsCollector,
    LinuxProcessExecCollector,
    LinuxSystemIntegrityCollector,
    LinuxUsbDevicesCollector,
    LinuxWifiCollector,
    HostJournal,
    LogTailCollector,
    NetworkFlowsCollector,
    ProcessConnectionResolver,
    SetuidFilesCollector,
    SnapshotCollector,
    StreamingCollector,
    TcpdumpCapture,
    YaraRulesetCompiler,
)
from ..constants import BROWSER_PROFILES_LINUX, WATCHED_FILES_LINUX
from ..enums import Browser, PrivilegeKind
from ..exposure_collectors import (
    LinuxPromiscParser,
    LinuxProxyEnvParser,
    LinuxTrustListParser,
    LoginSessionsCollector,
    NetworkSharesCollector,
    ProcMountsSharesParser,
    PromiscuousInterfacesCollector,
    ProxyConfigCollector,
    TrustedRootsCollector,
    WhoParser,
)
from ..net_collectors import (
    ArpTableCollector,
    DnsResolversCollector,
    IpNeighParser,
    IpRouteParser,
    NdpNeighborsCollector,
    ResolvConfParser,
    RoutesCollector,
)
from ..persistence_collectors import (
    InjectionEnvCollector,
    KernelModulesCollector,
    LdSoPreloadParser,
    ProcModulesParser,
)
from ..prompts import Prompts
from ..runtime import (
    CommandRunner,
    CommandSnapshot,
    FileSnapshot,
    HostIo,
    HostPaths,
    PsutilConnections,
)
from .portable import AccountCollectors, PortableCollectors

# name:password:gid:members
GROUP_FIELDS = 4
# name:password:uid:gid:gecos:home:shell
PASSWD_FIELDS = 7


class LinuxFilesystemLayout:
    """Linux filesystem facts. Absolute paths pass through ``host_path``
    so a container monitor reads the host's bind-mounted tree."""

    _BIN_DIRS = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
        "/opt",
    )

    def __init__(self, paths: HostPaths) -> None:
        self._paths = paths

    def privileged_bin_dirs(self) -> list[Path]:
        return [self._paths.translate(directory) for directory in self._BIN_DIRS]

    def app_executables(self) -> list[Path]:
        # No macOS-style app bundles on Linux; /opt is already covered by
        # privileged_bin_dirs, so there's nothing extra to enumerate here.
        return []

    def home_dirs(self) -> list[Path]:
        root = self._paths.translate("/root")
        roots = [root] if root.is_dir() else []
        return self._user_homes(self._paths.translate("/home")) + roots

    def hosts_file(self) -> Path:
        return self._paths.translate("/etc/hosts")

    def sudoers_file(self) -> Path:
        return self._paths.translate("/etc/sudoers")

    def sudoers_dir(self) -> Path:
        return self._paths.translate("/etc/sudoers.d")

    def tcpdump_interface_args(self) -> list[str]:
        # '-i any' prefixes each line with the interface + direction.
        return ["-i", "any"]

    def _user_homes(self, base: Path) -> list[Path]:
        try:
            if not base.is_dir():
                return []
            return [entry for entry in base.iterdir() if entry.is_dir()]
        except OSError:
            return []


class LinuxPrivilegedAccounts:
    """Linux privileged-account state parsed from ``/etc/group`` and
    ``/etc/passwd`` (via ``host_path`` for container mode)."""

    PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin"})

    def __init__(self, paths: HostPaths) -> None:
        self._paths = paths

    def privileged_group_members(self) -> Iterable[dict[str, Any]]:
        path = self._paths.translate("/etc/group")
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from self.group_rows(content, str(path))

    def uid0_accounts(self) -> Iterable[dict[str, Any]]:
        path = self._paths.translate("/etc/passwd")
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from self.uid0_rows(content, str(path))

    def group_rows(self, content: str, path: str) -> list[dict[str, Any]]:
        """Members of privileged groups, from ``/etc/group`` text."""
        records = self._records(content, GROUP_FIELDS)
        return [
            {
                "kind": PrivilegeKind.GROUP.value,
                "subject": name,
                "detail": members,
                "source_path": path,
            }
            for name, _password, _gid, members in records
            if name in self.PRIVILEGED_GROUPS and members
        ]

    def uid0_rows(self, content: str, path: str) -> list[dict[str, Any]]:
        """Accounts with uid 0, from ``/etc/passwd`` text."""
        records = self._records(content, PASSWD_FIELDS)
        return [
            {
                "kind": PrivilegeKind.ACCOUNT.value,
                "subject": user,
                "detail": f"uid=0 shell={shell}",
                "source_path": path,
            }
            for user, _password, uid, _gid, _gecos, _home, shell in records
            if uid == "0"
        ]

    def _records(self, content: str, width: int) -> list[list[str]]:
        rows = (line.strip().split(":") for line in content.splitlines())
        return [fields[:width] for fields in rows if len(fields) >= width]


class LinuxHost:
    """Composition root for Linux. Drops macOS-only slices (quarantine
    events) by simply not assembling them."""

    def __init__(self, io: HostIo, logger: logging.Logger) -> None:
        self._io = io
        self._logger = logger

    @classmethod
    def create(cls, logger: logging.Logger) -> LinuxHost:
        return cls(HostIo(CommandRunner(), HostPaths.from_environ(os.environ)), logger)

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        fs = LinuxFilesystemLayout(self._io.paths)
        accounts = LinuxPrivilegedAccounts(self._io.paths)
        return [
            *PortableCollectors(self._logger, self._io.paths).build(prompts),
            *AccountCollectors(fs, accounts).build(prompts),
            *self._capture(prompts, fs),
            *self._devices(prompts),
            *self._software(prompts),
            *self._files(prompts, fs),
            *self._neighborhood(prompts),
            *self._exposure(prompts),
            *self._persistence(prompts),
        ]

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        hint = prompts.hint_for
        journal = HostJournal(self._io.paths)
        return [
            LinuxAuthEventsCollector(journal, hint("auth_events")),
            LinuxProcessExecCollector(journal, hint("process_exec_events")),
        ]

    def _capture(
        self, prompts: Prompts, fs: LinuxFilesystemLayout
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        capture = TcpdumpCapture(self._io.runner, tuple(fs.tcpdump_interface_args()))
        resolver = ProcessConnectionResolver(PsutilConnections())
        return [
            NetworkFlowsCollector(capture, resolver, hint("network_flows")),
            DnsQueriesCollector(capture, resolver, hint("dns_queries")),
        ]

    def _devices(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            LogTailCollector.create(hint("log_entries"), self._io, self._logger),
            LinuxUsbDevicesCollector(self._io.paths, hint("usb_devices")),
            LinuxBluetoothCollector(self._io.paths, hint("bluetooth_devices")),
            LinuxWifiCollector(self._io, hint("wifi_state")),
            LinuxSystemIntegrityCollector.create(self._io, hint("system_integrity")),
        ]

    def _software(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            LinuxLaunchItemsCollector.create(self._io.paths, hint("launch_items")),
            BrowserExtensionsCollector.create(
                self._browser_profiles(), hint("browser_extensions")
            ),
            LinuxInstalledAppsCollector.create(self._io, hint("installed_apps")),
        ]

    def _files(
        self, prompts: Prompts, fs: LinuxFilesystemLayout
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        compiler = YaraRulesetCompiler(constants.YARA_RULES_DIR, self._logger)
        return [
            FileIntegrityCollector(
                self._io.paths, self._watched_files(), hint("file_integrity")
            ),
            FileScanCollector.create(fs, compiler, hint("file_scan")),
            SetuidFilesCollector(fs, hint("setuid_files")),
        ]

    def _neighborhood(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        runner = self._io.runner
        arp = CommandSnapshot(runner, ["ip", "neigh"], IpNeighParser("flags"))
        ndp = CommandSnapshot(runner, ["ip", "-6", "neigh"], IpNeighParser("state"))
        routes = CommandSnapshot(runner, ["ip", "route"], IpRouteParser())
        resolv_conf = self._io.paths.translate("/etc/resolv.conf")
        resolvers = FileSnapshot(resolv_conf, ResolvConfParser())
        return [
            ArpTableCollector(arp, hint("arp_table")),
            NdpNeighborsCollector(ndp, hint("ndp_neighbors")),
            RoutesCollector(routes, hint("routes")),
            DnsResolversCollector(resolvers, hint("dns_resolvers")),
        ]

    def _exposure(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        paths, runner = self._io.paths, self._io.runner
        environment = paths.translate("/etc/environment")
        proxy = FileSnapshot(environment, LinuxProxyEnvParser())
        sessions = CommandSnapshot(runner, ["who"], WhoParser())
        shares = FileSnapshot(paths.translate("/proc/mounts"), ProcMountsSharesParser())
        promisc = CommandSnapshot(runner, ["ip", "link"], LinuxPromiscParser())
        roots = CommandSnapshot(runner, ["trust", "list"], LinuxTrustListParser())
        return [
            ProxyConfigCollector(proxy, hint("proxy_config")),
            LoginSessionsCollector(sessions, hint("login_sessions")),
            NetworkSharesCollector(shares, hint("network_shares")),
            PromiscuousInterfacesCollector(promisc, hint("promiscuous_ifaces")),
            TrustedRootsCollector(roots, hint("trusted_roots")),
        ]

    def _persistence(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        preload = self._io.paths.translate("/etc/ld.so.preload")
        modules = self._io.paths.translate("/proc/modules")
        return [
            InjectionEnvCollector(
                FileSnapshot(preload, LdSoPreloadParser()), hint("injection_env")
            ),
            KernelModulesCollector(
                FileSnapshot(modules, ProcModulesParser()), hint("kernel_modules")
            ),
        ]

    def _watched_files(self) -> list[str]:
        # ~/-prefixed templates expand to one path per user home (under the
        # container's bind-mounted /host/home when set); absolute /etc paths
        # become /host/etc paths automatically.
        paths = self._io.paths
        return [
            str(path) for tmpl in WATCHED_FILES_LINUX for path in paths.for_home(tmpl)
        ]

    def _browser_profiles(self) -> dict[Browser, list[str]]:
        paths = self._io.paths
        return {
            browser: [str(path) for tmpl in templates for path in paths.for_home(tmpl)]
            for browser, templates in BROWSER_PROFILES_LINUX
        }
