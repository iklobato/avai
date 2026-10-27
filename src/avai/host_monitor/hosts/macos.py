"""macOS host: capability adapters + collector set."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable

from ..collectors import (
    AuthEventsCollector,
    BluetoothCollector,
    BrowserExtensionsCollector,
    DnsQueriesCollector,
    FileIntegrityCollector,
    FileScanCollector,
    InstalledAppsCollector,
    KernelExtensionsCollector,
    LaunchItemsCollector,
    MacosProcessExecCollector,
    MdmProfilesCollector,
    NetworkFlowsCollector,
    ProcessConnectionResolver,
    QuarantineCollector,
    SetuidFilesCollector,
    SnapshotCollector,
    StreamingCollector,
    SystemExtensionsCollector,
    SystemIntegrityCollector,
    TcpdumpCapture,
    UsbDevicesCollector,
    WifiCollector,
    YaraRulesDir,
    YaraRulesetCompiler,
)
from ..constants import BROWSER_PROFILES
from ..enums import PrivilegeKind
from ..exposure_collectors import (
    LoginSessionsCollector,
    MacosCertParser,
    MacosMountSharesParser,
    MacosPromiscParser,
    MacosProxyParser,
    NetworkSharesCollector,
    PromiscuousInterfacesCollector,
    ProxyConfigCollector,
    TrustedRootsCollector,
    WhoParser,
)
from ..net_collectors import (
    ArpTableCollector,
    DnsResolversCollector,
    MacosArpParser,
    MacosDnsParser,
    MacosNdpParser,
    MacosRouteParser,
    NdpNeighborsCollector,
    RoutesCollector,
)
from ..persistence_collectors import EnvValueParser, InjectionEnvCollector
from ..prompts import Prompts
from ..runtime import (
    Clock,
    CommandRunner,
    CommandSnapshot,
    HostIo,
    HostPaths,
    PsutilConnections,
)
from .portable import AccountCollectors, PortableCollectors


class MacOSFilesystemLayout:
    """macOS filesystem facts (native paths — no container translation)."""

    _BIN_DIRS = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
    )

    def privileged_bin_dirs(self) -> list[Path]:
        return [Path(directory) for directory in self._BIN_DIRS]

    def app_executables(self) -> list[Path]:
        # The bundle's main binary lives at <App>.app/Contents/MacOS/*.
        # Globbing per-bundle bounds this to the app count (~hundreds),
        # not the ~150k resource files a full /Applications walk would hit.
        app_roots = [Path("/Applications")] + [
            home / "Applications" for home in self.home_dirs()
        ]
        return [path for root in app_roots for path in self._bundle_binaries(root)]

    def home_dirs(self) -> list[Path]:
        root = Path("/var/root")
        roots = [root] if root.is_dir() else []
        return self._user_homes(Path("/Users")) + roots

    def hosts_file(self) -> Path:
        return Path("/etc/hosts")

    def sudoers_file(self) -> Path:
        return Path("/etc/sudoers")

    def sudoers_dir(self) -> Path:
        return Path("/etc/sudoers.d")

    def tcpdump_interface_args(self) -> list[str]:
        # macOS auto-selects the 'pktap' aggregating pseudo-device; '-k I'
        # prints the real per-packet interface as the leading token.
        return ["-k", "I"]

    def _bundle_binaries(self, root: Path) -> list[Path]:
        # is_dir() re-raises EACCES (e.g. /var/root/Applications when not
        # root), so it must sit inside the guard, not before it.
        try:
            if not root.is_dir():
                return []
            return [
                path for path in root.glob("*.app/Contents/MacOS/*") if path.is_file()
            ]
        except OSError:
            return []

    def _user_homes(self, users: Path) -> list[Path]:
        try:
            if not users.is_dir():
                return []
            return [
                entry
                for entry in users.iterdir()
                if entry.is_dir() and not entry.name.startswith(".")
            ]
        except OSError:
            return []


class MacOSPrivilegedAccounts:
    """macOS privileged-account state via the directory service (``dscl``)."""

    _PRIV_GROUPS = ("admin", "wheel")

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def privileged_group_members(self) -> Iterable[dict]:
        for gname in self._PRIV_GROUPS:
            out = self._runner.text(
                ["dscl", ".", "-read", f"/Groups/{gname}", "GroupMembership"]
            )
            members = out.split(":", 1)[1].strip() if ":" in out else out.strip()
            if members:
                yield {
                    "kind": PrivilegeKind.GROUP.value,
                    "subject": gname,
                    "detail": members,
                    "source_path": "dscl:/Groups",
                }

    def uid0_accounts(self) -> Iterable[dict]:
        out = self._runner.text(["dscl", ".", "-list", "/Users", "UniqueID"])
        for line in out.splitlines():
            cols = line.split()
            if len(cols) > 1 and cols[-1] == "0":
                yield {
                    "kind": PrivilegeKind.ACCOUNT.value,
                    "subject": cols[0],
                    "detail": "uid=0",
                    "source_path": "dscl:/Users",
                }


class MacOSHost:
    """Composition root for macOS: wires capability adapters into the
    OS-agnostic collectors and assembles the macOS collector set."""

    SYSTEM_CERTS = (
        "security",
        "find-certificate",
        "-a",
        "-Z",
        "/Library/Keychains/System.keychain",
    )

    def __init__(self, io: HostIo, logger: logging.Logger) -> None:
        self._io = io
        self._logger = logger

    @classmethod
    def create(cls, logger: logging.Logger) -> MacOSHost:
        return cls(HostIo(CommandRunner(), HostPaths.from_environ(os.environ)), logger)

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        fs = MacOSFilesystemLayout()
        accounts = MacOSPrivilegedAccounts(self._io.runner)
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
        return [
            AuthEventsCollector(hint("auth_events")),
            MacosProcessExecCollector(hint("process_exec_events")),
        ]

    def _capture(
        self, prompts: Prompts, fs: MacOSFilesystemLayout
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        iface_args = tuple(fs.tcpdump_interface_args())
        capture = TcpdumpCapture(self._io.runner, iface_args, Clock())
        resolver = ProcessConnectionResolver(PsutilConnections())
        return [
            NetworkFlowsCollector(capture, resolver, hint("network_flows")),
            DnsQueriesCollector(capture, resolver, hint("dns_queries")),
        ]

    def _devices(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            UsbDevicesCollector(self._io.runner, hint("usb_devices")),
            BluetoothCollector(self._io.runner, hint("bluetooth_devices")),
            WifiCollector(self._io.runner, hint("wifi_state")),
            SystemIntegrityCollector.create(self._io, hint("system_integrity")),
            MdmProfilesCollector(self._io.runner, hint("mdm_profiles")),
            KernelExtensionsCollector(self._io.runner, hint("kernel_extensions")),
            SystemExtensionsCollector(self._io.paths, hint("system_extensions")),
        ]

    def _software(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            LaunchItemsCollector(self._io.paths, hint("launch_items")),
            QuarantineCollector(hint("quarantine_events")),
            BrowserExtensionsCollector.create(
                dict(BROWSER_PROFILES), hint("browser_extensions")
            ),
            InstalledAppsCollector(self._io.paths, hint("installed_apps")),
        ]

    def _files(
        self, prompts: Prompts, fs: MacOSFilesystemLayout
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        rules_dir = YaraRulesDir().from_environ(os.environ)
        compiler = YaraRulesetCompiler(rules_dir, self._logger)
        return [
            FileIntegrityCollector(self._io.paths, judge_hints=hint("file_integrity")),
            FileScanCollector.create(fs, compiler, hint("file_scan")),
            SetuidFilesCollector(fs, hint("setuid_files")),
        ]

    def _neighborhood(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        runner = self._io.runner
        arp = CommandSnapshot(runner, ["arp", "-an"], MacosArpParser())
        ndp = CommandSnapshot(runner, ["ndp", "-an"], MacosNdpParser())
        routes = CommandSnapshot(runner, ["netstat", "-rn"], MacosRouteParser())
        resolvers = CommandSnapshot(runner, ["scutil", "--dns"], MacosDnsParser())
        return [
            ArpTableCollector(arp, hint("arp_table")),
            NdpNeighborsCollector(ndp, hint("ndp_neighbors")),
            RoutesCollector(routes, hint("routes")),
            DnsResolversCollector(resolvers, hint("dns_resolvers")),
        ]

    def _exposure(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        runner = self._io.runner
        proxy = CommandSnapshot(runner, ["scutil", "--proxy"], MacosProxyParser())
        sessions = CommandSnapshot(runner, ["who"], WhoParser())
        shares = CommandSnapshot(runner, ["mount"], MacosMountSharesParser())
        promisc = CommandSnapshot(runner, ["ifconfig"], MacosPromiscParser())
        roots = CommandSnapshot(runner, list(self.SYSTEM_CERTS), MacosCertParser())
        return [
            ProxyConfigCollector(proxy, hint("proxy_config")),
            LoginSessionsCollector(sessions, hint("login_sessions")),
            NetworkSharesCollector(shares, hint("network_shares")),
            PromiscuousInterfacesCollector(promisc, hint("promiscuous_ifaces")),
            TrustedRootsCollector(roots, hint("trusted_roots")),
        ]

    def _persistence(self, prompts: Prompts) -> list[SnapshotCollector]:
        # kernel_modules is composed out: the kernel_extensions collector
        # covers loaded kernel code on macOS.
        dyld = CommandSnapshot(
            self._io.runner,
            ["launchctl", "getenv", "DYLD_INSERT_LIBRARIES"],
            EnvValueParser("DYLD_INSERT_LIBRARIES", "launchd"),
        )
        return [InjectionEnvCollector(dyld, prompts.hint_for("injection_env"))]
