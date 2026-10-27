"""Windows host: capability adapters and the collector set.

The Windows-native collectors and their parsers live in
:mod:`.windows_collectors`. Composed OUT on Windows (no analog):
setuid_files, quarantine_events, mdm_profiles, kernel/system extensions,
promiscuous_ifaces. They are simply not assembled, never a runtime branch.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Iterable

from ..collectors import SnapshotCollector, StreamingCollector
from ..exposure_collectors import (
    LoginSessionsCollector,
    NetworkSharesCollector,
    ProxyConfigCollector,
    TrustedRootsCollector,
    WindowsCertParser,
    WindowsProxyParser,
    WindowsSessionParser,
    WindowsSharesParser,
)
from ..net_collectors import (
    ArpTableCollector,
    DnsResolversCollector,
    NdpNeighborsCollector,
    PsDnsParser,
    PsNeighborParser,
    PsRouteParser,
    RoutesCollector,
)
from ..persistence_collectors import (
    InjectionEnvCollector,
    KernelModulesCollector,
    WindowsAppInitParser,
    WindowsDriverParser,
)
from ..enums import PrivilegeKind
from ..prompts import Prompts
from ..runtime import CommandRunner, CommandSnapshot, HostIo, HostPaths
from .portable import AccountCollectors, PortableCollectors
from .windows_collectors import (
    LocalGroupParser,
    PowerShell,
    WindowsAuthEventsCollector,
    WindowsBluetoothCollector,
    WindowsInstalledAppsCollector,
    WindowsLaunchItemsCollector,
    WindowsProcessExecCollector,
    WindowsSystemIntegrityCollector,
    WindowsUsbDevicesCollector,
    WindowsWifiCollector,
)

# A path guaranteed not to exist, handed to collectors that read a file
# Windows doesn't have (e.g. sudoers) so their shared parser yields nothing
# without needing a platform branch.
NONEXISTENT_PATH = Path("C:/Windows/Temp/__avai_no_such_file__")


class WindowsFilesystemLayout:
    """Windows filesystem facts."""

    SHARED_PROFILES = frozenset({"Public", "Default", "All Users"})

    def home_dirs(self) -> list[Path]:
        users = Path("C:/Users")
        try:
            if not users.is_dir():
                return []
            return [
                entry
                for entry in users.iterdir()
                if entry.is_dir() and entry.name not in self.SHARED_PROFILES
            ]
        except OSError:
            return []

    def hosts_file(self) -> Path:
        return Path(r"C:\Windows\System32\drivers\etc\hosts")

    def sudoers_file(self) -> Path:
        return NONEXISTENT_PATH

    def sudoers_dir(self) -> Path:
        return NONEXISTENT_PATH


class WindowsPrivilegedAccounts:
    """Local Administrators membership via ``net localgroup``. Windows has
    no uid-0 / sudoers concept, so those gathers are empty."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def privileged_group_members(self) -> Iterable[dict[str, Any]]:
        output = self._runner.text(["net", "localgroup", "Administrators"])
        members = LocalGroupParser().members(output)
        if members:
            yield {
                "kind": PrivilegeKind.GROUP.value,
                "subject": "Administrators",
                "detail": ", ".join(members),
                "source_path": "net:localgroup",
            }

    def uid0_accounts(self) -> Iterable[dict[str, Any]]:
        return iter(())


class WindowsHost:
    """Composition root for Windows.

    Wires the cross-platform psutil collectors, the path-based collectors
    that work unchanged with Windows paths (hosts_file, ssh_authorized_keys
    via OpenSSH's ``C:\\Users\\*\\.ssh``), the local Administrators view,
    and the Windows-native collectors.
    """

    NEIGHBORS_SCRIPT = (
        "Get-NetNeighbor -AddressFamily {family} | "
        "Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | "
        "ConvertTo-Json -Compress"
    )
    ROUTES_SCRIPT = (
        "Get-NetRoute | Select-Object "
        "DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | "
        "ConvertTo-Json -Compress"
    )
    DNS_SCRIPT = (
        "Get-DnsClientServerAddress | "
        "Select-Object InterfaceAlias,ServerAddresses | "
        "ConvertTo-Json -Compress"
    )
    PROXY_SCRIPT = (
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\"
        "CurrentVersion\\Internet Settings' | Select-Object "
        "ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress"
    )
    SHARES_SCRIPT = (
        "Get-SmbConnection | Select-Object ServerName,ShareName,Dialect | "
        "ConvertTo-Json -Compress"
    )
    ROOTS_SCRIPT = (
        "Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object "
        "Subject,Thumbprint | ConvertTo-Json -Compress"
    )
    APPINIT_SCRIPT = (
        "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\"
        "Windows NT\\CurrentVersion\\Windows' | Select-Object "
        "AppInit_DLLs,LoadAppInit_DLLs | ConvertTo-Json -Compress"
    )

    def __init__(self, io: HostIo, logger: logging.Logger) -> None:
        self._io = io
        self._logger = logger

    @classmethod
    def create(cls, logger: logging.Logger) -> WindowsHost:
        return cls(HostIo(CommandRunner(), HostPaths.from_environ(os.environ)), logger)

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        accounts = WindowsPrivilegedAccounts(self._io.runner)
        shell = PowerShell(self._io.runner)
        return [
            *PortableCollectors(self._logger, self._io.paths).build(prompts),
            *AccountCollectors(WindowsFilesystemLayout(), accounts).build(prompts),
            *self._native(prompts, shell),
            *self._neighborhood(prompts, shell),
            *self._exposure(prompts, shell),
            *self._persistence(prompts, shell),
        ]

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        hint = prompts.hint_for
        return [
            WindowsAuthEventsCollector(hint("auth_events")),
            WindowsProcessExecCollector(hint("process_exec_events")),
        ]

    def _native(self, prompts: Prompts, shell: PowerShell) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            WindowsInstalledAppsCollector(shell, hint("installed_apps")),
            WindowsLaunchItemsCollector(self._io.runner, shell, hint("launch_items")),
            WindowsSystemIntegrityCollector(shell, hint("system_integrity")),
            WindowsUsbDevicesCollector(shell, hint("usb_devices")),
            WindowsBluetoothCollector(shell, hint("bluetooth_devices")),
            WindowsWifiCollector(self._io.runner, hint("wifi_state")),
        ]

    def _neighborhood(
        self, prompts: Prompts, shell: PowerShell
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        ipv4 = self.NEIGHBORS_SCRIPT.format(family="IPv4")
        ipv6 = self.NEIGHBORS_SCRIPT.format(family="IPv6")
        return [
            ArpTableCollector(
                shell.snapshot(ipv4, PsNeighborParser("flags")), hint("arp_table")
            ),
            NdpNeighborsCollector(
                shell.snapshot(ipv6, PsNeighborParser("state")), hint("ndp_neighbors")
            ),
            RoutesCollector(
                shell.snapshot(self.ROUTES_SCRIPT, PsRouteParser()), hint("routes")
            ),
            DnsResolversCollector(
                shell.snapshot(self.DNS_SCRIPT, PsDnsParser()), hint("dns_resolvers")
            ),
        ]

    def _exposure(self, prompts: Prompts, shell: PowerShell) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        sessions = CommandSnapshot(
            self._io.runner, ["query", "user"], WindowsSessionParser()
        )
        return [
            ProxyConfigCollector(
                shell.snapshot(self.PROXY_SCRIPT, WindowsProxyParser()),
                hint("proxy_config"),
            ),
            LoginSessionsCollector(sessions, hint("login_sessions")),
            NetworkSharesCollector(
                shell.snapshot(self.SHARES_SCRIPT, WindowsSharesParser()),
                hint("network_shares"),
            ),
            TrustedRootsCollector(
                shell.snapshot(self.ROOTS_SCRIPT, WindowsCertParser()),
                hint("trusted_roots"),
            ),
        ]

    def _persistence(
        self, prompts: Prompts, shell: PowerShell
    ) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        drivers = CommandSnapshot(
            self._io.runner, ["driverquery", "/fo", "csv"], WindowsDriverParser()
        )
        return [
            InjectionEnvCollector(
                shell.snapshot(self.APPINIT_SCRIPT, WindowsAppInitParser()),
                hint("injection_env"),
            ),
            KernelModulesCollector(drivers, hint("kernel_modules")),
        ]
