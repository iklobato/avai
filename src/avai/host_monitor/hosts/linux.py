"""Linux host: capability adapters + collector set.

This host owns the ``HOST_PREFIX`` container-path translation (via
``host_path``); the macOS/Windows hosts never see it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..collectors import (
    BrowserExtensionsCollector,
    DnsQueriesCollector,
    FileIntegrityCollector,
    HostsFileCollector,
    LinuxAuthEventsCollector,
    LinuxBluetoothCollector,
    LinuxInstalledAppsCollector,
    LinuxLaunchItemsCollector,
    LinuxProcessExecCollector,
    LinuxSystemIntegrityCollector,
    LinuxUsbDevicesCollector,
    LinuxWifiCollector,
    ListeningPortsCollector,
    MountsCollector,
    NetworkConnectionsCollector,
    NetworkFlowsCollector,
    NetworkInterfacesCollector,
    PrivilegeConfigCollector,
    ProcessCollector,
    SetuidFilesCollector,
    SnapshotCollector,
    SshAuthorizedKeysCollector,
    StreamingCollector,
)
from ..constants import BROWSER_PROFILES_LINUX, WATCHED_FILES_LINUX
from ..enums import Browser
from ..net_collectors import (
    ArpTableCollector,
    DnsResolversCollector,
    IpNeighParser,
    IpRouteParser,
    NdpNeighborsCollector,
    ResolvConfParser,
    RoutesCollector,
)
from ..prompts import Prompts
from ..runtime import CommandRunner, CommandSnapshot, FileSnapshot, HostPaths


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

    def privileged_bin_dirs(self) -> list[Path]:
        return [HostPaths.translate(d) for d in self._BIN_DIRS]

    def home_dirs(self) -> list[Path]:
        homes: list[Path] = []
        base = HostPaths.translate("/home")
        if base.is_dir():
            try:
                homes += [d for d in base.iterdir() if d.is_dir()]
            except OSError:
                pass
        root = HostPaths.translate("/root")
        if root.is_dir():
            homes.append(root)
        return homes

    def hosts_file(self) -> Path:
        return HostPaths.translate("/etc/hosts")

    def sudoers_file(self) -> Path:
        return HostPaths.translate("/etc/sudoers")

    def sudoers_dir(self) -> Path:
        return HostPaths.translate("/etc/sudoers.d")

    def tcpdump_interface_args(self) -> list[str]:
        # '-i any' prefixes each line with the interface + direction.
        return ["-i", "any"]


class LinuxPrivilegedAccounts:
    """Linux privileged-account state parsed from ``/etc/group`` and
    ``/etc/passwd`` (via ``host_path`` for container mode)."""

    _PRIV_GROUPS = frozenset({"sudo", "wheel", "admin"})

    def privileged_group_members(self) -> Iterable[dict]:
        path = HostPaths.translate("/etc/group")
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from self._parse_groups(content, str(path), self._PRIV_GROUPS)

    def uid0_accounts(self) -> Iterable[dict]:
        path = HostPaths.translate("/etc/passwd")
        try:
            content = path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return
        yield from self._parse_passwd_uid0(content, str(path))

    @staticmethod
    def _parse_groups(content: str, path: str, priv_groups) -> list[dict]:
        """Pure parser for /etc/group: members of privileged groups."""
        rows = []
        for line in content.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue
            gname, members = parts[0], parts[3]
            if gname in priv_groups and members:
                rows.append(
                    {
                        "kind": "group",
                        "subject": gname,
                        "detail": members,
                        "source_path": path,
                    }
                )
        return rows

    @staticmethod
    def _parse_passwd_uid0(content: str, path: str) -> list[dict]:
        """Pure parser for /etc/passwd: accounts with uid 0."""
        rows = []
        for line in content.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            user, uid, shell = parts[0], parts[2], parts[6]
            if uid == "0":
                rows.append(
                    {
                        "kind": "account",
                        "subject": user,
                        "detail": f"uid=0 shell={shell}",
                        "source_path": path,
                    }
                )
        return rows


class LinuxHost:
    """Composition root for Linux. Drops macOS-only slices (quarantine
    events) by simply not assembling them."""

    def __init__(self) -> None:
        self._runner = CommandRunner()
        self._fs = LinuxFilesystemLayout()
        self._accounts = LinuxPrivilegedAccounts()

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        h = prompts.hint_for
        iface = self._fs.tcpdump_interface_args()

        # Expand ~/-prefixed watched-file templates to one path per user
        # home (under the container's bind-mounted /host/home when set);
        # absolute /etc paths become /host/etc paths automatically.
        watched: list[str] = []
        for tmpl in WATCHED_FILES_LINUX:
            for p in HostPaths.for_home(tmpl):
                watched.append(str(p))

        expanded_browser_profiles: dict[Browser, list[str]] = {}
        for browser, templates in BROWSER_PROFILES_LINUX.items():
            out: list[str] = []
            for tmpl in templates:
                for p in HostPaths.for_home(tmpl):
                    out.append(str(p))
            expanded_browser_profiles[browser] = out

        return [
            ProcessCollector(judge_hints=h("processes")),
            NetworkConnectionsCollector(judge_hints=h("network_connections")),
            ListeningPortsCollector(judge_hints=h("listening_ports")),
            NetworkFlowsCollector(judge_hints=h("network_flows"), iface_args=iface),
            DnsQueriesCollector(judge_hints=h("dns_queries"), iface_args=iface),
            NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
            LinuxUsbDevicesCollector(judge_hints=h("usb_devices")),
            LinuxBluetoothCollector(judge_hints=h("bluetooth_devices")),
            LinuxWifiCollector(judge_hints=h("wifi_state")),
            LinuxLaunchItemsCollector(judge_hints=h("launch_items")),
            BrowserExtensionsCollector(
                judge_hints=h("browser_extensions"),
                profiles=expanded_browser_profiles,
            ),
            LinuxSystemIntegrityCollector(judge_hints=h("system_integrity")),
            FileIntegrityCollector(judge_hints=h("file_integrity"), watched=watched),
            LinuxInstalledAppsCollector(judge_hints=h("installed_apps")),
            MountsCollector(judge_hints=h("mounts")),
            SetuidFilesCollector(judge_hints=h("setuid_files"), fs=self._fs),
            SshAuthorizedKeysCollector(
                judge_hints=h("ssh_authorized_keys"), fs=self._fs
            ),
            HostsFileCollector(judge_hints=h("hosts_file"), fs=self._fs),
            PrivilegeConfigCollector(
                judge_hints=h("privilege_config"),
                fs=self._fs,
                accounts=self._accounts,
            ),
            # Network neighborhood & topology
            ArpTableCollector(
                CommandSnapshot(self._runner, ["ip", "neigh"], IpNeighParser("flags")),
                judge_hints=h("arp_table"),
            ),
            NdpNeighborsCollector(
                CommandSnapshot(
                    self._runner, ["ip", "-6", "neigh"], IpNeighParser("state")
                ),
                judge_hints=h("ndp_neighbors"),
            ),
            RoutesCollector(
                CommandSnapshot(self._runner, ["ip", "route"], IpRouteParser()),
                judge_hints=h("routes"),
            ),
            DnsResolversCollector(
                FileSnapshot(
                    HostPaths.translate("/etc/resolv.conf"), ResolvConfParser()
                ),
                judge_hints=h("dns_resolvers"),
            ),
        ]

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        h = prompts.hint_for
        return [
            LinuxAuthEventsCollector(judge_hints=h("auth_events")),
            LinuxProcessExecCollector(judge_hints=h("process_exec_events")),
        ]
