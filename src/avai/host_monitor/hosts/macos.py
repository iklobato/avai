"""macOS host: capability adapters + collector set."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..collectors import (
    AuthEventsCollector,
    BluetoothCollector,
    BrowserExtensionsCollector,
    DnsQueriesCollector,
    FileIntegrityCollector,
    HostsFileCollector,
    InstalledAppsCollector,
    KernelExtensionsCollector,
    LaunchItemsCollector,
    ListeningPortsCollector,
    MacosProcessExecCollector,
    MdmProfilesCollector,
    MountsCollector,
    NetworkConnectionsCollector,
    NetworkFlowsCollector,
    NetworkInterfacesCollector,
    PrivilegeConfigCollector,
    ProcessCollector,
    QuarantineCollector,
    SetuidFilesCollector,
    SnapshotCollector,
    SshAuthorizedKeysCollector,
    StreamingCollector,
    SystemExtensionsCollector,
    SystemIntegrityCollector,
    UsbDevicesCollector,
    WifiCollector,
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
from ..prompts import Prompts
from ..runtime import CommandRunner, CommandSnapshot


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
        return [Path(d) for d in self._BIN_DIRS]

    def home_dirs(self) -> list[Path]:
        homes: list[Path] = []
        users = Path("/Users")
        if users.is_dir():
            try:
                homes += [
                    d
                    for d in users.iterdir()
                    if d.is_dir() and not d.name.startswith(".")
                ]
            except OSError:
                pass
        root = Path("/var/root")
        if root.is_dir():
            homes.append(root)
        return homes

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
                    "kind": "group",
                    "subject": gname,
                    "detail": members,
                    "source_path": "dscl:/Groups",
                }

    def uid0_accounts(self) -> Iterable[dict]:
        out = self._runner.text(["dscl", ".", "-list", "/Users", "UniqueID"])
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 2 and cols[-1] == "0":
                yield {
                    "kind": "account",
                    "subject": cols[0],
                    "detail": "uid=0",
                    "source_path": "dscl:/Users",
                }


class MacOSHost:
    """Composition root for macOS: wires capability adapters into the
    OS-agnostic collectors and assembles the macOS collector set."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or CommandRunner()
        self._fs = MacOSFilesystemLayout()
        self._accounts = MacOSPrivilegedAccounts(self._runner)

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        h = prompts.hint_for
        iface = self._fs.tcpdump_interface_args()
        return [
            ProcessCollector(judge_hints=h("processes")),
            NetworkConnectionsCollector(judge_hints=h("network_connections")),
            ListeningPortsCollector(judge_hints=h("listening_ports")),
            NetworkFlowsCollector(judge_hints=h("network_flows"), iface_args=iface),
            DnsQueriesCollector(judge_hints=h("dns_queries"), iface_args=iface),
            NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
            UsbDevicesCollector(judge_hints=h("usb_devices")),
            BluetoothCollector(judge_hints=h("bluetooth_devices")),
            WifiCollector(judge_hints=h("wifi_state")),
            LaunchItemsCollector(judge_hints=h("launch_items")),
            QuarantineCollector(judge_hints=h("quarantine_events")),
            BrowserExtensionsCollector(judge_hints=h("browser_extensions")),
            SystemIntegrityCollector(judge_hints=h("system_integrity")),
            FileIntegrityCollector(judge_hints=h("file_integrity")),
            InstalledAppsCollector(judge_hints=h("installed_apps")),
            MountsCollector(judge_hints=h("mounts")),
            SetuidFilesCollector(judge_hints=h("setuid_files"), fs=self._fs),
            MdmProfilesCollector(judge_hints=h("mdm_profiles")),
            KernelExtensionsCollector(judge_hints=h("kernel_extensions")),
            SystemExtensionsCollector(judge_hints=h("system_extensions")),
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
                CommandSnapshot(self._runner, ["arp", "-an"], MacosArpParser()),
                judge_hints=h("arp_table"),
            ),
            NdpNeighborsCollector(
                CommandSnapshot(self._runner, ["ndp", "-an"], MacosNdpParser()),
                judge_hints=h("ndp_neighbors"),
            ),
            RoutesCollector(
                CommandSnapshot(self._runner, ["netstat", "-rn"], MacosRouteParser()),
                judge_hints=h("routes"),
            ),
            DnsResolversCollector(
                CommandSnapshot(self._runner, ["scutil", "--dns"], MacosDnsParser()),
                judge_hints=h("dns_resolvers"),
            ),
        ]

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        h = prompts.hint_for
        return [
            AuthEventsCollector(judge_hints=h("auth_events")),
            MacosProcessExecCollector(judge_hints=h("process_exec_events")),
        ]
