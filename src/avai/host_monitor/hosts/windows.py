"""Windows host: capability adapters, Windows-native collectors, and the
collector set.

VERIFICATION NOTE: this module is written against the documented output
of the Windows tools it shells out to (``powershell``/``ConvertTo-Json``,
``schtasks /fo CSV``, ``net localgroup``). It has NOT been executed on a
Windows host. The pure parsers below are unit-tested (test_windows.py)
against representative command output; the live *gather* — the actual
subprocess calls — is unvalidated and should be smoke-tested on a real
Windows machine before relying on it.

Design: gathering goes through the injected :class:`CommandRunner` seam
(no ``winreg``/``wmi`` Python modules, so this file imports cleanly on any
OS and adds no dependencies). Each collector is ``gather -> pure parse``,
mirroring the macOS/Linux adapters.

Composed OUT on Windows (no analog, or not yet implemented): setuid_files,
quarantine_events, mdm_profiles, kernel/system extensions, usb/bluetooth/
wifi devices, system_integrity. These are simply not assembled — never a
runtime branch.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Iterable

from ..collectors import (
    HostsFileCollector,
    ListeningPortsCollector,
    MountsCollector,
    NetworkConnectionsCollector,
    NetworkInterfacesCollector,
    PrivilegeConfigCollector,
    ProcessCollector,
    SnapshotCollector,
    SshAuthorizedKeysCollector,
    StreamingCollector,
)
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
from ..models import InstalledAppRow, LaunchItemRow
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
    SshKnownHostsCollector,
    WindowsAppInitParser,
    WindowsDriverParser,
)
from ..prompts import Prompts
from ..runtime import CommandRunner, CommandSnapshot

# A path guaranteed not to exist, handed to collectors that read a file
# Windows doesn't have (e.g. sudoers) so their shared parser yields nothing
# without needing a platform branch.
_NONEXISTENT = Path("C:/Windows/Temp/__avai_no_such_file__")


class WindowsFilesystemLayout:
    """Windows filesystem facts."""

    def privileged_bin_dirs(self) -> list[Path]:
        # No setuid concept on Windows; SetuidFilesCollector is composed
        # out, so this is never called — return empty for completeness.
        return []

    def home_dirs(self) -> list[Path]:
        homes: list[Path] = []
        users = Path("C:/Users")
        if users.is_dir():
            try:
                homes += [
                    d
                    for d in users.iterdir()
                    if d.is_dir() and d.name not in {"Public", "Default", "All Users"}
                ]
            except OSError:
                pass
        return homes

    def hosts_file(self) -> Path:
        return Path(r"C:\Windows\System32\drivers\etc\hosts")

    def sudoers_file(self) -> Path:
        return _NONEXISTENT

    def sudoers_dir(self) -> Path:
        return _NONEXISTENT

    def tcpdump_interface_args(self) -> list[str]:
        # tcpdump isn't a default Windows tool; the flow/DNS collectors are
        # composed out, so this is unused. Empty keeps the contract.
        return []


class WindowsPrivilegedAccounts:
    """Local Administrators membership via ``net localgroup``. Windows has
    no uid-0 / sudoers concept, so those gathers are empty."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def privileged_group_members(self) -> Iterable[dict]:
        out = self._runner.text(["net", "localgroup", "Administrators"])
        members = self._parse_localgroup(out)
        if members:
            yield {
                "kind": "group",
                "subject": "Administrators",
                "detail": ", ".join(members),
                "source_path": "net:localgroup",
            }

    def uid0_accounts(self) -> Iterable[dict]:
        return iter(())

    @staticmethod
    def _parse_localgroup(text: str) -> list[str]:
        """Pure parser for ``net localgroup <name>`` output: the member
        names sit between a dashed separator line and the trailing
        'The command completed successfully.' line."""
        lines = text.splitlines()
        start = None
        for i, line in enumerate(lines):
            if set(line.strip()) == {"-"} and line.strip():
                start = i + 1
                break
        if start is None:
            return []
        members: list[str] = []
        for line in lines[start:]:
            s = line.strip()
            if not s:
                continue
            if s.lower().startswith("the command completed"):
                break
            members.append(s)
        return members


class WindowsInstalledAppsCollector(SnapshotCollector):
    """Installed programs from the registry Uninstall keys, read as JSON
    via PowerShell."""

    name = "installed_apps"
    model = InstalledAppRow
    judge_fields = ("bundle_id", "name", "path")

    _PS = (
        "$p=@("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "Get-ItemProperty $p -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName} | "
        "Select-Object DisplayName,DisplayVersion,InstallLocation,PSChildName | "
        "ConvertTo-Json -Compress"
    )

    def __init__(self, runner: CommandRunner, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self._runner = runner

    def collect(self):
        try:
            data = self._runner.json(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PS]
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        yield from self._rows_from_json(data)

    @staticmethod
    def _rows_from_json(data) -> list[dict]:
        """Pure parser. ConvertTo-Json emits a bare object for a single
        result and an array for many; normalise both."""
        if data is None:
            return []
        items = data if isinstance(data, list) else [data]
        rows = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            rows.append(
                {
                    "path": obj.get("InstallLocation") or "",
                    "bundle_id": obj.get("PSChildName"),
                    "name": obj.get("DisplayName"),
                    "version": obj.get("DisplayVersion"),
                    "raw_json": json.dumps(obj),
                }
            )
        return rows


class WindowsLaunchItemsCollector(SnapshotCollector):
    """Autostart persistence: registry Run keys (HKLM + HKCU) plus
    scheduled tasks."""

    name = "launch_items"
    model = LaunchItemRow
    judge_fields = (
        "scope",
        "label",
        "program",
        "program_arguments_json",
        "user_name",
        "run_at_load",
        "keep_alive",
    )

    _RUN_PS = (
        "$keys=@("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
        ");"
        "foreach($k in $keys){$i=Get-Item $k -ErrorAction SilentlyContinue;"
        "if($i){foreach($v in $i.Property){"
        "[pscustomobject]@{scope=$k;name=$v;command=$i.GetValue($v)}}}} | "
        "ConvertTo-Json -Compress"
    )

    def __init__(self, runner: CommandRunner, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self._runner = runner

    def collect(self):
        try:
            run_data = self._runner.json(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self._RUN_PS,
                ]
            )
        except (RuntimeError, json.JSONDecodeError):
            run_data = None
        yield from self._rows_from_run_keys(run_data)

        tasks_csv = self._runner.text(
            ["schtasks", "/query", "/fo", "CSV", "/nh", "/v"], timeout=60
        )
        yield from self._rows_from_schtasks(tasks_csv)

    @staticmethod
    def _rows_from_run_keys(data) -> list[dict]:
        """Pure parser for the Run-key JSON."""
        if data is None:
            return []
        items = data if isinstance(data, list) else [data]
        rows = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            scope, name = obj.get("scope") or "", obj.get("name")
            rows.append(
                {
                    "scope": "registry_run",
                    "path": f"{scope}\\{name}",
                    "label": name,
                    "program": obj.get("command"),
                    "program_arguments_json": None,
                    "run_at_load": 1,
                    "keep_alive": None,
                    "raw_json": json.dumps(obj),
                }
            )
        return rows

    @staticmethod
    def _rows_from_schtasks(text: str) -> list[dict]:
        """Pure parser for ``schtasks /query /fo CSV /nh /v`` output.

        The verbose CSV has a stable column layout; we read by header name
        when a header row is present, else by the known column offsets for
        TaskName (1) and Task To Run (8)."""
        if not text.strip():
            return []
        rows = []
        reader = csv.reader(io.StringIO(text))
        for cols in reader:
            if len(cols) < 9:
                continue
            taskname = cols[1].strip()
            # Skip repeated header rows that /v sometimes interleaves.
            if not taskname or taskname.lower() == "taskname":
                continue
            command = cols[8].strip()
            rows.append(
                {
                    "scope": "scheduled_task",
                    "path": taskname,
                    "label": taskname.rsplit("\\", 1)[-1],
                    "program": command or None,
                    "program_arguments_json": None,
                    "run_at_load": None,
                    "keep_alive": None,
                    "raw_json": json.dumps({"task": taskname, "command": command}),
                }
            )
        return rows


class WindowsHost:
    """Composition root for Windows.

    Wires the genuinely cross-platform psutil collectors, the path-based
    collectors that work unchanged with Windows paths (hosts_file,
    ssh_authorized_keys via OpenSSH's ``C:\\Users\\*\\.ssh``), the local
    Administrators privilege view, and the Windows-native launch/installed
    collectors. Everything with no Windows analog (or not yet implemented)
    is simply not assembled.
    """

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or CommandRunner()
        self._fs = WindowsFilesystemLayout()
        self._accounts = WindowsPrivilegedAccounts(self._runner)

    def snapshot_collectors(self, prompts: Prompts) -> list[SnapshotCollector]:
        h = prompts.hint_for
        return [
            ProcessCollector(judge_hints=h("processes")),
            NetworkConnectionsCollector(judge_hints=h("network_connections")),
            ListeningPortsCollector(judge_hints=h("listening_ports")),
            NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
            MountsCollector(judge_hints=h("mounts")),
            WindowsInstalledAppsCollector(
                self._runner, judge_hints=h("installed_apps")
            ),
            WindowsLaunchItemsCollector(self._runner, judge_hints=h("launch_items")),
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
                self._ps(
                    "Get-NetNeighbor -AddressFamily IPv4 | "
                    "Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | "
                    "ConvertTo-Json -Compress",
                    PsNeighborParser("flags"),
                ),
                judge_hints=h("arp_table"),
            ),
            NdpNeighborsCollector(
                self._ps(
                    "Get-NetNeighbor -AddressFamily IPv6 | "
                    "Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | "
                    "ConvertTo-Json -Compress",
                    PsNeighborParser("state"),
                ),
                judge_hints=h("ndp_neighbors"),
            ),
            RoutesCollector(
                self._ps(
                    "Get-NetRoute | Select-Object "
                    "DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | "
                    "ConvertTo-Json -Compress",
                    PsRouteParser(),
                ),
                judge_hints=h("routes"),
            ),
            DnsResolversCollector(
                self._ps(
                    "Get-DnsClientServerAddress | "
                    "Select-Object InterfaceAlias,ServerAddresses | "
                    "ConvertTo-Json -Compress",
                    PsDnsParser(),
                ),
                judge_hints=h("dns_resolvers"),
            ),
            # Exposure & MITM surface (promiscuous_ifaces composed out — no
            # clean Windows analog).
            ProxyConfigCollector(
                self._ps(
                    "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Internet Settings' | Select-Object "
                    "ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress",
                    WindowsProxyParser(),
                ),
                judge_hints=h("proxy_config"),
            ),
            LoginSessionsCollector(
                CommandSnapshot(
                    self._runner, ["query", "user"], WindowsSessionParser()
                ),
                judge_hints=h("login_sessions"),
            ),
            NetworkSharesCollector(
                self._ps(
                    "Get-SmbConnection | Select-Object ServerName,ShareName,Dialect | "
                    "ConvertTo-Json -Compress",
                    WindowsSharesParser(),
                ),
                judge_hints=h("network_shares"),
            ),
            TrustedRootsCollector(
                self._ps(
                    "Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object "
                    "Subject,Thumbprint | ConvertTo-Json -Compress",
                    WindowsCertParser(),
                ),
                judge_hints=h("trusted_roots"),
            ),
            # Persistence / injection
            InjectionEnvCollector(
                self._ps(
                    "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\"
                    "Windows NT\\CurrentVersion\\Windows' | Select-Object "
                    "AppInit_DLLs,LoadAppInit_DLLs | ConvertTo-Json -Compress",
                    WindowsAppInitParser(),
                ),
                judge_hints=h("injection_env"),
            ),
            KernelModulesCollector(
                CommandSnapshot(
                    self._runner, ["driverquery", "/fo", "csv"], WindowsDriverParser()
                ),
                judge_hints=h("kernel_modules"),
            ),
            SshKnownHostsCollector(judge_hints=h("ssh_known_hosts"), fs=self._fs),
        ]

    def _ps(self, script: str, parser) -> CommandSnapshot:
        """A PowerShell-backed CommandSnapshot for a ConvertTo-Json query."""
        return CommandSnapshot(
            self._runner,
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            parser,
        )

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        # Windows Event Log / Sysmon streaming is the remaining work; no
        # streaming collectors are assembled yet.
        return []
