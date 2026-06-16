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
mirroring the macOS/Linux adapters. Streaming uses the shared
:class:`JsonLineStreamSource` loop fed by a PowerShell ``RecordId``-keyed
poll over the Security event log (PowerShell has no native log ``-Follow``).

Composed OUT on Windows (no analog): setuid_files, quarantine_events,
mdm_profiles, kernel/system extensions, promiscuous_ifaces. These are
simply not assembled — never a runtime branch.
"""

from __future__ import annotations

import csv
import io
import json
import threading
from pathlib import Path
from typing import Iterable, Optional

from ..collectors import (
    DiskUsageCollector,
    HostResourcesCollector,
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
from ..models import (
    AuthEventRow,
    BluetoothDeviceRow,
    InstalledAppRow,
    LaunchItemRow,
    ProcessExecRow,
    SystemIntegrityRow,
    UsbDeviceRow,
    WifiStateRow,
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
    SshKnownHostsCollector,
    WindowsAppInitParser,
    WindowsDriverParser,
)
from ..prompts import Prompts
from ..runtime import CommandRunner, CommandSnapshot, JsonLineStreamSource

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

    def app_executables(self) -> list[Path]:
        # No macOS-style app bundles; FileScanCollector isn't wired on
        # Windows. Present so the FilesystemLayout shape stays complete.
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


class WindowsSystemIntegrityCollector(SnapshotCollector):
    """Windows security posture mapped into the macOS-shaped
    ``system_integrity`` row (same columns, so the dashboard renders it
    unchanged), mirroring :class:`LinuxSystemIntegrityCollector`:

    - ``filevault_active``          → any BitLocker volume protected.
    - ``firewall_global_state``     → any Windows Firewall profile enabled.
    - ``gatekeeper_assessments_*``  → Defender real-time protection on OR
                                      Secure Boot enabled (closest "code is
                                      vetted before it runs" analog).
    - ``remote_login_enabled``      → RDP accepting connections
                                      (``fDenyTSConnections=0``).
    - ``screen_sharing_enabled``    → same RDP flag.
    - ``remote_management_enabled`` → WinRM service running (the Windows
                                      analog of Apple Remote Desktop).

    Raw posture (Defender, firewall profiles, BitLocker, Secure Boot, RDP,
    WinRM) is preserved in ``raw_json`` for the judge.
    """

    name = "system_integrity"
    model = SystemIntegrityRow
    judge_fields = (
        "filevault_active",
        "firewall_global_state",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    _PS = (
        "$o=[ordered]@{};"
        "$o.defender=try{Get-MpComputerStatus|"
        "Select-Object RealTimeProtectionEnabled,AntivirusEnabled}catch{$null};"
        "$o.firewall=try{Get-NetFirewallProfile|"
        "Select-Object Name,Enabled}catch{$null};"
        "$o.bitlocker=try{Get-BitLockerVolume|"
        "Select-Object MountPoint,ProtectionStatus}catch{$null};"
        "$o.secureboot=try{[bool](Confirm-SecureBootUEFI)}catch{$null};"
        "$o.rdp_deny=try{(Get-ItemProperty "
        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name fDenyTSConnections).fDenyTSConnections}catch{$null};"
        "$o.winrm=try{(Get-Service WinRM).Status.ToString()}catch{$null};"
        "[pscustomobject]$o|ConvertTo-Json -Compress -Depth 4"
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
        row = self._row_from_status(data)
        if row is not None:
            yield row

    @staticmethod
    def _row_from_status(data) -> Optional[dict]:
        """Pure parser. ConvertTo-Json emits a bare object for a single
        firewall profile / BitLocker volume and a list for many; normalise
        both, and treat bool / 'True' / 1 alike."""
        if not isinstance(data, dict):
            return None

        def _truthy(value) -> bool:
            return str(value).strip().lower() in ("true", "1", "on")

        def _as_list(value) -> list:
            if value is None:
                return []
            return value if isinstance(value, list) else [value]

        firewall_on = any(
            _truthy((p or {}).get("Enabled")) for p in _as_list(data.get("firewall"))
        )
        bitlocker_on = any(
            str((v or {}).get("ProtectionStatus")) in ("1", "On")
            for v in _as_list(data.get("bitlocker"))
        )
        defender = data.get("defender") or {}
        realtime = _truthy(defender.get("RealTimeProtectionEnabled"))
        secureboot = data.get("secureboot") is True
        rdp_on = str(data.get("rdp_deny")) == "0"
        winrm_on = str(data.get("winrm")).strip().lower() == "running"
        return {
            "filevault_active": int(bitlocker_on),
            "firewall_global_state": int(firewall_on),
            "firewall_stealth": None,
            "firewall_logging": None,
            "gatekeeper_assessments_enabled": int(realtime or secureboot),
            "remote_login_enabled": int(rdp_on),
            "screen_sharing_enabled": int(rdp_on),
            "remote_management_enabled": int(winrm_on),
            "raw_json": json.dumps(data),
        }


class WindowsUsbDevicesCollector(SnapshotCollector):
    """Present USB devices via ``Get-PnpDevice -Class USB``. Vendor/product
    IDs are parsed from the PnP ``InstanceId`` (``USB\\VID_xxxx&PID_yyyy\\..``),
    filling the same columns :class:`LinuxUsbDevicesCollector` reads from
    sysfs."""

    name = "usb_devices"
    model = UsbDeviceRow
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    _PS = (
        "Get-PnpDevice -PresentOnly -Class USB -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName,InstanceId,Manufacturer,Status | "
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
        if data is None:
            return []
        items = data if isinstance(data, list) else [data]
        rows = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            instance = obj.get("InstanceId") or ""
            vid, pid = WindowsUsbDevicesCollector._ids_from_instance(instance)
            rows.append(
                {
                    "name": obj.get("FriendlyName"),
                    "vendor_id": vid,
                    "product_id": pid,
                    "serial_number": None,
                    "manufacturer": obj.get("Manufacturer"),
                    "location_id": instance or None,
                    "speed": None,
                    "raw_json": json.dumps(obj),
                }
            )
        return rows

    @staticmethod
    def _ids_from_instance(instance: str) -> tuple[Optional[str], Optional[str]]:
        vid = pid = None
        for token in instance.replace("\\", "&").split("&"):
            if token.startswith("VID_"):
                vid = token[4:]
            elif token.startswith("PID_"):
                pid = token[4:]
        return vid, pid


class WindowsBluetoothCollector(SnapshotCollector):
    """Present Bluetooth devices via ``Get-PnpDevice -Class Bluetooth``.
    Presence implies paired; ``Status == 'OK'`` implies connected. The MAC
    is parsed from the ``DEV_<mac>`` segment of the ``InstanceId``."""

    name = "bluetooth_devices"
    model = BluetoothDeviceRow
    judge_fields = ("name", "address", "minor_type")

    _PS = (
        "Get-PnpDevice -PresentOnly -Class Bluetooth -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress"
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
        if data is None:
            return []
        items = data if isinstance(data, list) else [data]
        rows = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            instance = obj.get("InstanceId") or ""
            rows.append(
                {
                    "name": obj.get("FriendlyName"),
                    "address": WindowsBluetoothCollector._addr_from_instance(instance),
                    "connected": int(str(obj.get("Status")).upper() == "OK"),
                    "paired": 1,
                    "minor_type": None,
                    "raw_json": json.dumps(obj),
                }
            )
        return rows

    @staticmethod
    def _addr_from_instance(instance: str) -> Optional[str]:
        # BTHENUM instance IDs carry the MAC in a ``Dev_<mac>`` segment;
        # match case-insensitively (Windows renders it ``Dev_``).
        for token in instance.replace("\\", "&").split("&"):
            if token.upper().startswith("DEV_"):
                return token[4:]
        return None


class WindowsWifiCollector(SnapshotCollector):
    """Wireless interface state via ``netsh wlan show interfaces`` (text,
    not JSON — netsh has no JSON mode). One row per interface block,
    mirroring :class:`LinuxWifiCollector`'s columns."""

    name = "wifi_state"
    model = WifiStateRow
    judge_fields = ("ssid", "bssid", "security")

    def __init__(self, runner: CommandRunner, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self._runner = runner

    def collect(self):
        out = self._runner.text(["netsh", "wlan", "show", "interfaces"], timeout=15)
        yield from self._rows_from_netsh(out)

    @staticmethod
    def _rows_from_netsh(text: str) -> list[dict]:
        """Pure parser. ``netsh`` prints ``key : value`` lines, one blank
        line between interface blocks. Only blocks carrying a ``Name`` are
        real interfaces (the leading 'There is N interface...' preamble has
        none)."""
        rows: list[dict] = []
        block: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                rows.append(WindowsWifiCollector._row(block))
                block = {}
                continue
            key, sep, value = line.partition(":")
            if sep:
                block[key.strip().lower()] = value.strip()
        rows.append(WindowsWifiCollector._row(block))
        return [r for r in rows if r]

    @staticmethod
    def _row(block: dict) -> dict:
        if not block.get("name"):
            return {}
        return {
            "interface": block.get("name"),
            "ssid": block.get("ssid") or None,
            "bssid": block.get("bssid") or None,
            "channel": block.get("channel") or None,
            "security": block.get("authentication") or None,
            "raw_json": json.dumps(block),
        }


class WinSecurityAuthParser:
    """Strategy: a Windows Security-log event (as emitted by the
    ``auth_events`` poll loop) → :class:`AuthEventRow` dict. Mirrors
    :class:`JournalAuthParser` so the dashboard treats all OSes alike."""

    def parse(self, event: dict) -> dict:
        try:
            pid = (
                int(event["ProcessId"]) if event.get("ProcessId") is not None else None
            )
        except (TypeError, ValueError):
            pid = None
        event_id = event.get("Id")
        return {
            "event_timestamp": event.get("TimeCreated"),
            "process": event.get("Provider"),
            "subsystem": "Security",
            "category": str(event_id or ""),
            "event_type": f"event_id={event_id}",
            "event_message": event.get("Message"),
            "pid": pid,
            "raw_json": json.dumps(event),
        }


class WinSecurityExecParser:
    """Strategy: a Windows 4688 process-creation event (with its
    ``EventData`` flattened to a name→value object) → :class:`ProcessExecRow`
    dict. Mirrors :class:`EsloggerExecParser` / :class:`AuditExecParser`."""

    def parse(self, event: dict) -> dict:
        data = event.get("Data") or {}
        cmdline = data.get("CommandLine")
        return {
            "event_timestamp": event.get("TimeCreated"),
            "event_type": "exec",
            "pid": self._pid(data.get("NewProcessId")),
            "ppid": self._pid(data.get("ProcessId")),
            "uid": None,
            "username": data.get("SubjectUserName"),
            "exe_path": data.get("NewProcessName"),
            "exe_args_json": json.dumps([cmdline]) if cmdline else None,
            "parent_path": data.get("ParentProcessName"),
            "signing_id": None,
            "raw_json": json.dumps(event),
        }

    @staticmethod
    def _pid(value) -> Optional[int]:
        # 4688 EventData renders PIDs as hex strings ("0x1a4"); be liberal.
        if value is None:
            return None
        s = str(value)
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (TypeError, ValueError):
            return None


class WindowsAuthEventsCollector(StreamingCollector):
    """Windows equivalent of :class:`LinuxAuthEventsCollector`. Tails the
    Security event log for logon / privilege / account-management events and
    yields :class:`AuthEventRow`-shaped rows.

    PowerShell has no native ``-Follow`` for event logs, so ``_cmd`` runs a
    ``RecordId``-keyed poll loop that emits one compact JSON object per new
    event — exactly the NDJSON contract :class:`JsonLineStreamSource`
    consumes. Requires the Security-log audit policy that records these IDs
    (interactive-logon auditing is on by default).
    """

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    # Logon success/failure, logoff, special-privilege logon, account
    # created, member added to a security-enabled (local/global/universal)
    # group.
    _EVENT_IDS = "4624,4625,4634,4647,4672,4720,4728,4732,4756"

    _PS = (
        "$f=@{LogName='Security';Id=@(" + _EVENT_IDS + ")};"
        "$last=(Get-WinEvent -FilterHashtable $f -MaxEvents 1 "
        "-ErrorAction SilentlyContinue).RecordId;"
        "if($null -eq $last){$last=0};"
        "while($true){"
        "Start-Sleep -Seconds 2;"
        "$evs=Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue|"
        "Where-Object{$_.RecordId -gt $last}|Sort-Object RecordId;"
        "foreach($e in $evs){"
        "$last=$e.RecordId;"
        "[pscustomobject]@{"
        "TimeCreated=$e.TimeCreated.ToString('o');Id=$e.Id;"
        "Provider=$e.ProviderName;ProcessId=$e.ProcessId;"
        "RecordId=$e.RecordId;Message=$e.Message}|"
        "ConvertTo-Json -Compress}}"
    )

    def _cmd(self) -> list[str]:
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PS]

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), WinSecurityAuthParser(), killer_name="winevent-auth-killer"
        )
        yield from source.stream(stop_event)


class WindowsProcessExecCollector(StreamingCollector):
    """Windows equivalent of :class:`MacosProcessExecCollector` /
    :class:`LinuxProcessExecCollector`. Tails Security event 4688 (process
    creation) and yields :class:`ProcessExecRow`-shaped rows.

    Requires the 'Audit Process Creation' policy, and the
    ``ProcessCreationIncludeCmdLine_Enabled`` policy for the ``CommandLine``
    field. Same ``RecordId``-keyed poll loop as
    :class:`WindowsAuthEventsCollector`; each event's ``EventData`` is
    flattened to a name→value object so the parser is a pure dict transform.
    """

    name = "process_exec_events"
    model = ProcessExecRow
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "parent_path", "username")

    _PS = (
        "$f=@{LogName='Security';Id=4688};"
        "$last=(Get-WinEvent -FilterHashtable $f -MaxEvents 1 "
        "-ErrorAction SilentlyContinue).RecordId;"
        "if($null -eq $last){$last=0};"
        "while($true){"
        "Start-Sleep -Seconds 2;"
        "$evs=Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue|"
        "Where-Object{$_.RecordId -gt $last}|Sort-Object RecordId;"
        "foreach($e in $evs){"
        "$last=$e.RecordId;"
        "$x=[xml]$e.ToXml();$d=@{};"
        "foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};"
        "[pscustomobject]@{TimeCreated=$e.TimeCreated.ToString('o');"
        "RecordId=$e.RecordId;Data=$d}|ConvertTo-Json -Compress -Depth 4"
        "}}"
    )

    def _cmd(self) -> list[str]:
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PS]

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), WinSecurityExecParser(), killer_name="winevent-exec-killer"
        )
        yield from source.stream(stop_event)


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
            HostResourcesCollector(judge_hints=h("host_resources")),
            DiskUsageCollector(judge_hints=h("disk_usage")),
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
            # Security posture & devices (Windows-native gathers).
            WindowsSystemIntegrityCollector(
                self._runner, judge_hints=h("system_integrity")
            ),
            WindowsUsbDevicesCollector(self._runner, judge_hints=h("usb_devices")),
            WindowsBluetoothCollector(self._runner, judge_hints=h("bluetooth_devices")),
            WindowsWifiCollector(self._runner, judge_hints=h("wifi_state")),
        ]

    def _ps(self, script: str, parser) -> CommandSnapshot:
        """A PowerShell-backed CommandSnapshot for a ConvertTo-Json query."""
        return CommandSnapshot(
            self._runner,
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            parser,
        )

    def streaming_collectors(self, prompts: Prompts) -> list[StreamingCollector]:
        h = prompts.hint_for
        return [
            WindowsAuthEventsCollector(judge_hints=h("auth_events")),
            WindowsProcessExecCollector(judge_hints=h("process_exec_events")),
        ]
