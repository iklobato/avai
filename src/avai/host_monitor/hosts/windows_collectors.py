"""Windows-native collectors and their pure parsers.

VERIFICATION NOTE: written against the documented output of the Windows
tools it shells out to (``powershell``/``ConvertTo-Json``, ``schtasks /fo
CSV``, ``net localgroup``, ``netsh``). It has NOT been executed on a
Windows host. The pure parsers are unit-tested (test_windows.py) against
representative command output; the live gather is unvalidated and should
be smoke-tested on a real Windows machine before relying on it.

Gathering goes through the injected :class:`CommandRunner` seam (no
``winreg``/``wmi`` Python modules), so this file imports cleanly on any OS.
"""

from __future__ import annotations

import csv
import io
import json
import threading
from itertools import takewhile
from typing import Any, Iterator

from ..slices import Slices
from ..collectors import SnapshotCollector, StreamingCollector
from ..net_collectors import PsJson
from ..runtime import CommandRunner, CommandSnapshot, JsonLineStreamSource, RowParser
from ..runtime.command_runner import CommandFailedError


class PowerShell:
    """Run a PowerShell script through the injected runner."""

    COMMAND = ("powershell", "-NoProfile", "-NonInteractive", "-Command")

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def command(self, script: str) -> list[str]:
        return [*self.COMMAND, script]

    def json(self, script: str) -> Any | None:
        """Parsed ``ConvertTo-Json`` output, or None when the script fails."""
        try:
            return self._runner.json(self.command(script))
        except (CommandFailedError, json.JSONDecodeError):
            return None

    def snapshot(self, script: str, parser: RowParser) -> CommandSnapshot:
        return CommandSnapshot(self._runner, self.command(script), parser)


class LocalGroupParser:
    """``net localgroup <name>`` output: the member names sit between a
    dashed separator line and the 'The command completed successfully.'
    footer."""

    FOOTER = "the command completed"

    def members(self, text: str) -> list[str]:
        lines = [line.strip() for line in text.splitlines()]
        starts = (index + 1 for index, line in enumerate(lines) if self._rule(line))
        start = next(starts, None)
        if start is None:
            return []
        body = takewhile(self._before_footer, lines[start:])
        return [line for line in body if line]

    def _rule(self, line: str) -> bool:
        return bool(line) and set(line) == {"-"}

    def _before_footer(self, line: str) -> bool:
        return not line.lower().startswith(self.FOOTER)


class InstalledAppsParser:
    def rows(self, payload: Any) -> list[dict[str, Any]]:
        return [
            {
                "path": item.get("InstallLocation") or "",
                "bundle_id": item.get("PSChildName"),
                "name": item.get("DisplayName"),
                "version": item.get("DisplayVersion"),
                "raw_json": json.dumps(item),
            }
            for item in PsJson().objects(payload)
        ]


class RunKeysParser:
    def rows(self, payload: Any) -> list[dict[str, Any]]:
        return [self._row(item) for item in PsJson().objects(payload)]

    def _row(self, item: dict[str, Any]) -> dict[str, Any]:
        scope, name = item.get("scope") or "", item.get("name")
        return {
            "scope": "registry_run",
            "path": f"{scope}\\{name}",
            "label": name,
            "program": item.get("command"),
            "program_arguments_json": None,
            "run_at_load": 1,
            "keep_alive": None,
            "raw_json": json.dumps(item),
        }


class SchtasksParser:
    """``schtasks /query /fo CSV /nh /v`` output, read by the known column
    offsets for TaskName and Task To Run."""

    TASK_NAME_COLUMN = 1
    COMMAND_COLUMN = 8
    MIN_COLUMNS = COMMAND_COLUMN + 1

    def rows(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        records = csv.reader(io.StringIO(text))
        wide = (cols for cols in records if len(cols) >= self.MIN_COLUMNS)
        return [row for row in map(self._row, wide) if row is not None]

    def _row(self, cols: list[str]) -> dict[str, Any] | None:
        taskname = cols[self.TASK_NAME_COLUMN].strip()
        # Skip repeated header rows that /v sometimes interleaves.
        if not taskname or taskname.lower() == "taskname":
            return None
        command = cols[self.COMMAND_COLUMN].strip()
        return {
            "scope": "scheduled_task",
            "path": taskname,
            "label": taskname.rsplit("\\", 1)[-1],
            "program": command or None,
            "program_arguments_json": None,
            "run_at_load": None,
            "keep_alive": None,
            "raw_json": json.dumps({"task": taskname, "command": command}),
        }


class SecurityPostureParser:
    """Windows posture mapped into the macOS-shaped ``system_integrity``
    row. Firewall profiles and BitLocker volumes may arrive as one object
    or a list; bool / 'True' / 1 read alike."""

    TRUTHY = ("true", "1", "on")
    PROTECTED = ("1", "On")

    def row(self, payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        defender = payload.get("defender") or {}
        realtime = self._truthy(defender.get("RealTimeProtectionEnabled"))
        rdp_on = str(payload.get("rdp_deny")) == "0"
        winrm_on = str(payload.get("winrm")).strip().lower() == "running"
        return {
            "filevault_active": int(self._bitlocker_on(payload)),
            "firewall_global_state": int(self._firewall_on(payload)),
            "firewall_stealth": None,
            "firewall_logging": None,
            "gatekeeper_assessments_enabled": int(
                realtime or payload.get("secureboot") is True
            ),
            "remote_login_enabled": int(rdp_on),
            "screen_sharing_enabled": int(rdp_on),
            "remote_management_enabled": int(winrm_on),
            "raw_json": json.dumps(payload),
        }

    def _firewall_on(self, payload: dict[str, Any]) -> bool:
        profiles = PsJson().objects(payload.get("firewall"))
        return any(self._truthy(profile.get("Enabled")) for profile in profiles)

    def _bitlocker_on(self, payload: dict[str, Any]) -> bool:
        volumes = PsJson().objects(payload.get("bitlocker"))
        return any(
            str(volume.get("ProtectionStatus")) in self.PROTECTED for volume in volumes
        )

    def _truthy(self, value: object) -> bool:
        return str(value).strip().lower() in self.TRUTHY


class PnpInstanceId:
    """A PnP ``InstanceId`` such as ``USB\\VID_xxxx&PID_yyyy\\..``."""

    def __init__(self, instance: str) -> None:
        self._instance = instance

    def value(self, prefix: str) -> str | None:
        """The text after the last ``prefix`` token, matched case-insensitively
        (Windows renders BTHENUM's MAC segment as ``Dev_``)."""
        tokens = self._instance.replace("\\", "&").split("&")
        values = [
            token[len(prefix) :]
            for token in tokens
            if token.upper().startswith(prefix.upper())
        ]
        return values[-1] if values else None


class UsbPnpParser:
    def rows(self, payload: Any) -> list[dict[str, Any]]:
        return [self._row(item) for item in PsJson().objects(payload)]

    def _row(self, item: dict[str, Any]) -> dict[str, Any]:
        instance = item.get("InstanceId") or ""
        ids = PnpInstanceId(instance)
        return {
            "name": item.get("FriendlyName"),
            "vendor_id": ids.value("VID_"),
            "product_id": ids.value("PID_"),
            "serial_number": None,
            "manufacturer": item.get("Manufacturer"),
            "location_id": instance or None,
            "speed": None,
            "raw_json": json.dumps(item),
        }


class BluetoothPnpParser:
    """Presence implies paired; ``Status == 'OK'`` implies connected. The MAC
    comes from the ``DEV_<mac>`` segment of the ``InstanceId``."""

    def rows(self, payload: Any) -> list[dict[str, Any]]:
        return [self._row(item) for item in PsJson().objects(payload)]

    def _row(self, item: dict[str, Any]) -> dict[str, Any]:
        instance = PnpInstanceId(item.get("InstanceId") or "")
        return {
            "name": item.get("FriendlyName"),
            "address": instance.value("DEV_"),
            "connected": int(str(item.get("Status")).upper() == "OK"),
            "paired": 1,
            "minor_type": None,
            "raw_json": json.dumps(item),
        }


class NetshWlanParser:
    """``netsh wlan show interfaces`` prints ``key : value`` lines with a
    blank line between interface blocks. Only blocks carrying a ``Name`` are
    real interfaces (the 'There is N interface...' preamble has none)."""

    def rows(self, text: str) -> list[dict[str, Any]]:
        return [self._row(block) for block in self._blocks(text) if block.get("name")]

    def _blocks(self, text: str) -> list[dict[str, str]]:
        blocks: list[dict[str, str]] = [{}]
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                blocks.append({})
                continue
            key, sep, value = line.partition(":")
            if sep:
                blocks[-1][key.strip().lower()] = value.strip()
        return blocks

    def _row(self, block: dict[str, str]) -> dict[str, Any]:
        return {
            "interface": block.get("name"),
            "ssid": block.get("ssid") or None,
            "bssid": block.get("bssid") or None,
            "channel": block.get("channel") or None,
            "security": block.get("authentication") or None,
            "raw_json": json.dumps(block),
        }


class WindowsInstalledAppsCollector(SnapshotCollector):
    """Installed programs from the registry Uninstall keys."""

    slice = Slices.INSTALLED_APPS
    judge_fields = ("bundle_id", "name", "path")

    SCRIPT = (
        "$p=@("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "Get-ItemProperty $p -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName} | "
        "Select-Object DisplayName,DisplayVersion,InstallLocation,PSChildName | "
        "ConvertTo-Json -Compress"
    )

    def __init__(self, shell: PowerShell, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._shell = shell

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from InstalledAppsParser().rows(self._shell.json(self.SCRIPT))


class WindowsLaunchItemsCollector(SnapshotCollector):
    """Autostart persistence: registry Run keys (HKLM + HKCU) plus
    scheduled tasks."""

    slice = Slices.LAUNCH_ITEMS
    judge_fields = (
        "scope",
        "label",
        "program",
        "program_arguments_json",
        "user_name",
        "run_at_load",
        "keep_alive",
    )

    SCHTASKS_TIMEOUT_S = 60
    RUN_KEYS_SCRIPT = (
        "$keys=@("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
        ");"
        "foreach($k in $keys){$i=Get-Item $k -ErrorAction SilentlyContinue;"
        "if($i){foreach($v in $i.Property){"
        "[pscustomobject]@{scope=$k;name=$v;command=$i.GetValue($v)}}}} | "
        "ConvertTo-Json -Compress"
    )

    def __init__(
        self, runner: CommandRunner, shell: PowerShell, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._runner = runner
        self._shell = shell

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from RunKeysParser().rows(self._shell.json(self.RUN_KEYS_SCRIPT))
        tasks_csv = self._runner.text(
            ["schtasks", "/query", "/fo", "CSV", "/nh", "/v"],
            timeout=self.SCHTASKS_TIMEOUT_S,
        )
        yield from SchtasksParser().rows(tasks_csv)


class WindowsSystemIntegrityCollector(SnapshotCollector):
    """Windows security posture in the macOS-shaped ``system_integrity`` row
    (same columns, so the dashboard renders it unchanged):

    - ``filevault_active``          : any BitLocker volume protected.
    - ``firewall_global_state``     : any Windows Firewall profile enabled.
    - ``gatekeeper_assessments_*``  : Defender real-time protection on OR
                                      Secure Boot enabled.
    - ``remote_login_enabled``      : RDP accepting connections.
    - ``screen_sharing_enabled``    : same RDP flag.
    - ``remote_management_enabled`` : WinRM service running.

    Raw posture is kept in ``raw_json`` for the judge.
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

    SCRIPT = (
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

    def __init__(self, shell: PowerShell, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._shell = shell

    def collect(self) -> Iterator[dict[str, Any]]:
        row = SecurityPostureParser().row(self._shell.json(self.SCRIPT))
        if row is not None:
            yield row


class WindowsUsbDevicesCollector(SnapshotCollector):
    """Present USB devices via ``Get-PnpDevice -Class USB``, filling the
    columns :class:`LinuxUsbDevicesCollector` reads from sysfs."""

    slice = Slices.USB_DEVICES
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    SCRIPT = (
        "Get-PnpDevice -PresentOnly -Class USB -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName,InstanceId,Manufacturer,Status | "
        "ConvertTo-Json -Compress"
    )

    def __init__(self, shell: PowerShell, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._shell = shell

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from UsbPnpParser().rows(self._shell.json(self.SCRIPT))


class WindowsBluetoothCollector(SnapshotCollector):
    """Present Bluetooth devices via ``Get-PnpDevice -Class Bluetooth``."""

    slice = Slices.BLUETOOTH_DEVICES
    judge_fields = ("name", "address", "minor_type")

    SCRIPT = (
        "Get-PnpDevice -PresentOnly -Class Bluetooth -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress"
    )

    def __init__(self, shell: PowerShell, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._shell = shell

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from BluetoothPnpParser().rows(self._shell.json(self.SCRIPT))


class WindowsWifiCollector(SnapshotCollector):
    """Wireless interface state via ``netsh wlan show interfaces`` (text;
    netsh has no JSON mode), in :class:`LinuxWifiCollector`'s columns."""

    slice = Slices.WIFI_STATE
    judge_fields = ("ssid", "bssid", "security")

    NETSH_TIMEOUT_S = 15

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        output = self._runner.text(
            ["netsh", "wlan", "show", "interfaces"], timeout=self.NETSH_TIMEOUT_S
        )
        yield from NetshWlanParser().rows(output)


class WinSecurityAuthParser:
    """Strategy: a Windows Security-log event (as emitted by the
    ``auth_events`` poll loop) to an :class:`AuthEventRow` dict. Mirrors
    :class:`JournalAuthParser` so the dashboard treats all OSes alike."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        event_id = event.get("Id")
        return {
            "event_timestamp": event.get("TimeCreated"),
            "process": event.get("Provider"),
            "subsystem": "Security",
            "category": str(event_id or ""),
            "event_type": f"event_id={event_id}",
            "event_message": event.get("Message"),
            "pid": self._pid(event.get("ProcessId")),
            "raw_json": json.dumps(event),
        }

    def _pid(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


class WinSecurityExecParser:
    """Strategy: a Windows 4688 process-creation event (``EventData``
    flattened to a name-to-value object) to a :class:`ProcessExecRow` dict.
    Mirrors :class:`EsloggerExecParser` / :class:`AuditExecParser`."""

    HEX_PREFIX = "0x"
    HEX_BASE = 16
    DECIMAL_BASE = 10

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        fields = event.get("Data") or {}
        cmdline = fields.get("CommandLine")
        return {
            "event_timestamp": event.get("TimeCreated"),
            "event_type": "exec",
            "pid": self._pid(fields.get("NewProcessId")),
            "ppid": self._pid(fields.get("ProcessId")),
            "uid": None,
            "username": fields.get("SubjectUserName"),
            "exe_path": fields.get("NewProcessName"),
            "exe_args_json": json.dumps([cmdline]) if cmdline else None,
            "parent_path": fields.get("ParentProcessName"),
            "signing_id": None,
            "raw_json": json.dumps(event),
        }

    def _pid(self, value: object) -> int | None:
        # 4688 EventData renders PIDs as hex strings ("0x1a4"); be liberal.
        if value is None:
            return None
        text = str(value)
        hexadecimal = text.lower().startswith(self.HEX_PREFIX)
        base = self.HEX_BASE if hexadecimal else self.DECIMAL_BASE
        try:
            return int(text, base)
        except ValueError:
            return None


class WindowsAuthEventsCollector(StreamingCollector):
    """Windows equivalent of :class:`LinuxAuthEventsCollector`: tails the
    Security event log for logon / privilege / account-management events.

    PowerShell has no native ``-Follow`` for event logs, so :meth:`command`
    runs a ``RecordId``-keyed poll loop that emits one compact JSON object
    per new event, the NDJSON contract :class:`JsonLineStreamSource`
    consumes. Needs the Security-log audit policy that records these IDs.
    """

    slice = Slices.AUTH_EVENTS
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    # Logon success/failure, logoff, special-privilege logon, account
    # created, member added to a security-enabled group.
    EVENT_IDS = "4624,4625,4634,4647,4672,4720,4728,4732,4756"
    SCRIPT = (
        "$f=@{LogName='Security';Id=@(" + EVENT_IDS + ")};"
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

    def command(self) -> list[str]:
        return [*PowerShell.COMMAND, self.SCRIPT]

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        source = JsonLineStreamSource(
            self.command(), WinSecurityAuthParser(), "winevent-auth-killer"
        )
        yield from source.stream(stop_event)


class WindowsProcessExecCollector(StreamingCollector):
    """Windows equivalent of :class:`LinuxProcessExecCollector`: tails
    Security event 4688 (process creation).

    Needs the 'Audit Process Creation' policy, plus
    ``ProcessCreationIncludeCmdLine_Enabled`` for ``CommandLine``. Same
    ``RecordId``-keyed poll loop as :class:`WindowsAuthEventsCollector`.
    """

    slice = Slices.PROCESS_EXEC_EVENTS
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "parent_path", "username")

    SCRIPT = (
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

    def command(self) -> list[str]:
        return [*PowerShell.COMMAND, self.SCRIPT]

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        source = JsonLineStreamSource(
            self.command(), WinSecurityExecParser(), "winevent-exec-killer"
        )
        yield from source.stream(stop_event)
