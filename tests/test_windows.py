"""Tests for the WindowsHost parsers and wiring.

The Windows *gather* (subprocess calls) cannot run on this CI host, but
the pure parsers — where the bugs live — are exercised here against
representative command output, exactly as for the macOS/Linux adapters.
"""

from __future__ import annotations

from avai.host_monitor.hosts import HostFactory
from avai.host_monitor.hosts.windows import (
    WindowsBluetoothCollector,
    WindowsHost,
    WindowsInstalledAppsCollector,
    WindowsLaunchItemsCollector,
    WindowsPrivilegedAccounts,
    WindowsSystemIntegrityCollector,
    WindowsUsbDevicesCollector,
    WindowsWifiCollector,
    WinSecurityAuthParser,
    WinSecurityExecParser,
)
from avai.host_monitor.prompts import Prompts


class _FakeRunner:
    def __init__(self, text_responses=None):
        self._text = text_responses or {}

    def text(self, cmd, timeout=10):
        return self._text.get(tuple(cmd), "")


_NET_LOCALGROUP = """\
Alias name     Administrators
Comment        Administrators have complete and unrestricted access

Members

-------------------------------------------------------------------------------
Administrator
alice
Domain Admins
The command completed successfully.

"""


class TestLocalGroupParser:
    def test_extracts_members_between_separator_and_footer(self):
        members = WindowsPrivilegedAccounts._parse_localgroup(_NET_LOCALGROUP)
        assert members == ["Administrator", "alice", "Domain Admins"]

    def test_empty_or_malformed_is_empty(self):
        assert WindowsPrivilegedAccounts._parse_localgroup("") == []
        assert WindowsPrivilegedAccounts._parse_localgroup("no separator here") == []

    def test_privileged_group_members_yields_row(self):
        runner = _FakeRunner({("net", "localgroup", "Administrators"): _NET_LOCALGROUP})
        rows = list(WindowsPrivilegedAccounts(runner).privileged_group_members())
        assert len(rows) == 1
        assert rows[0]["subject"] == "Administrators"
        assert "alice" in rows[0]["detail"]

    def test_no_uid0_concept(self):
        assert list(WindowsPrivilegedAccounts(_FakeRunner()).uid0_accounts()) == []


class TestInstalledAppsParser:
    def test_array_of_apps(self):
        data = [
            {
                "DisplayName": "7-Zip",
                "DisplayVersion": "23.01",
                "InstallLocation": "C:\\Program Files\\7-Zip",
                "PSChildName": "7-Zip",
            },
            {"DisplayName": "Foo", "DisplayVersion": None, "PSChildName": "{guid}"},
        ]
        rows = WindowsInstalledAppsCollector._rows_from_json(data)
        assert [r["name"] for r in rows] == ["7-Zip", "Foo"]
        assert rows[0]["path"] == "C:\\Program Files\\7-Zip"
        assert rows[1]["path"] == ""  # missing InstallLocation → empty

    def test_single_object_is_normalised_to_one_row(self):
        obj = {"DisplayName": "Solo", "PSChildName": "solo"}
        rows = WindowsInstalledAppsCollector._rows_from_json(obj)
        assert len(rows) == 1
        assert rows[0]["bundle_id"] == "solo"

    def test_none_is_empty(self):
        assert WindowsInstalledAppsCollector._rows_from_json(None) == []


class TestLaunchItemsParsers:
    def test_run_keys(self):
        data = [
            {
                "scope": "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "name": "OneDrive",
                "command": "C:\\OneDrive.exe /background",
            }
        ]
        rows = WindowsLaunchItemsCollector._rows_from_run_keys(data)
        assert rows[0]["scope"] == "registry_run"
        assert rows[0]["label"] == "OneDrive"
        assert rows[0]["program"] == "C:\\OneDrive.exe /background"
        assert rows[0]["run_at_load"] == 1

    def test_schtasks_csv_verbose(self):
        # /v CSV: col 1 = TaskName, col 8 = Task To Run (>=9 columns).
        csv_text = (
            '"\\","\\MyTask","Ready","N/A","2026-01-01","Interactive","SYSTEM",'
            '"daily","C:\\evil.exe","x","y"\r\n'
        )
        rows = WindowsLaunchItemsCollector._rows_from_schtasks(csv_text)
        assert len(rows) == 1
        assert rows[0]["scope"] == "scheduled_task"
        assert rows[0]["path"] == "\\MyTask"
        assert rows[0]["label"] == "MyTask"
        assert rows[0]["program"] == "C:\\evil.exe"

    def test_schtasks_skips_header_and_short_rows(self):
        csv_text = (
            'folder,"TaskName","Status",a,b,c,d,e,"Task To Run",x\r\n' "too,short\r\n"
        )
        assert WindowsLaunchItemsCollector._rows_from_schtasks(csv_text) == []

    def test_empty_inputs(self):
        assert WindowsLaunchItemsCollector._rows_from_run_keys(None) == []
        assert WindowsLaunchItemsCollector._rows_from_schtasks("") == []


class TestWindowsHostWiring:
    def test_factory_resolves_windows(self):
        assert isinstance(HostFactory.create("Windows"), WindowsHost)

    def test_collector_set_includes_windows_native(self):
        collectors = WindowsHost().snapshot_collectors(
            Prompts(system="", user_template="")
        )
        names = {c.name for c in collectors}
        assert {"processes", "installed_apps", "launch_items", "hosts_file"} <= names
        # Windows-native posture + device collectors are wired.
        assert {
            "system_integrity",
            "usb_devices",
            "bluetooth_devices",
            "wifi_state",
        } <= names
        # Still no Unix-only concepts on Windows.
        assert "setuid_files" not in names
        assert "quarantine_events" not in names

    def test_streaming_collectors_assembled(self):
        collectors = WindowsHost().streaming_collectors(
            Prompts(system="", user_template="")
        )
        names = {c.name for c in collectors}
        assert names == {"auth_events", "process_exec_events"}
        # Both feed the shared row models so the dashboard treats every OS
        # identically.
        models = {c.model.__name__ for c in collectors}
        assert models == {"AuthEventRow", "ProcessExecRow"}


class TestSystemIntegrityParser:
    def test_maps_posture_into_macos_shaped_row(self):
        data = {
            "defender": {"RealTimeProtectionEnabled": True, "AntivirusEnabled": True},
            "firewall": [
                {"Name": "Domain", "Enabled": "True"},
                {"Name": "Public", "Enabled": False},
            ],
            "bitlocker": {"MountPoint": "C:", "ProtectionStatus": 1},
            "secureboot": True,
            "rdp_deny": 0,
            "winrm": "Running",
        }
        row = WindowsSystemIntegrityCollector._row_from_status(data)
        assert row["filevault_active"] == 1  # BitLocker protected
        assert row["firewall_global_state"] == 1  # at least one profile on
        assert row["gatekeeper_assessments_enabled"] == 1  # Defender/SecureBoot
        assert row["remote_login_enabled"] == 1  # RDP accepting
        assert row["remote_management_enabled"] == 1  # WinRM running

    def test_all_off_posture(self):
        data = {
            "defender": {"RealTimeProtectionEnabled": False},
            "firewall": {"Name": "Public", "Enabled": False},
            "bitlocker": None,
            "secureboot": False,
            "rdp_deny": 1,
            "winrm": "Stopped",
        }
        row = WindowsSystemIntegrityCollector._row_from_status(data)
        assert row["filevault_active"] == 0
        assert row["firewall_global_state"] == 0
        assert row["gatekeeper_assessments_enabled"] == 0
        assert row["remote_login_enabled"] == 0
        assert row["remote_management_enabled"] == 0

    def test_non_dict_is_none(self):
        assert WindowsSystemIntegrityCollector._row_from_status(None) is None


class TestUsbDevicesParser:
    def test_ids_parsed_from_instance(self):
        data = {
            "FriendlyName": "USB Mass Storage Device",
            "InstanceId": "USB\\VID_0781&PID_5583\\0123456789",
            "Manufacturer": "SanDisk",
            "Status": "OK",
        }
        rows = WindowsUsbDevicesCollector._rows_from_json(data)
        assert len(rows) == 1
        assert rows[0]["vendor_id"] == "0781"
        assert rows[0]["product_id"] == "5583"
        assert rows[0]["name"] == "USB Mass Storage Device"

    def test_missing_ids_are_none(self):
        rows = WindowsUsbDevicesCollector._rows_from_json(
            {"FriendlyName": "Hub", "InstanceId": "USB\\ROOT_HUB30\\4&abc"}
        )
        assert rows[0]["vendor_id"] is None
        assert rows[0]["product_id"] is None

    def test_none_is_empty(self):
        assert WindowsUsbDevicesCollector._rows_from_json(None) == []


class TestBluetoothParser:
    def test_address_and_connected(self):
        data = {
            "FriendlyName": "WH-1000XM4",
            "InstanceId": "BTHENUM\\Dev_AABBCCDDEEFF\\7&x",
            "Status": "OK",
        }
        rows = WindowsBluetoothCollector._rows_from_json(data)
        assert rows[0]["address"] == "AABBCCDDEEFF"
        assert rows[0]["connected"] == 1
        assert rows[0]["paired"] == 1

    def test_disconnected_present_device(self):
        rows = WindowsBluetoothCollector._rows_from_json(
            {"FriendlyName": "Mouse", "InstanceId": "x", "Status": "Unknown"}
        )
        assert rows[0]["connected"] == 0
        assert rows[0]["address"] is None


class TestWifiParser:
    _NETSH = """\
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : 00:11:22:33:44:55
    Authentication         : WPA2-Personal
    Channel                : 36
"""

    def test_parses_interface_block(self):
        rows = WindowsWifiCollector._rows_from_netsh(self._NETSH)
        assert len(rows) == 1
        assert rows[0]["interface"] == "Wi-Fi"
        assert rows[0]["ssid"] == "HomeNet"
        # The MAC's own colons survive single-split partition.
        assert rows[0]["bssid"] == "00:11:22:33:44:55"
        assert rows[0]["security"] == "WPA2-Personal"
        assert rows[0]["channel"] == "36"

    def test_preamble_without_name_is_skipped(self):
        assert WindowsWifiCollector._rows_from_netsh("There is 0 interfaces\n") == []

    def test_empty_is_empty(self):
        assert WindowsWifiCollector._rows_from_netsh("") == []


class TestStreamingParsers:
    def test_auth_event_to_row(self):
        event = {
            "TimeCreated": "2026-06-16T12:00:00.000000+00:00",
            "Id": 4625,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "ProcessId": 612,
            "RecordId": 99,
            "Message": "An account failed to log on.",
        }
        row = WinSecurityAuthParser().parse(event)
        assert row["event_timestamp"] == "2026-06-16T12:00:00.000000+00:00"
        assert row["subsystem"] == "Security"
        assert row["category"] == "4625"
        assert row["event_type"] == "event_id=4625"
        assert row["pid"] == 612
        assert "failed to log on" in row["event_message"]

    def test_auth_event_missing_pid_is_none(self):
        row = WinSecurityAuthParser().parse({"Id": 4624, "ProcessId": None})
        assert row["pid"] is None

    def test_exec_event_to_row_with_hex_pids(self):
        event = {
            "TimeCreated": "2026-06-16T12:00:01+00:00",
            "RecordId": 100,
            "Data": {
                "NewProcessId": "0x1a4",
                "ProcessId": "0x4",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "CommandLine": "cmd.exe /c whoami",
                "SubjectUserName": "alice",
            },
        }
        row = WinSecurityExecParser().parse(event)
        assert row["event_type"] == "exec"
        assert row["pid"] == 420  # 0x1a4
        assert row["ppid"] == 4
        assert row["exe_path"] == "C:\\Windows\\System32\\cmd.exe"
        assert row["parent_path"] == "C:\\Windows\\explorer.exe"
        assert row["username"] == "alice"
        assert "/c whoami" in row["exe_args_json"]

    def test_exec_event_empty_data(self):
        row = WinSecurityExecParser().parse({"Data": {}})
        assert row["exe_path"] is None
        assert row["exe_args_json"] is None
        assert row["pid"] is None
