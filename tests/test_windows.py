"""Tests for the WindowsHost parsers and wiring.

The Windows *gather* (subprocess calls) cannot run on this CI host, but
the pure parsers — where the bugs live — are exercised here against
representative command output, exactly as for the macOS/Linux adapters.
"""

from __future__ import annotations

from avai.host_monitor.hosts import HostFactory
from avai.host_monitor.hosts.windows import (
    WindowsHost,
    WindowsInstalledAppsCollector,
    WindowsLaunchItemsCollector,
    WindowsPrivilegedAccounts,
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

    def test_collector_set_composes_out_unix_only(self):
        collectors = WindowsHost().snapshot_collectors(
            Prompts(system="", user_template="")
        )
        names = {c.name for c in collectors}
        assert {"processes", "installed_apps", "launch_items", "hosts_file"} <= names
        # No setuid / quarantine / device collectors on Windows.
        assert "setuid_files" not in names
        assert "quarantine_events" not in names
        assert "usb_devices" not in names

    def test_no_streaming_collectors_yet(self):
        assert (
            WindowsHost().streaming_collectors(Prompts(system="", user_template=""))
            == []
        )
