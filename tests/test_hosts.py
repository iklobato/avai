"""Tests for the Host abstraction, the HostFactory detection point, and
the per-OS capability adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from avai.host_monitor.hosts import HostFactory
from avai.host_monitor.hosts.linux import (
    LinuxFilesystemLayout,
    LinuxHost,
    LinuxPrivilegedAccounts,
)
from avai.host_monitor.hosts.macos import (
    MacOSFilesystemLayout,
    MacOSHost,
    MacOSPrivilegedAccounts,
)
from avai.host_monitor.prompts import Prompts


class _FakeRunner:
    """CommandRunner stand-in returning canned text per command."""

    def __init__(self, responses: dict[tuple, str]) -> None:
        self._responses = responses

    def text(self, cmd: list[str], timeout: int = 10) -> str:
        return self._responses.get(tuple(cmd), "")


class TestHostFactory:
    def test_resolves_each_known_platform(self):
        assert isinstance(HostFactory.create("Darwin"), MacOSHost)
        assert isinstance(HostFactory.create("Linux"), LinuxHost)

    def test_unknown_platform_raises_loudly(self):
        with pytest.raises(RuntimeError) as exc:
            HostFactory.create("Plan9")
        assert "Plan9" in str(exc.value)

    def test_default_uses_current_platform(self):
        # Whatever this test host is, it must resolve to *some* Host with
        # the collector-assembly interface — never the silent-macOS default.
        host = HostFactory.create()
        assert hasattr(host, "snapshot_collectors")
        assert hasattr(host, "streaming_collectors")


class TestFilesystemLayouts:
    def test_macos_uses_native_paths(self):
        fs = MacOSFilesystemLayout()
        assert fs.hosts_file() == Path("/etc/hosts")
        assert fs.sudoers_file() == Path("/etc/sudoers")
        assert fs.tcpdump_interface_args() == ["-k", "I"]
        assert Path("/usr/bin") in fs.privileged_bin_dirs()

    def test_linux_uses_any_interface_and_opt_in_bin_dirs(self):
        fs = LinuxFilesystemLayout()
        assert fs.tcpdump_interface_args() == ["-i", "any"]
        # Linux scans /opt too; macOS does not.
        assert Path("/opt") in fs.privileged_bin_dirs()

    def test_layouts_are_distinct_per_os(self):
        assert (
            MacOSFilesystemLayout().tcpdump_interface_args()
            != LinuxFilesystemLayout().tcpdump_interface_args()
        )


class TestMacOSPrivilegedAccounts:
    def test_parses_dscl_group_membership(self):
        runner = _FakeRunner(
            {
                ("dscl", ".", "-read", "/Groups/admin", "GroupMembership"): (
                    "GroupMembership: alice bob"
                ),
                ("dscl", ".", "-read", "/Groups/wheel", "GroupMembership"): "",
            }
        )
        rows = list(MacOSPrivilegedAccounts(runner).privileged_group_members())
        assert len(rows) == 1
        assert rows[0]["subject"] == "admin"
        assert rows[0]["detail"] == "alice bob"
        assert rows[0]["source_path"] == "dscl:/Groups"

    def test_parses_dscl_uid0_accounts(self):
        runner = _FakeRunner(
            {
                ("dscl", ".", "-list", "/Users", "UniqueID"): (
                    "root 0\ndaemon 1\n_backdoor 0\n"
                ),
            }
        )
        rows = list(MacOSPrivilegedAccounts(runner).uid0_accounts())
        assert sorted(r["subject"] for r in rows) == ["_backdoor", "root"]


class TestLinuxPrivilegedAccountsReadFiles:
    def test_reads_and_parses_group_file(self, tmp_path, monkeypatch):
        group = tmp_path / "group"
        group.write_text("sudo:x:27:alice\nstaff:x:50:bob\n")
        # host_path is identity when HOST_PREFIX is unset; point the reader
        # at our temp file by patching host_path for /etc/group.
        import avai.host_monitor.hosts.linux as linux_mod

        monkeypatch.setattr(linux_mod, "host_path", lambda p: group)
        rows = list(LinuxPrivilegedAccounts().privileged_group_members())
        assert len(rows) == 1
        assert rows[0]["subject"] == "sudo"


class TestHostWiring:
    def test_macos_host_injects_capabilities_into_collectors(self):
        host = MacOSHost()
        collectors = host.snapshot_collectors(Prompts(system="", user_template=""))
        by_name = {c.name: c for c in collectors}
        # Quarantine is macOS-only and must be present.
        assert "quarantine_events" in by_name
        # The path/account collectors must have their capability injected.
        assert by_name["hosts_file"]._fs is not None
        assert by_name["setuid_files"]._fs is not None
        assert by_name["privilege_config"]._accounts is not None

    def test_linux_host_drops_macos_only_and_wires_capabilities(self):
        host = LinuxHost()
        collectors = host.snapshot_collectors(Prompts(system="", user_template=""))
        names = {c.name for c in collectors}
        # Linux composes OUT the macOS-only quarantine collector — by
        # absence, not a runtime branch.
        assert "quarantine_events" not in names
        assert "hosts_file" in names

    def test_streaming_sets_differ_per_os(self):
        mac = {c.name for c in MacOSHost().streaming_collectors(Prompts(system="", user_template=""))}
        linux = {c.name for c in LinuxHost().streaming_collectors(Prompts(system="", user_template=""))}
        assert mac == linux == {"auth_events", "process_exec_events"}
