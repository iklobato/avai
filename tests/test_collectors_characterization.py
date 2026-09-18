"""Characterization tests for the collectors the rest of the suite does not
reach. They pin today's rows through ``collect()``, faking the OS at the
module boundary (``subprocess.run``, ``shutil.which``, ``psutil``) or with a
temp tree under ``HOST_PREFIX`` / ``HOME``, so they keep passing while the
collectors move between modules."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from avai.host_monitor import constants
from avai.host_monitor.collectors import (
    BluetoothCollector,
    BrowserExtensionsCollector,
    DnsQueriesCollector,
    FileIntegrityCollector,
    HostsFileCollector,
    InstalledAppsCollector,
    KernelExtensionsCollector,
    LaunchItemsCollector,
    LinuxAuthEventsCollector,
    LinuxBluetoothCollector,
    LinuxInstalledAppsCollector,
    LinuxProcessExecCollector,
    LinuxSystemIntegrityCollector,
    LinuxUsbDevicesCollector,
    LinuxWifiCollector,
    ListeningPortsCollector,
    LogTailCollector,
    MdmProfilesCollector,
    MountsCollector,
    NetworkFlowsCollector,
    NetworkInterfacesCollector,
    PrivilegeConfigCollector,
    ProcessCollector,
    ProcessConnectionResolver,
    QuarantineCollector,
    SetuidFilesCollector,
    SshAuthorizedKeysCollector,
    SystemExtensionsCollector,
    SystemIntegrityCollector,
    UsbDevicesCollector,
    WifiCollector,
)
from avai.host_monitor.enums import Browser
from avai.host_monitor.runtime import HostPaths


# These classes drive the macOS and Linux collectors over a fake POSIX
# layout (forward-slash joins, a sysfs name with a colon). Those collectors
# never run on Windows, where the paths and file names do not hold.
_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="macOS / Linux collector over a POSIX layout"
)


class FakeRun:
    """Stands in for ``subprocess.run``. ``answer(cmd)`` returns
    ``(stdout, returncode, stderr)`` as text, or an exception to raise;
    bytes are handed back unless the caller asked for ``text=True``."""

    def __init__(self, answer):
        self._answer = answer
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        result = self._answer(list(cmd))
        if isinstance(result, BaseException):
            raise result
        stdout, returncode, stderr = result
        if not kwargs.get("text"):
            stdout, stderr = stdout.encode(), stderr.encode()
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)


def _on_path(monkeypatch, *tools):
    monkeypatch.setattr(
        shutil, "which", lambda name: f"/usr/bin/{name}" if name in tools else None
    )


def _fake_run(monkeypatch, answer) -> FakeRun:
    run = FakeRun(answer)
    monkeypatch.setattr(subprocess, "run", run)
    return run


@pytest.fixture
def host_root(tmp_path, monkeypatch):
    """A container-style host tree: every translated path lands under it."""
    monkeypatch.setattr(constants, "HOST_PREFIX", str(tmp_path))
    return tmp_path


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class FakeServices:
    def __init__(self, enabled):
        self._enabled = enabled

    def enabled(self, unit):
        return self._enabled


class FakePorts:
    def __init__(self, listening=0, established=0):
        self._listening, self._established = listening, established

    def listening(self, port):
        return self._listening

    def established(self, port):
        return self._established


class FakeProcesses:
    def running(self, name):
        return 0


# ---- psutil-backed collectors -------------------------------------------


class TestProcessCollector:
    def test_row_per_process_with_uid_and_rss(self, monkeypatch):
        info = {
            "pid": 7,
            "ppid": 1,
            "name": "sshd",
            "exe": "/usr/sbin/sshd",
            "cmdline": ["sshd", "-D"],
            "username": "root",
            "uids": (0, 0, 0),
            "status": "sleeping",
            "create_time": 1.5,
            "cpu_percent": 0.1,
            "memory_info": SimpleNamespace(rss=4096),
            "num_fds": 5,
            "num_threads": 1,
        }
        bare = {"pid": 8, "memory_info": None, "uids": None, "cmdline": None}
        monkeypatch.setattr(
            psutil,
            "process_iter",
            lambda attrs, ad_value=None: [
                SimpleNamespace(info=info),
                SimpleNamespace(info=bare),
            ],
        )
        full, empty = list(ProcessCollector().collect())
        assert full["uid"] == 0
        assert full["memory_rss"] == 4096
        assert full["cmdline_json"] == '["sshd", "-D"]'
        assert empty["uid"] is None
        assert empty["memory_rss"] is None
        assert empty["cmdline_json"] == "[]"


def _conn(status, pid, port=22, raddr=None):
    return SimpleNamespace(
        status=status,
        pid=pid,
        family=SimpleNamespace(name="AF_INET"),
        type=SimpleNamespace(name="SOCK_STREAM"),
        laddr=SimpleNamespace(ip="0.0.0.0", port=port),
        raddr=raddr,
    )


class TestListeningPortsCollector:
    def test_only_listeners_named_once_per_pid(self, monkeypatch):
        conns = [
            _conn(psutil.CONN_LISTEN, 10, 22),
            _conn(psutil.CONN_LISTEN, 10, 2222),
            _conn(psutil.CONN_ESTABLISHED, 11, 5000),
            _conn(psutil.CONN_LISTEN, 12, 80),
            _conn(psutil.CONN_LISTEN, None, 53),
        ]
        looked_up = []

        def process(pid):
            looked_up.append(pid)
            if pid == 12:
                raise psutil.AccessDenied(pid)
            return SimpleNamespace(name=lambda: "sshd")

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
        monkeypatch.setattr(psutil, "Process", process)
        rows = list(ListeningPortsCollector().collect())
        assert [(r["laddr_port"], r["process_name"]) for r in rows] == [
            (22, "sshd"),
            (2222, "sshd"),
            (80, None),
            (53, None),
        ]
        assert looked_up == [10, 12]


class TestProcessConnectionResolver:
    def test_access_denied_gives_an_empty_map(self, monkeypatch):
        def denied(kind="inet"):
            raise psutil.AccessDenied()

        monkeypatch.setattr(psutil, "net_connections", denied)
        assert ProcessConnectionResolver().snapshot() == {}

    def test_vanished_process_is_labelled_by_pid_and_first_owner_wins(
        self, monkeypatch
    ):
        peer = SimpleNamespace(ip="8.8.8.8", port=443)
        conns = [
            _conn("ESTABLISHED", 40, raddr=peer),
            _conn("ESTABLISHED", 41, raddr=peer),
        ]

        def gone(pid):
            raise psutil.NoSuchProcess(pid)

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
        monkeypatch.setattr(psutil, "Process", gone)
        assert ProcessConnectionResolver().snapshot() == {
            ("8.8.8.8", 443): ("pid 40", 40)
        }


class TestNetworkInterfacesCollector:
    def test_joins_addresses_stats_and_counters_by_name(self, monkeypatch):
        addr = SimpleNamespace(
            family=SimpleNamespace(name="AF_INET"),
            address="10.0.0.5",
            netmask="255.255.255.0",
            broadcast=None,
        )
        counters = SimpleNamespace(
            bytes_sent=1,
            bytes_recv=2,
            packets_sent=3,
            packets_recv=4,
            errin=0,
            errout=0,
            dropin=0,
            dropout=0,
        )
        monkeypatch.setattr(
            psutil, "net_if_addrs", lambda: {"en0": [addr], "utun9": []}
        )
        monkeypatch.setattr(
            psutil,
            "net_if_stats",
            lambda: {"en0": SimpleNamespace(isup=True, speed=1000, mtu=1500)},
        )
        monkeypatch.setattr(
            psutil, "net_io_counters", lambda pernic=True: {"en0": counters}
        )
        en0, utun = list(NetworkInterfacesCollector().collect())
        assert (en0["is_up"], en0["mtu"], en0["bytes_recv"]) == (1, 1500, 2)
        assert json.loads(en0["addresses_json"])[0]["address"] == "10.0.0.5"
        assert (utun["is_up"], utun["bytes_sent"], utun["addresses_json"]) == (
            None,
            None,
            "[]",
        )


class TestMountsCollector:
    def test_row_per_partition(self, monkeypatch):
        part = SimpleNamespace(
            device="/dev/disk1s1", mountpoint="/", fstype="apfs", opts="rw"
        )
        monkeypatch.setattr(psutil, "disk_partitions", lambda all=True: [part])
        (row,) = MountsCollector().collect()
        assert (row["device"], row["mountpoint"]) == ("/dev/disk1s1", "/")
        assert json.loads(row["raw_json"])["maxfile"] is None

    def test_access_denied_yields_nothing(self, monkeypatch):
        def denied(all=True):
            raise psutil.AccessDenied()

        monkeypatch.setattr(psutil, "disk_partitions", denied)
        assert list(MountsCollector().collect()) == []


# ---- tcpdump capture ----------------------------------------------------


class TestTcpdumpCapture:
    def test_flows_capture_needs_tcpdump(self, monkeypatch):
        _on_path(monkeypatch)
        with pytest.raises(RuntimeError, match="tcpdump not found"):
            NetworkFlowsCollector()._capture()

    def test_flows_capture_reads_banner_iface_and_passes_iface_args(self, monkeypatch):
        _on_path(monkeypatch, "tcpdump")
        run = _fake_run(
            monkeypatch,
            lambda cmd: (
                "IP 1.1.1.1.5 > 2.2.2.2.443: tcp 10\n",
                0,
                "listening on en0, link",
            ),
        )
        stdout, iface = NetworkFlowsCollector(iface_args=["-k", "I"])._capture()
        assert iface == "en0"
        assert stdout.startswith("IP 1.1.1.1.5")
        assert run.calls[0][:7] == ["tcpdump", "-n", "-q", "-l", "-t", "-c", "2000"]
        assert run.calls[0][7:] == ["-k", "I", "tcp", "or", "udp"]

    def test_flows_capture_keeps_partial_output_on_timeout(self, monkeypatch):
        _on_path(monkeypatch, "tcpdump")
        _fake_run(
            monkeypatch,
            lambda cmd: subprocess.TimeoutExpired(
                cmd, 8, output=b"partial", stderr=b"listening on pktap, link"
            ),
        )
        assert NetworkFlowsCollector()._capture() == ("partial", None)

    def test_dns_capture_filters_port_53_and_keeps_partial_output(self, monkeypatch):
        _on_path(monkeypatch, "tcpdump")
        run = _fake_run(
            monkeypatch,
            lambda cmd: subprocess.TimeoutExpired(
                cmd, 8, output=None, stderr="listening on eth0, link"
            ),
        )
        assert DnsQueriesCollector()._capture() == ("", "eth0")
        assert run.calls[0][-7:] == ["udp", "port", "53", "or", "tcp", "port", "53"]

    def test_dns_capture_needs_tcpdump(self, monkeypatch):
        _on_path(monkeypatch)
        with pytest.raises(RuntimeError, match="tcpdump not found"):
            DnsQueriesCollector()._capture()


class _FakeResolver:
    def __init__(self, mapping):
        self._mapping = mapping

    def snapshot(self):
        return self._mapping


class TestDnsDoh:
    def test_connection_to_a_doh_resolver_is_reported_once(self, monkeypatch):
        c = DnsQueriesCollector(
            resolver=_FakeResolver(
                {
                    ("1.1.1.1", 443): ("firefox", 9),
                    ("1.1.1.1", 80): ("curl", 10),
                    ("5.5.5.5", 443): ("curl", 11),
                }
            )
        )
        monkeypatch.setattr(c, "_capture", lambda: ("", None))
        (row,) = c.collect()
        assert (row["qname"], row["qtype"], row["server_ip"], row["process"]) == (
            "Cloudflare",
            "DoH",
            "1.1.1.1",
            "firefox",
        )


# ---- macOS system_profiler collectors -----------------------------------


def _profiler(monkeypatch, payload: dict) -> FakeRun:
    return _fake_run(monkeypatch, lambda cmd: (json.dumps(payload), 0, ""))


class TestSystemProfilerCollectors:
    def test_usb_walks_nested_items_inheriting_location(self, monkeypatch):
        run = _profiler(
            monkeypatch,
            {
                "SPUSBDataType": [
                    {
                        "_name": "hub",
                        "location_id": "0x14",
                        "_items": [{"_name": "YubiKey", "vendor_id": "0x1050"}],
                    }
                ]
            },
        )
        hub, key = UsbDevicesCollector().collect()
        assert run.calls[0] == ["system_profiler", "-json", "SPUSBDataType"]
        assert (key["name"], key["location_id"]) == ("YubiKey", "0x14")
        assert "_items" not in json.loads(hub["raw_json"])

    def test_bluetooth_flags_connected_and_paired_groups(self, monkeypatch):
        _profiler(
            monkeypatch,
            {
                "SPBluetoothDataType": [
                    {
                        "device_connected": [
                            {
                                "AirPods": {
                                    "device_address": "AA",
                                    "device_minorType": "Headphones",
                                }
                            }
                        ],
                        "devices_list": [{"Mouse": {"device_address": "BB"}}, "junk"],
                    }
                ]
            },
        )
        rows = list(BluetoothCollector().collect())
        assert [(r["name"], r["connected"], r["paired"]) for r in rows] == [
            ("AirPods", 1, 1),
            ("Mouse", 0, 0),
        ]

    def test_wifi_reads_current_network(self, monkeypatch):
        _profiler(
            monkeypatch,
            {
                "SPAirPortDataType": [
                    {
                        "spairport_airport_interfaces": [
                            {
                                "_name": "en0",
                                "spairport_current_network_information": {
                                    "_name": "home",
                                    "spairport_network_channel": 36,
                                    "spairport_security_mode": "wpa3",
                                },
                            },
                            {"_name": "awdl0"},
                        ]
                    }
                ]
            },
        )
        en0, awdl = WifiCollector().collect()
        assert (en0["ssid"], en0["channel"], en0["security"]) == ("home", "36", "wpa3")
        assert (awdl["ssid"], awdl["channel"]) == (None, None)

    def test_mdm_profiles_walk_nested_groups(self, monkeypatch):
        _profiler(
            monkeypatch,
            {
                "SPConfigurationProfileDataType": [
                    {
                        "_name": "group",
                        "_items": [
                            {
                                "_name": "Corp VPN",
                                "spconfigprofile_profile_identifier": "com.corp.vpn",
                                "spconfigprofile_profile_scope": "System",
                            }
                        ],
                    }
                ]
            },
        )
        (row,) = MdmProfilesCollector().collect()
        assert (row["identifier"], row["display_name"], row["profile_scope"]) == (
            "com.corp.vpn",
            "Corp VPN",
            "System",
        )

    def test_mdm_profiles_command_failure_yields_nothing(self, monkeypatch):
        _fake_run(monkeypatch, lambda cmd: ("", 1, "boom"))
        assert list(MdmProfilesCollector().collect()) == []

    def test_kernel_extensions_keep_listed_fields_only(self, monkeypatch):
        _profiler(
            monkeypatch,
            {
                "SPExtensionsDataType": [
                    {
                        "_name": "Foo",
                        "spext_bundleid": "com.foo.kext",
                        "spext_signed_by": "Developer ID",
                        "spext_architectures": ["x86_64"],
                    },
                    "junk",
                ]
            },
        )
        (row,) = KernelExtensionsCollector().collect()
        assert (row["bundle_id"], row["signing_id"], row["team_id"]) == (
            "com.foo.kext",
            "Developer ID",
            None,
        )
        assert "spext_architectures" not in json.loads(row["raw_json"])

    def test_kernel_extensions_non_dict_output_yields_nothing(self, monkeypatch):
        _fake_run(monkeypatch, lambda cmd: ("[]", 0, ""))
        assert list(KernelExtensionsCollector().collect()) == []


class TestMacSystemIntegrity:
    @pytest.mark.parametrize(
        "spctl,expected",
        [
            ("assessments enabled\n", 1),
            ("assessments disabled\n", 0),
            ("???", None),
        ],
    )
    def test_gatekeeper_state_from_spctl_text(self, monkeypatch, spctl, expected):
        def answer(cmd):
            if cmd[0] == "spctl":
                return (spctl, 0, "")
            return ("", 0, "")  # fdesetup isactive: exit 0 means on

        _fake_run(monkeypatch, answer)
        monkeypatch.setattr(HostPaths, "read_plist", staticmethod(lambda p: None))
        col = SystemIntegrityCollector(
            services=FakeServices(0), ports=FakePorts(), processes=FakeProcesses()
        )
        (row,) = col.collect()
        assert row["gatekeeper_assessments_enabled"] == expected
        assert row["filevault_active"] == 1
        assert row["firewall_stealth"] is None

    def test_missing_tools_read_as_unknown(self, monkeypatch):
        _fake_run(monkeypatch, lambda cmd: FileNotFoundError(cmd[0]))
        monkeypatch.setattr(
            HostPaths,
            "read_plist",
            staticmethod(lambda p: {"globalstate": 1, "stealthenabled": True}),
        )
        col = SystemIntegrityCollector(
            services=FakeServices(0), ports=FakePorts(), processes=FakeProcesses()
        )
        (row,) = col.collect()
        assert row["filevault_active"] is None
        assert row["gatekeeper_assessments_enabled"] is None
        assert (row["firewall_global_state"], row["firewall_stealth"]) == (1, 1)


# ---- macOS file-backed collectors ---------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _plist(path: Path, data: dict) -> Path:
    import plistlib

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(data))
    return path


@_posix_only
class TestMacFileCollectors:
    def test_user_launch_agent_row(self, home):
        agent = _plist(
            home / "Library" / "LaunchAgents" / "com.evil.plist",
            {
                "Label": "com.evil",
                "ProgramArguments": ["/tmp/x", "-q"],
                "RunAtLoad": True,
                "StartCalendarInterval": {"Hour": 3},
            },
        )
        _write(home / "Library" / "LaunchAgents" / "broken.plist", "not a plist")
        rows = [
            r
            for r in LaunchItemsCollector().collect()
            if r["path"].startswith(str(home))
        ]
        assert [r["path"] for r in rows] == [str(agent)]
        (row,) = rows
        assert (row["label"], row["run_at_load"], row["keep_alive"]) == (
            "com.evil",
            1,
            0,
        )
        assert json.loads(row["start_calendar_interval_json"]) == {"Hour": 3}
        assert row["sha256"] and len(row["sha256"]) == 64

    def test_quarantine_events_renamed_columns(self, home):
        db = (
            home
            / "Library"
            / "Preferences"
            / "com.apple.LaunchServices.QuarantineEventsV2"
        )
        db.parent.mkdir(parents=True)
        con = sqlite3.connect(db)
        con.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT,"
            " LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT,"
            " LSQuarantineAgentName TEXT, LSQuarantineOriginURLString TEXT,"
            " LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT,"
            " LSQuarantineTypeNumber INTEGER)"
        )
        con.execute(
            "INSERT INTO LSQuarantineEvent VALUES"
            " ('E1', 1.0, 'com.google.Chrome', 'Chrome', 'https://x', 'https://x/a.dmg', NULL, 0)"
        )
        con.commit()
        con.close()
        (row,) = QuarantineCollector().collect()
        assert (row["event_id"], row["agent_name"], row["data_url"]) == (
            "E1",
            "Chrome",
            "https://x/a.dmg",
        )

    def test_quarantine_without_db_yields_nothing(self, home):
        assert list(QuarantineCollector().collect()) == []

    def test_user_application_row(self, home):
        _plist(
            home / "Applications" / "Tool.app" / "Contents" / "Info.plist",
            {
                "CFBundleIdentifier": "com.tool",
                "CFBundleDisplayName": "Tool",
                "CFBundleShortVersionString": "1.2",
            },
        )
        (row,) = [
            r
            for r in InstalledAppsCollector().collect()
            if r["path"].startswith(str(home))
        ]
        assert (row["bundle_id"], row["name"], row["version"]) == (
            "com.tool",
            "Tool",
            "1.2",
        )

    def test_system_extensions_from_db_plist(self, monkeypatch):
        db = {
            "extensions": [
                {
                    "identifier": "com.vpn.ext",
                    "teamID": "ABC123",
                    "bundleVersion": {"CFBundleVersion": "7"},
                    "categories": ["com.apple.system_extension.network_extension"],
                    "state": "activated_enabled",
                },
                "junk",
            ]
        }
        monkeypatch.setattr(HostPaths, "read_plist", staticmethod(lambda p: db))
        (row,) = SystemExtensionsCollector().collect()
        assert (row["bundle_id"], row["version"], row["state"]) == (
            "com.vpn.ext",
            "7",
            "activated_enabled",
        )
        assert row["categories"] == "com.apple.system_extension.network_extension"

    def test_system_extensions_without_db_yields_nothing(self, monkeypatch):
        monkeypatch.setattr(HostPaths, "read_plist", staticmethod(lambda p: None))
        assert list(SystemExtensionsCollector().collect()) == []


class _Reader:
    def read(self, base, browser):
        yield {"browser": str(browser), "base": str(base)}


class TestBrowserExtensionsCollector:
    def test_reads_each_existing_profile_root_with_its_reader(self, tmp_path):
        present = tmp_path / "chrome"
        present.mkdir()
        col = BrowserExtensionsCollector(
            default_reader=_Reader(),
            profiles={Browser.CHROME: [str(present), str(tmp_path / "absent")]},
        )
        assert list(col.collect()) == [
            {"browser": str(Browser.CHROME), "base": str(present)}
        ]


class TestFileIntegrityCollector:
    def test_present_and_missing_files(self, tmp_path):
        present = _write(tmp_path / "sudoers", "root ALL=(ALL) ALL\n")
        missing = tmp_path / "gone"
        rows = list(
            FileIntegrityCollector(watched=[str(present), str(missing)]).collect()
        )
        assert [(r["path"], r["exists_flag"]) for r in rows] == [
            (str(present), 1),
            (str(missing), 0),
        ]
        assert rows[0]["size"] == present.stat().st_size
        assert rows[1]["sha256"] is None


# ---- filesystem-layout collectors ---------------------------------------


class _Fs:
    def __init__(self, tmp_path: Path):
        self.root = tmp_path

    def privileged_bin_dirs(self):
        return [self.root / "bin", self.root / "no-such-dir"]

    def home_dirs(self):
        return [self.root / "home" / "alice"]

    def hosts_file(self):
        return self.root / "hosts"

    def sudoers_file(self):
        return self.root / "sudoers"

    def sudoers_dir(self):
        return self.root / "sudoers.d"


class _Accounts:
    def privileged_group_members(self):
        yield {
            "kind": "group",
            "subject": "alice",
            "detail": "admin",
            "source_path": "g",
        }

    def uid0_accounts(self):
        return []


@_posix_only
class TestLayoutCollectors:
    def test_setuid_and_setgid_files_only(self, tmp_path):
        suid = _write(tmp_path / "bin" / "passwd", "x")
        suid.chmod(0o4755)
        _write(tmp_path / "bin" / "ls", "x").chmod(0o755)
        (row,) = SetuidFilesCollector(fs=_Fs(tmp_path)).collect()
        assert (row["path"], row["setuid"], row["setgid"]) == (str(suid), 1, 0)
        assert json.loads(row["raw_json"])["mode"] == oct(row["mode"])

    def test_authorized_keys_from_both_files(self, tmp_path):
        ssh = tmp_path / "home" / "alice" / ".ssh"
        _write(ssh / "authorized_keys", "ssh-ed25519 AAAAC3Nza alice@laptop\n")
        _write(ssh / "authorized_keys2", 'from="10.0.0.1" ssh-rsa AAAAB3Nza\n')
        rows = list(SshAuthorizedKeysCollector(fs=_Fs(tmp_path)).collect())
        assert [(r["owner"], r["key_type"], r["options"]) for r in rows] == [
            ("alice", "ssh-ed25519", None),
            ("alice", "ssh-rsa", 'from="10.0.0.1"'),
        ]

    def test_hosts_file_rows_and_missing_file(self, tmp_path):
        fs = _Fs(tmp_path)
        assert list(HostsFileCollector(fs=fs).collect()) == []
        _write(tmp_path / "hosts", "127.0.0.1 localhost\n6.6.6.6 bank.com\n")
        rows = list(HostsFileCollector(fs=fs).collect())
        assert [r["hostnames"] for r in rows] == ["localhost", "bank.com"]

    def test_sudoers_file_and_drop_ins_then_accounts(self, tmp_path):
        _write(tmp_path / "sudoers", "Defaults env_reset\nroot ALL=(ALL) ALL\n")
        _write(tmp_path / "sudoers.d" / "10-deploy", "deploy ALL=NOPASSWD: ALL\n")
        rows = list(
            PrivilegeConfigCollector(fs=_Fs(tmp_path), accounts=_Accounts()).collect()
        )
        assert [(r["kind"], r["subject"]) for r in rows] == [
            ("sudoers", "root"),
            ("sudoers", "deploy"),
            ("group", "alice"),
        ]


# ---- Linux collectors under HOST_PREFIX ---------------------------------


@_posix_only
class TestLinuxDevices:
    def test_usb_devices_skip_interfaces_and_empty_hubs(self, host_root):
        devices = host_root / "sys" / "bus" / "usb" / "devices"
        _write(devices / "1-1" / "idVendor", "1050\n")
        _write(devices / "1-1" / "product", "YubiKey\n")
        _write(devices / "1-1:1.0" / "idVendor", "1050\n")
        (devices / "usb1").mkdir()
        (row,) = LinuxUsbDevicesCollector().collect()
        assert (row["name"], row["vendor_id"], row["location_id"]) == (
            "YubiKey",
            "1050",
            "1-1",
        )

    def test_usb_without_sysfs_yields_nothing(self, host_root):
        assert list(LinuxUsbDevicesCollector().collect()) == []

    def test_bluetooth_paired_devices_from_bluez_info(self, host_root):
        dev = host_root / "var" / "lib" / "bluetooth" / "AA_BB" / "11_22_33"
        _write(dev / "info", "[General]\nName=Keyboard\nClass=0x000540\n")
        (dev.parent / "no_info_dev").mkdir()
        (row,) = LinuxBluetoothCollector().collect()
        assert (row["name"], row["address"], row["paired"], row["connected"]) == (
            "Keyboard",
            "11:22:33",
            1,
            0,
        )

    def test_wifi_reads_iw_link(self, host_root, monkeypatch):
        net = host_root / "sys" / "class" / "net"
        (net / "wlan0" / "wireless").mkdir(parents=True)
        (net / "eth0").mkdir()
        _on_path(monkeypatch, "iw")
        _fake_run(
            monkeypatch,
            lambda cmd: (
                "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: home\n\tfreq: 5180\n",
                0,
                "",
            ),
        )
        (row,) = LinuxWifiCollector().collect()
        assert (row["interface"], row["ssid"], row["bssid"], row["channel"]) == (
            "wlan0",
            "home",
            "aa:bb:cc:dd:ee:ff",
            "5180",
        )

    def test_wifi_without_iw_still_lists_the_interface(self, host_root, monkeypatch):
        (host_root / "sys" / "class" / "net" / "wlan0" / "wireless").mkdir(parents=True)
        _on_path(monkeypatch)
        (row,) = LinuxWifiCollector().collect()
        assert (row["interface"], row["ssid"], row["raw_json"]) == ("wlan0", None, "{}")

    def test_wifi_not_connected_and_failed_iw(self, host_root, monkeypatch):
        (host_root / "sys" / "class" / "net" / "wlan0" / "wireless").mkdir(parents=True)
        _on_path(monkeypatch, "iw")
        _fake_run(monkeypatch, lambda cmd: ("Not connected.\n", 0, ""))
        (row,) = LinuxWifiCollector().collect()
        assert json.loads(row["raw_json"]) == {"connected": "no"}
        _fake_run(monkeypatch, lambda cmd: ("", 1, "nl80211 not found"))
        (row,) = LinuxWifiCollector().collect()
        assert row["raw_json"] == "{}"


@_posix_only
class TestLinuxInstalledApps:
    DPKG = (
        "installed\tcurl\t8.5\tamd64\tcommand line tool\n"
        "config-files\told\t1.0\tamd64\tgone\n"
        "short\tline\n"
    )

    def test_installed_dpkg_packages_and_desktop_entries(self, host_root, monkeypatch):
        _on_path(monkeypatch, "dpkg-query")
        run = _fake_run(monkeypatch, lambda cmd: (self.DPKG, 0, ""))
        (host_root / "var" / "lib" / "dpkg").mkdir(parents=True)
        _write(
            host_root / "usr" / "share" / "applications" / "code.desktop",
            "[Desktop Entry]\nName=Code\nExec=code %F\nNoDisplay=true\n",
        )
        _write(
            host_root / "usr" / "share" / "applications" / "bad.desktop",
            "[Other]\nName=x\n",
        )
        rows = list(LinuxInstalledAppsCollector().collect())
        assert [(r["path"], r["name"]) for r in rows] == [
            ("dpkg:curl", "curl"),
            (str(host_root / "usr/share/applications/code.desktop"), "Code"),
        ]
        assert json.loads(rows[1]["raw_json"])["no_display"] is True
        assert run.calls[0][:3] == [
            "dpkg-query",
            "--admindir",
            str(host_root / "var/lib/dpkg"),
        ]

    def test_dpkg_failure_yields_no_package_rows(self, host_root, monkeypatch):
        _on_path(monkeypatch, "dpkg-query")
        _fake_run(monkeypatch, lambda cmd: (self.DPKG, 2, ""))
        assert list(LinuxInstalledAppsCollector().collect()) == []

    def test_dpkg_timeout_yields_no_package_rows(self, host_root, monkeypatch):
        _on_path(monkeypatch, "dpkg-query")
        _fake_run(monkeypatch, lambda cmd: subprocess.TimeoutExpired(cmd, 30))
        assert list(LinuxInstalledAppsCollector().collect()) == []


@_posix_only
class TestLinuxSystemIntegrity:
    def _collect(self, **kw):
        col = LinuxSystemIntegrityCollector(
            services=FakeServices(0),
            ports=FakePorts(**kw),
            processes=FakeProcesses(),
        )
        (row,) = col.collect()
        return row, json.loads(row["raw_json"])

    def test_hardened_host(self, host_root, monkeypatch):
        _write(host_root / "sys/fs/selinux/enforce", "1\n")
        _write(host_root / "sys/module/apparmor/parameters/enabled", "Y\n")
        _write(host_root / "etc/ufw/ufw.conf", '# comment\nENABLED="yes"\n')
        _on_path(monkeypatch, "dmsetup")

        def answer(cmd):
            if cmd[0] == "dmsetup":
                return ("luks-root\t(253:0)\n", 0, "")
            active = cmd[-1] in ("firewalld", "xrdp")
            return ("active\n" if active else "inactive\n", 0 if active else 3, "")

        _fake_run(monkeypatch, answer)
        row, raw = self._collect()
        assert (raw["selinux"], raw["apparmor"], raw["ufw_active"]) == (
            "Enforcing",
            {"enabled": True},
            True,
        )
        assert raw["firewalld_active"] is True
        assert raw["luks_mappings"] == 1
        assert row["filevault_active"] == 1
        assert row["firewall_global_state"] == 1
        assert row["gatekeeper_assessments_enabled"] == 1
        assert row["screen_sharing_enabled"] == 1

    def test_bare_host(self, host_root, monkeypatch):
        _write(host_root / "sys/fs/selinux/enforce", "0\n")
        _write(host_root / "etc/ufw/ufw.conf", "ENABLED=no\n")
        _on_path(monkeypatch, "dmsetup")

        def answer(cmd):
            if cmd[0] == "dmsetup":
                return ("No devices found\n", 0, "")
            return FileNotFoundError(cmd[0])

        _fake_run(monkeypatch, answer)
        row, raw = self._collect()
        assert (raw["selinux"], raw["apparmor"], raw["ufw_active"]) == (
            "Permissive",
            {"enabled": False},
            False,
        )
        assert raw["luks_mappings"] == 0
        assert row["gatekeeper_assessments_enabled"] == 0
        assert row["screen_sharing_enabled"] == 0

    def test_vnc_port_listening_counts_as_enabled(self, host_root, monkeypatch):
        _on_path(monkeypatch)
        _fake_run(monkeypatch, lambda cmd: subprocess.TimeoutExpired(cmd, 5))
        row, raw = self._collect(listening=1, established=1)
        assert raw["selinux"] is None
        assert row["screen_sharing_enabled"] == 1
        assert raw["services"]["screen_sharing"] == {"enabled": 1, "active": 1}
        assert row["filevault_active"] == 0


@_posix_only
class TestLinuxStreamCommands:
    def test_auth_events_fall_back_to_the_runtime_journal(self, host_root):
        (host_root / "run" / "log" / "journal").mkdir(parents=True)
        cmd = LinuxAuthEventsCollector(priority="warning")._cmd()
        assert "--priority=warning" in cmd
        i = cmd.index("--directory")
        assert cmd[i + 1] == str(host_root / "run/log/journal")
        assert cmd.count("+") == len(LinuxAuthEventsCollector._MATCH_GROUPS) - 1

    def test_process_exec_reads_the_host_journal(self, host_root):
        (host_root / "var" / "log" / "journal").mkdir(parents=True)
        cmd = LinuxProcessExecCollector()._cmd()
        assert cmd[-3:] == ["_AUDIT_TYPE_NAME=EXECVE", "+", "_AUDIT_TYPE_NAME=SYSCALL"]
        assert cmd[cmd.index("--directory") + 1] == str(host_root / "var/log/journal")


class TestLogTailJournald:
    def test_journal_lines_become_rows(self, monkeypatch):
        _on_path(monkeypatch, "journalctl")
        lines = "\n".join(
            [
                json.dumps(
                    {
                        "MESSAGE": "Accepted key",
                        "_SYSTEMD_UNIT": "ssh.service",
                        "PRIORITY": "6",
                        "_PID": "42",
                        "__REALTIME_TIMESTAMP": "1700000000000000",
                    }
                ),
                "not json",
                json.dumps({"MESSAGE": [104, 105], "_COMM": "kernel", "_PID": "x"}),
            ]
        )
        run = _fake_run(monkeypatch, lambda cmd: (lines, 1, ""))
        rows = list(LogTailCollector(files=[])._journald())
        assert [(r["unit"], r["message"], r["pid"]) for r in rows] == [
            ("ssh.service", "Accepted key", 42),
            ("kernel", "hi", None),
        ]
        assert rows[0]["level"] == "info"
        assert run.calls[0][:5] == ["journalctl", "-o", "json", "--no-pager", "-n"]

    def test_journal_timeout_is_logged_and_skipped(self, monkeypatch, caplog):
        _on_path(monkeypatch, "journalctl")
        _fake_run(monkeypatch, lambda cmd: subprocess.TimeoutExpired(cmd, 10))
        assert list(LogTailCollector(files=[])._journald()) == []
        assert "journalctl read failed" in caplog.text

    def test_tail_drops_the_partial_first_line_of_a_big_file(self, tmp_path):
        big = tmp_path / "syslog"
        big.write_text("x" * (LogTailCollector._TAIL_BYTES + 10) + "\nlast line\n")
        rows = list(LogTailCollector(files=[])._tail_file(str(big)))
        assert [r["message"] for r in rows] == ["last line"]
