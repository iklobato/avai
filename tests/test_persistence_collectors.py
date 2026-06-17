"""Tier 3 persistence-collector parsers and wiring."""

from __future__ import annotations

from avai.host_monitor.hosts.linux import LinuxHost
from avai.host_monitor.hosts.macos import MacOSHost
from avai.host_monitor.hosts.windows import WindowsHost
from avai.host_monitor.persistence_collectors import (
    EnvValueParser,
    LdSoPreloadParser,
    ProcModulesParser,
    SshKnownHostsCollector,
    WindowsAppInitParser,
    WindowsDriverParser,
)
from avai.host_monitor.prompts import Prompts

_P = Prompts(system="", user_template="")


class TestInjectionEnvParsers:
    def test_env_value_set_yields_row(self):
        rows = EnvValueParser("DYLD_INSERT_LIBRARIES", "launchd").parse(
            "/tmp/evil.dylib\n"
        )
        assert rows == [
            {
                "scope": "launchd",
                "variable": "DYLD_INSERT_LIBRARIES",
                "value": "/tmp/evil.dylib",
                "raw_json": rows[0]["raw_json"],
            }
        ]

    def test_env_value_empty_yields_nothing(self):
        assert EnvValueParser("DYLD_INSERT_LIBRARIES", "launchd").parse("\n") == []

    def test_ld_so_preload_one_row_per_lib(self):
        rows = LdSoPreloadParser().parse("# c\n/opt/hook.so\n/usr/lib/x.so\n")
        assert [r["value"] for r in rows] == ["/opt/hook.so", "/usr/lib/x.so"]
        assert all(r["variable"] == "LD_PRELOAD" for r in rows)

    def test_windows_appinit_only_when_set(self):
        assert (
            WindowsAppInitParser().parse('{"AppInit_DLLs":"","LoadAppInit_DLLs":0}')
            == []
        )
        rows = WindowsAppInitParser().parse('{"AppInit_DLLs":"c:\\\\evil.dll"}')
        assert rows[0]["value"] == "c:\\evil.dll"


class TestKernelModuleParsers:
    def test_proc_modules(self):
        text = (
            "nf_tables 245760 1 - Live 0x0\n"
            "evilmod 16384 0 - Live 0x0\n"
            "ext4 1000000 1 nf_tables Live 0x0\n"
        )
        rows = ProcModulesParser().parse(text)
        by = {r["name"]: r for r in rows}
        assert by["nf_tables"]["used_by"] is None  # "-" → None
        assert by["ext4"]["used_by"] == "nf_tables"
        assert by["evilmod"]["size"] == "16384"

    def test_driverquery_csv_skips_header(self):
        text = (
            '"Module Name","Display Name","Driver Type"\r\n'
            '"evildrv","Evil Driver","Kernel"\r\n'
        )
        rows = WindowsDriverParser().parse(text)
        assert len(rows) == 1
        assert rows[0]["name"] == "evildrv"
        assert rows[0]["used_by"] == "Evil Driver"


class TestKnownHostsParser:
    def test_parses_host_keytype_fingerprint(self):
        text = (
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0a\n"
            "# comment\n"
            "@cert-authority *.corp ssh-rsa AAAAB3NzaC1yc2E\n"
            "192.168.1.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n"
        )
        rows = SshKnownHostsCollector._parse_known_hosts(text, "/h/.ssh/known_hosts")
        hosts = [r["host"] for r in rows]
        assert hosts == ["github.com", "*.corp", "192.168.1.5"]
        assert rows[0]["key_type"] == "ssh-ed25519"
        assert rows[0]["fingerprint"].startswith("SHA256:")
        assert rows[1]["host"] == "*.corp"  # @cert-authority marker stripped

    def test_blank_and_unknown_keytype_skipped(self):
        assert (
            SshKnownHostsCollector._parse_known_hosts("\nhost notakey blob\n", "/p")
            == []
        )


class TestWiring:
    def test_macos_has_injection_and_known_hosts_no_kernel_modules(self):
        names = {c.name for c in MacOSHost().snapshot_collectors(_P)}
        assert {"injection_env", "ssh_known_hosts"} <= names
        assert "kernel_modules" not in names  # composed out (kexts cover it)

    def test_linux_and_windows_have_all_three(self):
        for host in (LinuxHost(), WindowsHost()):
            names = {c.name for c in host.snapshot_collectors(_P)}
            assert {"injection_env", "kernel_modules", "ssh_known_hosts"} <= names
