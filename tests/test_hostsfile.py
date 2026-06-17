"""Tests for the avai.local hosts-file mapping.

The pure text transform (HostsTable) and the platform factory are exercised
directly; the registrar's read/transform/write + permission translation run
against a tmp_path file through an injected fake Platform, so nothing here
touches /etc/hosts.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from avai.hostsfile import (
    DASHBOARD_HOSTNAME,
    LOOPBACK_ADDRESSES,
    LOOPBACK_IPV4,
    LOOPBACK_IPV6,
    HostsError,
    HostsPermissionError,
    HostsRegistrar,
    HostsTable,
    Outcome,
    UnsupportedPlatformError,
    _WindowsPlatform,
    resolve_platform,
)


class FakePlatform:
    """Satisfies the Platform protocol by shape; points at a tmp file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def hosts_path(self) -> Path:
        return self._path

    def elevation_hint(self, path: Path) -> str:
        return "use sudo"


class TestHostsTableTransform:
    def test_install_maps_both_ipv4_and_ipv6_loopback(self):
        # The IPv6 line is what dodges the macOS .local mDNS AAAA delay.
        table = HostsTable("").with_mapping(DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES)
        assert table.is_managed(DASHBOARD_HOSTNAME)
        assert table.resolves(DASHBOARD_HOSTNAME)
        assert f"{LOOPBACK_IPV4}\t{DASHBOARD_HOSTNAME}" in table.text
        assert f"{LOOPBACK_IPV6}\t{DASHBOARD_HOSTNAME}" in table.text

    def test_install_is_idempotent(self):
        once = HostsTable("").with_mapping(DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES)
        twice = once.with_mapping(DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES)
        assert twice.text == once.text

    def test_changing_addresses_rewrites_the_entry(self):
        table = (
            HostsTable("")
            .with_mapping(DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES)
            .with_mapping(DASHBOARD_HOSTNAME, ("127.0.0.2",))
        )
        assert table.text.count(DASHBOARD_HOSTNAME) == 1  # old IPv4+IPv6 lines gone
        assert "127.0.0.2\tavai.local" in table.text

    def test_remove_drops_block_and_preserves_other_lines(self):
        original = "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n"
        added = HostsTable(original).with_mapping(
            DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES
        )
        removed = added.without(DASHBOARD_HOSTNAME)
        assert not removed.is_managed(DASHBOARD_HOSTNAME)
        assert "127.0.0.1\tlocalhost" in removed.text
        assert "broadcasthost" in removed.text
        assert _BLOCK_marker_absent(removed.text)

    def test_user_lines_are_left_verbatim(self):
        original = "1.2.3.4   example.com   # my entry\n"
        table = HostsTable(original).with_mapping(
            DASHBOARD_HOSTNAME, LOOPBACK_ADDRESSES
        )
        assert "1.2.3.4   example.com   # my entry" in table.text

    def test_resolves_detects_a_hand_added_entry_outside_the_block(self):
        table = HostsTable("127.0.0.1 avai.local\n")
        assert table.resolves(DASHBOARD_HOSTNAME)
        assert not table.is_managed(DASHBOARD_HOSTNAME)

    def test_comment_lines_do_not_count_as_resolving(self):
        table = HostsTable("# 127.0.0.1 avai.local\n")
        assert not table.resolves(DASHBOARD_HOSTNAME)

    def test_crlf_line_endings_are_preserved(self):
        original = "127.0.0.1\tlocalhost\r\n"
        table = HostsTable(original).with_mapping(DASHBOARD_HOSTNAME, LOOPBACK_IPV4)
        assert "\r\n" in table.text
        assert "\n" not in table.text.replace("\r\n", "")


def _BLOCK_marker_absent(text: str) -> bool:
    return ">>> avai >>>" not in text and "<<< avai <<<" not in text


class TestPlatformFactory:
    def test_macos_and_linux_use_etc_hosts(self):
        assert resolve_platform("Darwin").hosts_path() == Path("/etc/hosts")
        assert resolve_platform("Linux").hosts_path() == Path("/etc/hosts")

    def test_windows_uses_drivers_etc_under_system_root(self, monkeypatch):
        monkeypatch.setenv("SystemRoot", r"C:\Windows")
        path = _WindowsPlatform().hosts_path()
        assert path.name == "hosts"
        assert "drivers" in path.parts and "etc" in path.parts

    def test_unsupported_platform_fails_loudly(self):
        with pytest.raises(UnsupportedPlatformError):
            resolve_platform("Plan9")


class TestRegistrar:
    def test_install_writes_file_and_is_idempotent(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        registrar = HostsRegistrar(FakePlatform(hosts))

        assert registrar.install() is Outcome.CREATED
        assert registrar.resolves()
        text = hosts.read_text()
        assert f"{LOOPBACK_IPV4}\tavai.local" in text
        assert f"{LOOPBACK_IPV6}\tavai.local" in text  # IPv6 line for fast .local
        assert registrar.install() is Outcome.UNCHANGED  # second run no-ops

    def test_remove_round_trips(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        registrar = HostsRegistrar(FakePlatform(hosts))
        registrar.install()

        assert registrar.remove() is Outcome.REMOVED
        assert not registrar.resolves()
        assert registrar.remove() is Outcome.UNCHANGED

    def test_install_on_missing_file_creates_it(self, tmp_path):
        hosts = tmp_path / "hosts"  # does not exist
        registrar = HostsRegistrar(FakePlatform(hosts))
        assert registrar.install() is Outcome.CREATED
        assert hosts.exists()

    def test_write_preserves_file_mode(self, tmp_path):
        # Assert preservation, not a hardcoded POSIX value: Windows has no
        # real file modes (a writable file reports 0o666), so pin "unchanged"
        # rather than "== 0o644".
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        hosts.chmod(0o644)
        before = stat.S_IMODE(hosts.stat().st_mode)
        HostsRegistrar(FakePlatform(hosts)).install()
        assert stat.S_IMODE(hosts.stat().st_mode) == before

    def test_invalid_hostname_is_rejected_at_the_edge(self, tmp_path):
        registrar = HostsRegistrar(FakePlatform(tmp_path / "hosts"))
        with pytest.raises(HostsError):
            registrar.install("not a hostname")

    def test_permission_error_is_translated_with_a_hint(self, tmp_path, monkeypatch):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        registrar = HostsRegistrar(FakePlatform(hosts))

        def _denied(*_a, **_k):
            raise PermissionError("not the owner")

        monkeypatch.setattr("avai.hostsfile._atomic_write", _denied)
        with pytest.raises(HostsPermissionError) as excinfo:
            registrar.install()
        assert excinfo.value.hint == "use sudo"
        assert excinfo.value.path == hosts

    def test_ensure_reachable_maps_when_writable(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        assert HostsRegistrar(FakePlatform(hosts)).ensure_reachable() is Outcome.CREATED

    def test_ensure_reachable_is_unchanged_when_already_resolvable(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 avai.local\n")  # user already added it
        assert (
            HostsRegistrar(FakePlatform(hosts)).ensure_reachable() is Outcome.UNCHANGED
        )

    def test_ensure_reachable_reports_needs_privilege_instead_of_raising(
        self, tmp_path, monkeypatch
    ):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        registrar = HostsRegistrar(FakePlatform(hosts))

        def _denied(*_a, **_k):
            raise PermissionError("not the owner")

        monkeypatch.setattr("avai.hostsfile._atomic_write", _denied)
        assert registrar.ensure_reachable() is Outcome.NEEDS_PRIVILEGE


class TestCli:
    def test_install_hosts_command_maps_via_registrar(self, tmp_path, monkeypatch):
        from avai import cli, hostsfile

        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        monkeypatch.setattr(
            hostsfile.HostsRegistrar,
            "for_current_platform",
            classmethod(lambda c: hostsfile.HostsRegistrar(FakePlatform(hosts))),
        )

        assert cli.main(["install-hosts"]) == 0
        assert "avai.local" in hosts.read_text()

        assert cli.main(["install-hosts", "--remove"]) == 0
        assert "avai.local" not in hosts.read_text()

    def test_install_hosts_command_reports_permission_failure(
        self, tmp_path, monkeypatch
    ):
        from avai import cli, hostsfile

        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n")
        monkeypatch.setattr(
            hostsfile.HostsRegistrar,
            "for_current_platform",
            classmethod(lambda c: hostsfile.HostsRegistrar(FakePlatform(hosts))),
        )

        def _denied(*_a, **_k):
            raise PermissionError("nope")

        monkeypatch.setattr("avai.hostsfile._atomic_write", _denied)
        assert cli.main(["install-hosts"]) == 1  # non-zero, no traceback


def test_atomic_write_replaces_content(tmp_path):
    from avai.hostsfile import _atomic_write

    target = tmp_path / "hosts"
    target.write_text("old\n")
    _atomic_write(target, "new\n")
    assert target.read_text() == "new\n"
    # no temp files left behind
    assert [p.name for p in tmp_path.iterdir()] == ["hosts"]


def test_atomic_write_wraps_os_error_and_cleans_up(tmp_path, monkeypatch):
    """A failing os.replace (e.g. EBUSY on a container's bind-mounted
    /etc/hosts) is surfaced as HostsError — not a raw OSError that would
    crash the dashboard — and the temp file is cleaned up."""
    from avai import hostsfile

    target = tmp_path / "hosts"
    target.write_text("old\n")

    def _boom(*_a, **_k):
        raise OSError(16, "Device or resource busy")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(hostsfile.HostsError):
        hostsfile._atomic_write(target, "new\n")
    assert [p.name for p in tmp_path.iterdir()] == ["hosts"]  # temp cleaned up
    assert target.read_text() == "old\n"  # original untouched
