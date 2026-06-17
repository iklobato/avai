"""Tests for DiskMetrics container-mode behaviour.

In a container, psutil reads the *container's* mount table and statvfs's
the *container's* paths, so disk_usage would report the overlay + bind
mounts as "host disks". DiskMetrics instead reads the real host mount
table and measures each filesystem through the read-only host-root mount
at $HOST_PREFIX/rootfs. Without that mount it emits nothing (rather than
mislead). These tests pin the parsing, path-translation, statvfs math,
and the three modes (native / container-no-rootfs / container-rootfs).
"""

from __future__ import annotations

import sys
from collections import namedtuple

import pytest

import avai.host_monitor.constants as constants
from avai.host_monitor.runtime import probes
from avai.host_monitor.runtime.probes import (
    DiskMetrics,
    _join_rootfs,
    _parse_mounts,
    _statvfs_usage,
    _unescape_mount_field,
)

# DiskMetrics container mode is Linux-specific: it parses /proc-style mount
# tables and measures filesystems via os.statvfs (absent on Windows) through
# the $HOST_PREFIX/rootfs mount. None of it runs on Windows, so the suite
# would only fail there on an AttributeError, not a real regression.
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux container disk-metrics; no os.statvfs on Windows",
)


class TestUnescapeMountField:
    def test_plain_field_unchanged(self):
        assert _unescape_mount_field("/dev/sda1") == "/dev/sda1"

    def test_octal_space_and_tab_decoded(self):
        assert _unescape_mount_field(r"/mnt/My\040Disk") == "/mnt/My Disk"
        assert _unescape_mount_field(r"a\011b") == "a\tb"


class TestParseMounts:
    def test_drops_pseudo_filesystems(self):
        text = (
            "proc /proc proc rw 0 0\n"
            "sysfs /sys sysfs rw 0 0\n"
            "tmpfs /run tmpfs rw 0 0\n"
            "overlay / overlay rw 0 0\n"
            "/dev/sda1 /mnt/data ext4 rw 0 0\n"
        )
        parts = _parse_mounts(text)
        assert [p.mountpoint for p in parts] == ["/mnt/data"]
        assert parts[0].device == "/dev/sda1"
        assert parts[0].fstype == "ext4"

    def test_dedupes_by_mountpoint_keeping_first(self):
        text = (
            "/dev/sda1 / ext4 rw 0 0\n"
            "/dev/sdb1 / ext4 ro 0 0\n"  # later bind/overlay of same point
        )
        parts = _parse_mounts(text)
        assert [(p.device, p.opts) for p in parts] == [("/dev/sda1", "rw")]

    def test_unescapes_mountpoint_whitespace(self):
        parts = _parse_mounts(r"/dev/sda2 /mnt/My\040Disk ext4 rw 0 0")
        assert parts[0].mountpoint == "/mnt/My Disk"

    def test_short_lines_skipped(self):
        assert _parse_mounts("garbage\n/dev/sda1 /data\n") == []


class TestJoinRootfs:
    def test_root_maps_to_rootfs_itself(self):
        assert _join_rootfs("/host/rootfs", "/") == "/host/rootfs"

    def test_subpath_appended(self):
        assert _join_rootfs("/host/rootfs", "/home") == "/host/rootfs/home"
        assert _join_rootfs("/host/rootfs/", "/var/log") == "/host/rootfs/var/log"


class TestStatvfsUsage:
    def test_matches_psutil_style_math(self, monkeypatch):
        # 100 blocks * 4096 = 409600 total; 10 free-to-root, 5 avail-to-user.
        Sv = namedtuple("Sv", "f_blocks f_bfree f_bavail f_frsize")
        monkeypatch.setattr(probes.os, "statvfs", lambda _p: Sv(100, 10, 5, 4096))
        u = _statvfs_usage("/anything")
        assert u.total == 100 * 4096
        assert u.used == (100 - 10) * 4096
        assert u.free == 5 * 4096  # avail-to-user, not free-to-root
        # percent against user-visible total (used + avail), reserved excluded
        assert u.percent == round((90 * 4096) / ((90 + 5) * 4096) * 100, 1)

    def test_zero_total_no_division_error(self, monkeypatch):
        Sv = namedtuple("Sv", "f_blocks f_bfree f_bavail f_frsize")
        monkeypatch.setattr(probes.os, "statvfs", lambda _p: Sv(0, 0, 0, 4096))
        assert _statvfs_usage("/x").percent == 0.0


class TestDiskMetricsModes:
    def test_native_mode_uses_psutil(self, monkeypatch):
        monkeypatch.setattr(constants, "HOST_PREFIX", "")
        sentinel = [object()]
        monkeypatch.setattr(probes.psutil, "disk_partitions", lambda all: sentinel)
        assert DiskMetrics().partitions() is sentinel

    def test_container_without_rootfs_emits_nothing(self, monkeypatch, tmp_path):
        # HOST_PREFIX set but no <prefix>/rootfs dir → skip, don't mislead.
        monkeypatch.setattr(constants, "HOST_PREFIX", str(tmp_path))
        called = []
        monkeypatch.setattr(
            probes.psutil,
            "disk_partitions",
            lambda all: called.append(True) or [],
        )
        assert DiskMetrics().partitions() == []
        assert called == []  # psutil must NOT be consulted in container mode

    def test_container_with_rootfs_reads_host_table(self, monkeypatch, tmp_path):
        rootfs = tmp_path / "rootfs"
        (rootfs / "proc" / "1").mkdir(parents=True)
        (rootfs / "proc" / "1" / "mounts").write_text(
            "proc /proc proc rw 0 0\n/dev/sda1 / ext4 rw 0 0\n"
        )
        monkeypatch.setattr(constants, "HOST_PREFIX", str(tmp_path))
        # <prefix>/rootfs exists → container-with-rootfs branch. Capture the
        # prefix routed to _host_partitions (the real reader is exercised by
        # TestParseMounts; here we pin the wiring + path derivation).
        captured = {}

        def _fake_host_partitions(rf):
            captured["rf"] = rf
            return _parse_mounts((rootfs / "proc" / "1" / "mounts").read_text())

        monkeypatch.setattr(probes, "_host_partitions", _fake_host_partitions)
        parts = DiskMetrics().partitions()
        assert captured["rf"] == str(rootfs)
        assert [p.mountpoint for p in parts] == ["/"]

    def test_usage_translates_through_rootfs(self, monkeypatch):
        captured = {}
        Sv = namedtuple("Sv", "f_blocks f_bfree f_bavail f_frsize")

        def _fake_statvfs(path):
            captured["path"] = path
            return Sv(10, 2, 2, 4096)

        monkeypatch.setattr(probes.os, "statvfs", _fake_statvfs)
        dm = DiskMetrics(rootfs="/host/rootfs")
        dm.usage("/home")
        assert captured["path"] == "/host/rootfs/home"

    def test_usage_native_uses_psutil(self, monkeypatch):
        monkeypatch.setattr(constants, "HOST_PREFIX", "")
        marker = object()
        monkeypatch.setattr(probes.psutil, "disk_usage", lambda mp: marker)
        assert DiskMetrics().usage("/") is marker
