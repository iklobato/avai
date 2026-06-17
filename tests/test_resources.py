"""Tests for the htop-style resource collectors + dashboard surface.

The collectors are psutil-backed snapshots whose psutil access lives behind
the injectable ``SystemMetrics`` / ``DiskMetrics`` seams (like
``PsutilConnections``), so these run without touching the real machine:
every test passes a fake seam and a ``FrozenClock``. No psutil global is
monkeypatched.
"""

from __future__ import annotations

from collections import namedtuple

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from avai.dashboard import app, disk_usage, host_resources, resource_trend
from avai.host_monitor import (
    DiskUsageCollector,
    DiskUsageRow,
    FrozenClock,
    HostResourceRow,
    HostResourcesCollector,
    Sink,
)
from avai.host_monitor.runtime import Digest

# psutil-shaped fakes ---------------------------------------------------------

_VM = namedtuple(
    "VM",
    "total available used free percent active inactive buffers cached wired",
)
_SW = namedtuple("SW", "total used free percent")
# Linux scputimes carries iowait; the macOS one does not — exercise both.
_CT_LINUX = namedtuple("CT", "user system idle iowait")
_CT_MACOS = namedtuple("CT", "user nice system idle")
_PART = namedtuple("Part", "device mountpoint fstype opts")
_USAGE = namedtuple("Usage", "total used free percent")
_IO = namedtuple("IO", "read_bytes write_bytes read_count write_count")

# Epoch of the frozen instant below, for deterministic uptime assertions.
_FROZEN_ISO = "2026-06-08T00:16:40+00:00"


class FakeSystemMetrics:
    def __init__(self, sample, load=(1.0, 2.0, 3.0)):
        self._sample = sample
        self._load = load

    def virtual_memory(self):
        return _VM(16_000, 8_000, 7_000, 1_000, 50.0, 2_000, 1_000, 500, 3_000, 0)

    def swap_memory(self):
        return _SW(4_000, 1_000, 3_000, 25.0)

    def cpu_sample(self, interval):
        return self._sample

    def load_average(self):
        return self._load

    def cpu_count(self):
        return (4, 8)

    def boot_time(self):
        return 1000.0

    def task_counts(self):
        return {"total": 100, "running": 2, "threads": 500}


class FakeDiskMetrics:
    def __init__(self, partitions, io=None, unreadable=()):
        self._partitions = partitions
        self._io = io or {}
        self._unreadable = set(unreadable)

    def io_counters(self):
        return self._io

    def partitions(self):
        return self._partitions

    def usage(self, mountpoint):
        if mountpoint in self._unreadable:
            raise PermissionError(mountpoint)
        return _USAGE(500, 300, 200, 60.0)


# HostResourcesCollector ------------------------------------------------------


class TestHostResourcesCollector:
    def _collect(self, sample, **kw):
        c = HostResourcesCollector(
            metrics=FakeSystemMetrics(sample, **kw),
            clock=FrozenClock(_FROZEN_ISO),
        )
        return list(c.collect())[0]

    def test_memory_and_swap_mapping(self):
        row = self._collect([_CT_LINUX(10.0, 5.0, 83.0, 2.0)])
        assert row["mem_total"] == 16_000
        assert row["mem_used"] == 7_000
        assert row["mem_percent"] == 50.0
        assert row["mem_cached"] == 3_000
        assert row["swap_percent"] == 25.0

    def test_cpu_aggregate_and_per_core(self):
        # Two cores, idle 83 and 68 → busy 17 and 32; overall busy = 24.5.
        row = self._collect(
            [_CT_LINUX(10.0, 5.0, 83.0, 2.0), _CT_LINUX(20.0, 10.0, 68.0, 2.0)]
        )
        assert row["cpu_percent"] == 24.5
        assert row["cpu_idle"] == 75.5
        assert row["cpu_iowait"] == 2.0
        assert row["cpu_per_core_json"] == "[17.0, 32.0]"
        assert row["cpu_count_logical"] == 8

    def test_iowait_none_on_platforms_without_it(self):
        # macOS scputimes has no iowait attribute → column stays NULL, not 0.
        row = self._collect([_CT_MACOS(10.0, 0.0, 5.0, 85.0)])
        assert row["cpu_iowait"] is None
        assert row["cpu_percent"] == 15.0

    def test_empty_sample_yields_null_cpu(self):
        row = self._collect([])
        assert row["cpu_percent"] is None
        assert row["cpu_per_core_json"] == "[]"

    def test_uptime_uses_injected_clock(self):
        # Deterministic: uptime = frozen-now epoch - boot_time(1000).
        from datetime import datetime

        expected = int(datetime.fromisoformat(_FROZEN_ISO).timestamp() - 1000.0)
        row = self._collect([_CT_LINUX(10.0, 5.0, 83.0, 2.0)])
        assert row["uptime_seconds"] == expected

    def test_load_and_tasks(self):
        row = self._collect([_CT_LINUX(10.0, 5.0, 83.0, 2.0)])
        assert (row["load_1"], row["load_5"], row["load_15"]) == (1.0, 2.0, 3.0)
        assert row["tasks_total"] == 100
        assert row["tasks_running"] == 2
        assert row["threads_total"] == 500

    def test_load_none_is_tolerated(self):
        row = self._collect([_CT_LINUX(1.0, 1.0, 98.0, 0.0)], load=None)
        assert row["load_1"] is None and row["load_15"] is None

    def test_not_judged(self):
        assert HostResourcesCollector.judge_enabled is False


# DiskUsageCollector ----------------------------------------------------------


class TestDiskUsageCollector:
    def test_skips_unreadable_partition(self):
        parts = [
            _PART("/dev/disk0", "/", "apfs", "rw"),
            _PART("tmpfs", "/bad", "tmpfs", "rw"),
        ]
        metrics = FakeDiskMetrics(parts, unreadable={"/bad"})
        rows = list(DiskUsageCollector(metrics=metrics).collect())
        assert [r["mountpoint"] for r in rows] == ["/"]
        assert rows[0]["percent"] == 60.0

    def test_io_matched_by_device_basename(self):
        parts = [_PART("/dev/sda1", "/", "ext4", "rw")]
        io = {"sda1": _IO(111, 222, 3, 4)}
        rows = list(DiskUsageCollector(metrics=FakeDiskMetrics(parts, io)).collect())
        assert rows[0]["io_read_bytes"] == 111
        assert rows[0]["io_write_count"] == 4

    def test_io_none_when_unmatched(self):
        parts = [_PART("/dev/disk5", "/data", "apfs", "rw")]
        rows = list(
            DiskUsageCollector(
                metrics=FakeDiskMetrics(parts, {"sda1": _IO(1, 2, 3, 4)})
            ).collect()
        )
        assert rows[0]["io_read_bytes"] is None


# Dashboard query layer + routes ----------------------------------------------


@pytest.fixture
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'r.db'}", connect_args={"check_same_thread": False}
    )
    sink = Sink(engine)
    sink.setup()
    run_id, ts = sink.start_run("h", 5)
    return engine, sink, run_id, ts, tmp_path


def _write(sink, model, rows, ts, run_id):
    for r in rows:
        r["run_id"] = run_id
        r["collected_at"] = ts
        r["content_hash"] = Digest.of_row(r, ())
    sink.write(model, rows)


def _seed(db):
    engine, sink, run_id, ts, _ = db
    _write(
        sink,
        HostResourceRow,
        [
            {
                "mem_percent": 42.0,
                "cpu_percent": 13.0,
                "swap_percent": 5.0,
                "cpu_per_core_json": "[10.0, 16.0]",
                "uptime_seconds": 3600,
                "mem_total": 16_000,
                "mem_used": 7_000,
                "load_1": 1.0,
                "load_5": 2.0,
                "load_15": 3.0,
                "tasks_total": 50,
                "tasks_running": 1,
                "threads_total": 200,
                "cpu_count_logical": 8,
            }
        ],
        ts,
        run_id,
    )
    _write(
        sink,
        DiskUsageRow,
        [
            {
                "device": "/dev/disk0",
                "mountpoint": "/",
                "fstype": "apfs",
                "total": 500,
                "used": 300,
                "free": 200,
                "percent": 60.0,
            },
            {
                "device": "/dev/disk1",
                "mountpoint": "/boot",
                "fstype": "ext4",
                "total": 100,
                "used": 95,
                "free": 5,
                "percent": 95.0,
            },
        ],
        ts,
        run_id,
    )
    sink.end_run(ok=2, failed=0)


class TestQueries:
    def test_host_resources_latest_row(self, db):
        engine, _, run_id, _, _ = db
        _seed(db)
        with Session(engine) as s:
            res = host_resources(s, run_id)
        assert res is not None
        assert res["row"].mem_percent == 42.0
        assert res["per_core"] == [10.0, 16.0]

    def test_disk_usage_sorted_fullest_first(self, db):
        engine, _, run_id, _, _ = db
        _seed(db)
        with Session(engine) as s:
            disks = disk_usage(s, run_id)
        assert [d.mountpoint for d in disks] == ["/boot", "/"]  # 95% before 60%

    def test_resource_trend_shape(self, db):
        engine, _, run_id, _, _ = db
        _seed(db)
        with Session(engine) as s:
            trend = resource_trend(s)
        assert trend["mem"] == [42.0]
        assert trend["cpu"] == [13.0]
        assert len(trend["labels"]) == 1

    def test_host_resources_none_when_table_absent(self, db):
        engine, sink, run_id, _, _ = db
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE host_resources"))
            conn.execute(text("DROP TABLE disk_usage"))
        with Session(engine) as s:
            assert host_resources(s, run_id) is None
            assert disk_usage(s, run_id) == []
            assert resource_trend(s)["labels"] == []


class TestRoutes:
    def test_fragment_renders_with_data(self, db):
        engine, _, _, _, tmp_path = db
        _seed(db)
        engine.dispose()
        app.config.update(TESTING=True, DB_PATH=str(tmp_path / "r.db"))
        with app.test_client() as c:
            r = c.get("/fragments/resources")
        assert r.status_code == 200
        body = r.data.decode()
        assert "system resources" in body
        assert "/boot" in body  # disk row rendered

    def test_fragment_200_on_db_without_tables(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'e.db'}")
        Sink(engine).setup()
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE host_resources"))
            conn.execute(text("DROP TABLE disk_usage"))
        engine.dispose()
        app.config.update(TESTING=True, DB_PATH=str(tmp_path / "e.db"))
        with app.test_client() as c:
            r = c.get("/fragments/resources")
        assert r.status_code == 200

    def test_chart_api_returns_series(self, db):
        engine, _, _, _, tmp_path = db
        _seed(db)
        engine.dispose()
        app.config.update(TESTING=True, DB_PATH=str(tmp_path / "r.db"))
        with app.test_client() as c:
            r = c.get("/api/chart/resources")
        assert r.status_code == 200
        data = r.get_json()
        assert data["cpu"] == [13.0]
        assert set(data) == {"labels", "mem", "cpu", "swap"}
