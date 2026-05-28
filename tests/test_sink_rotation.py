"""Tests for Sink.prune_to_size — the DB rotation logic.

The monitor enforces a configurable maximum DB size by pruning the
oldest completed runs after each cycle. Easy place to introduce bugs:
SQL filter logic, the loop termination condition, the VACUUM after
deletes. Use a real on-disk SQLite so size measurements are real.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Base,
    CollectionRun,
    LaunchItemRow,
    Sink,
    utcnow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def file_sink(tmp_path):
    """An on-disk Sink so size measurements actually mean something."""
    db = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db}",
                           connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


def _make_run(sink, started_at: datetime, finished_at: datetime,
              rows: int = 0):
    """Insert a CollectionRun row + N child LaunchItemRow rows."""
    started = started_at.isoformat(timespec="seconds")
    finished = finished_at.isoformat(timespec="seconds")
    run_id, _ = sink.start_run("h", 5)
    # Backdate so we can control the chronology.
    with Session(sink.engine) as s:
        s.query(CollectionRun).filter(
            CollectionRun.run_id == run_id
        ).update({
            "started_at":  started,
            "finished_at": finished,
        })
        s.commit()
    sink.write(LaunchItemRow, [{
        "run_id":       run_id,
        "collected_at": started,
        "content_hash": f"h{i}",
        "label":        f"item-{i}",
        "program":      "/x",
        "scope":        "user_agent",
        "path":         "/x.plist",
        "run_at_load":  False,
        "keep_alive":   False,
    } for i in range(rows)])
    return run_id


# ---------------------------------------------------------------------------
# database_size_bytes / database_live_bytes
# ---------------------------------------------------------------------------

class TestDatabaseSizeBytes:
    def test_grows_after_writes(self, file_sink):
        before = file_sink.database_size_bytes()
        # Add a lot of rows so the on-disk file grows.
        ts = utcnow()
        run_id, _ = file_sink.start_run("h", 5)
        file_sink.write(LaunchItemRow, [{
            "run_id": run_id, "collected_at": ts,
            "content_hash": f"hash-{i}",
            "label": f"x-{i}" * 100,    # ~700 bytes per row
            "program": "/x", "scope": "user_agent", "path": "/x.plist",
            "run_at_load": False, "keep_alive": False,
        } for i in range(200)])
        after = file_sink.database_size_bytes()
        assert after > before


class TestDatabaseLiveBytes:
    def test_returns_nonneg(self, file_sink):
        assert file_sink.database_live_bytes() >= 0

    def test_decreases_after_delete_and_pragma(self, file_sink):
        ts = utcnow()
        run_id, _ = file_sink.start_run("h", 5)
        file_sink.write(LaunchItemRow, [{
            "run_id": run_id, "collected_at": ts,
            "content_hash": f"h-{i}",
            "label": f"x-{i}" * 100,
            "program": "/x", "scope": "user_agent", "path": "/x.plist",
            "run_at_load": False, "keep_alive": False,
        } for i in range(200)])
        before = file_sink.database_live_bytes()
        # Wipe the rows; live_bytes is computed from
        # page_count - freelist_count which should drop immediately.
        with Session(file_sink.engine) as s:
            s.query(LaunchItemRow).delete()
            s.commit()
        after = file_sink.database_live_bytes()
        # The estimate should drop (post-vacuum approximation).
        assert after < before


# ---------------------------------------------------------------------------
# prune_to_size — the actual rotation
# ---------------------------------------------------------------------------

class TestPruneToSize:
    def test_no_op_when_under_cap(self, file_sink):
        # Cap huge → never prunes. Returns stats indicating no work.
        stats = file_sink.prune_to_size(max_bytes=10_000_000)
        assert stats["runs_pruned"] == 0
        assert stats["events_pruned"] == 0

    def test_no_op_when_no_runs(self, file_sink):
        # Empty DB with tight cap — must not crash.
        stats = file_sink.prune_to_size(max_bytes=1024)
        assert stats["runs_pruned"] == 0

    def test_prunes_oldest_completed_runs_first(self, file_sink):
        # Create three runs, oldest first, each ~50 rows.
        now = datetime.now(timezone.utc)
        old   = _make_run(file_sink, now - timedelta(hours=3),
                          now - timedelta(hours=2), rows=50)
        mid   = _make_run(file_sink, now - timedelta(hours=2),
                          now - timedelta(hours=1), rows=50)
        newer = _make_run(file_sink, now - timedelta(hours=1),
                          now, rows=50)

        # Pick a cap that forces pruning. Use a low value so at least
        # one run gets pruned. After the first prune the live size
        # should drop measurably.
        stats = file_sink.prune_to_size(max_bytes=1)
        with Session(file_sink.engine) as s:
            remaining = [r.run_id for r in s.execute(
                select(CollectionRun)).scalars()]

        # Some runs were pruned (stats has reasonable counts).
        assert stats["runs_pruned"] >= 1
        # The newest is always preserved (we prune oldest first).
        assert newer in remaining
        # The oldest is gone first.
        assert old not in remaining


# ---------------------------------------------------------------------------
# touch_judgments — the "last seen at" stamper used by the dashboard
# ---------------------------------------------------------------------------

class TestTouchJudgments:
    def test_marks_observed_hashes_as_seen_now(self, file_sink):
        from avai.host_monitor import Judgment, Verdict, ThreatCategory
        h = "a" * 64
        # Pre-seed a judgement.
        file_sink.write_judgments([Judgment(
            content_hash=h, collector="processes",
            verdict=Verdict.BENIGN, category=ThreatCategory.NONE,
            confidence=0.9, reasoning="r", remediation="",
            model="m", created_at=utcnow(),
        )])
        # Bump last_seen.
        new_ts = utcnow()
        file_sink.touch_judgments("processes", [h], new_ts)
        # Read it back.
        from avai.host_monitor import Judgement
        with Session(file_sink.engine) as s:
            row = s.execute(select(Judgement).where(
                Judgement.content_hash == h)).scalar_one()
        assert row.last_seen_at == new_ts

    def test_empty_hash_list_is_noop(self, file_sink):
        file_sink.touch_judgments("processes", [], utcnow())  # no crash
