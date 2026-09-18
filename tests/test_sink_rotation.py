"""Tests for Sink.prune_to_size — the DB rotation logic.

The monitor enforces a configurable maximum DB size by pruning the
oldest completed runs after each cycle. Easy place to introduce bugs:
SQL filter logic, the loop termination condition, the VACUUM after
deletes. Use a real on-disk SQLite so size measurements are real.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from avai.host_monitor import CollectionRun, LaunchItemRow, Sink
from avai.host_monitor.models import (
    AuthEventRow,
    CollectorErrorRow,
    StreamingSession,
)
from avai.host_monitor.runtime import Clock
from avai.host_monitor.sink import _BUSY_TIMEOUT_MS


class TestConnectionPragmas:
    """Regression for the streaming-flush 'database is locked' failure: the
    snapshot loop and streaming-worker threads serialise their writes through
    SQLite, so every connection must carry a generous busy_timeout (the 5s
    pysqlite default was too short for write/checkpoint windows on a large DB,
    so the losing writer raised instead of waiting)."""

    def test_busy_timeout_is_generous(self, file_sink):
        with file_sink.engine.connect() as c:
            assert c.execute(text("PRAGMA busy_timeout")).scalar() == _BUSY_TIMEOUT_MS
        assert _BUSY_TIMEOUT_MS >= 30_000

    def test_wal_mode_enabled(self, file_sink):
        with file_sink.engine.connect() as c:
            assert c.execute(text("PRAGMA journal_mode")).scalar() == "wal"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def file_sink(tmp_path):
    """An on-disk Sink so size measurements actually mean something."""
    db = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


def _make_run(sink, started_at: datetime, finished_at: datetime, rows: int = 0):
    """Insert a CollectionRun row + N child LaunchItemRow rows."""
    started = started_at.isoformat(timespec="seconds")
    finished = finished_at.isoformat(timespec="seconds")
    run_id, _ = sink.start_run("h", 5)
    # Backdate so we can control the chronology.
    with Session(sink.engine) as s:
        s.query(CollectionRun).filter(CollectionRun.run_id == run_id).update(
            {
                "started_at": started,
                "finished_at": finished,
            }
        )
        s.commit()
    sink.write(
        LaunchItemRow,
        [
            {
                "run_id": run_id,
                "collected_at": started,
                "content_hash": f"h{i}",
                "label": f"item-{i}",
                "program": "/x",
                "scope": "user_agent",
                "path": "/x.plist",
                "run_at_load": False,
                "keep_alive": False,
            }
            for i in range(rows)
        ],
    )
    return run_id


# ---------------------------------------------------------------------------
# database_size_bytes / database_live_bytes
# ---------------------------------------------------------------------------


class TestDatabaseSizeBytes:
    def test_grows_after_writes(self, file_sink):
        before = file_sink.database_size_bytes()
        # Add a lot of rows so the on-disk file grows.
        ts = Clock().now_iso()
        run_id, _ = file_sink.start_run("h", 5)
        file_sink.write(
            LaunchItemRow,
            [
                {
                    "run_id": run_id,
                    "collected_at": ts,
                    "content_hash": f"hash-{i}",
                    "label": f"x-{i}" * 100,  # ~700 bytes per row
                    "program": "/x",
                    "scope": "user_agent",
                    "path": "/x.plist",
                    "run_at_load": False,
                    "keep_alive": False,
                }
                for i in range(200)
            ],
        )
        after = file_sink.database_size_bytes()
        assert after > before


class TestDatabaseLiveBytes:
    def test_decreases_after_delete_and_pragma(self, file_sink):
        ts = Clock().now_iso()
        run_id, _ = file_sink.start_run("h", 5)
        file_sink.write(
            LaunchItemRow,
            [
                {
                    "run_id": run_id,
                    "collected_at": ts,
                    "content_hash": f"h-{i}",
                    "label": f"x-{i}" * 100,
                    "program": "/x",
                    "scope": "user_agent",
                    "path": "/x.plist",
                    "run_at_load": False,
                    "keep_alive": False,
                }
                for i in range(200)
            ],
        )
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
        old = _make_run(
            file_sink, now - timedelta(hours=3), now - timedelta(hours=2), rows=50
        )
        _make_run(
            file_sink, now - timedelta(hours=2), now - timedelta(hours=1), rows=50
        )
        newer = _make_run(file_sink, now - timedelta(hours=1), now, rows=50)

        # Pick a cap that forces pruning. Use a low value so at least
        # one run gets pruned. After the first prune the live size
        # should drop measurably.
        stats = file_sink.prune_to_size(max_bytes=1)
        with Session(file_sink.engine) as s:
            remaining = [r.run_id for r in s.execute(select(CollectionRun)).scalars()]

        # Some runs were pruned (stats has reasonable counts).
        assert stats["runs_pruned"] >= 1
        # The newest is always preserved (we prune oldest first).
        assert newer in remaining
        # The oldest is gone first.
        assert old not in remaining


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _count(sink, model, *where) -> int:
    with Session(sink.engine) as s:
        return len(s.execute(select(model).where(*where)).scalars().all())


def _three_runs(sink):
    """Three completed runs, one hour apart, oldest first."""
    now = datetime.now(timezone.utc)
    return now, [
        _make_run(sink, now - timedelta(hours=h), now - timedelta(hours=h - 1), rows=50)
        for h in (3, 2, 1)
    ]


def _auth_events(sink, collected_at: str, count: int) -> None:
    sink.write(
        AuthEventRow,
        [
            {
                "run_id": "stream",
                "collected_at": collected_at,
                "content_hash": f"a{collected_at}{i}",
                "process": "sshd",
            }
            for i in range(count)
        ],
    )


def _streaming_session(sink, finished_at: str) -> str:
    run_id = sink.start_streaming_session("auth_events", "h")
    sink.end_streaming_session(run_id, 0)
    with Session(sink.engine) as s:
        s.query(StreamingSession).filter(StreamingSession.run_id == run_id).update(
            {"started_at": finished_at, "finished_at": finished_at}
        )
        s.commit()
    return run_id


class TestPruneToSizeBehaviour:
    def test_zero_cap_means_unlimited(self, file_sink):
        _three_runs(file_sink)

        stats = file_sink.prune_to_size(max_bytes=0)

        assert stats == {
            "runs_pruned": 0,
            "events_pruned": 0,
            "bytes_before": 0,
            "bytes_after": 0,
        }
        assert _count(file_sink, CollectionRun) == 3

    def test_under_the_cap_reports_the_current_size(self, file_sink):
        size = file_sink.database_size_bytes()

        stats = file_sink.prune_to_size(max_bytes=size + 10_000_000)

        assert stats["bytes_before"] == stats["bytes_after"] == size

    def test_always_keeps_the_newest_completed_run(self, file_sink):
        _, (_old, _mid, newest) = _three_runs(file_sink)

        stats = file_sink.prune_to_size(max_bytes=1)

        assert stats["runs_pruned"] == 2
        assert _count(file_sink, CollectionRun) == 1
        assert _count(file_sink, LaunchItemRow, LaunchItemRow.run_id == newest) == 50

    def test_child_rows_and_errors_of_a_pruned_run_go_with_it(self, file_sink):
        _, (old, _mid, _newest) = _three_runs(file_sink)
        with Session(file_sink.engine) as s:
            s.add(CollectorErrorRow(run_id=old, collector="x", occurred_at="t"))
            s.commit()

        file_sink.prune_to_size(max_bytes=1)

        assert _count(file_sink, LaunchItemRow, LaunchItemRow.run_id == old) == 0
        assert _count(file_sink, CollectorErrorRow) == 0

    def test_an_unfinished_run_is_never_pruned(self, file_sink):
        _three_runs(file_sink)
        in_progress, _ = file_sink.start_run("h", 5)

        file_sink.prune_to_size(max_bytes=1)

        assert (
            _count(file_sink, CollectionRun, CollectionRun.run_id == in_progress) == 1
        )

    def test_auth_events_older_than_the_oldest_kept_run_are_pruned(self, file_sink):
        now, _ = _three_runs(file_sink)
        _auth_events(file_sink, _iso(now - timedelta(hours=5)), 30)
        _auth_events(file_sink, _iso(now), 4)

        stats = file_sink.prune_to_size(max_bytes=1)

        assert stats["events_pruned"] == 30
        assert _count(file_sink, AuthEventRow) == 4

    def test_streaming_sessions_that_ended_before_the_kept_runs_are_pruned(
        self, file_sink
    ):
        now, _ = _three_runs(file_sink)
        stale = _streaming_session(file_sink, _iso(now - timedelta(hours=5)))
        live = _streaming_session(file_sink, _iso(now))

        file_sink.prune_to_size(max_bytes=1)

        assert (
            _count(file_sink, StreamingSession, StreamingSession.run_id == stale) == 0
        )
        assert _count(file_sink, StreamingSession, StreamingSession.run_id == live) == 1

    def test_the_file_shrinks_after_pruning(self, file_sink):
        _three_runs(file_sink)

        stats = file_sink.prune_to_size(max_bytes=1)

        assert stats["bytes_after"] < stats["bytes_before"]


# ---------------------------------------------------------------------------
# touch_judgments — the "last seen at" stamper used by the dashboard
# ---------------------------------------------------------------------------


class TestTouchJudgments:
    def test_marks_observed_hashes_as_seen_now(self, file_sink):
        from avai.host_monitor import Judgment, ThreatCategory, Verdict

        h = "a" * 64
        # Pre-seed a judgement.
        file_sink.write_judgments(
            [
                Judgment(
                    content_hash=h,
                    collector="processes",
                    verdict=Verdict.BENIGN,
                    category=ThreatCategory.NONE,
                    confidence=0.9,
                    reasoning="r",
                    remediation="",
                    model="m",
                    created_at=Clock().now_iso(),
                )
            ]
        )
        # Bump last_seen.
        new_ts = Clock().now_iso()
        file_sink.touch_judgments("processes", [h], new_ts)
        # Read it back.
        from avai.host_monitor import Judgement

        with Session(file_sink.engine) as s:
            row = s.execute(
                select(Judgement).where(Judgement.content_hash == h)
            ).scalar_one()
        assert row.last_seen_at == new_ts

    def test_empty_hash_list_is_noop(self, file_sink):
        file_sink.touch_judgments("processes", [], Clock().now_iso())  # no crash
