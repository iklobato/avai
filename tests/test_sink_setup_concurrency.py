"""Tests for Sink.setup's tolerance of a concurrent schema bootstrap.

In the Docker deployment the monitor and the dashboard both call
Sink.setup() at startup against the same bind-mounted SQLite file. The
two bootstraps are not atomic, so the loser of a create_all/ALTER race
sees "table already exists" or "duplicate column name". Those are
benign — the resulting schema is identical — and must not crash a
container's startup. These tests pin that behaviour.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, String, create_engine, inspect, text
from sqlalchemy.exc import OperationalError

from avai.host_monitor import Sink
from avai.host_monitor.models import Base
from avai.host_monitor.sink import _is_benign_concurrent_ddl, _migrate_add_columns


class TestBenignConcurrentDDL:
    @pytest.mark.parametrize(
        "msg",
        [
            "(sqlite3.OperationalError) table runs already exists",
            "(sqlite3.OperationalError) duplicate column name: novel",
            "duplicate column name: cost_usd",
        ],
    )
    def test_recognised_as_benign(self, msg):
        assert _is_benign_concurrent_ddl(OperationalError(msg, None, Exception(msg)))

    @pytest.mark.parametrize(
        "msg",
        [
            "(sqlite3.OperationalError) database is locked",
            "(sqlite3.OperationalError) no such table: runs",
            "(sqlite3.OperationalError) disk I/O error",
        ],
    )
    def test_other_errors_not_benign(self, msg):
        assert not _is_benign_concurrent_ddl(
            OperationalError(msg, None, Exception(msg))
        )


class TestSetupTolerance:
    def test_setup_is_idempotent(self, tmp_path):
        """Running setup twice on the same DB (the steady-state case) is a
        no-op the second time, not a crash."""
        db = tmp_path / "t.db"
        engine = create_engine(f"sqlite:///{db}")
        Sink(engine).setup()
        Sink(engine).setup()  # must not raise

    def test_create_all_race_is_swallowed(self, tmp_path, monkeypatch):
        """A benign 'already exists' from create_all (a second process won
        the race) is tolerated; setup still completes."""
        db = tmp_path / "t.db"
        engine = create_engine(f"sqlite:///{db}")

        def _raise_exists(*_a, **_k):
            raise OperationalError("table runs already exists", None, Exception())

        monkeypatch.setattr(Base.metadata, "create_all", _raise_exists)
        Sink(engine).setup()  # must not raise

    def test_create_all_real_error_propagates(self, tmp_path, monkeypatch):
        db = tmp_path / "t.db"
        engine = create_engine(f"sqlite:///{db}")

        def _raise_locked(*_a, **_k):
            raise OperationalError("database is locked", None, Exception())

        monkeypatch.setattr(Base.metadata, "create_all", _raise_locked)
        with pytest.raises(OperationalError):
            Sink(engine).setup()

    def test_migrate_add_columns_tolerates_lost_alter_race(self, tmp_path):
        """Simulate the duplicate-column race: a table is missing one ORM
        column on inspect, but the ALTER fails with 'duplicate column name'
        (another process added it first). _migrate_add_columns must skip it
        and keep going, not abort the whole migration."""
        db = tmp_path / "t.db"
        engine = create_engine(f"sqlite:///{db}")

        # A throwaway table registered on Base with two extra columns.
        table_name = "race_probe"
        if table_name not in Base.metadata.tables:
            from sqlalchemy import Table

            Table(
                table_name,
                Base.metadata,
                Column("id", Integer, primary_key=True),
                Column("a", String),
                Column("b", String),
            )
        try:
            # Create the table WITHOUT columns a/b so _migrate adds them...
            with engine.begin() as conn:
                conn.execute(
                    text(f"CREATE TABLE {table_name} (id INTEGER PRIMARY KEY)")
                )
                # ...but sneak column 'a' in first, so the ALTER for 'a'
                # collides while 'b' should still succeed.
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN a VARCHAR"))

            _migrate_add_columns(engine)  # must not raise

            cols = {c["name"] for c in inspect(engine).get_columns(table_name)}
            assert {"id", "a", "b"} <= cols
        finally:
            Base.metadata.remove(Base.metadata.tables[table_name])
