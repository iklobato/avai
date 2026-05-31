"""Alembic migration tests: setup applies them, the stamp path works on a
pre-existing create_all DB, and upgrade/downgrade round-trips cleanly."""

from __future__ import annotations

import sqlite3

from sqlalchemy import create_engine

from avai.db_migrate import _config, upgrade_to_head
from avai.host_monitor import Base, Sink

_IDX = [
    "ix_collection_runs_started_at",
    "ix_judgements_created_at",
    "ix_enrichment_evidence_indicator_value",
]


def _indexes(db: str) -> set[str]:
    con = sqlite3.connect(db)
    try:
        return {
            r[0]
            for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    finally:
        con.close()


def _version(db: str) -> str | None:
    con = sqlite3.connect(db)
    try:
        row = con.execute("SELECT version_num FROM alembic_version").fetchone()
        return row[0] if row else None
    finally:
        con.close()


def test_sink_setup_applies_migrations(tmp_path):
    db = str(tmp_path / "a.db")
    Sink(create_engine(f"sqlite:///{db}")).setup()
    assert set(_IDX) <= _indexes(db)
    assert _version(db) == "0002_perf_indexes"


def test_upgrade_stamps_preexisting_create_all_db(tmp_path):
    db = str(tmp_path / "b.db")
    eng = create_engine(f"sqlite:///{db}")
    from avai.enrichers.cache import register_schema

    register_schema(Base)
    Base.metadata.create_all(eng)  # tables, but emulate an old DB:
    con = sqlite3.connect(db)
    for i in _IDX:
        con.execute(f"DROP INDEX IF EXISTS {i}")
    con.execute("DROP TABLE IF EXISTS alembic_version")
    con.commit()
    con.close()
    eng.dispose()
    assert not (_indexes(db) & set(_IDX))  # gone

    upgrade_to_head(f"sqlite:///{db}")  # stamps baseline then adds indexes
    assert set(_IDX) <= _indexes(db)
    assert _version(db) == "0002_perf_indexes"


def test_downgrade_then_upgrade_roundtrip(tmp_path):
    from alembic import command

    db = str(tmp_path / "c.db")
    Sink(create_engine(f"sqlite:///{db}")).setup()
    assert set(_IDX) <= _indexes(db)

    command.downgrade(_config(f"sqlite:///{db}"), "0001_baseline")
    assert not (_indexes(db) & set(_IDX))  # dropped

    command.upgrade(_config(f"sqlite:///{db}"), "head")
    assert set(_IDX) <= _indexes(db)  # recreated
