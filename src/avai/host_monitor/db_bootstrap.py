"""Database bootstrap: SQLite connection settings, schema creation and
forward migration, and the file permissions the monitor and dashboard
share."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from alembic.util import CommandError
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.schema import Column, Table

from avai import db_migrate
from avai.enrichers.cache import EnrichmentSchema

from .models import Base


class DdlRace:
    """Tells a DDL statement that failed only because another process ran
    the same bootstrap first (monitor + dashboard both call Sink.setup on
    the shared SQLite file). SQLite reports these as "table ... already
    exists" or "duplicate column name ...". The resulting schema is
    identical either way, so the loser can safely continue."""

    def is_benign(self, exc: OperationalError) -> bool:
        message = str(exc).lower()
        return "already exists" in message or "duplicate column name" in message


class SqlitePragmas:
    """Connection settings applied to every new SQLite connection."""

    # How long a writer waits for the SQLite write lock before raising
    # "database is locked". Generous (vs. the 5s pysqlite default) so the
    # snapshot loop and streaming-worker threads can serialise their writes
    # through WAL checkpoints on a large DB without losing a batch.
    BUSY_TIMEOUT_MS = 30_000

    def apply(self, dbapi_conn: Any, _connection_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        # SQLite serialises writes, so the snapshot loop and the streaming
        # threads contend for the single write lock; a generous timeout makes
        # the contending writer block-and-retry rather than fail.
        cursor.execute(f"PRAGMA busy_timeout={self.BUSY_TIMEOUT_MS}")
        cursor.close()


class DbPermissions:
    """Make the DB dir + files group-writable so a root monitor and a
    same-group unprivileged dashboard can both write (the dashboard's only
    write is the control_state row). Best-effort: only the owner may chmod,
    so the non-owning process no-ops; the owning (root) monitor sets the
    mode, which is what unblocks the dashboard. SQLite creates the -wal/-shm
    siblings in the dir, so the directory itself must be group-writable."""

    DIR_MODE = 0o775  # rwxrwxr-x
    FILE_MODE = 0o664  # rw-rw-r--

    def relax(self, db_path: Path) -> None:
        targets = (
            (db_path.parent, self.DIR_MODE),
            (db_path, self.FILE_MODE),
            (db_path.with_name(db_path.name + "-wal"), self.FILE_MODE),
            (db_path.with_name(db_path.name + "-shm"), self.FILE_MODE),
        )
        for path, mode in targets:
            if path.exists():
                self._chmod(path, mode)

    def _chmod(self, path: Path, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except PermissionError:
            return  # not the owner; the owning process sets the mode


class ColumnMigration:
    """Idempotent forward-only migration: add any columns that exist on the
    ORM models but not yet on the live tables. SQLite supports ``ALTER
    TABLE ADD COLUMN`` (no ALTER COLUMN, no DROP COLUMN), so this handles
    the common case of adding a new optional field to a model."""

    def __init__(self, engine: Engine, logger: logging.Logger) -> None:
        self._engine = engine
        self._logger = logger

    def add_missing(self) -> None:
        inspector = inspect(self._engine)
        live_tables = set(inspector.get_table_names())
        for table in Base.metadata.tables.values():
            if table.name not in live_tables:
                continue
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            missing = [
                column for column in table.columns if column.name not in existing
            ]
            for column in missing:
                self._add(table, column)

    def _add(self, table: Table, column: Column[Any]) -> None:
        column_type = column.type.compile(self._engine.dialect)
        nullable = "" if column.nullable else " NOT NULL DEFAULT ''"
        statement = (
            f"ALTER TABLE {table.name} ADD COLUMN {column.name} {column_type}{nullable}"
        )
        try:
            with self._engine.begin() as conn:
                conn.execute(text(statement))
        except OperationalError as exc:
            # Another process added the column between our inspect and our
            # ALTER. Benign: keep going with the rest.
            if not DdlRace().is_benign(exc):
                raise
            return
        self._logger.info("schema migration: added %s.%s", table.name, column.name)


class SchemaMigrationError(RuntimeError):
    """The Alembic upgrade to head failed, so the DB would serve on a stale
    schema."""


class SchemaBootstrap:
    """Brings the database to the current schema on startup."""

    MIGRATION_FAILURES = (SQLAlchemyError, OSError, CommandError)

    def __init__(self, engine: Engine, logger: logging.Logger) -> None:
        self._engine = engine
        self._logger = logger

    def setup(self) -> None:
        # Register the enrichment evidence model on Base.metadata so
        # create_all provisions its table even when the enrichment chain
        # isn't enabled (the dashboard reads from it regardless).
        EnrichmentSchema(Base).model()
        self._create_all()
        ColumnMigration(self._engine, self._logger).add_missing()
        # An in-memory DB is per-connection: create_all already built the
        # head schema and Alembic (on its own connection) would see an empty
        # DB, so only file DBs get the real upgrade.
        db_file = self._engine.url.database
        if not db_file or db_file == ":memory:":
            return
        self._upgrade()
        DbPermissions().relax(Path(db_file))

    def _create_all(self) -> None:
        # create_all is not atomic against a second process running the same
        # bootstrap on the shared SQLite file; the loser's "already exists"
        # is benign because the schema is the same.
        try:
            Base.metadata.create_all(self._engine)
        except OperationalError as exc:
            if not DdlRace().is_benign(exc):
                raise
            self._logger.info(
                "create_all raced with another bootstrap (continuing): %s", exc
            )

    def _upgrade(self) -> None:
        # Runs on every start so a freshly updated build reaches head before
        # serving; a failure (e.g. a read-only DB owned by another user) is
        # loud rather than a stale schema that 500s later.
        try:
            db_migrate.AlembicMigrator(str(self._engine.url)).upgrade_to_head()
        except self.MIGRATION_FAILURES as exc:
            raise SchemaMigrationError(
                f"database migration to head failed for {self._engine.url}: {exc}. "
                "If this is 'readonly database', the DB is owned by another user "
                "(run the monitor as the owner so it can migrate + chmod it)."
            ) from exc
