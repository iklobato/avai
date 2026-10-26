"""Programmatic Alembic runner.

The monitor calls :meth:`AlembicMigrator.upgrade_to_head` on startup (after ``create_all``)
and the ``avai migrate`` CLI exposes it for standalone DBs (e.g. a seeded
demo DB). Migrations are stored in ``avai/migrations`` and ship with the
package, so there's no repo-root ``alembic.ini`` to locate at runtime — the
config is built in code.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

SCRIPT_LOCATION = str(Path(__file__).resolve().parent / "migrations")
BASELINE_REVISION = "0001_baseline"
VERSION_TABLE = "alembic_version"


class AlembicMigrator:
    """Runs the packaged Alembic migrations against one database URL."""

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def config(self) -> Config:
        alembic_config = Config()
        alembic_config.set_main_option("script_location", SCRIPT_LOCATION)
        alembic_config.set_main_option("sqlalchemy.url", self._db_url)
        return alembic_config

    def upgrade_to_head(self) -> None:
        """Apply all pending migrations.

        A DB created by ``create_all`` already has the tables but no
        ``alembic_version`` row: stamp it to the baseline first so Alembic
        only runs the *incremental* migrations on top (the index migration uses
        ``IF NOT EXISTS``, so it's a no-op when ``create_all`` already made them).
        """
        tables = self._tables()
        alembic_config = self.config()
        if tables and VERSION_TABLE not in tables:
            command.stamp(alembic_config, BASELINE_REVISION)
        command.upgrade(alembic_config, "head")

    def _tables(self) -> set[str]:
        engine = create_engine(self._db_url)
        try:
            return set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
