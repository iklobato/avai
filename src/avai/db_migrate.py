"""Programmatic Alembic runner.

The monitor calls :func:`upgrade_to_head` on startup (after ``create_all``)
and the ``avai migrate`` CLI exposes it for standalone DBs (e.g. a seeded
demo DB). Migrations are stored in ``avai/migrations`` and ship with the
package, so there's no repo-root ``alembic.ini`` to locate at runtime — the
config is built in code.
"""

from __future__ import annotations

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPT_LOCATION = os.path.join(_HERE, "migrations")
_BASELINE = "0001_baseline"


def _config(db_url: str):
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", _SCRIPT_LOCATION)
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def upgrade_to_head(db_url: str) -> None:
    """Apply all pending migrations to ``db_url``.

    A DB created by ``create_all`` already has the tables but no
    ``alembic_version`` row — we stamp it to the baseline first so Alembic
    only runs the *incremental* migrations on top (the index migration uses
    ``IF NOT EXISTS``, so it's a no-op when ``create_all`` already made them).
    """
    from alembic import command
    from sqlalchemy import create_engine, inspect

    engine = create_engine(db_url)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    cfg = _config(db_url)
    if tables and "alembic_version" not in tables:
        command.stamp(cfg, _BASELINE)
    command.upgrade(cfg, "head")
