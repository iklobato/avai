"""Alembic environment for avai. Migrations are run programmatically via
avai.db_migrate (and the ``avai migrate`` CLI); the sqlalchemy.url is set by
the caller, not read from an ini file."""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the full schema visible to Alembic autogenerate. register_schema
# attaches the enrichment_evidence table to the shared Base.metadata.
from avai.enrichers.cache import register_schema
from avai.host_monitor import Base

register_schema(Base)
target_metadata = Base.metadata

config = context.config


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,  # SQLite-safe ALTERs
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
