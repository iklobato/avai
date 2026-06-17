"""baseline — the schema as built by Base.metadata.create_all

This is an empty baseline: avai still creates tables via create_all at
startup, and existing DBs are stamped to this revision so Alembic only runs
the *incremental* migrations that follow.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-05-31
"""

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
