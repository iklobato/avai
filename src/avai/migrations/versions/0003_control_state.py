"""control_state — cooperative dashboard→monitor control channel

One single-row table (id=1) the dashboard writes and the monitor reads each
poll tick. Uses CREATE TABLE IF NOT EXISTS so it's a no-op when a fresh DB
already got the table from create_all (the model defines it), and a real
create on older DBs that predate it. Schema matches models.ControlState.

The id=1 row is seeded at runtime by Sink.ensure_control_row (so a
dashboard-only DB gets it too), not here.

Revision ID: 0003_control_state
Revises: 0002_perf_indexes
Create Date: 2026-05-31
"""

from alembic import op

revision = "0003_control_state"
down_revision = "0002_perf_indexes"
branch_labels = None
depends_on = None

_CREATE = """
CREATE TABLE IF NOT EXISTS control_state (
    id INTEGER NOT NULL PRIMARY KEY,
    paused INTEGER NOT NULL DEFAULT 0,
    interval_override INTEGER,
    judge_enabled INTEGER,
    enrich_enabled INTEGER,
    disabled_collectors VARCHAR,
    scan_now_nonce INTEGER NOT NULL DEFAULT 0,
    scan_now_applied INTEGER NOT NULL DEFAULT 0,
    command VARCHAR,
    command_nonce INTEGER NOT NULL DEFAULT 0,
    command_applied INTEGER NOT NULL DEFAULT 0,
    command_result VARCHAR,
    pid INTEGER,
    status VARCHAR,
    last_seen_at VARCHAR,
    applied_at VARCHAR,
    current_interval INTEGER
)
"""


def upgrade() -> None:
    op.execute(_CREATE)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS control_state")
