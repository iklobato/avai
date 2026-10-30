"""judgements.remediation_plain / verify_outcome, control_state second-pass
switches and capabilities_json

The panels board explains a finding in plain words and says what the skeptic
second pass decided; the Setup panel shows what the monitor runs with and
lets the operator switch the second passes off. All columns are nullable and
optional for readers: NULL means "not written by this monitor yet".

Guarded with a PRAGMA check per column: a fresh DB already has them from
create_all, so ALTER would raise "duplicate column" there; only an
incrementally-migrated DB needs the ADD COLUMN.

Revision ID: 0013_board_phase2
Revises: 0012_log_entries
Create Date: 2026-10-30
"""

from alembic import op

revision = "0013_board_phase2"
down_revision = "0012_log_entries"
branch_labels = None
depends_on = None

_COLUMNS = [
    ("judgements", "remediation_plain", "VARCHAR"),
    ("judgements", "verify_outcome", "VARCHAR"),
    ("control_state", "verify_enabled", "INTEGER"),
    ("control_state", "investigate_enabled", "INTEGER"),
    ("control_state", "capabilities_json", "VARCHAR"),
]


def _has_column(bind, table: str, column: str) -> bool:
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def upgrade() -> None:
    bind = op.get_bind()
    for table, column, kind in _COLUMNS:
        if not _has_column(bind, table, column):
            op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")


def downgrade() -> None:
    # SQLite gained DROP COLUMN in 3.35; guard so it's a no-op when absent.
    bind = op.get_bind()
    for table, column, _ in reversed(_COLUMNS):
        if _has_column(bind, table, column):
            op.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
