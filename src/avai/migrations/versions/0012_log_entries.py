"""log_entries — generic host log capture (journald + tailed files)

Adds the table written by LogTailCollector: a per-run snapshot of the most
recent log lines from journald and a configured set of plain-text log files,
surfaced in the dashboard's logs panel. High-volume telemetry, not LLM-judged.

CREATE TABLE/INDEX IF NOT EXISTS so it's a no-op on a fresh DB that already
got the table from create_all (the model columns carry the indexes), and a
real create on a DB that migrates incrementally. Index names match
SQLAlchemy's ix_<table>_<column>.

Revision ID: 0012_log_entries
Revises: 0011_feedback
Create Date: 2026-06-24
"""

from alembic import op

revision = "0012_log_entries"
down_revision = "0011_feedback"
branch_labels = None
depends_on = None

_LOG_ENTRIES = """
CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    run_id VARCHAR NOT NULL,
    collected_at VARCHAR NOT NULL,
    content_hash VARCHAR,
    source VARCHAR,
    unit VARCHAR,
    level VARCHAR,
    event_timestamp VARCHAR,
    pid INTEGER,
    message VARCHAR
)
"""

_INDEXES = [
    ("ix_log_entries_run_id", "log_entries", "run_id"),
    ("ix_log_entries_content_hash", "log_entries", "content_hash"),
    ("ix_log_entries_source", "log_entries", "source"),
    ("ix_log_entries_unit", "log_entries", "unit"),
    ("ix_log_entries_level", "log_entries", "level"),
    ("ix_log_entries_event_timestamp", "log_entries", "event_timestamp"),
]


def upgrade() -> None:
    op.execute(_LOG_ENTRIES)
    for name, table, col in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})")


def downgrade() -> None:
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    op.execute("DROP TABLE IF EXISTS log_entries")
