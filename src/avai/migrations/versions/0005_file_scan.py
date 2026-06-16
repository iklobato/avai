"""file_scan — YARA file-scan match table

Adds the table written by FileScanCollector: one row per (file, matched
YARA rule). content_hash is derived from the judgeable fields so the same
file matching the same rule dedupes across cycles.

Uses CREATE TABLE/INDEX IF NOT EXISTS so it's a no-op on a fresh DB that
already got the table from create_all (the model columns carry the
indexes), and a real create on a DB that migrates incrementally. Index
names match SQLAlchemy's ix_<table>_<column>.

Revision ID: 0005_file_scan
Revises: 0004_host_resources
Create Date: 2026-06-16
"""

from alembic import op

revision = "0005_file_scan"
down_revision = "0004_host_resources"
branch_labels = None
depends_on = None

_FILE_SCAN = """
CREATE TABLE IF NOT EXISTS file_scan (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    run_id VARCHAR NOT NULL,
    collected_at VARCHAR NOT NULL,
    content_hash VARCHAR,
    path VARCHAR NOT NULL,
    sha256 VARCHAR,
    rule VARCHAR,
    namespace VARCHAR,
    tags_json VARCHAR,
    size INTEGER,
    mtime FLOAT,
    scan_source VARCHAR
)
"""

_INDEXES = [
    ("ix_file_scan_run_id", "file_scan", "run_id"),
    ("ix_file_scan_content_hash", "file_scan", "content_hash"),
    ("ix_file_scan_path", "file_scan", "path"),
    ("ix_file_scan_sha256", "file_scan", "sha256"),
]


def upgrade() -> None:
    op.execute(_FILE_SCAN)
    for name, table, col in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})")


def downgrade() -> None:
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    op.execute("DROP TABLE IF EXISTS file_scan")
