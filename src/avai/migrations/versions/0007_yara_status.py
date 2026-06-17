"""yara_status — single-row snapshot of the compiled file-scan ruleset

The dashboard is read-only and can't see the monitor's in-memory YARA
ruleset, so the monitor persists a summary here (counts, sources, skip
reasons, per-category breakdown) for the File Scan panel to render.

CREATE TABLE IF NOT EXISTS so it's a no-op on a fresh create_all DB and a
real create on an incrementally-migrated one.

Revision ID: 0007_yara_status
Revises: 0006_file_scan_meta
Create Date: 2026-06-17
"""

from alembic import op

revision = "0007_yara_status"
down_revision = "0006_file_scan_meta"
branch_labels = None
depends_on = None

_YARA_STATUS = """
CREATE TABLE IF NOT EXISTS yara_status (
    id INTEGER NOT NULL PRIMARY KEY,
    compiled_at VARCHAR,
    rules_loaded INTEGER,
    files_loaded INTEGER,
    files_skipped INTEGER,
    rules_dir VARCHAR,
    sources_json VARCHAR,
    skip_reasons_json VARCHAR,
    by_category_json VARCHAR
)
"""


def upgrade() -> None:
    op.execute(_YARA_STATUS)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS yara_status")
