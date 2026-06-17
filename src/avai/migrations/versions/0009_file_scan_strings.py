"""file_scan.strings_json — retain a redacted sample of matched bytes

Adds the strings_json column written by FileScanCollector. It carries a
bounded, redacted sample of the bytes that actually matched each YARA rule
([{id, offset, text|hex, truncated}]), so the judge can distinguish a
substantive hit (a real C2 URL / mutex / command line) from a generic
substring that points to a false positive.

Guarded with a PRAGMA check: a fresh DB already has the column from
create_all (the model carries it), so ALTER would raise "duplicate column"
there — only an incrementally-migrated DB needs the ADD COLUMN.

Revision ID: 0009_file_scan_strings
Revises: 0008_yara_rule
Create Date: 2026-06-17
"""

from alembic import op

revision = "0009_file_scan_strings"
down_revision = "0008_yara_rule"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "file_scan", "strings_json"):
        op.execute("ALTER TABLE file_scan ADD COLUMN strings_json VARCHAR")


def downgrade() -> None:
    # SQLite gained DROP COLUMN in 3.35; guard so it's a no-op when absent.
    bind = op.get_bind()
    if _has_column(bind, "file_scan", "strings_json"):
        op.execute("ALTER TABLE file_scan DROP COLUMN strings_json")
