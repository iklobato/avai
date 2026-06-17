"""file_scan.meta_json — retain matched-rule meta (author/reference/…)

Adds the meta_json column written by FileScanCollector. It carries each
matched YARA rule's meta dict, which is needed to satisfy the
signature-base DRL attribution obligation (match output must retain author
identification) and gives the judge/dashboard rule context.

Guarded with a PRAGMA check: a fresh DB already has the column from
create_all (the model carries it), so ALTER would raise "duplicate column"
there — only an incrementally-migrated DB needs the ADD COLUMN.

Revision ID: 0006_file_scan_meta
Revises: 0005_file_scan
Create Date: 2026-06-16
"""

from alembic import op

revision = "0006_file_scan_meta"
down_revision = "0005_file_scan"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "file_scan", "meta_json"):
        op.execute("ALTER TABLE file_scan ADD COLUMN meta_json VARCHAR")


def downgrade() -> None:
    # SQLite gained DROP COLUMN in 3.35; guard so it's a no-op when absent.
    bind = op.get_bind()
    if _has_column(bind, "file_scan", "meta_json"):
        op.execute("ALTER TABLE file_scan DROP COLUMN meta_json")
