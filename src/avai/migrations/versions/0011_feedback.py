"""feedback — operator corrections fed back into judging

One row per operator correction on a finding (content_hash + collector,
label, note, artifact). The dashboard writes these; the monitor applies them
to the verdict and uses recent ones as host-specific ground-truth for the
judge.

CREATE TABLE / INDEX IF NOT EXISTS so it's a no-op on a fresh create_all DB
and a real create on an incrementally-migrated one.

Revision ID: 0011_feedback
Revises: 0010_yara_coverage
Create Date: 2026-06-17
"""

from alembic import op

revision = "0011_feedback"
down_revision = "0010_yara_coverage"
branch_labels = None
depends_on = None

_FEEDBACK = """
CREATE TABLE IF NOT EXISTS feedback (
    content_hash VARCHAR NOT NULL,
    collector VARCHAR NOT NULL,
    label VARCHAR NOT NULL,
    note VARCHAR,
    artifact VARCHAR,
    created_at VARCHAR NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (content_hash, collector)
)
"""


def upgrade() -> None:
    op.execute(_FEEDBACK)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_feedback_created_at ON feedback (created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_feedback_created_at")
    op.execute("DROP TABLE IF EXISTS feedback")
