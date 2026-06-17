"""yara_coverage — LLM assessment of ruleset coverage vs the host

One row per assessment of how well the loaded YARA ruleset covers this
host's threat surface (posture / headline / summary / gaps /
recommendations). The dashboard shows the most recent row; the monitor
regenerates only when the ruleset fingerprint changes.

CREATE TABLE / INDEX IF NOT EXISTS so it's a no-op on a fresh create_all DB
and a real create on an incrementally-migrated one.

Revision ID: 0010_yara_coverage
Revises: 0009_file_scan_strings
Create Date: 2026-06-17
"""

from alembic import op

revision = "0010_yara_coverage"
down_revision = "0009_file_scan_strings"
branch_labels = None
depends_on = None

_YARA_COVERAGE = """
CREATE TABLE IF NOT EXISTS yara_coverage (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at VARCHAR NOT NULL,
    run_id VARCHAR,
    model VARCHAR NOT NULL,
    posture VARCHAR NOT NULL,
    headline VARCHAR NOT NULL,
    summary VARCHAR,
    gaps_json VARCHAR,
    recommendations_json VARCHAR,
    ruleset_fingerprint VARCHAR
)
"""


def upgrade() -> None:
    op.execute(_YARA_COVERAGE)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_yara_coverage_created_at "
        "ON yara_coverage (created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_yara_coverage_created_at")
    op.execute("DROP TABLE IF EXISTS yara_coverage")
