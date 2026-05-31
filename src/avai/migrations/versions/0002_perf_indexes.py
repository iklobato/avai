"""perf indexes — surgical indexes for hot dashboard query paths

- collection_runs.started_at  → latest_run / prior_run / recent_runs ORDER BY
- judgements.created_at        → overview sums, notifications, verdict chart
- enrichment_evidence.indicator_value → flow-geo lookup (IN-list, non-leading PK)

Uses CREATE INDEX IF NOT EXISTS so it's a no-op when a fresh DB already got
the index from create_all (the model columns carry index=True), and a real
create on older DBs that predate them. Names match SQLAlchemy's ix_<t>_<c>.

Revision ID: 0002_perf_indexes
Revises: 0001_baseline
Create Date: 2026-05-31
"""

from alembic import op

revision = "0002_perf_indexes"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

_INDEXES = [
    ("ix_collection_runs_started_at", "collection_runs", "started_at"),
    ("ix_judgements_created_at", "judgements", "created_at"),
    (
        "ix_enrichment_evidence_indicator_value",
        "enrichment_evidence",
        "indicator_value",
    ),
]


def upgrade() -> None:
    for name, table, col in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})")


def downgrade() -> None:
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
