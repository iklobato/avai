"""yara_rule — browsable inventory of compiled YARA rules

One row per loaded rule (identifier / tags / author / source / category) so
the dashboard can list and search every available rule. Rewritten by the
monitor when the rule count changes.

CREATE TABLE / INDEX IF NOT EXISTS so it's a no-op on a fresh create_all DB
and a real create on an incrementally-migrated one.

Revision ID: 0008_yara_rule
Revises: 0007_yara_status
Create Date: 2026-06-17
"""

from alembic import op

revision = "0008_yara_rule"
down_revision = "0007_yara_status"
branch_labels = None
depends_on = None

_YARA_RULE = """
CREATE TABLE IF NOT EXISTS yara_rule (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    identifier VARCHAR NOT NULL,
    tags VARCHAR,
    author VARCHAR,
    source VARCHAR,
    category VARCHAR
)
"""

_INDEXES = [
    ("ix_yara_rule_identifier", "yara_rule", "identifier"),
    ("ix_yara_rule_source", "yara_rule", "source"),
    ("ix_yara_rule_category", "yara_rule", "category"),
]


def upgrade() -> None:
    op.execute(_YARA_RULE)
    for name, table, col in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})")


def downgrade() -> None:
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    op.execute("DROP TABLE IF EXISTS yara_rule")
