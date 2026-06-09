"""host_resources + disk_usage — htop-style resource snapshot tables

Adds the two continuous-metric tables collected by HostResourcesCollector
and DiskUsageCollector (memory/swap/CPU/load/uptime + per-filesystem df).

Uses CREATE TABLE/INDEX IF NOT EXISTS so it's a no-op on a fresh DB that
already got the tables from create_all (the model columns carry the
indexes), and a real create on a DB that migrates incrementally. Index
names match SQLAlchemy's ix_<table>_<column>.

Revision ID: 0004_host_resources
Revises: 0003_control_state
Create Date: 2026-06-08
"""

from alembic import op

revision = "0004_host_resources"
down_revision = "0003_control_state"
branch_labels = None
depends_on = None

_HOST_RESOURCES = """
CREATE TABLE IF NOT EXISTS host_resources (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    run_id VARCHAR NOT NULL,
    collected_at VARCHAR NOT NULL,
    content_hash VARCHAR,
    mem_total INTEGER, mem_available INTEGER, mem_used INTEGER,
    mem_free INTEGER, mem_percent FLOAT,
    mem_active INTEGER, mem_inactive INTEGER, mem_buffers INTEGER,
    mem_cached INTEGER, mem_wired INTEGER,
    swap_total INTEGER, swap_used INTEGER, swap_free INTEGER, swap_percent FLOAT,
    cpu_percent FLOAT, cpu_user FLOAT, cpu_system FLOAT, cpu_idle FLOAT,
    cpu_iowait FLOAT, cpu_per_core_json VARCHAR,
    cpu_count_physical INTEGER, cpu_count_logical INTEGER,
    load_1 FLOAT, load_5 FLOAT, load_15 FLOAT,
    boot_time FLOAT, uptime_seconds INTEGER,
    tasks_total INTEGER, tasks_running INTEGER, threads_total INTEGER
)
"""

_DISK_USAGE = """
CREATE TABLE IF NOT EXISTS disk_usage (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    run_id VARCHAR NOT NULL,
    collected_at VARCHAR NOT NULL,
    content_hash VARCHAR,
    device VARCHAR, mountpoint VARCHAR, fstype VARCHAR, opts VARCHAR,
    total INTEGER, used INTEGER, free INTEGER, percent FLOAT,
    io_read_bytes INTEGER, io_write_bytes INTEGER,
    io_read_count INTEGER, io_write_count INTEGER
)
"""

_INDEXES = [
    ("ix_host_resources_run_id", "host_resources", "run_id"),
    ("ix_host_resources_content_hash", "host_resources", "content_hash"),
    ("ix_disk_usage_run_id", "disk_usage", "run_id"),
    ("ix_disk_usage_content_hash", "disk_usage", "content_hash"),
    ("ix_disk_usage_mountpoint", "disk_usage", "mountpoint"),
]


def upgrade() -> None:
    op.execute(_HOST_RESOURCES)
    op.execute(_DISK_USAGE)
    for name, table, col in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})")


def downgrade() -> None:
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    op.execute("DROP TABLE IF EXISTS disk_usage")
    op.execute("DROP TABLE IF EXISTS host_resources")
