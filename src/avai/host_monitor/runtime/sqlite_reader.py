"""Read-only reader for external SQLite databases.

Browser/quarantine collectors reflect tables out of third-party SQLite
files (Chrome history, the macOS quarantine DB, …). This collaborator
owns the engine lifecycle and exposes a single ``rows`` method; it issues
no raw SQL (the table is reflected and columns are selected by name).
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from sqlalchemy import MetaData, Table, create_engine, select


class ExternalSqliteReader:
    """Reflect an external SQLite table and yield row dicts."""

    def rows(self, path: Path, table_name: str, columns: list[str]) -> Iterable[dict]:
        url = f"sqlite:///file:{path}?mode=ro&uri=true"
        engine = create_engine(url)
        try:
            meta = MetaData()
            table = Table(table_name, meta, autoload_with=engine)
            stmt = select(*(table.c[c] for c in columns))
            with engine.connect() as conn:
                for row in conn.execute(stmt):
                    yield dict(row._mapping)
        finally:
            engine.dispose()
