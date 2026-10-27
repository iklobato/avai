from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, MetaData, Table, create_engine, select


class ExternalSqliteReader:
    """Reflect an external SQLite table and yield row dicts."""

    def rows(
        self, path: Path, table_name: str, columns: list[str]
    ) -> Iterator[dict[str, Any]]:
        engine = create_engine(f"sqlite:///file:{path}?mode=ro&uri=true")
        try:
            yield from self._read(engine, table_name, columns)
        finally:
            engine.dispose()

    def _read(
        self, engine: Engine, table_name: str, columns: list[str]
    ) -> Iterator[dict[str, Any]]:
        table = Table(table_name, MetaData(), autoload_with=engine)
        stmt = select(*(table.c[column] for column in columns))
        with engine.connect() as conn:
            for row in conn.execute(stmt):
                yield dict(row._mapping)
