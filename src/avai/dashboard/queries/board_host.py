"""Host numbers and vulnerability detail for the panels board."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from avai.host_monitor import HostResourceRow

from .board_findings import EvidenceLookup
from .panel_reads import Page, SchemaProbe
from .vulnerabilities import VulnerabilitiesPanel, VulnQuery

TREND_POINTS = 12
# Enough rows to find one package among everything the panel lists.
VULN_SCAN_LIMIT = 500


@dataclass(frozen=True)
class SvgBox:
    """The drawing area a series is scaled into."""

    width: float
    height: float
    top: float

    def points(self, values: list[float]) -> str:
        if not values:
            return ""
        series = values if len(values) > 1 else values + values
        step = self.width / (len(series) - 1)
        peak = max(self.top, max(series))
        return " ".join(
            f"{index * step:.1f},{self.height - value / peak * self.height:.1f}"
            for index, value in enumerate(series)
        )


class HostTrend:
    """The last few cycles of CPU, memory and load, oldest first."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def series(self) -> dict[str, list[Any]]:
        empty: dict[str, list[Any]] = {"labels": [], "cpu": [], "mem": [], "load": []}
        if "host_resources" not in SchemaProbe(self._session).tables():
            return empty
        rows = self._rows()
        if not rows:
            return empty
        labels, cpu, mem, load = (list(column) for column in zip(*rows))
        return {
            "labels": labels,
            "cpu": self._clean(cpu),
            "mem": self._clean(mem),
            "load": self._clean(load),
        }

    def _rows(self) -> list[Any]:
        row = HostResourceRow
        columns = (row.collected_at, row.cpu_percent, row.mem_percent, row.load_1)
        statement = (
            select(*columns).order_by(desc(row.collected_at)).limit(TREND_POINTS)
        )
        return list(reversed(self._session.execute(statement).all()))

    def _clean(self, values: list[Any]) -> list[float]:
        return [float(value or 0.0) for value in values]


class VulnInspector:
    """One vulnerable package and every database answer about it."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def detail(self, software: str) -> dict[str, Any] | None:
        query = VulnQuery(search=software, page=Page(1, VULN_SCAN_LIMIT))
        rows = VulnerabilitiesPanel(self._session).vulnerabilities(query)["rows"]
        match = next((row for row in rows if row["software"] == software), None)
        if match is None:
            return None
        values = [software, *(cve["id"] for cve in match["cves"])]
        evidence = EvidenceLookup(self._session).for_values(values)
        return {"kind": "vuln", **match, "evidence": evidence}
