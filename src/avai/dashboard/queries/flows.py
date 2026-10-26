"""The network flows panel."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from avai.host_monitor import Judgement, NetworkFlowRow

from .ip_enrichment import IpEnrichment
from .panel_reads import (
    ColumnPicker,
    Page,
    PortLabel,
    RowFilter,
    SchemaProbe,
    VerdictRank,
    VerdictTally,
)

FLOW_SEARCH = ("dst_ip", "hostname", "process")


class DestinationGroup:
    """Raw flows to one destination IP, rolled up: summed packets and bytes,
    the flow count, the interfaces / protocols / ports / processes seen, and
    the worst verdict among them."""

    def __init__(self, dst_ip: str) -> None:
        self._dst_ip = dst_ip
        self._flows: list[Any] = []

    def add(self, flow: Any) -> None:
        self._flows.append(flow)

    def row(self) -> dict[str, Any]:
        flows = self._flows
        protocols = sorted(filter(None, {flow.proto for flow in flows}))
        return {
            "dst_ip": self._dst_ip,
            "iface": self._joined({flow.iface for flow in flows}),
            "proto": [protocol.upper() for protocol in protocols],
            "ports": sorted(self._ports(), key=PortLabel().sort_key),
            "process": self._joined({flow.process for flow in flows}),
            "packets": sum(flow.packets or 0 for flow in flows),
            "bytes": sum(flow.byte_count or 0 for flow in flows),
            "flows": len(flows),
            **self._worst(),
            "geo": None,  # filled from the enrichment cache
            "hostname": None,  # filled from the enrichment cache
        }

    def _joined(self, values: set[str | None]) -> str:
        return ", ".join(sorted(filter(None, values))) or "—"

    def _ports(self) -> set[str]:
        return {
            f"{flow.dst_port}/{flow.service}" if flow.service else str(flow.dst_port)
            for flow in self._flows
            if flow.dst_port is not None
        }

    def _worst(self) -> dict[str, Any]:
        worst: dict[str, Any] = {"verdict": None, "confidence": None, "reasoning": ""}
        rank = VerdictRank()
        for flow in self._flows:
            rank.take_worse(worst, (flow.verdict, flow.confidence, flow.reasoning))
        return worst


@dataclass(frozen=True)
class FlowQuery:
    filters: RowFilter = field(default_factory=RowFilter)
    page: Page = field(default_factory=Page)


class FlowsPanel:
    """Tcpdump flows for a run, **aggregated by destination IP**, worst
    verdict first then by total packets. Empty when the network_flows table
    doesn't exist yet (a DB written by an older monitor)."""

    FLOW_LIMIT = 1000
    EMPTY_SUMMARY = (
        ("destinations", 0),
        ("flows", 0),
        ("packets", 0),
        ("malicious", 0),
        ("suspicious", 0),
    )

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def flows(self, query: FlowQuery) -> dict[str, Any]:
        if "network_flows" not in SchemaProbe(self._session).tables():
            return {"summary": dict(self.EMPTY_SUMMARY), "rows": []}
        rows = self._by_destination(self._flows())
        # Geolocation + resolved hostname per destination, from the evidence
        # cache the monitor already populated.
        IpEnrichment(self._session).attach(rows)
        rows = query.filters.keep(sorted(rows, key=self._order), FLOW_SEARCH)
        page_rows, paging = query.page.slice(rows)
        return {
            "summary": self._summary(rows),
            "rows": page_rows,
            **paging,
            **query.filters.fields(),
        }

    def _order(self, row: dict[str, Any]) -> tuple[int, int]:
        return VerdictRank().rank(row["verdict"]), -row["packets"]

    def _summary(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        tally = VerdictTally().of(rows)
        return {
            "destinations": len(rows),
            "flows": sum(row["flows"] for row in rows),
            "packets": sum(row["packets"] for row in rows),
            "bytes": sum(row["bytes"] for row in rows),
            "malicious": tally["malicious"],
            "suspicious": tally["suspicious"],
        }

    def _by_destination(self, flows: list[Any]) -> list[dict[str, Any]]:
        groups: dict[str, DestinationGroup] = {}
        for flow in flows:
            groups.setdefault(flow.dst_ip, DestinationGroup(flow.dst_ip)).add(flow)
        return [group.row() for group in groups.values()]

    def _flows(self) -> list[Any]:
        """This run's raw flows, each LEFT JOINed to its LLM verdict. A table
        written by an older monitor reads its missing columns as NULL."""
        model = NetworkFlowRow
        picker = ColumnPicker(
            model, SchemaProbe(self._session).columns("network_flows")
        )
        statement = self._statement(picker).where(model.run_id == self._run_id)
        return list(self._session.execute(statement.limit(self.FLOW_LIMIT)).all())

    def _statement(self, picker: ColumnPicker) -> Any:
        model = NetworkFlowRow
        judged = and_(
            Judgement.content_hash == model.content_hash,
            Judgement.collector == "network_flows",
        )
        return select(
            picker.column("iface"),
            model.proto,
            model.dst_ip,
            model.dst_port,
            picker.column("service"),
            model.packets,
            picker.column("byte_count"),
            picker.column("process"),
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        ).outerjoin(Judgement, judged)
