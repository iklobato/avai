"""The network flows panel."""

from __future__ import annotations

from sqlalchemy import (
    and_,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Judgement,
    NetworkFlowRow,
)

from .common import (
    _FLOW_SEV,
    Page,
    RowFilter,
    _column_or_null,
    _existing_columns,
    _existing_tables,
    _port_sort_key,
    _take_worse_verdict,
)
from .ip_enrichment import _attach_ip_enrichment

_FLOW_LIMIT = 1000
_FLOW_SEARCH = ("dst_ip", "hostname", "process")


def _flows_with_verdict(session: Session, run_id: str):
    """This run's raw flows, each LEFT JOINed to its LLM verdict. Tolerates a
    table written by an older monitor that lacks the newer columns."""
    cols = _existing_columns(session, "network_flows")
    return session.execute(
        select(
            _column_or_null(NetworkFlowRow, "iface", cols),
            NetworkFlowRow.proto,
            NetworkFlowRow.dst_ip,
            NetworkFlowRow.dst_port,
            _column_or_null(NetworkFlowRow, "service", cols),
            NetworkFlowRow.packets,
            _column_or_null(NetworkFlowRow, "byte_count", cols),
            _column_or_null(NetworkFlowRow, "process", cols),
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        )
        .outerjoin(
            Judgement,
            and_(
                Judgement.content_hash == NetworkFlowRow.content_hash,
                Judgement.collector == "network_flows",
            ),
        )
        .where(NetworkFlowRow.run_id == run_id)
        .limit(_FLOW_LIMIT)
    ).all()


def _flows_by_destination(flows) -> list[dict]:
    """Roll raw flows up per destination IP: summed packets and bytes, the
    flow count, the sets of interfaces / protocols / ports / processes, and
    the worst verdict among them."""
    groups: dict[str, dict] = {}
    for flow in flows:
        g = groups.get(flow.dst_ip)
        if g is None:
            g = groups[flow.dst_ip] = {
                "dst_ip": flow.dst_ip,
                "packets": 0,
                "bytes": 0,
                "flows": 0,
                "_ifaces": set(),
                "_protos": set(),
                "_ports": set(),
                "_procs": set(),
                "verdict": None,
                "confidence": None,
                "reasoning": "",
            }
        g["packets"] += flow.packets or 0
        g["bytes"] += flow.byte_count or 0
        g["flows"] += 1
        g["_ifaces"].add(flow.iface)
        g["_protos"].add(flow.proto)
        g["_procs"].add(flow.process)
        if flow.dst_port is not None:
            port = flow.dst_port
            g["_ports"].add(f"{port}/{flow.service}" if flow.service else str(port))
        _take_worse_verdict(g, flow.verdict, flow.confidence, flow.reasoning)
    return [_destination_row(g) for g in groups.values()]


def _destination_row(group: dict) -> dict:
    ifaces = sorted(filter(None, group["_ifaces"]))
    procs = sorted(filter(None, group["_procs"]))
    return {
        "dst_ip": group["dst_ip"],
        "iface": ", ".join(ifaces) or "—",
        "proto": [p.upper() for p in sorted(filter(None, group["_protos"]))],
        "ports": sorted(group["_ports"], key=_port_sort_key),
        "process": ", ".join(procs) or "—",
        "packets": group["packets"],
        "bytes": group["bytes"],
        "flows": group["flows"],
        "verdict": group["verdict"],
        "confidence": group["confidence"],
        "reasoning": group["reasoning"],
        "geo": None,  # filled from the enrichment cache
        "hostname": None,  # filled from the enrichment cache
    }


def network_flows(
    session: Session,
    run_id: str,
    filters: RowFilter = RowFilter(),
    page: Page = Page(),
):
    """Tcpdump flows for ``run_id``, **aggregated by destination IP** for
    a compact, glanceable table, worst verdict first then by total packets.
    Returns ``{"summary": {...}, "rows": [...]}``.

    Degrades to empty if the network_flows table doesn't exist yet
    (DB written by a monitor that predates this collector)."""
    if "network_flows" not in _existing_tables(session):
        return {
            "summary": {
                "destinations": 0,
                "flows": 0,
                "packets": 0,
                "malicious": 0,
                "suspicious": 0,
            },
            "rows": [],
        }
    rows = _flows_by_destination(_flows_with_verdict(session, run_id))
    # Geolocation + resolved hostname per destination, from the evidence
    # cache the monitor already populated.
    _attach_ip_enrichment(session, rows)
    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -r["packets"]))
    rows = filters.keep(rows, _FLOW_SEARCH)

    summary = {
        "destinations": len(rows),
        "flows": sum(r["flows"] for r in rows),
        "packets": sum(r["packets"] for r in rows),
        "bytes": sum(r["bytes"] for r in rows),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }
    page_rows, paging = page.slice(rows)
    return {"summary": summary, "rows": page_rows, **paging, **filters.fields()}
