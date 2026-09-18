"""The network flows panel."""

from __future__ import annotations

from sqlalchemy import (
    and_,
    literal,
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
    _existing_columns,
    _existing_tables,
    _port_sort_key,
)
from .ip_enrichment import _attach_ip_enrichment


def network_flows(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    q: str = "",
    page: Page = Page(),
):
    """Tcpdump flows for ``run_id``, **aggregated by destination IP** for
    a compact, glanceable table.

    Each raw flow is one (iface, proto, dst_ip, dst_port) with a packet
    count and (LEFT JOIN) its LLM verdict. We roll those up per dst_ip:
    SUM(packets), COUNT(flows), the set of interfaces / protocols /
    ports, and the worst verdict among the destination's flows. Returns
    ``{"summary": {...}, "rows": [...]}`` with rows worst-verdict first
    then by total packets.

    Degrades to empty if the network_flows table doesn't exist yet
    (DB written by a monitor that predates this collector)."""
    empty = {
        "summary": {
            "destinations": 0,
            "flows": 0,
            "packets": 0,
            "malicious": 0,
            "suspicious": 0,
        },
        "rows": [],
    }
    if "network_flows" not in _existing_tables(session):
        return empty

    # Tolerate a network_flows table written by an older monitor that
    # lacks newer columns (iface / service) — substitute a NULL literal
    # so the SELECT doesn't 500 on "no such column".
    cols = _existing_columns(session, "network_flows")
    iface_sel = (
        NetworkFlowRow.iface if "iface" in cols else literal(None).label("iface")
    )
    service_sel = (
        NetworkFlowRow.service if "service" in cols else literal(None).label("service")
    )
    process_sel = (
        NetworkFlowRow.process if "process" in cols else literal(None).label("process")
    )
    bytes_sel = (
        NetworkFlowRow.byte_count
        if "byte_count" in cols
        else literal(None).label("byte_count")
    )

    stmt = (
        select(
            iface_sel,
            NetworkFlowRow.proto,
            NetworkFlowRow.dst_ip,
            NetworkFlowRow.dst_port,
            service_sel,
            NetworkFlowRow.packets,
            bytes_sel,
            process_sel,
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
        .limit(limit)
    )

    groups: dict[str, dict] = {}
    for (
        iface,
        proto,
        dst_ip,
        dst_port,
        service,
        packets,
        byte_count,
        process,
        row_verdict,
        conf,
        reason,
    ) in session.execute(stmt).all():
        g = groups.get(dst_ip)
        if g is None:
            g = groups[dst_ip] = {
                "dst_ip": dst_ip,
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
        g["packets"] += packets or 0
        g["bytes"] += byte_count or 0
        g["flows"] += 1
        if iface:
            g["_ifaces"].add(iface)
        if proto:
            g["_protos"].add(proto)
        if process:
            g["_procs"].add(process)
        if dst_port is not None:
            g["_ports"].add(f"{dst_port}/{service}" if service else str(dst_port))
        # Keep the worst (lowest-severity-number) verdict + its reasoning.
        if _FLOW_SEV.get(row_verdict, 4) < _FLOW_SEV.get(g["verdict"], 4):
            g["verdict"] = row_verdict
            g["confidence"] = conf
            g["reasoning"] = reason or ""

    rows = []
    for g in groups.values():
        rows.append(
            {
                "dst_ip": g["dst_ip"],
                "iface": ", ".join(sorted(g["_ifaces"])) or "—",
                "proto": [p.upper() for p in sorted(g["_protos"])],
                "ports": sorted(g["_ports"], key=_port_sort_key),
                "process": ", ".join(sorted(g["_procs"])) or "—",
                "packets": g["packets"],
                "bytes": g["bytes"],
                "flows": g["flows"],
                "verdict": g["verdict"],
                "confidence": g["confidence"],
                "reasoning": g["reasoning"],
                "geo": None,  # filled below from the enrichment cache
                "hostname": None,  # filled below from the enrichment cache
            }
        )

    # Attach geolocation + resolved hostname per destination IP from the
    # enrichment_evidence cache the monitor already populated (ipwho.is
    # geo, Shodan/AbuseIPDB hostnames, AbuseIPDB/Feodo geo fallbacks).
    _attach_ip_enrichment(session, rows)

    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -r["packets"]))

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("dst_ip") or "").lower()
            or ql in (r.get("hostname") or "").lower()
            or ql in (r.get("process") or "").lower()
        ]

    summary = {
        "destinations": len(rows),
        "flows": sum(r["flows"] for r in rows),
        "packets": sum(r["packets"] for r in rows),
        "bytes": sum(r["bytes"] for r in rows),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }

    page_rows, paging = page.slice(rows)
    return {
        "summary": summary,
        "rows": page_rows,
        **paging,
        "q": q,
        "verdict": verdict,
    }
