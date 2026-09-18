"""The listening ports panel."""

from __future__ import annotations

import ipaddress
import json

from sqlalchemy import (
    and_,
    func,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Judgement,
    ListeningPortRow,
    NetworkConnectionRow,
    ProcessRow,
)

from .common import _FLOW_SEV, Page, RowFilter, _existing_tables, _take_worse_verdict

_PROTO_BY_SOCK = {"SOCK_STREAM": "TCP", "SOCK_DGRAM": "UDP"}


_FAMILY_LABEL = {"AF_INET": "IPv4", "AF_INET6": "IPv6"}


def _addr_scope(ip) -> str:
    """Classify a listening bind address — the dominant threat signal:
    ``all`` (0.0.0.0 / ::, reachable from any interface), ``loopback``
    (127.0.0.0/8 / ::1, local-only), ``specific`` (a routable/LAN IP), or
    ``unknown``."""
    if not ip:
        return "unknown"
    if ip in ("0.0.0.0", "::"):
        return "all"
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return "loopback"
    except ValueError:
        return "unknown"
    return "specific"


_SCOPE_SEV = {"all": 0, "specific": 1, "unknown": 2, "loopback": 3}


def _cmdline_str(raw) -> str | None:
    """ProcessRow.cmdline_json is a JSON-encoded argv list; render it as a
    single command string, or None when absent/unparseable."""
    if not raw:
        return None
    try:
        parts = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(parts, list) and parts:
        return " ".join(str(x) for x in parts)
    return None


_PORT_LIMIT = 1000
_PORT_SEARCH = ("process", "port")
_PROC_COLUMNS = (
    "ppid",
    "exe",
    "cmdline_json",
    "username",
    "uid",
    "status",
    "cpu_percent",
    "memory_rss",
    "num_fds",
    "num_threads",
)


def _processes_by_pid(session: Session, run_id: str) -> dict[int, dict]:
    """Owning-process detail, keyed by pid, from the same run's snapshot."""
    if "processes" not in _existing_tables(session):
        return {}
    stmt = select(
        ProcessRow.pid, *(getattr(ProcessRow, c) for c in _PROC_COLUMNS)
    ).where(ProcessRow.run_id == run_id)
    procs = {}
    for p in session.execute(stmt).all():
        if p.pid is None:
            continue
        detail = {c: getattr(p, c) for c in _PROC_COLUMNS}
        detail["cmdline"] = _cmdline_str(detail.pop("cmdline_json"))
        procs[p.pid] = detail
    return procs


def _established_by_port(session: Session, run_id: str) -> dict[int, int]:
    """Established connections terminating on each local port: "is anyone
    actually talking to this listener right now"."""
    if "network_connections" not in _existing_tables(session):
        return {}
    counts = session.execute(
        select(NetworkConnectionRow.laddr_port, func.count())
        .where(
            NetworkConnectionRow.run_id == run_id,
            NetworkConnectionRow.status == "ESTABLISHED",
        )
        .group_by(NetworkConnectionRow.laddr_port)
    ).all()
    return {port: n for port, n in counts if port is not None}


def _sockets_by_port_and_pid(session: Session, run_id: str) -> list[dict]:
    """One group per (port, pid): wildcard binds (0.0.0.0 + :: on the same
    port/pid) merge, keeping every address, protocol and family and the
    worst verdict."""
    stmt = (
        select(
            ListeningPortRow.pid,
            ListeningPortRow.process_name,
            ListeningPortRow.family,
            ListeningPortRow.type,
            ListeningPortRow.laddr_ip,
            ListeningPortRow.laddr_port,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        )
        .outerjoin(
            Judgement,
            and_(
                Judgement.content_hash == ListeningPortRow.content_hash,
                Judgement.collector == "listening_ports",
            ),
        )
        .where(ListeningPortRow.run_id == run_id)
        .limit(_PORT_LIMIT)
    )
    groups: dict[tuple, dict] = {}
    for sock in session.execute(stmt).all():
        key = (sock.laddr_port, sock.pid)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "port": sock.laddr_port,
                "pid": sock.pid,
                "process": sock.process_name,
                "_addrs": set(),
                "_protos": set(),
                "_families": set(),
                "verdict": None,
                "confidence": None,
                "reasoning": "",
            }
        g["_addrs"].add(sock.laddr_ip)
        g["_protos"].add(_PROTO_BY_SOCK.get(sock.type, sock.type))
        g["_families"].add(_FAMILY_LABEL.get(sock.family, sock.family))
        _take_worse_verdict(g, sock.verdict, sock.confidence, sock.reasoning)
    return list(groups.values())


def _port_row(group: dict, procs: dict[int, dict], conns: dict[int, int]) -> dict:
    addrs = sorted(filter(None, group["_addrs"]))
    scopes = {_addr_scope(a) for a in addrs} or {"unknown"}
    scope = min(scopes, key=lambda s: _SCOPE_SEV.get(s, 2))
    return {
        "port": group["port"],
        "pid": group["pid"],
        "process": group["process"] or "—",
        "addrs": addrs,
        "scope": scope,
        "exposed": scope in ("all", "specific"),
        "proto": sorted(filter(None, group["_protos"])),
        "family": sorted(filter(None, group["_families"])),
        "conns": conns.get(group["port"], 0),
        "proc": procs.get(group["pid"]),
        "verdict": group["verdict"],
        "confidence": group["confidence"],
        "reasoning": group["reasoning"],
    }


def listening_ports(
    session: Session,
    run_id: str,
    filters: RowFilter = RowFilter(),
    scope_filter: str = "",
    page: Page = Page(),
):
    """Listening sockets for ``run_id`` as a glanceable table: one row per
    (port, pid) socket, annotated with its LLM verdict (LEFT JOIN
    Judgement, same as :func:`network_flows`) and enriched with
    owning-process detail (user, exe, cmdline, cpu/mem, ppid) from the
    ``processes`` snapshot plus a count of established connections to that
    local port from ``network_connections``.

    Each row carries the worst bind scope of its merged addresses, so the
    table reads as "what is this process exposing, and to whom".
    Worst-verdict-first, then by port. Returns ``{"summary": {...},
    "rows": [...]}``; degrades to empty when the table predates this
    collector."""
    if "listening_ports" not in _existing_tables(session):
        return {
            "summary": {"ports": 0, "exposed": 0, "malicious": 0, "suspicious": 0},
            "rows": [],
        }
    procs = _processes_by_pid(session, run_id)
    conns = _established_by_port(session, run_id)
    rows = [
        _port_row(g, procs, conns) for g in _sockets_by_port_and_pid(session, run_id)
    ]
    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), r["port"] or 0))
    rows = filters.keep(rows, _PORT_SEARCH)
    if scope_filter:
        rows = [r for r in rows if r.get("scope") == scope_filter]

    summary = {
        "ports": len(rows),
        "exposed": sum(1 for r in rows if r["exposed"]),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }
    page_rows, paging = page.slice(rows)
    return {
        "summary": summary,
        "rows": page_rows,
        **paging,
        **filters.fields(),
        "scope_filter": scope_filter,
    }
