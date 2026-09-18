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

from .common import _FLOW_SEV, Page, _existing_tables

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


def listening_ports(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    scope_filter: str = "",
    q: str = "",
    page: Page = Page(),
):
    """Listening sockets for ``run_id`` as a glanceable table: one row per
    (port, pid) socket, annotated with its LLM verdict (LEFT JOIN
    Judgement, same as :func:`network_flows`) and enriched with
    owning-process detail (user, exe, cmdline, cpu/mem, ppid) from the
    ``processes`` snapshot plus a count of established connections to that
    local port from ``network_connections``.

    Wildcard binds (0.0.0.0 + :: on the same port/pid) merge into one row
    carrying the worst bind scope, so the table reads as "what is this
    process exposing, and to whom". Worst-verdict-first, then by port.
    Returns ``{"summary": {...}, "rows": [...]}``; degrades to empty when
    the table predates this collector."""
    empty = {
        "summary": {"ports": 0, "exposed": 0, "malicious": 0, "suspicious": 0},
        "rows": [],
    }
    if "listening_ports" not in _existing_tables(session):
        return empty

    # Owning-process detail, keyed by pid, from the same run's snapshot.
    proc_by_pid: dict[int, dict] = {}
    if "processes" in _existing_tables(session):
        for p in session.execute(
            select(
                ProcessRow.pid,
                ProcessRow.ppid,
                ProcessRow.exe,
                ProcessRow.cmdline_json,
                ProcessRow.username,
                ProcessRow.uid,
                ProcessRow.status,
                ProcessRow.cpu_percent,
                ProcessRow.memory_rss,
                ProcessRow.num_fds,
                ProcessRow.num_threads,
            ).where(ProcessRow.run_id == run_id)
        ).all():
            if p.pid is None:
                continue
            proc_by_pid[p.pid] = {
                "ppid": p.ppid,
                "exe": p.exe,
                "cmdline": _cmdline_str(p.cmdline_json),
                "username": p.username,
                "uid": p.uid,
                "status": p.status,
                "cpu_percent": p.cpu_percent,
                "memory_rss": p.memory_rss,
                "num_fds": p.num_fds,
                "num_threads": p.num_threads,
            }

    # Established connections terminating on each local port — "is anyone
    # actually talking to this listener right now".
    conn_count: dict[int, int] = {}
    if "network_connections" in _existing_tables(session):
        for port, n in session.execute(
            select(NetworkConnectionRow.laddr_port, func.count())
            .where(
                NetworkConnectionRow.run_id == run_id,
                NetworkConnectionRow.status == "ESTABLISHED",
            )
            .group_by(NetworkConnectionRow.laddr_port)
        ).all():
            if port is not None:
                conn_count[port] = n

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
        .limit(limit)
    )

    groups: dict[tuple, dict] = {}
    for (
        pid,
        process_name,
        family,
        type_,
        laddr_ip,
        laddr_port,
        verdict,
        conf,
        reason,
    ) in session.execute(stmt).all():
        key = (laddr_port, pid)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "port": laddr_port,
                "pid": pid,
                "process": process_name,
                "_addrs": set(),
                "_protos": set(),
                "_families": set(),
                "verdict": None,
                "confidence": None,
                "reasoning": "",
            }
        if laddr_ip:
            g["_addrs"].add(laddr_ip)
        if type_:
            g["_protos"].add(_PROTO_BY_SOCK.get(type_, type_))
        if family:
            g["_families"].add(_FAMILY_LABEL.get(family, family))
        if _FLOW_SEV.get(verdict, 4) < _FLOW_SEV.get(g["verdict"], 4):
            g["verdict"] = verdict
            g["confidence"] = conf
            g["reasoning"] = reason or ""

    rows = []
    for g in groups.values():
        scopes = {_addr_scope(a) for a in g["_addrs"]} or {"unknown"}
        scope = min(scopes, key=lambda s: _SCOPE_SEV.get(s, 2))
        rows.append(
            {
                "port": g["port"],
                "pid": g["pid"],
                "process": g["process"] or "—",
                "addrs": sorted(g["_addrs"]),
                "scope": scope,
                "exposed": scope in ("all", "specific"),
                "proto": sorted(g["_protos"]),
                "family": sorted(g["_families"]),
                "conns": conn_count.get(g["port"], 0),
                "proc": proc_by_pid.get(g["pid"]),
                "verdict": g["verdict"],
                "confidence": g["confidence"],
                "reasoning": g["reasoning"],
            }
        )

    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), r["port"] or 0))

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if scope_filter:
        rows = [r for r in rows if r.get("scope") == scope_filter]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("process") or "").lower() or ql in str(r.get("port") or "")
        ]

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
        "q": q,
        "verdict": verdict,
        "scope_filter": scope_filter,
    }
