"""The listening ports panel."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Judgement,
    ListeningPortRow,
    NetworkConnectionRow,
    ProcessRow,
)

from .panel_reads import (
    Page,
    RowFilter,
    SchemaProbe,
    StoredJson,
    VerdictRank,
    VerdictTally,
)

PROTOCOL_BY_SOCKET = (("SOCK_STREAM", "TCP"), ("SOCK_DGRAM", "UDP"))
FAMILY_LABELS = (("AF_INET", "IPv4"), ("AF_INET6", "IPv6"))
# Bind scopes, most exposed first.
SCOPE_ORDER = ("all", "specific", "unknown", "loopback")
PORT_SEARCH = ("process", "port")
PROCESS_COLUMNS = (
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


class BindScope:
    """Classify a listening bind address, the dominant threat signal: ``all``
    (0.0.0.0 / ::, reachable from any interface), ``loopback`` (127.0.0.0/8 /
    ::1, local-only), ``specific`` (a routable/LAN IP), or ``unknown``."""

    def of(self, ip: str | None) -> str:
        if not ip:
            return "unknown"
        if ip in ("0.0.0.0", "::"):
            return "all"
        try:
            loopback = ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return "unknown"
        return "loopback" if loopback else "specific"

    def widest(self, addresses: list[str]) -> str:
        scopes = {self.of(address) for address in addresses} or {"unknown"}
        return min(scopes, key=SCOPE_ORDER.index)


class Cmdline:
    def of(self, raw: str | None) -> str | None:
        """ProcessRow.cmdline_json is a JSON-encoded argv list; render it as
        one command string, or None when absent or unparseable."""
        parts = StoredJson().as_list(raw)
        return " ".join(str(part) for part in parts) if parts else None


class SocketGroup:
    """The sockets one pid listens on for one port: wildcard binds
    (0.0.0.0 + :: on the same port/pid) merge, keeping every address,
    protocol and family and the worst verdict."""

    def __init__(self, socket: Any) -> None:
        self._first = socket
        self._sockets: list[Any] = []

    def add(self, socket: Any) -> None:
        self._sockets.append(socket)

    def row(
        self, procs: dict[int, dict[str, Any]], conns: dict[int, int]
    ) -> dict[str, Any]:
        first = self._first
        addresses = sorted(filter(None, {socket.laddr_ip for socket in self._sockets}))
        scope = BindScope().widest(addresses)
        return {
            "port": first.laddr_port,
            "pid": first.pid,
            "process": first.process_name or "—",
            "addrs": addresses,
            "scope": scope,
            "exposed": scope in ("all", "specific"),
            "proto": self._labels(PROTOCOL_BY_SOCKET, "type"),
            "family": self._labels(FAMILY_LABELS, "family"),
            "conns": conns.get(first.laddr_port, 0),
            "proc": procs.get(first.pid),
            **self._worst(),
        }

    def _labels(self, names: tuple[tuple[str, str], ...], attribute: str) -> list[str]:
        known = dict(names)
        raw = {getattr(socket, attribute) for socket in self._sockets}
        return sorted(filter(None, {known.get(value, value) for value in raw}))

    def _worst(self) -> dict[str, Any]:
        worst: dict[str, Any] = {"verdict": None, "confidence": None, "reasoning": ""}
        rank = VerdictRank()
        for socket in self._sockets:
            rank.take_worse(
                worst, (socket.verdict, socket.confidence, socket.reasoning)
            )
        return worst


@dataclass(frozen=True)
class PortQuery:
    filters: RowFilter = field(default_factory=RowFilter)
    scope_filter: str = ""
    page: Page = field(default_factory=Page)


class PortsPanel:
    """Listening sockets for a run: one row per (port, pid), annotated with
    its LLM verdict and enriched with owning-process detail (user, exe,
    cmdline, cpu/mem, ppid) plus a count of established connections to that
    local port. Each row carries the widest bind scope of its addresses, so
    the table reads as "what is this process exposing, and to whom".
    Worst verdict first, then by port; empty when the table predates this
    collector."""

    PORT_LIMIT = 1000
    EMPTY_SUMMARY = (("ports", 0), ("exposed", 0), ("malicious", 0), ("suspicious", 0))

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def ports(self, query: PortQuery) -> dict[str, Any]:
        if "listening_ports" not in SchemaProbe(self._session).tables():
            return {"summary": dict(self.EMPTY_SUMMARY), "rows": []}
        procs, conns = self._processes(), self._established()
        rows = [group.row(procs, conns) for group in self._groups()]
        rows = query.filters.keep(sorted(rows, key=self._order), PORT_SEARCH)
        if query.scope_filter:
            rows = [row for row in rows if row.get("scope") == query.scope_filter]
        page_rows, paging = query.page.slice(rows)
        return {
            "summary": self._summary(rows),
            "rows": page_rows,
            **paging,
            **query.filters.fields(),
            "scope_filter": query.scope_filter,
        }

    def _order(self, row: dict[str, Any]) -> tuple[int, int]:
        return VerdictRank().rank(row["verdict"]), row["port"] or 0

    def _summary(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        tally = VerdictTally().of(rows)
        return {
            "ports": len(rows),
            "exposed": sum(1 for row in rows if row["exposed"]),
            "malicious": tally["malicious"],
            "suspicious": tally["suspicious"],
        }

    def _processes(self) -> dict[int, dict[str, Any]]:
        """Owning-process detail, keyed by pid, from the same run's snapshot."""
        if "processes" not in SchemaProbe(self._session).tables():
            return {}
        columns = (getattr(ProcessRow, name) for name in PROCESS_COLUMNS)
        statement = select(ProcessRow.pid, *columns).where(
            ProcessRow.run_id == self._run_id
        )
        found = self._session.execute(statement).all()
        return {
            process.pid: self._detail(process)
            for process in found
            if process.pid is not None
        }

    def _detail(self, process: Any) -> dict[str, Any]:
        detail = {name: getattr(process, name) for name in PROCESS_COLUMNS}
        detail["cmdline"] = Cmdline().of(detail.pop("cmdline_json"))
        return detail

    def _established(self) -> dict[int, int]:
        """Established connections terminating on each local port: "is anyone
        actually talking to this listener right now"."""
        if "network_connections" not in SchemaProbe(self._session).tables():
            return {}
        statement = (
            select(NetworkConnectionRow.laddr_port, func.count())
            .where(
                NetworkConnectionRow.run_id == self._run_id,
                NetworkConnectionRow.status == "ESTABLISHED",
            )
            .group_by(NetworkConnectionRow.laddr_port)
        )
        counts = self._session.execute(statement).all()
        return {port: count for port, count in counts if port is not None}

    def _groups(self) -> list[SocketGroup]:
        groups: dict[tuple[Any, Any], SocketGroup] = {}
        for socket in self._sockets():
            key = (socket.laddr_port, socket.pid)
            groups.setdefault(key, SocketGroup(socket)).add(socket)
        return list(groups.values())

    def _sockets(self) -> list[Any]:
        model = ListeningPortRow
        statement = self._select().where(model.run_id == self._run_id)
        return list(self._session.execute(statement.limit(self.PORT_LIMIT)).all())

    def _select(self) -> Any:
        model = ListeningPortRow
        judged = and_(
            Judgement.content_hash == model.content_hash,
            Judgement.collector == "listening_ports",
        )
        return select(
            model.pid,
            model.process_name,
            model.family,
            model.type,
            model.laddr_ip,
            model.laddr_port,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        ).outerjoin(Judgement, judged)
