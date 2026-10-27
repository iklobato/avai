"""The DNS queries panel."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from avai.host_monitor.enums import DnsQueryType, Verdict

from .panel_reads import Page, RowFilter, VerdictRank, VerdictTable


class DnsLevel:
    """Classify *how/where* a name resolved, from the resolver it was asked
    and the transport:

    - ``DoH (encrypted)``: answered over DNS-over-HTTPS (the name is hidden,
      only that the host used an encrypted resolver is visible).
    - ``local resolver``: asked a private/LAN address (the router or a local
      stub like 127.0.0.1 / mDNSResponder forwarder).
    - ``external DNS``: asked a public resolver directly (8.8.8.8, the ISP),
      bypassing any local one.

    Names served from ``/etc/hosts`` never hit the wire, so they don't appear
    here; they're shown in the persistence & tampering section.
    """

    def of(self, server_ip: str | None, qtype: str | None) -> str:
        if qtype == DnsQueryType.DNS_OVER_HTTPS:
            return "DoH (encrypted)"
        if not server_ip:
            return "unknown"
        try:
            address = ipaddress.ip_address(server_ip)
        except ValueError:
            return "unknown"
        if address.is_private or address.is_loopback or address.is_link_local:
            return "local resolver"
        return "external DNS"


@dataclass(frozen=True)
class DnsQuery:
    filters: RowFilter = field(default_factory=RowFilter)
    level: str = ""
    page: Page = field(default_factory=Page)


class DnsPanel:
    """DNS questions seen this run (+ detected DoH endpoints), each with its
    LLM verdict and the resolution level, worst verdict then most queried."""

    TABLE = VerdictTable(
        "dns_queries",
        ("qname", "qtype", "server_ip", "process", "count"),
        search=("qname", "process"),
        limit=1000,
    )

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def queries(self, query: DnsQuery) -> dict[str, Any]:
        rows = self.TABLE.rows(self._session, self._run_id)
        levels = DnsLevel()
        for row in rows:
            row["level"] = levels.of(row["server_ip"], row["qtype"])
        rows = query.filters.keep(sorted(rows, key=self._order), self.TABLE.search)
        if query.level:
            rows = [row for row in rows if row.get("level") == query.level]
        page_rows, paging = query.page.slice(rows)
        return {
            "summary": self._summary(rows),
            "rows": page_rows,
            **paging,
            **query.filters.fields(),
            "level": query.level,
        }

    def _order(self, row: dict[str, Any]) -> tuple[int, int]:
        return VerdictRank().rank(row["verdict"]), -(row["count"] or 0)

    def _summary(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        verdicts = [row["verdict"] for row in rows]
        return {
            "domains": len({row["qname"] for row in rows}),
            "queries": sum(row["count"] or 0 for row in rows),
            "doh": sum(
                1 for row in rows if row["qtype"] == DnsQueryType.DNS_OVER_HTTPS
            ),
            Verdict.MALICIOUS.value: verdicts.count(Verdict.MALICIOUS),
            Verdict.SUSPICIOUS.value: verdicts.count(Verdict.SUSPICIOUS),
        }
