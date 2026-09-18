"""The DNS queries panel."""

from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from .common import _FLOW_SEV, Page, RowFilter, VerdictTable


def _dns_resolution_level(server_ip, qtype) -> str:
    """Classify *how/where* a name resolved, from the resolver it was
    asked and the transport:

    - ``DoH (encrypted)`` — answered over DNS-over-HTTPS (we can't see the
      name, only that the host used an encrypted resolver).
    - ``local resolver`` — asked a private/LAN address (the router or a
      local stub like 127.0.0.1 / mDNSResponder forwarder).
    - ``external DNS`` — asked a public resolver directly (8.8.8.8, the
      ISP, …), bypassing any local one.

    Names served from ``/etc/hosts`` never hit the wire, so they don't
    appear here — they're shown in the persistence & tampering section.
    """
    if qtype == "DoH":
        return "DoH (encrypted)"
    if not server_ip:
        return "unknown"
    try:
        ip = ipaddress.ip_address(server_ip)
    except ValueError:
        return "unknown"
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "local resolver"
    return "external DNS"


_DNS_TABLE = VerdictTable(
    "dns_queries",
    ("qname", "qtype", "server_ip", "process", "count"),
    search=("qname", "process"),
    limit=1000,
)


def dns_queries(
    session: Session,
    run_id: str,
    filters: RowFilter = RowFilter(),
    level: str = "",
    page: Page = Page(),
):
    """DNS questions seen this run (+ detected DoH endpoints), each with
    its LLM verdict and the resolution level (where/how it resolved).
    Returns ``{"summary": {...}, "rows": [...]}`` sorted worst-verdict
    then most-queried."""
    rows = _DNS_TABLE.rows(session, run_id)
    for r in rows:
        r["level"] = _dns_resolution_level(r["server_ip"], r["qtype"])
    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -(r["count"] or 0)))

    rows = filters.keep(rows, _DNS_TABLE.search)
    if level:
        rows = [r for r in rows if r.get("level") == level]

    summary = {
        "domains": len({r["qname"] for r in rows}),
        "queries": sum(r["count"] or 0 for r in rows),
        "doh": sum(1 for r in rows if r["qtype"] == "DoH"),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }

    page_rows, paging = page.slice(rows)
    return {
        "summary": summary,
        "rows": page_rows,
        **paging,
        **filters.fields(),
        "level": level,
    }
