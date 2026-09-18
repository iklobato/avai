"""The DNS queries panel."""

from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from avai.host_monitor import (
    DnsQueryRow,
)

from .common import _FLOW_SEV, Page, _collector_rows_with_verdict


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


def dns_queries(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    level: str = "",
    q: str = "",
    page: Page = Page(),
):
    """DNS questions seen this run (+ detected DoH endpoints), each with
    its LLM verdict and the resolution level (where/how it resolved).
    Returns ``{"summary": {...}, "rows": [...]}`` sorted worst-verdict
    then most-queried."""
    rows = _collector_rows_with_verdict(
        session,
        run_id,
        DnsQueryRow,
        "dns_queries",
        ("qname", "qtype", "server_ip", "process", "count"),
        limit=limit,
    )
    for r in rows:
        r["level"] = _dns_resolution_level(r["server_ip"], r["qtype"])
    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -(r["count"] or 0)))

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if level:
        rows = [r for r in rows if r.get("level") == level]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("qname") or "").lower()
            or ql in (r.get("process") or "").lower()
        ]

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
        "q": q,
        "verdict": verdict,
        "level": level,
    }
