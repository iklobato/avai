"""The vulnerabilities panel: advisories matched to installed software."""

from __future__ import annotations

from typing import NamedTuple

from sqlalchemy import (
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Base,
    ListeningPortRow,
    ProcessRow,
)

from .collection import latest_run
from .common import Page, _existing_tables, _parse_json_obj

_VULN_SOURCES = ("osv", "nvd", "cisa_kev", "github_advisory", "endoflife")


# Severity buckets, most-severe first. The rank doubles as the primary sort key
# for the vulnerabilities panel ("always sort by severity") and as the set of
# values the severity filter accepts.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "none")


_SEVERITY_RANK = {label: i for i, label in enumerate(SEVERITY_ORDER)}


# CVSS base-score → qualitative severity (CVSS v3.1 rating bands).
_SEVERITY_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def _severity_from_cvss(score: float | None) -> str | None:
    """Map a CVSS base score to its qualitative band, or None when unscored."""
    if score is None:
        return None
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "none"


def _item_severity(cvss: float | None, cves: list[dict], kev: bool) -> str:
    """Worst severity for a vulnerable-software item: the CVSS band if scored,
    else the most-severe per-CVE label, else 'critical' for an unscored but
    actively-exploited (KEV) item, else 'none'."""
    label = _severity_from_cvss(cvss)
    if label is None:
        labelled = [c["severity"] for c in cves if c.get("severity")]
        if labelled:
            label = min(labelled, key=lambda s: _SEVERITY_RANK.get(s, 99))
    if label is None:
        return "critical" if kev else "none"
    return label


def _normalize_software(name: str) -> str:
    """Reduce a software/package/exe string to a comparable base token:
    drop the ``@version`` suffix, take the path basename, strip a ``.app``
    suffix. ``"openssl@3.0.2"`` → ``"openssl"``; ``"/usr/sbin/nginx"`` →
    ``"nginx"``; ``"Firefox.app"`` → ``"firefox"``."""
    base = str(name or "").split("@", 1)[0].strip().lower()
    base = base.rsplit("/", 1)[-1]
    if base.endswith(".app"):
        base = base[:-4]
    return base


def _software_presence(session: Session, run_id) -> tuple[set, set]:
    """``(running, exposed)`` normalized software names for ``run_id``:
    ``running`` from the process snapshot (name + exe basename), ``exposed``
    from the listening-port owners. Used to tell whether a vulnerable package
    is actually present and reachable on the host, not just installed."""
    running: set = set()
    exposed: set = set()
    if run_id is None:
        return running, exposed
    present = _existing_tables(session)
    if "processes" in present:
        for name, exe in session.execute(
            select(ProcessRow.name, ProcessRow.exe).where(ProcessRow.run_id == run_id)
        ).all():
            if name:
                running.add(_normalize_software(name))
            if exe:
                running.add(_normalize_software(exe))
    if "listening_ports" in present:
        for pname in session.execute(
            select(ListeningPortRow.process_name).where(
                ListeningPortRow.run_id == run_id
            )
        ).scalars():
            if pname:
                exposed.add(_normalize_software(pname))
    running.discard("")
    exposed.discard("")
    return running, exposed


class _Evidence(NamedTuple):
    source: str
    indicator_type: str
    indicator_value: str
    verdict_hint: str | None
    summary: str | None
    details: dict


def _vuln_evidence(session: Session) -> list[_Evidence]:
    from avai.enrichers.cache import register_schema

    model = register_schema(Base)
    rows = session.execute(
        select(
            model.source,
            model.indicator_type,
            model.indicator_value,
            model.verdict_hint,
            model.summary,
            model.details_json,
        ).where(model.source.in_(_VULN_SOURCES))
    ).all()
    return [
        _Evidence(src, itype, ival, hint, summary, _parse_json_obj(dj))
        for src, itype, ival, hint, summary, dj in rows
    ]


def _cvss_score(details: dict) -> float | None:
    score = (details.get("cvss31") or {}).get("baseScore")
    if score is None:
        score = (details.get("cvss") or {}).get("score")
    try:
        return float(score) if score is not None else None
    except (TypeError, ValueError):
        return None


def _no_cve_detail() -> dict:
    return {"kev": False, "cvss": None, "severity": None}


def _cve_details(evidence: list[_Evidence]) -> dict[str, dict]:
    """CVE id -> {kev, cvss, severity}, merged across the forward-chained
    CVE rows: KEV if any source lists it, the highest CVSS, the first
    severity."""
    detail: dict[str, dict] = {}
    for ev in evidence:
        if ev.indicator_type != "cve":
            continue
        d = detail.setdefault(ev.indicator_value.upper(), _no_cve_detail())
        d["kev"] = d["kev"] or ev.source == "cisa_kev"
        score = _cvss_score(ev.details)
        if score is not None and (d["cvss"] is None or score > d["cvss"]):
            d["cvss"] = score
        sev = (ev.details.get("cvss31") or {}).get("baseSeverity") or ev.details.get(
            "severity"
        )
        if sev and not d["severity"]:
            d["severity"] = str(sev).lower()
    return detail


def _vuln_item(ev: _Evidence, cve_detail: dict, running: set, exposed: set):
    """One patch-me row for a package or end-of-life product, or None for a
    row that only feeds CVE detail (shown attached to its parent package)."""
    eol = ev.source == "endoflife" and ev.verdict_hint != "benign"
    ids = ev.details.get("vuln_ids") or []
    if not ids and not eol:
        return None
    cves = [
        {"id": cid, **cve_detail.get(str(cid).upper(), _no_cve_detail())} for cid in ids
    ]
    kev = any(c["kev"] for c in cves)
    cvss = max((c["cvss"] for c in cves if c["cvss"] is not None), default=None)
    base = _normalize_software(ev.indicator_value)
    return {
        "software": ev.indicator_value,
        "source": ev.source,
        "cves": cves,
        "kev": kev,
        "cvss": cvss,
        "severity": _item_severity(cvss, cves, kev),
        "eol": eol,
        "summary": ev.summary or "",
        # Is this vulnerable software actually present on the host?
        "running": base in running,
        "exposed": base in exposed,
    }


def _mentions(item: dict, needle: str) -> bool:
    return (
        needle in item["software"].lower()
        or needle in item["summary"].lower()
        or any(needle in str(c["id"]).lower() for c in item["cves"])
    )


def _patch_priority(item: dict) -> tuple:
    """Severity first (critical -> none), then actively exploited (KEV) ->
    reachable (exposed) -> present (running) -> highest CVSS -> name."""
    return (
        _SEVERITY_RANK.get(item["severity"], 99),
        not item["kev"],
        not item["exposed"],
        not item["running"],
        -(item["cvss"] or 0.0),
        item["software"],
    )


def vulnerabilities(
    session: Session,
    *,
    q: str = "",
    severity: str = "",
    source: str = "",
    page: Page = Page(),
) -> dict:
    """Aggregate the CVE / EOL evidence the enrichment chain already collected
    into a prioritised 'patch me' list. Each item carries its worst
    ``severity`` (CVSS band) and whether the vulnerable software is actually
    ``running`` and/or ``exposed`` (listening) on the host, and is ordered by
    :func:`_patch_priority`. Supports a text search (``q`` over software /
    CVE id / summary) and ``severity`` / ``source`` filters, and paginates the
    result. Returns a dict with ``rows`` plus the pagination + echoed-filter
    fields the panel template expects; an empty result (same shape) if the
    evidence table is absent."""
    echoed = {"q": q, "severity": severity, "source": source}
    if "enrichment_evidence" not in _existing_tables(session):
        return {
            "rows": [],
            **page.fields(0),
            **echoed,
            "sources": list(_VULN_SOURCES),
            "summary": {"critical": 0, "high": 0, "kev": 0, "exposed": 0},
        }
    latest = latest_run(session)
    running, exposed = _software_presence(session, latest.run_id if latest else None)
    evidence = _vuln_evidence(session)
    cve_detail = _cve_details(evidence)
    items = [
        item
        for ev in evidence
        if (item := _vuln_item(ev, cve_detail, running, exposed)) is not None
    ]
    if q:
        items = [i for i in items if _mentions(i, q.lower())]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    if source:
        items = [i for i in items if i["source"] == source]
    items.sort(key=_patch_priority)

    summary = {
        "critical": sum(1 for i in items if i["severity"] == "critical"),
        "high": sum(1 for i in items if i["severity"] == "high"),
        "kev": sum(1 for i in items if i["kev"]),
        "exposed": sum(1 for i in items if i["exposed"]),
    }
    page_rows, paging = page.slice(items)
    return {
        "rows": page_rows,
        **paging,
        **echoed,
        "sources": list(_VULN_SOURCES),
        "summary": summary,
    }
