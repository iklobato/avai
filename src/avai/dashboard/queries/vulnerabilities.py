"""The vulnerabilities panel: advisories matched to installed software."""

from __future__ import annotations

import json

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
from .common import DEFAULT_PER_PAGE, _existing_tables, _paginate

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


def vulnerabilities(
    session: Session,
    *,
    q: str = "",
    severity: str = "",
    source: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
) -> dict:
    """Aggregate the CVE / EOL evidence the enrichment chain already collected
    into a prioritised 'patch me' list. Each item carries its worst
    ``severity`` (CVSS band) and whether the vulnerable software is actually
    ``running`` and/or ``exposed`` (listening) on the host.

    Always ordered by severity first (critical → none), then
    KEV → exposed → running → CVSS → name within a band. Supports a text
    search (``q`` over software / CVE id / summary) and ``severity`` / ``source``
    filters, and paginates the result. Returns a dict with ``rows`` plus the
    pagination + echoed-filter fields the panel template expects; an empty
    result (same shape) if the evidence table is absent."""
    empty = {
        "rows": [],
        "total": 0,
        "page": 1,
        "per_page": per_page,
        "total_pages": 1,
        "q": q,
        "severity": severity,
        "source": source,
        "sources": list(_VULN_SOURCES),
        "summary": {"critical": 0, "high": 0, "kev": 0, "exposed": 0},
    }
    if "enrichment_evidence" not in _existing_tables(session):
        return empty
    from avai.enrichers.cache import register_schema

    latest = latest_run(session)
    running, exposed = _software_presence(session, latest.run_id if latest else None)
    model = register_schema(Base)
    rows = session.execute(
        select(
            model.source,
            model.indicator_type,
            model.indicator_value,
            model.verdict_hint,
            model.confidence,
            model.summary,
            model.details_json,
        ).where(model.source.in_(_VULN_SOURCES))
    ).all()

    parsed = []
    cve_detail: dict[str, dict] = {}  # CVE id -> {kev, cvss, severity}
    for src, itype, ival, hint, conf, summary, dj in rows:
        try:
            details = json.loads(dj) if dj else {}
        except (TypeError, ValueError):
            details = {}
        parsed.append((src, itype, ival, hint, summary, details))
        if itype == "cve":
            # forward-chained CVE rows carry the severity/exploited detail
            d = cve_detail.setdefault(
                ival.upper(), {"kev": False, "cvss": None, "severity": None}
            )
            if src == "cisa_kev":
                d["kev"] = True
            score = (details.get("cvss31") or {}).get("baseScore")
            if score is None:
                score = (details.get("cvss") or {}).get("score")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            if score is not None and (d["cvss"] is None or score > d["cvss"]):
                d["cvss"] = score
            sev = (details.get("cvss31") or {}).get("baseSeverity") or details.get(
                "severity"
            )
            if sev and not d["severity"]:
                d["severity"] = str(sev).lower()

    items: list[dict] = []
    for src, itype, ival, hint, summary, details in parsed:
        eol = src == "endoflife" and hint != "benign"
        ids = details.get("vuln_ids") or []
        # CVE-typed rows feed cve_detail only — they're shown attached to
        # their parent package, not as standalone rows.
        if not ids and not eol:
            continue
        cves = [
            {
                "id": cid,
                **cve_detail.get(
                    str(cid).upper(), {"kev": False, "cvss": None, "severity": None}
                ),
            }
            for cid in ids
        ]
        kev = any(c["kev"] for c in cves)
        cvss = max((c["cvss"] for c in cves if c["cvss"] is not None), default=None)
        base = _normalize_software(ival)
        items.append(
            {
                "software": ival,
                "source": src,
                "cves": cves,
                "kev": kev,
                "cvss": cvss,
                "severity": _item_severity(cvss, cves, kev),
                "eol": eol,
                "summary": summary or "",
                # Is this vulnerable software actually present on the host?
                "running": base in running,
                "exposed": base in exposed,
            }
        )

    if q:
        ql = q.lower()
        items = [
            i
            for i in items
            if ql in i["software"].lower()
            or ql in i["summary"].lower()
            or any(ql in str(c["id"]).lower() for c in i["cves"])
        ]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    if source:
        items = [i for i in items if i["source"] == source]

    # Always severity-first (critical → none), then actively-exploited (KEV) →
    # reachable (exposed) → present (running) → highest CVSS → name.
    items.sort(
        key=lambda i: (
            _SEVERITY_RANK.get(i["severity"], 99),
            not i["kev"],
            not i["exposed"],
            not i["running"],
            -(i["cvss"] or 0.0),
            i["software"],
        )
    )

    summary = {
        "critical": sum(1 for i in items if i["severity"] == "critical"),
        "high": sum(1 for i in items if i["severity"] == "high"),
        "kev": sum(1 for i in items if i["kev"]),
        "exposed": sum(1 for i in items if i["exposed"]),
    }
    page_rows, total, total_pages = _paginate(items, page, per_page)
    return {
        "rows": page_rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "severity": severity,
        "source": source,
        "sources": list(_VULN_SOURCES),
        "summary": summary,
    }
