"""The vulnerabilities panel: advisories matched to installed software."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from avai.enrichers.cache import EnrichmentSchema
from avai.host_monitor import Base, ListeningPortRow, ProcessRow

from .collection import RunQueries
from .panel_reads import Page, SchemaProbe, StoredJson

VULN_SOURCES = ("osv", "nvd", "cisa_kev", "github_advisory", "endoflife")

# Severity buckets, most-severe first. The rank doubles as the primary sort
# key for the panel ("always sort by severity") and as the set of values the
# severity filter accepts.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "none")

# CVSS base-score to qualitative severity (CVSS v3.1 rating bands).
SEVERITY_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


class Severity:
    def rank(self, label: str | None) -> int:
        return (
            SEVERITY_ORDER.index(label)
            if label in SEVERITY_ORDER
            else len(SEVERITY_ORDER)
        )

    def from_cvss(self, score: float | None) -> str | None:
        """A CVSS base score's qualitative band, or None when unscored."""
        if score is None:
            return None
        bands = (label for threshold, label in SEVERITY_BANDS if score >= threshold)
        return next(bands, "none")

    def of_item(self, cvss: float | None, cves: list[dict[str, Any]]) -> str:
        """Worst severity for a vulnerable-software item: the CVSS band if
        scored, else the most-severe per-CVE label, else 'critical' for an
        unscored but actively-exploited (KEV) item, else 'none'."""
        label = self.from_cvss(cvss)
        labelled = [cve["severity"] for cve in cves if cve.get("severity")]
        if label is None and labelled:
            label = min(labelled, key=self.rank)
        if label is not None:
            return label
        return "critical" if any(cve.get("kev") for cve in cves) else "none"


class SoftwareName:
    def normalize(self, name: str | None) -> str:
        """A software/package/exe string as a comparable base token: no
        ``@version`` suffix, the path basename, no ``.app`` suffix.
        ``"openssl@3.0.2"`` -> ``"openssl"``; ``"/usr/sbin/nginx"`` ->
        ``"nginx"``; ``"Firefox.app"`` -> ``"firefox"``."""
        base = str(name or "").split("@", 1)[0].strip().lower()
        return base.rsplit("/", 1)[-1].removesuffix(".app")


class SoftwarePresence:
    """``(running, exposed)`` software names for a run: ``running`` from the
    process snapshot (name + exe basename), ``exposed`` from the
    listening-port owners. Tells whether a vulnerable package is actually
    present and reachable, not just installed."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_run(self, run_id: str | None) -> tuple[set[str], set[str]]:
        if run_id is None:
            return set(), set()
        present = SchemaProbe(self._session).tables()
        running = self._running(run_id) if "processes" in present else set()
        exposed = self._exposed(run_id) if "listening_ports" in present else set()
        return running - {""}, exposed - {""}

    def _running(self, run_id: str) -> set[str]:
        statement = select(ProcessRow.name, ProcessRow.exe).where(
            ProcessRow.run_id == run_id
        )
        names = SoftwareName()
        rows = self._session.execute(statement).all()
        return {names.normalize(value) for row in rows for value in row if value}

    def _exposed(self, run_id: str) -> set[str]:
        statement = select(ListeningPortRow.process_name).where(
            ListeningPortRow.run_id == run_id
        )
        names = SoftwareName()
        found = self._session.execute(statement).scalars()
        return {names.normalize(name) for name in found if name}


class Evidence(NamedTuple):
    source: str
    indicator_type: str
    indicator_value: str
    verdict_hint: str | None
    summary: str | None
    details: dict[str, Any]


class CveDetails:
    """CVE id -> {kev, cvss, severity}, merged across the forward-chained CVE
    rows: KEV if any source lists it, the highest CVSS, the first severity."""

    def merge(self, evidence: list[Evidence]) -> dict[str, dict[str, Any]]:
        detail: dict[str, dict[str, Any]] = {}
        for found in (row for row in evidence if row.indicator_type == "cve"):
            merged = detail.setdefault(found.indicator_value.upper(), self.empty())
            merged["kev"] = merged["kev"] or found.source == "cisa_kev"
            score = self.cvss(found.details)
            if score is not None and (merged["cvss"] is None or score > merged["cvss"]):
                merged["cvss"] = score
            severity = self._severity(found.details)
            if severity and not merged["severity"]:
                merged["severity"] = str(severity).lower()
        return detail

    def empty(self) -> dict[str, Any]:
        return {"kev": False, "cvss": None, "severity": None}

    def cvss(self, details: dict[str, Any]) -> float | None:
        score = (details.get("cvss31") or {}).get("baseScore")
        if score is None:
            score = (details.get("cvss") or {}).get("score")
        try:
            return float(score) if score is not None else None
        except (TypeError, ValueError):
            return None

    def _severity(self, details: dict[str, Any]) -> Any:
        return (details.get("cvss31") or {}).get("baseSeverity") or details.get(
            "severity"
        )


class VulnItem:
    """Builds the patch-me row for a package or end-of-life product."""

    def __init__(
        self, cve_detail: dict[str, dict[str, Any]], presence: tuple[set[str], set[str]]
    ) -> None:
        self._cve_detail = cve_detail
        self._presence = presence

    def of(self, evidence: Evidence) -> dict[str, Any] | None:
        """None for a row that only feeds CVE detail (shown attached to its
        parent package)."""
        ids = evidence.details.get("vuln_ids") or []
        if not ids and not self._eol(evidence):
            return None
        return self._row(evidence, [{"id": cve, **self._cve(cve)} for cve in ids])

    def _eol(self, evidence: Evidence) -> bool:
        return evidence.source == "endoflife" and evidence.verdict_hint != "benign"

    def _row(self, evidence: Evidence, cves: list[dict[str, Any]]) -> dict[str, Any]:
        cvss = max(
            (cve["cvss"] for cve in cves if cve["cvss"] is not None), default=None
        )
        base = SoftwareName().normalize(evidence.indicator_value)
        running, exposed = self._presence
        return {
            "software": evidence.indicator_value,
            "source": evidence.source,
            "cves": cves,
            "kev": any(cve["kev"] for cve in cves),
            "cvss": cvss,
            "severity": Severity().of_item(cvss, cves),
            "eol": self._eol(evidence),
            "summary": evidence.summary or "",
            # Is this vulnerable software actually present on the host?
            "running": base in running,
            "exposed": base in exposed,
        }

    def _cve(self, cve: Any) -> dict[str, Any]:
        return self._cve_detail.get(str(cve).upper(), CveDetails().empty())


@dataclass(frozen=True)
class VulnQuery:
    search: str = ""
    severity: str = ""
    source: str = ""
    page: Page = field(default_factory=Page)

    def echoed(self) -> dict[str, str]:
        return {"q": self.search, "severity": self.severity, "source": self.source}

    def keep(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        needle = self.search.lower()
        return [
            item
            for item in items
            if (not needle or self._mentions(item, needle))
            and (not self.severity or item["severity"] == self.severity)
            and (not self.source or item["source"] == self.source)
        ]

    def _mentions(self, item: dict[str, Any], needle: str) -> bool:
        return (
            needle in item["software"].lower()
            or needle in item["summary"].lower()
            or any(needle in str(cve["id"]).lower() for cve in item["cves"])
        )


class VulnerabilitiesPanel:
    """The CVE / EOL evidence the enrichment chain collected, as a
    prioritised 'patch me' list. Each item carries its worst ``severity``
    and whether the software is ``running`` and/or ``exposed``; the same
    empty shape comes back when the evidence table is absent."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def vulnerabilities(self, query: VulnQuery) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        if "enrichment_evidence" in SchemaProbe(self._session).tables():
            items = sorted(query.keep(self._items()), key=self._priority)
        page_rows, paging = query.page.slice(items)
        return {
            "rows": page_rows,
            **paging,
            **query.echoed(),
            "sources": list(VULN_SOURCES),
            "summary": self._summary(items),
        }

    def _items(self) -> list[dict[str, Any]]:
        latest = RunQueries(self._session).latest_run()
        presence = SoftwarePresence(self._session).for_run(
            latest.run_id if latest else None
        )
        evidence = self._evidence()
        builder = VulnItem(CveDetails().merge(evidence), presence)
        built = (builder.of(row) for row in evidence)
        return [item for item in built if item is not None]

    def _evidence(self) -> list[Evidence]:
        model = EnrichmentSchema(Base).model()
        statement = select(
            model.source,
            model.indicator_type,
            model.indicator_value,
            model.verdict_hint,
            model.summary,
            model.details_json,
        ).where(model.source.in_(VULN_SOURCES))
        rows = self._session.execute(statement).all()
        return [Evidence(*row[:-1], StoredJson().as_dict(row[-1])) for row in rows]

    def _priority(self, item: dict[str, Any]) -> tuple[Any, ...]:
        """Severity first (critical -> none), then actively exploited (KEV)
        -> reachable (exposed) -> present (running) -> highest CVSS -> name."""
        return (
            Severity().rank(item["severity"]),
            not item["kev"],
            not item["exposed"],
            not item["running"],
            -(item["cvss"] or 0.0),
            item["software"],
        )

    def _summary(self, items: list[dict[str, Any]]) -> dict[str, int]:
        severities = [item["severity"] for item in items]
        return {
            "critical": severities.count("critical"),
            "high": severities.count("high"),
            "kev": sum(1 for item in items if item["kev"]),
            "exposed": sum(1 for item in items if item["exposed"]),
        }
