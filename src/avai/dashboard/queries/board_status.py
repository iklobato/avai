"""Summary numbers for the panels board: active verdicts, the AI's cost,
what changed since the last cycle, and the Setup and privacy cards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from avai.enrichers.cache import EnrichmentSchema
from avai.host_monitor import Base, CollectionRun, CollectorErrorRow, Judgement
from avai.host_monitor.enums import Verdict

from .collection import RowCounts, RunMark, RunQueries
from .findings import FindingFilter, FindingsPanel, FindingsQuery, FindingStatus
from .panel_reads import Page, SchemaProbe

SECONDS_PER_MINUTE = 60
PERMISSION_ERROR = "PermissionError"


class ActiveVerdicts:
    """Findings still present on the machine, per verdict."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def counts(self) -> dict[str, int]:
        return {
            verdict.value: self._total(verdict) for verdict in Verdict.worst_first()
        }

    def _total(self, verdict: Verdict) -> int:
        filters = FindingFilter(verdict=verdict.value, status=FindingStatus.ACTIVE)
        query = FindingsQuery(filters=filters, page=Page(1, 1))
        return FindingsPanel(self._session).findings(query)["total"]


class JudgeTotals:
    """What the AI judge did over the life of this database."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def fields(self) -> dict[str, Any]:
        cost = func.coalesce(func.sum(Judgement.cost_usd), 0.0)
        judged, spent = self._session.execute(
            select(func.count(Judgement.content_hash), cost)
        ).one()
        newest = select(Judgement.model).order_by(desc(Judgement.created_at)).limit(1)
        model = self._session.execute(newest).scalar()
        return {"judged": judged or 0, "cost": float(spent or 0.0), "model": model}


class PersistenceChanges:
    """Row counts of the places malware hides, this cycle against the last."""

    COLLECTORS = (
        "launch_items",
        "kernel_extensions",
        "system_extensions",
        "browser_extensions",
        "trusted_roots",
        "usb_devices",
        "setuid_files",
        "ssh_authorized_keys",
        "processes",
    )

    def __init__(self, session: Session) -> None:
        self._session = session

    def rows(self) -> dict[str, Any]:
        runs = RunQueries(self._session)
        latest = runs.latest_run()
        if latest is None:
            return {"items": [], "since": None, "until": None}
        before_id, before_started = runs.prior_run(latest.started_at)
        counts = RowCounts(self._session).for_runs(
            RunMark(latest.run_id, latest.started_at),
            RunMark(before_id, before_started),
        )
        by_name = {entry["name"]: entry for entry in counts}
        items = [
            self._item(by_name[name]) for name in self.COLLECTORS if name in by_name
        ]
        return {"items": items, "since": before_started, "until": latest.started_at}

    def _item(self, entry: dict[str, Any]) -> dict[str, Any]:
        delta = entry["delta"]
        before = None if delta is None else entry["rows"] - delta
        return {
            "name": entry["name"],
            "before": before,
            "after": entry["rows"],
            "delta": delta,
        }


class NovelFindings:
    """Active findings avai had never seen before."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def collectors(self) -> list[str]:
        query = FindingsQuery(filters=FindingFilter(status=FindingStatus.ACTIVE))
        items = FindingsPanel(self._session).findings(query)["items"]
        return sorted({item["collector"] for item in items if item["novel"]})


@dataclass(frozen=True)
class MonitorState:
    """The control row as the board reads it."""

    alive: bool
    state: dict[str, Any] | None

    def label(self) -> str:
        if not self.alive:
            return "offline"
        if self.state and self.state.get("paused"):
            return "paused"
        return (self.state or {}).get("status") or "running"

    def interval_minutes(self) -> int | None:
        seconds = (self.state or {}).get("current_interval")
        return round(seconds / SECONDS_PER_MINUTE) if seconds else None


class AccessCheck:
    """Collectors the OS refused in the latest run: the sign the monitor
    runs without full access."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def refused(self) -> list[str]:
        latest = RunQueries(self._session).latest_run()
        if latest is None:
            return []
        statement = select(CollectorErrorRow.collector).where(
            CollectorErrorRow.run_id == latest.run_id,
            CollectorErrorRow.error_class == PERMISSION_ERROR,
        )
        return sorted(set(self._session.execute(statement).scalars()))


class LookupSources:
    """Threat-intel sources that returned at least one answer."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def names(self) -> list[str]:
        if "enrichment_evidence" not in SchemaProbe(self._session).tables():
            return []
        model = EnrichmentSchema(Base).model()
        statement = select(model.source).distinct().order_by(model.source)
        return list(self._session.execute(statement).scalars())


class HostName:
    def __init__(self, session: Session) -> None:
        self._session = session

    def latest(self) -> str:
        statement = (
            select(CollectionRun.hostname)
            .order_by(desc(CollectionRun.started_at))
            .limit(1)
        )
        return self._session.execute(statement).scalar() or "this computer"
