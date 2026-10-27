"""The report, retention and control stores behind
:class:`~avai.host_monitor.sink.Sink`."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, asc, delete, func, select, text, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .models import (
    BrowserExtensionRow,
    CollectionRun,
    CollectorErrorRow,
    ControlState,
    IncidentNarrativeRow,
    InstalledAppRow,
    Judgement,
    KernelExtensionRow,
    LaunchItemRow,
    ListeningPortRow,
    PrivilegeConfigRow,
    ProcessRow,
    RiskScoreRow,
    StreamingSession,
    SystemExtensionRow,
    SystemIntegrityRow,
    YaraRuleRow,
    YaraStatusRow,
    _RowBase,
)
from .enums import PrivilegeKind
from .runtime import Clock
from .slices import Slices

# The control_state and yara_status tables each hold one row with this id.
SINGLE_ROW_ID = 1


class ReportStore:
    """End-of-cycle reports: incident narratives, risk scores, the YARA
    ruleset summary and its coverage assessment."""

    RISK_INTEGRITY_FIELDS = (
        "filevault_active",
        "firewall_global_state",
        "firewall_stealth",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )
    # Inventory tables describing the host's attack surface: the host side
    # of the coverage assessment.
    COVERAGE_INVENTORY = (
        ("processes", ProcessRow),
        ("installed_apps", InstalledAppRow),
        ("launch_items", LaunchItemRow),
        ("browser_extensions", BrowserExtensionRow),
        ("kernel_extensions", KernelExtensionRow),
        ("system_extensions", SystemExtensionRow),
        ("listening_ports", ListeningPortRow),
    )

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def add(self, row: Any) -> None:
        with Session(self._engine) as session:
            session.add(row)
            session.commit()

    def latest(self, column: Any, created_at: Any) -> Any:
        """The ``column`` value of the newest row ordered by ``created_at``."""
        statement = select(column).order_by(created_at.desc()).limit(1)
        with Session(self._engine) as session:
            return session.execute(statement).scalar_one_or_none()

    def system_integrity_row(self, run_id: str) -> dict[str, Any] | None:
        """The system_integrity posture for a run as a plain dict, or None."""
        fields = self.RISK_INTEGRITY_FIELDS
        columns = [getattr(SystemIntegrityRow, name) for name in fields]
        statement = select(*columns).where(SystemIntegrityRow.run_id == run_id).limit(1)
        with Session(self._engine) as session:
            row = session.execute(statement).first()
        return None if row is None else dict(zip(fields, row))

    def privilege_risk_counts(self, run_id: str) -> tuple[int, int]:
        """``(nopasswd_sudoers, extra_uid0_accounts)`` for a run: the two
        privilege-config facts that feed the risk score."""
        nopasswd = self._privilege_count(
            run_id,
            PrivilegeConfigRow.kind == PrivilegeKind.SUDOERS,
            PrivilegeConfigRow.detail.like("%NOPASSWD%"),
        )
        extra_uid0 = self._privilege_count(
            run_id,
            PrivilegeConfigRow.kind == PrivilegeKind.ACCOUNT,
            PrivilegeConfigRow.subject != "root",
        )
        return nopasswd, extra_uid0

    def _privilege_count(self, run_id: str, kind: Any, detail: Any) -> int:
        statement = (
            select(func.count())
            .select_from(PrivilegeConfigRow)
            .where(PrivilegeConfigRow.run_id == run_id, kind, detail)
        )
        with Session(self._engine) as session:
            return int(session.execute(statement).scalar_one())

    def latest_risk_row(self) -> RiskScoreRow | None:
        return self.latest(RiskScoreRow, RiskScoreRow.created_at)

    def write_yara_status(self, stats: dict[str, Any]) -> None:
        """Upsert the single-row ruleset summary so the read-only dashboard
        can show what's loaded."""
        status = YaraStatusRow(
            id=SINGLE_ROW_ID,
            compiled_at=Clock().now_iso(),
            rules_loaded=stats.get("rules_loaded"),
            files_loaded=stats.get("files_loaded"),
            files_skipped=stats.get("files_skipped"),
            rules_dir=stats.get("rules_dir"),
            sources_json=json.dumps(stats.get("sources") or {}),
            skip_reasons_json=json.dumps(stats.get("skip_reasons") or {}),
            by_category_json=json.dumps(stats.get("by_category") or {}),
        )
        with Session(self._engine) as session:
            session.merge(status)
            session.commit()

    def write_yara_rules(self, inventory: list[dict[str, Any]]) -> None:
        """Replace the browsable rule inventory. Skipped when the row count
        already matches: the ruleset is static within a monitor process."""
        with Session(self._engine) as session:
            current = session.scalar(select(func.count()).select_from(YaraRuleRow))
            if current == len(inventory):
                return
            session.execute(delete(YaraRuleRow))
            if inventory:
                session.execute(sqlite_insert(YaraRuleRow), inventory)
            session.commit()

    def read_yara_status(self) -> dict[str, Any] | None:
        """The persisted ruleset summary, or None. The coverage assessor reads
        this rather than in-memory compile stats to stay off the scan cycle."""
        with Session(self._engine) as session:
            row = session.get(YaraStatusRow, SINGLE_ROW_ID)
        if row is None:
            return None
        return {
            "rules_loaded": row.rules_loaded,
            "files_loaded": row.files_loaded,
            "files_skipped": row.files_skipped,
            "rules_dir": row.rules_dir,
            "sources": json.loads(row.sources_json or "{}"),
            "skip_reasons": json.loads(row.skip_reasons_json or "{}"),
            "by_category": json.loads(row.by_category_json or "{}"),
        }

    def coverage_profile(self, run_id: str) -> dict[str, int]:
        """Per-collector row counts for ``run_id`` over the inventory tables:
        a compact picture of the host's attack surface."""
        with Session(self._engine) as session:
            return {
                name: int(
                    session.execute(
                        select(func.count())
                        .select_from(model)
                        .where(model.run_id == run_id)
                    ).scalar()
                    or 0
                )
                for name, model in self.COVERAGE_INVENTORY
            }

    def clear(self, model: Any) -> int:
        with Session(self._engine) as session:
            deleted = session.execute(delete(model)).rowcount or 0
            session.commit()
        return deleted


@dataclass(frozen=True)
class PruneStats:
    runs_pruned: int
    events_pruned: int
    bytes_before: int
    bytes_after: int

    def as_dict(self) -> dict[str, int]:
        return {
            "runs_pruned": self.runs_pruned,
            "events_pruned": self.events_pruned,
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
        }


class DatabaseFile:
    """Sizes of the SQLite database behind an engine."""

    SQLITE_BACKEND = "sqlite"
    SIDECARS = ("", "-wal", "-shm")

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def size_bytes(self) -> int:
        """Total on-disk bytes including the SQLite WAL/SHM sidecars."""
        # url.database is the real path; str(url) percent-encodes it on
        # SQLAlchemy 2.1 (C%3A%5C... on Windows).
        url = self._engine.url
        if url.get_backend_name() != self.SQLITE_BACKEND or not url.database:
            return 0
        paths = (Path(url.database + suffix) for suffix in self.SIDECARS)
        return sum(self._size(path) for path in paths)

    def live_bytes(self) -> int:
        """Post-VACUUM size estimated from SQLite pragmas. Deletes only mark
        pages free, so this drops right after a delete while the file size
        does not; it is the prune loop's stop condition."""
        with self._engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            page_count = conn.execute(text("PRAGMA page_count")).scalar() or 0
            page_size = conn.execute(text("PRAGMA page_size")).scalar() or 0
            freelist = conn.execute(text("PRAGMA freelist_count")).scalar() or 0
        return max(0, (page_count - freelist) * page_size)

    def _size(self, path: Path) -> int:
        try:
            return path.stat().st_size if path.exists() else 0
        except OSError:
            return 0


class Retention:
    """Keeps the database under its size cap and wipes data on request."""

    # The oldest run plus the next one: the next one's start bounds the
    # streaming events that go with the oldest.
    OLDEST_PAIR = 2
    STREAMING_MODELS = tuple(item.model for item in Slices.ALL if item.streaming)

    def __init__(self, engine: Engine, logger: logging.Logger) -> None:
        self._engine = engine
        self._logger = logger

    def prune_to_size(self, max_bytes: int) -> dict[str, int]:
        """Delete oldest completed runs (and their child rows) plus the
        streaming events older than the oldest remaining run, until the
        database fits under ``max_bytes``. Always keeps one completed run.

        Returns ``{runs_pruned, events_pruned, bytes_before, bytes_after}``.
        """
        database = DatabaseFile(self._engine)
        if max_bytes <= 0:
            return PruneStats(0, 0, 0, 0).as_dict()
        before = database.size_bytes()
        if before <= max_bytes:
            return PruneStats(0, 0, before, before).as_dict()
        runs, events = self._prune(max_bytes, database)
        self._vacuum()
        return PruneStats(runs, events, before, database.size_bytes()).as_dict()

    def _prune(self, max_bytes: int, database: DatabaseFile) -> tuple[int, int]:
        with Session(self._engine) as session:
            return self._prune_in(session, max_bytes, database)

    def _prune_in(
        self, session: Session, max_bytes: int, database: DatabaseFile
    ) -> tuple[int, int]:
        runs = events = 0
        while database.live_bytes() > max_bytes:
            trimmed = self._prune_oldest(session)
            if trimmed is None:
                break
            runs, events = runs + 1, events + trimmed
            session.commit()
        return runs, events

    def _prune_oldest(self, session: Session) -> int | None:
        """Delete the oldest completed run; the streaming events trimmed, or
        None when only one completed run is left."""
        completed = self._oldest_completed(session)
        if len(completed) < self.OLDEST_PAIR:
            self._logger.warning(
                "prune_to_size: only %d completed run(s) left; cannot shrink further",
                len(completed),
            )
            return None
        oldest, next_kept = completed
        self._delete_run(session, oldest)
        return self._trim_streaming(session, next_kept.started_at)

    def _oldest_completed(self, session: Session) -> list[CollectionRun]:
        statement = (
            select(CollectionRun)
            .where(CollectionRun.finished_at.is_not(None))
            .order_by(asc(CollectionRun.started_at))
            .limit(self.OLDEST_PAIR)
        )
        return list(session.execute(statement).scalars())

    def _delete_run(self, session: Session, run: CollectionRun) -> None:
        snapshot_models = (
            model
            for model in _RowBase.__subclasses__()
            if model not in self.STREAMING_MODELS
        )
        for model in snapshot_models:
            session.execute(delete(model).where(model.run_id == run.run_id))
        session.execute(
            delete(CollectorErrorRow).where(CollectorErrorRow.run_id == run.run_id)
        )
        session.execute(delete(CollectionRun).where(CollectionRun.run_id == run.run_id))

    def _trim_streaming(self, session: Session, before: str) -> int:
        """Delete streaming events and sessions older than ``before`` (the
        earliest kept run). Returns the events deleted."""
        deleted = sum(
            session.execute(delete(model).where(model.collected_at < before)).rowcount
            or 0
            for model in self.STREAMING_MODELS
        )
        session.execute(
            delete(StreamingSession).where(StreamingSession.finished_at < before)
        )
        return deleted

    def _vacuum(self) -> None:
        """Reclaim the pruned pages. VACUUM cannot run inside a transaction,
        so use AUTOCOMMIT; checkpoint the WAL before and after."""
        try:
            with self._engine.connect() as conn:
                conn = conn.execution_options(isolation_level="AUTOCOMMIT")
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
                conn.execute(text("VACUUM"))
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        except SQLAlchemyError:
            self._logger.exception("VACUUM failed; space not yet reclaimed")

    def clear_data(self) -> int:
        """Wipe all telemetry, runs, judgements, narratives and risk scores.
        Keeps control_state and the enrichment cache. Returns rows deleted."""
        models = (
            *_RowBase.__subclasses__(),
            CollectionRun,
            CollectorErrorRow,
            StreamingSession,
            Judgement,
            IncidentNarrativeRow,
            RiskScoreRow,
        )
        with Session(self._engine) as session:
            deleted = sum(
                session.execute(delete(model)).rowcount or 0 for model in models
            )
            session.commit()
        return deleted


@dataclass(frozen=True)
class ControlSeed:
    """The monitor's startup settings, seeded into the control row."""

    interval: int
    judge_enabled: bool
    enrich_enabled: bool


class ControlStore:
    """The single control row (see models.ControlState): the dashboard's
    intent and the monitor's heartbeat."""

    def __init__(self, engine: Engine, logger: logging.Logger) -> None:
        self._engine = engine
        self._logger = logger

    def ensure_control_row(self, seed: ControlSeed) -> None:
        """Seed the control row with the startup settings. No-op if it
        already exists: control state persists across restarts by design."""
        statement = (
            sqlite_insert(ControlState)
            .values(
                id=SINGLE_ROW_ID,
                paused=0,
                interval_override=seed.interval,
                judge_enabled=int(seed.judge_enabled),
                enrich_enabled=int(seed.enrich_enabled),
            )
            .on_conflict_do_nothing()
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()

    def read_control(self) -> dict[str, Any] | None:
        """The control row as a plain dict, or None. A control read must
        never crash the monitor loop."""
        try:
            with Session(self._engine) as session:
                row = session.get(ControlState, SINGLE_ROW_ID)
                values = None if row is None else self._values(row)
        except SQLAlchemyError:
            self._logger.exception("read_control failed")
            return None
        return values

    def _values(self, row: ControlState) -> dict[str, Any]:
        columns = ControlState.__table__.columns
        return {column.name: getattr(row, column.name) for column in columns}

    def set_values(self, values: dict[str, Any]) -> None:
        statement = (
            update(ControlState)
            .where(ControlState.id == SINGLE_ROW_ID)
            .values(**values)
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()
