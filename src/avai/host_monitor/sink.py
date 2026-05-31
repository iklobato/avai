"""The single DB write/read gateway used by the runner."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    Engine,
    asc,
    delete,
    event,
    exists,
    func,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .constants import LOG
from .enums import Verdict
from .judge import Judgment
from .models import (
    AuthEventRow,
    Base,
    CollectionRun,
    CollectorErrorRow,
    DnsQueryRow,
    IncidentNarrativeRow,
    Judgement,
    ListeningPortRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    RiskScoreRow,
    StreamingSession,
    SystemIntegrityRow,
    _RowBase,
)
from .shell import utcnow

if TYPE_CHECKING:
    from .collectors import Collector


class Sink:
    """SQLAlchemy repository — owns schema, run lifecycle, writes, lookups."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.run_id: Optional[str] = None
        event.listen(engine, "connect", _set_sqlite_pragmas)

    def setup(self) -> None:
        # Register the enrichment evidence model on Base.metadata so
        # `create_all` provisions its table even when the enrichment
        # chain isn't enabled (the dashboard reads from it regardless).
        try:
            from avai.enrichers.cache import register_schema

            register_schema(Base)
        except Exception:
            LOG.exception("enrichment schema registration failed")
        Base.metadata.create_all(self.engine)
        _migrate_add_columns(self.engine)
        # Apply Alembic migrations (indexes / future schema changes). The DB
        # was just built by create_all, so this stamps the baseline and runs
        # only the incremental migrations on top. Best-effort: a migration
        # failure must not stop the monitor from collecting.
        try:
            from avai.db_migrate import upgrade_to_head

            upgrade_to_head(str(self.engine.url))
        except Exception:
            LOG.exception("alembic migration failed (continuing)")

    def start_run(self, hostname: str, lookback_min: int) -> tuple[str, str]:
        run_id = str(uuid.uuid4())
        started = utcnow()
        with Session(self.engine) as session:
            session.add(
                CollectionRun(
                    run_id=run_id,
                    started_at=started,
                    hostname=hostname,
                    lookback_min=lookback_min,
                )
            )
            session.commit()
        self.run_id = run_id
        return run_id, started

    def end_run(self, ok: int, failed: int) -> None:
        with Session(self.engine) as session:
            session.execute(
                update(CollectionRun)
                .where(CollectionRun.run_id == self.run_id)
                .values(
                    finished_at=utcnow(), collectors_ok=ok, collectors_failed=failed
                )
            )
            session.commit()

    def write(self, model: type[_RowBase], rows: list[dict]) -> None:
        if not rows:
            return
        with Session(self.engine) as session:
            session.execute(sqlite_insert(model), rows)
            session.commit()

    def write_error(self, collector: str, exc: BaseException) -> None:
        with Session(self.engine) as session:
            session.add(
                CollectorErrorRow(
                    run_id=self.run_id,
                    collector=collector,
                    error_class=type(exc).__name__,
                    message=str(exc)[:1000],
                    occurred_at=utcnow(),
                )
            )
            session.commit()

    def unjudged(self, collector: Collector) -> list[dict]:
        """Return one entry per distinct, unjudged content_hash for the
        current run (judge_fields drive what's selected)."""
        run_id = self.run_id
        if run_id is None or not collector.judge_fields:
            return []
        return self._unjudged_select(collector, run_id_filter=run_id)

    def unjudged_all(self, collector: Collector) -> list[dict]:
        """Same as ``unjudged`` but with no run_id filter — used for
        streaming collectors whose rows accumulate continuously
        between snapshot runs. The Runner calls this once per cycle
        so the judge gets a chance to classify newly-streamed
        content_hashes."""
        if not collector.judge_fields:
            return []
        return self._unjudged_select(collector, run_id_filter=None)

    def _unjudged_select(
        self, collector: Collector, run_id_filter: Optional[str]
    ) -> list[dict]:
        model = collector.model
        cols = [model.content_hash] + [
            getattr(model, f) for f in collector.judge_fields
        ]
        conditions = [
            model.content_hash.is_not(None),
            ~exists().where(
                Judgement.content_hash == model.content_hash,
                Judgement.collector == collector.name,
            ),
        ]
        if run_id_filter is not None:
            conditions.insert(0, model.run_id == run_id_filter)
        stmt = select(*cols).distinct().where(*conditions)
        col_names = ["content_hash"] + list(collector.judge_fields)
        with Session(self.engine) as session:
            return [
                {col_names[i]: row[i] for i in range(len(col_names))}
                for row in session.execute(stmt).all()
            ]

    # -- baseline / novelty -------------------------------------------------

    def completed_run_count(self) -> int:
        """Number of snapshot runs that have finished. The in-progress run
        is excluded (its ``finished_at`` is still NULL), so this reflects
        how much history the host already had *before* the current cycle."""
        with Session(self.engine) as session:
            return int(
                session.execute(
                    select(func.count())
                    .select_from(CollectionRun)
                    .where(CollectionRun.finished_at.is_not(None))
                ).scalar_one()
            )

    def nth_run_started_at(self, n: int) -> Optional[str]:
        """``started_at`` of the n-th completed run (1-indexed, oldest
        first), or None if fewer than ``n`` completed runs exist. Marks the
        end of the baseline-learning window."""
        if n < 1:
            return None
        with Session(self.engine) as session:
            return session.execute(
                select(CollectionRun.started_at)
                .where(CollectionRun.finished_at.is_not(None))
                .order_by(CollectionRun.started_at)
                .limit(1)
                .offset(n - 1)
            ).scalar_one_or_none()

    def first_seen_map(
        self, model: type[_RowBase], content_hashes: list[str]
    ) -> dict[str, tuple[str, int]]:
        """For each content_hash, return ``(first_seen, times_seen)``:
        the earliest ``collected_at`` still retained and the number of
        distinct runs it appeared in. Bounded by retention (pruned history
        is invisible) — but only ever queried for *unjudged* hashes, which
        are judged exactly once and never again, so the retention bound
        cannot make an already-established artifact look novel."""
        if not content_hashes:
            return {}
        stmt = (
            select(
                model.content_hash,
                func.min(model.collected_at),
                func.count(func.distinct(model.run_id)),
            )
            .where(model.content_hash.in_(content_hashes))
            .group_by(model.content_hash)
        )
        with Session(self.engine) as session:
            return {
                row[0]: (row[1], int(row[2])) for row in session.execute(stmt).all()
            }

    # -- correlation (process story) ---------------------------------------

    def prior_run_started_at(self, run_id: str) -> Optional[str]:
        """``started_at`` of the run immediately preceding ``run_id``, or
        None if it's the first run. Used to time-bound correlation so it
        only pulls the previous cycle's behaviour for a PID — long enough
        to be useful, short enough that PID reuse can't pollute it."""
        with Session(self.engine) as session:
            cur = session.execute(
                select(CollectionRun.started_at).where(CollectionRun.run_id == run_id)
            ).scalar_one_or_none()
            if cur is None:
                return None
            return session.execute(
                select(CollectionRun.started_at)
                .where(CollectionRun.started_at < cur)
                .order_by(CollectionRun.started_at.desc())
                .limit(1)
            ).scalar_one_or_none()

    def correlation_context(
        self,
        pids: list[int],
        proc_names: list[str],
        since: Optional[str],
        per_pid_cap: int = 10,
    ) -> dict:
        """Gather a PID's recent runtime behaviour for the process judge:
        listening ports, outbound flows, established remote connections,
        DNS queries (joined by process *name*, which is all DNS capture
        records), and exec lineage. ``since`` bounds every lookup to rows
        collected at/after the previous cycle. ProcessCollector runs first
        in a cycle, so the current run's network rows don't exist yet —
        this deliberately surfaces the *previous* cycle's behaviour for a
        still-running PID."""
        out: dict[str, dict] = {
            "ports": {},
            "flows": {},
            "conns": {},
            "dns": {},
            "exec": {},
        }
        pids = [p for p in pids if p is not None]
        names = [n for n in proc_names if n]
        if not pids and not names:
            return out

        def _bounded(stmt, model):
            return stmt.where(model.collected_at >= since) if since else stmt

        with Session(self.engine) as session:
            if pids:
                for pid, ip, port in session.execute(
                    _bounded(
                        select(
                            ListeningPortRow.pid,
                            ListeningPortRow.laddr_ip,
                            ListeningPortRow.laddr_port,
                        ).where(ListeningPortRow.pid.in_(pids)),
                        ListeningPortRow,
                    )
                ).all():
                    lst = out["ports"].setdefault(pid, [])
                    if len(lst) < per_pid_cap:
                        lst.append(f"{ip}:{port}")

                for pid, dip, dport, svc, pkts in session.execute(
                    _bounded(
                        select(
                            NetworkFlowRow.pid,
                            NetworkFlowRow.dst_ip,
                            NetworkFlowRow.dst_port,
                            NetworkFlowRow.service,
                            NetworkFlowRow.packets,
                        ).where(NetworkFlowRow.pid.in_(pids)),
                        NetworkFlowRow,
                    ).order_by(NetworkFlowRow.packets.desc())
                ).all():
                    lst = out["flows"].setdefault(pid, [])
                    if len(lst) < per_pid_cap:
                        lst.append(
                            {"dst": f"{dip}:{dport}", "service": svc, "packets": pkts}
                        )

                for pid, rip, rport, status in session.execute(
                    _bounded(
                        select(
                            NetworkConnectionRow.pid,
                            NetworkConnectionRow.raddr_ip,
                            NetworkConnectionRow.raddr_port,
                            NetworkConnectionRow.status,
                        ).where(
                            NetworkConnectionRow.pid.in_(pids),
                            NetworkConnectionRow.raddr_ip.is_not(None),
                        ),
                        NetworkConnectionRow,
                    )
                ).all():
                    lst = out["conns"].setdefault(pid, [])
                    if len(lst) < per_pid_cap:
                        lst.append(f"{rip}:{rport} {status}")

                for pid, parent, signing, exe in session.execute(
                    _bounded(
                        select(
                            ProcessExecRow.pid,
                            ProcessExecRow.parent_path,
                            ProcessExecRow.signing_id,
                            ProcessExecRow.exe_path,
                        ).where(ProcessExecRow.pid.in_(pids)),
                        ProcessExecRow,
                    ).order_by(ProcessExecRow.event_timestamp.desc())
                ).all():
                    # Keep the most recent exec event per PID.
                    if pid not in out["exec"]:
                        out["exec"][pid] = {
                            "parent": parent,
                            "signed": signing,
                            "exe": exe,
                        }

            if names:
                for proc, qname, qtype in session.execute(
                    _bounded(
                        select(
                            DnsQueryRow.process,
                            DnsQueryRow.qname,
                            DnsQueryRow.qtype,
                        ).where(DnsQueryRow.process.in_(names)),
                        DnsQueryRow,
                    )
                ).all():
                    lst = out["dns"].setdefault(proc, [])
                    if len(lst) < per_pid_cap + 5:
                        lst.append(f"{qname} ({qtype})")
        return out

    def write_judgments(
        self, judgments: list[Judgment], context: Optional[dict] = None
    ) -> None:
        """Persist judgments. ``context`` maps content_hash → a dict that may
        hold ``baseline`` and/or ``related`` (the novelty + correlated-story
        signals computed at judge time) so the dashboard can surface them on
        the finding."""
        if not judgments:
            return
        context = context or {}
        rows = []
        for j in judgments:
            ctx = context.get(j.content_hash) or {}
            baseline = ctx.get("baseline") or {}
            rows.append(
                {
                    "content_hash": j.content_hash,
                    "collector": j.collector,
                    "verdict": str(j.verdict),
                    "category": str(j.category),
                    "confidence": j.confidence,
                    "reasoning": j.reasoning,
                    "remediation": j.remediation,
                    "model": j.model,
                    "created_at": j.created_at,
                    "novel": 1 if baseline.get("novel") else (0 if baseline else None),
                    "context_json": json.dumps(ctx) if ctx else None,
                    "cost_usd": getattr(j, "cost_usd", 0.0) or None,
                }
            )
        with Session(self.engine) as session:
            session.execute(
                sqlite_insert(Judgement).on_conflict_do_nothing(),
                rows,
            )
            session.commit()

    # -- incident narrative -------------------------------------------------

    def active_findings(self, started: str) -> list[dict]:
        """Non-benign judgments still present as of the current run, i.e.
        ``last_seen_at == started`` (the same active/resolved rule the
        dashboard uses). These are what the incident narrator synthesises.
        Ordered oldest-first so the narrative reads as a timeline."""
        stmt = (
            select(
                Judgement.content_hash,
                Judgement.collector,
                Judgement.verdict,
                Judgement.category,
                Judgement.confidence,
                Judgement.reasoning,
                Judgement.remediation,
                Judgement.created_at,
            )
            .where(
                Judgement.verdict.in_(
                    [str(Verdict.SUSPICIOUS), str(Verdict.MALICIOUS)]
                ),
                Judgement.last_seen_at == started,
            )
            .order_by(Judgement.created_at)
        )
        with Session(self.engine) as session:
            return [
                {
                    "content_hash": r[0],
                    "collector": r[1],
                    "verdict": r[2],
                    "category": r[3],
                    "confidence": r[4],
                    "reasoning": r[5],
                    "remediation": r[6],
                    "first_flagged": r[7],
                }
                for r in session.execute(stmt).all()
            ]

    def latest_narrative_finding_hashes(self) -> Optional[str]:
        """``finding_hashes`` of the most recent narrative, or None. Used to
        skip regeneration when the active-finding set is unchanged."""
        with Session(self.engine) as session:
            return session.execute(
                select(IncidentNarrativeRow.finding_hashes)
                .order_by(IncidentNarrativeRow.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()

    def write_narrative(self, row: dict) -> None:
        with Session(self.engine) as session:
            session.add(IncidentNarrativeRow(**row))
            session.commit()

    # -- risk score ---------------------------------------------------------

    _RISK_INTEGRITY_FIELDS = (
        "filevault_active",
        "firewall_global_state",
        "firewall_stealth",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "remote_management_enabled",
    )

    def system_integrity_row(self, run_id: str) -> Optional[dict]:
        """The system_integrity posture for a run as a plain dict, or None."""
        cols = [getattr(SystemIntegrityRow, f) for f in self._RISK_INTEGRITY_FIELDS]
        with Session(self.engine) as session:
            row = session.execute(
                select(*cols).where(SystemIntegrityRow.run_id == run_id).limit(1)
            ).first()
        if row is None:
            return None
        return dict(zip(self._RISK_INTEGRITY_FIELDS, row))

    def privilege_risk_counts(self, run_id: str) -> tuple[int, int]:
        """``(nopasswd_sudoers, extra_uid0_accounts)`` for a run — the two
        privilege-config facts that feed the risk score."""
        with Session(self.engine) as session:
            nopasswd = session.execute(
                select(func.count())
                .select_from(PrivilegeConfigRow)
                .where(
                    PrivilegeConfigRow.run_id == run_id,
                    PrivilegeConfigRow.kind == "sudoers",
                    PrivilegeConfigRow.detail.like("%NOPASSWD%"),
                )
            ).scalar_one()
            extra_uid0 = session.execute(
                select(func.count())
                .select_from(PrivilegeConfigRow)
                .where(
                    PrivilegeConfigRow.run_id == run_id,
                    PrivilegeConfigRow.kind == "account",
                    PrivilegeConfigRow.subject != "root",
                )
            ).scalar_one()
        return int(nopasswd), int(extra_uid0)

    def latest_risk_row(self) -> Optional[RiskScoreRow]:
        with Session(self.engine) as session:
            return session.execute(
                select(RiskScoreRow).order_by(RiskScoreRow.created_at.desc()).limit(1)
            ).scalar_one_or_none()

    def write_risk_score(self, row: dict) -> None:
        with Session(self.engine) as session:
            session.add(RiskScoreRow(**row))
            session.commit()

    def database_size_bytes(self) -> int:
        """Total on-disk bytes including the SQLite WAL/SHM sidecars."""
        url = str(self.engine.url)
        prefix = "sqlite:///"
        if not url.startswith(prefix):
            return 0
        base = Path(url[len(prefix) :])
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(base) + suffix)
            if p.exists():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
        return total

    def database_live_bytes(self) -> int:
        """Estimate post-VACUUM database size from SQLite pragmas. Deletes
        only mark pages free; until VACUUM runs, the file size doesn't
        shrink. This estimate decreases immediately as we delete rows,
        so the prune loop has a meaningful stop condition."""
        with self.engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            page_count = conn.execute(text("PRAGMA page_count")).scalar() or 0
            page_size = conn.execute(text("PRAGMA page_size")).scalar() or 0
            freelist = conn.execute(text("PRAGMA freelist_count")).scalar() or 0
        return max(0, (page_count - freelist) * page_size)

    def prune_to_size(self, max_bytes: int) -> dict:
        """Delete oldest completed runs (and their child rows) plus the
        ``auth_events`` rows older than the oldest remaining run, until
        the database fits under ``max_bytes``. Always preserves at
        least one completed run so the dashboard stays useful.

        Returns ``{runs_pruned, events_pruned, bytes_before, bytes_after}``.
        """
        if max_bytes <= 0:
            return {
                "runs_pruned": 0,
                "events_pruned": 0,
                "bytes_before": 0,
                "bytes_after": 0,
            }

        bytes_before = self.database_size_bytes()
        if bytes_before <= max_bytes:
            return {
                "runs_pruned": 0,
                "events_pruned": 0,
                "bytes_before": bytes_before,
                "bytes_after": bytes_before,
            }

        # All collector-row tables EXCEPT auth_events. Streaming events
        # aren't tied to a CollectionRun.run_id, so we trim them by
        # collected_at instead of by run_id.
        snapshot_models = [
            m for m in _RowBase.__subclasses__() if m is not AuthEventRow
        ]

        runs_pruned = 0
        events_pruned = 0

        with Session(self.engine) as session:
            # Use the post-VACUUM estimate (page_count - freelist) inside
            # the loop. SQLite deletes only mark pages free; the actual
            # file size doesn't shrink until VACUUM runs. database_live_bytes
            # decreases immediately after each delete, so the loop has a
            # meaningful stop condition.
            while self.database_live_bytes() > max_bytes:
                # Safety: never delete the only completed run on file.
                completed = (
                    session.execute(
                        select(func.count())
                        .select_from(CollectionRun)
                        .where(CollectionRun.finished_at.is_not(None))
                    ).scalar()
                    or 0
                )
                if completed <= 1:
                    LOG.warning(
                        "prune_to_size: only %d completed run(s) "
                        "left; cannot shrink further",
                        completed,
                    )
                    break

                oldest = session.execute(
                    select(CollectionRun)
                    .where(CollectionRun.finished_at.is_not(None))
                    .order_by(asc(CollectionRun.started_at))
                    .limit(1)
                ).scalar_one_or_none()
                if oldest is None:
                    break

                for model in snapshot_models:
                    session.execute(delete(model).where(model.run_id == oldest.run_id))
                session.execute(
                    delete(CollectorErrorRow).where(
                        CollectorErrorRow.run_id == oldest.run_id
                    )
                )
                session.execute(
                    delete(CollectionRun).where(CollectionRun.run_id == oldest.run_id)
                )
                runs_pruned += 1

                # Trim streaming events older than the new earliest run.
                new_earliest = session.execute(
                    select(CollectionRun.started_at)
                    .where(CollectionRun.finished_at.is_not(None))
                    .order_by(asc(CollectionRun.started_at))
                    .limit(1)
                ).scalar()
                if new_earliest:
                    result = session.execute(
                        delete(AuthEventRow).where(
                            AuthEventRow.collected_at < new_earliest
                        )
                    )
                    events_pruned += result.rowcount or 0
                    session.execute(
                        delete(StreamingSession).where(
                            StreamingSession.finished_at < new_earliest
                        )
                    )

                session.commit()

        # Always VACUUM when entering this function (file size was over
        # the cap). VACUUM cannot run inside a transaction, so use
        # AUTOCOMMIT isolation. Checkpoint the WAL before and after so
        # VACUUM sees committed pages and the final on-disk file
        # accurately reflects the post-prune state.
        try:
            with self.engine.connect() as conn:
                conn = conn.execution_options(isolation_level="AUTOCOMMIT")
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
                conn.execute(text("VACUUM"))
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        except Exception:
            LOG.exception("VACUUM failed; space not yet reclaimed")

        return {
            "runs_pruned": runs_pruned,
            "events_pruned": events_pruned,
            "bytes_before": bytes_before,
            "bytes_after": self.database_size_bytes(),
        }

    def touch_judgments(
        self, collector: str, content_hashes: list[str], at: str
    ) -> None:
        """Update ``last_seen_at`` for every judgment whose ``content_hash``
        was observed in the current snapshot cycle. Used to derive
        "active vs resolved" status without storing transitions
        explicitly: a judgment whose ``last_seen_at`` matches the latest
        run started_at is still present on the host; anything older
        (including NULL) means the underlying artifact has gone away."""
        if not content_hashes:
            return
        with Session(self.engine) as session:
            session.execute(
                update(Judgement)
                .where(Judgement.collector == collector)
                .where(Judgement.content_hash.in_(content_hashes))
                .values(last_seen_at=at)
            )
            session.commit()

    # -- streaming sessions -------------------------------------------------

    def start_streaming_session(self, collector: str, hostname: str) -> str:
        run_id = str(uuid.uuid4())
        with Session(self.engine) as session:
            session.add(
                StreamingSession(
                    run_id=run_id,
                    collector=collector,
                    hostname=hostname,
                    started_at=utcnow(),
                )
            )
            session.commit()
        return run_id

    def end_streaming_session(self, run_id: str, row_count: int) -> None:
        with Session(self.engine) as session:
            session.execute(
                update(StreamingSession)
                .where(StreamingSession.run_id == run_id)
                .values(finished_at=utcnow(), row_count=row_count)
            )
            session.commit()


def _set_sqlite_pragmas(dbapi_conn, _connection_record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def _migrate_add_columns(engine: Engine) -> None:
    """Idempotent forward-only migration: add any columns that exist on
    the ORM models but not yet on the live tables. SQLite supports
    ``ALTER TABLE ADD COLUMN`` (no ALTER COLUMN, no DROP COLUMN) so this
    handles the common case of adding a new optional field to a model.
    """
    inspector = inspect(engine)
    live_tables = set(inspector.get_table_names())
    for table in Base.metadata.tables.values():
        if table.name not in live_tables:
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            col_type = col.type.compile(engine.dialect)
            nullable = "" if col.nullable else " NOT NULL DEFAULT ''"
            with engine.begin() as conn:
                conn.execute(
                    text(
                        f"ALTER TABLE {table.name} "
                        f"ADD COLUMN {col.name} {col_type}{nullable}"
                    )
                )
            LOG.info("schema migration: added %s.%s", table.name, col.name)
