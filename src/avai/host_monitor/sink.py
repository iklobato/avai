"""The single DB write/read gateway used by the monitor. A facade over the
stores in ``sink_stores`` and ``sink_admin``: callers keep one object."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine, event

from .constants import LOGGER_NAME
from .db_bootstrap import SchemaBootstrap, SqlitePragmas
from .judge import Judgment
from .models import (
    CollectionRun,
    IncidentNarrativeRow,
    Judgement,
    RiskScoreRow,
    YaraCoverageRow,
    _RowBase,
)
from .runtime import Clock
from .sink_admin import ControlSeed, ControlStore, DatabaseFile, ReportStore, Retention
from .sink_stores import BehaviorReader, CorrelationWindow, JudgmentStore, RunLog

if TYPE_CHECKING:
    from .collectors import Collector


@dataclass(frozen=True)
class SinkStores:
    runs: RunLog
    behavior: BehaviorReader
    judgments: JudgmentStore
    reports: ReportStore
    retention: Retention
    control: ControlStore


class Sink:
    """SQLAlchemy repository: owns schema, run lifecycle, writes, lookups."""

    def __init__(
        self, engine: Engine, stores: SinkStores, logger: logging.Logger
    ) -> None:
        self.engine = engine
        self._stores = stores
        self._logger = logger

    @classmethod
    def create(cls, engine: Engine) -> Sink:
        return cls.create_with_clock(engine, Clock())

    @classmethod
    def create_with_clock(cls, engine: Engine, clock: Clock) -> Sink:
        logger = logging.getLogger(LOGGER_NAME)
        event.listen(engine, "connect", SqlitePragmas().apply)
        stores = SinkStores(
            RunLog(engine, clock),
            BehaviorReader(engine),
            JudgmentStore(engine),
            ReportStore(engine, clock),
            Retention(engine, logger),
            ControlStore(engine, logger, clock),
        )
        return cls(engine, stores, logger)

    def setup(self) -> None:
        SchemaBootstrap(self.engine, self._logger).setup()

    # -- runs and rows ------------------------------------------------------

    def start_run(self, hostname: str, lookback_min: int) -> tuple[str, str]:
        return self._stores.runs.start_run(hostname, lookback_min)

    def end_run(self, run_id: str, ok: int, failed: int) -> None:
        self._stores.runs.end_run(run_id, ok, failed)

    def write(self, model: type[_RowBase], rows: list[dict[str, Any]]) -> None:
        self._stores.runs.write(model, rows)

    def write_error(self, run_id: str, collector: str, exc: BaseException) -> None:
        self._stores.runs.write_error(run_id, collector, exc)

    def unjudged(self, run_id: str, collector: Collector) -> list[dict[str, Any]]:
        return self._stores.runs.unjudged(run_id, collector)

    def unjudged_all(self, collector: Collector) -> list[dict[str, Any]]:
        return self._stores.runs.unjudged_all(collector)

    def completed_run_count(self) -> int:
        return self._stores.runs.completed_run_count()

    def nth_run_started_at(self, position: int) -> str | None:
        return self._stores.runs.nth_run_started_at(position)

    def run_started_ats(self) -> list[str]:
        return self._stores.runs.run_started_ats()

    def first_seen_map(
        self, model: type[_RowBase], hashes: list[str]
    ) -> dict[str, Any]:
        return self._stores.runs.first_seen_map(model, hashes)

    def prior_run_started_at(self, run_id: str | None) -> str | None:
        return self._stores.runs.prior_run_started_at(run_id)

    def touch_judgments(self, collector: str, hashes: list[str], seen_at: str) -> None:
        self._stores.runs.touch_judgments(collector, hashes, seen_at)

    def start_streaming_session(self, collector: str, hostname: str) -> str:
        return self._stores.runs.start_streaming_session(collector, hostname)

    def end_streaming_session(self, run_id: str | None, row_count: int) -> None:
        self._stores.runs.end_streaming_session(run_id, row_count)

    # -- behaviour ----------------------------------------------------------

    def pids_by_executable(self, exes: list[str], since: str | None = None) -> dict:
        return self._stores.behavior.pids_by_executable(exes, since)

    def correlation_context(
        self, pids: list[int], names: list[str], window: CorrelationWindow
    ) -> dict[str, dict[Any, Any]]:
        return self._stores.behavior.correlation_context(pids, names, window)

    # -- judgments ----------------------------------------------------------

    def write_judgments(
        self, judgments: list[Judgment], context: dict[str, Any] | None = None
    ) -> None:
        self._stores.judgments.write_judgments(judgments, context)

    def active_findings(self, started: str) -> list[dict[str, Any]]:
        return self._stores.judgments.active_findings(started)

    def apply_feedback(self) -> int:
        return self._stores.judgments.apply_feedback()

    def feedback_examples(self, collector: str) -> list[dict[str, Any]]:
        return self._stores.judgments.feedback_examples(collector)

    def recent_nonbenign(self, limit: int) -> list[dict[str, Any]]:
        return self._stores.judgments.recent_nonbenign(limit)

    # -- reports ------------------------------------------------------------

    def latest_narrative_finding_hashes(self) -> str | None:
        table = IncidentNarrativeRow
        return self._stores.reports.latest(table.finding_hashes, table.created_at)

    def write_narrative(self, row: dict[str, Any]) -> None:
        self._stores.reports.add(IncidentNarrativeRow(**row))

    def system_integrity_row(self, run_id: str) -> dict[str, Any] | None:
        return self._stores.reports.system_integrity_row(run_id)

    def privilege_risk_counts(self, run_id: str) -> tuple[int, int]:
        return self._stores.reports.privilege_risk_counts(run_id)

    def latest_risk_row(self) -> RiskScoreRow | None:
        return self._stores.reports.latest_risk_row()

    def write_risk_score(self, row: dict[str, Any]) -> None:
        self._stores.reports.add(RiskScoreRow(**row))

    def write_yara_status(self, stats: dict[str, Any]) -> None:
        self._stores.reports.write_yara_status(stats)

    def write_yara_rules(self, inventory: list[dict[str, Any]]) -> None:
        self._stores.reports.write_yara_rules(inventory)

    def read_yara_status(self) -> dict[str, Any] | None:
        return self._stores.reports.read_yara_status()

    def coverage_profile(self, run_id: str) -> dict[str, int]:
        return self._stores.reports.coverage_profile(run_id)

    def latest_yara_coverage_fingerprint(self) -> str | None:
        table = YaraCoverageRow
        return self._stores.reports.latest(table.ruleset_fingerprint, table.created_at)

    def write_yara_coverage(self, row: dict[str, Any]) -> None:
        self._stores.reports.add(YaraCoverageRow(**row))

    # -- retention and maintenance -------------------------------------------

    def database_size_bytes(self) -> int:
        return DatabaseFile(self.engine).size_bytes()

    def database_live_bytes(self) -> int:
        return DatabaseFile(self.engine).live_bytes()

    def prune_to_size(self, max_bytes: int) -> dict[str, int]:
        return self._stores.retention.prune_to_size(max_bytes)

    def clear_data(self) -> int:
        return self._stores.retention.clear_data()

    def clear_judgements(self) -> int:
        """Delete all verdicts so the next cycles re-judge from scratch."""
        return self._stores.reports.clear(Judgement)

    def clear_narratives(self) -> int:
        return self._stores.reports.clear(IncidentNarrativeRow)

    def reset_baseline(self) -> int:
        """Drop run history so novelty re-learns over the next runs."""
        return self._stores.reports.clear(CollectionRun)

    # -- control plane (see models.ControlState) ------------------------------

    def ensure_control_row(self, seed: ControlSeed) -> None:
        self._stores.control.ensure_control_row(seed)

    def read_control(self) -> dict[str, Any] | None:
        return self._stores.control.read_control()

    def write_heartbeat(self, *, pid: int, status: str, current_interval: int) -> None:
        self._stores.control.write_heartbeat(pid, status, current_interval)

    def write_capabilities(self, capabilities_json: str) -> None:
        """What this monitor runs with (see capabilities.MonitorCapabilities)."""
        self._stores.control.set_values({"capabilities_json": capabilities_json})

    def touch_heartbeat(self) -> None:
        """Refresh only ``last_seen_at``, so a long scan keeps proving
        liveness without claiming a status change."""
        self._stores.control.touch_heartbeat()

    def ack_scan_now(self, nonce: int) -> None:
        self._stores.control.set_values({"scan_now_applied": nonce})

    def ack_command(self, nonce: int, outcome: str) -> None:
        self._stores.control.set_values(
            {"command_applied": nonce, "command_result": outcome}
        )
