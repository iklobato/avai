"""Orchestrator: drives collectors against the sink each cycle."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from avai.enrichers import EnrichmentChain, IndicatorExtraction

from .collectors import SnapshotCollector, StreamingCollector
from .constants import DEFAULT_BASELINE_MIN_RUNS, LOGGER_NAME
from .control_loop import (
    ControlDefaults,
    ControlLoop,
    ControlPlane,
    ControlSettings,
    CycleSettings,
    ProgressHeartbeat,
)
from .coverage import YaraCoverageAssessor
from .cycle_steps import (
    CoverageStep,
    CycleStep,
    NarrativeStep,
    RiskScoreStep,
    YaraStatusStep,
)
from .failures import HOST_FAILURES
from .finding_stages import (
    BaselineStage,
    BatchOrigin,
    CorrelationStage,
    EvidenceStage,
    FindingBatch,
    FindingPipeline,
    FindingStage,
    HostBaseline,
    InvestigateStage,
    JudgeStage,
    ProcessBehavior,
    ThreatIntel,
    VerifyStage,
    YaraContextStage,
)
from .investigator import UnknownFindingInvestigator
from .judge import Judge, NullJudge
from .narrator import IncidentNarrator
from .runtime import Clock, Digest, HostIdentity
from .sink import Sink
from .step_io import StepIO
from .streaming import StreamChannel, StreamingSupervisor, SupervisionPolicy
from .verifier import MaliciousVerdictVerifier

BYTES_PER_MB = 1024 * 1024
MS_PER_SECOND = 1000
ERROR_EXCERPT_CHARS = 200


class HostMonitorLog:
    """Builds the logger every host_monitor component writes to."""

    @classmethod
    def logger(cls) -> logging.Logger:
        return logging.getLogger(LOGGER_NAME)


@dataclass(frozen=True)
class RunnerConfig:
    """Everything the monitor runs with. The optional LLM stages are None
    when disabled; so is the enrichment chain."""

    sink: Sink
    snapshot_collectors: list[SnapshotCollector]
    streaming_collectors: list[StreamingCollector]
    judge: Judge
    lookback_min: int
    max_db_bytes: int = 0  # 0 = unlimited
    enrichment_chain: Optional[EnrichmentChain] = None
    baseline_min_runs: int = DEFAULT_BASELINE_MIN_RUNS
    narrator: Optional[IncidentNarrator] = None
    coverage: Optional[YaraCoverageAssessor] = None
    verifier: Optional[MaliciousVerdictVerifier] = None
    investigator: Optional[UnknownFindingInvestigator] = None
    logger: logging.Logger = field(default_factory=HostMonitorLog.logger)
    clock: Clock = field(default_factory=Clock)
    identity: HostIdentity = field(default_factory=HostIdentity.current)


@dataclass(frozen=True)
class CycleStamp:
    """What every collector in one cycle shares."""

    run_id: str
    started: str
    baseline: HostBaseline
    settings: CycleSettings


@dataclass(frozen=True)
class CyclePlan:
    """The judging pipelines and end-of-cycle reports one cycle runs."""

    snapshot_pipeline: FindingPipeline
    streaming_pipeline: FindingPipeline
    steps: tuple[CycleStep, ...]


@dataclass(frozen=True)
class CycleControls:
    settings: ControlSettings
    heartbeat: ProgressHeartbeat
    shutdown_event: threading.Event


@dataclass(frozen=True)
class CollectionCycle:
    """One scan: collect every snapshot collector, judge what's new
    (snapshot and streaming), then write the end-of-cycle reports."""

    config: RunnerConfig
    controls: CycleControls
    plan: CyclePlan

    @property
    def _log(self) -> logging.Logger:
        return self.config.logger

    def scan(self) -> tuple[str, int, int]:
        sink = self.config.sink
        # Refresh toggles set from the dashboard, then apply operator
        # corrections so this cycle's narrative and risk see fixed verdicts.
        settings = self.controls.settings.current()
        self._apply_feedback()
        hostname = self.config.identity.hostname
        run_id, started = sink.start_run(hostname, self.config.lookback_min)
        self.controls.heartbeat.reset()
        # Measured once: it can't change mid-cycle, and every collector shares
        # the same cutoff.
        baseline = HostBaseline.measure(sink, self.config.baseline_min_runs)
        stamp = CycleStamp(run_id, started, baseline, settings)
        ok, failed = self._collect_all(stamp)
        # No point starting a fresh round of LLM calls on the way out.
        if not self.controls.shutdown_event.is_set():
            self._report(stamp)
        sink.end_run(run_id, ok, failed)
        self._rotate()
        return run_id, ok, failed

    def _report(self, stamp: CycleStamp) -> None:
        self._judge_streaming(stamp)
        for step in self.plan.steps:
            step.report(stamp.run_id, stamp.started)

    def _collect_all(self, stamp: CycleStamp) -> tuple[int, int]:
        disabled = stamp.settings.disabled_collectors()
        ok = failed = 0
        for collector in self.config.snapshot_collectors:
            # The first cycle judges every collector via the LLM, which can
            # take minutes; checking here lets Ctrl-C take effect mid-cycle.
            if self.controls.shutdown_event.is_set():
                self._log.info("shutdown requested, stopping collector loop early")
                break
            if collector.name in disabled:
                continue
            self.controls.heartbeat.beat()
            succeeded = self._collect_guarded(collector, stamp)
            ok, failed = ok + int(succeeded), failed + int(not succeeded)
        return ok, failed

    def _collect_guarded(self, collector: SnapshotCollector, stamp: CycleStamp) -> bool:
        try:
            self._collect(collector, stamp)
        except HOST_FAILURES as exc:
            self.config.sink.write_error(stamp.run_id, collector.name, exc)
            self._log.warning(
                "collector=%s status=failed error=%s message=%s",
                collector.name,
                type(exc).__name__,
                str(exc)[:ERROR_EXCERPT_CHARS],
            )
            return False
        return True

    def _collect(self, collector: SnapshotCollector, stamp: CycleStamp) -> None:
        clock = self.config.clock
        started_at = clock.monotonic()
        rows = self._stamped_rows(collector, stamp)
        self.config.sink.write(collector.model, rows)
        collected_ms = int((clock.monotonic() - started_at) * MS_PER_SECOND)
        judged, enriched = self._judge_rows(collector, rows, stamp)
        self._log.info(
            "collector=%s rows=%d duration_ms=%d judged=%d enriched=%d",
            collector.name,
            len(rows),
            collected_ms,
            judged,
            enriched,
        )

    def _stamped_rows(
        self, collector: SnapshotCollector, stamp: CycleStamp
    ) -> list[dict[str, Any]]:
        rows = list(collector.collect())
        for row in rows:
            row["run_id"] = stamp.run_id
            row["collected_at"] = stamp.started
            row["content_hash"] = Digest().of_row(row, collector.judge_fields)
        return rows

    def _judge_rows(
        self,
        collector: SnapshotCollector,
        rows: list[dict[str, Any]],
        stamp: CycleStamp,
    ) -> tuple[int, int]:
        """Returns (judgments written, indicators looked up)."""
        if not (collector.judge_enabled and collector.judge_fields):
            return 0, 0
        counts = self._judge_snapshot(collector, rows, stamp)
        # Runs even with judging off, so already-recorded findings keep an
        # accurate status: the dashboard derives active/resolved by comparing
        # last_seen_at to the latest run.
        observed = [row["content_hash"] for row in rows if row.get("content_hash")]
        if observed:
            self.config.sink.touch_judgments(collector.name, observed, stamp.started)
        return counts

    def _judge_snapshot(
        self,
        collector: SnapshotCollector,
        rows: list[dict[str, Any]],
        stamp: CycleStamp,
    ) -> tuple[int, int]:
        unjudged = self.config.sink.unjudged(stamp.run_id, collector)
        if not unjudged or not stamp.settings.judge_on():
            return 0, 0
        origin = BatchOrigin(rows, stamp.run_id, stamp.baseline, stamp.settings)
        pending = FindingBatch(collector, unjudged, origin)
        batch = self.plan.snapshot_pipeline.process(pending)
        self.config.sink.write_judgments(batch.judgments, context=batch.context())
        return len(batch.judgments), batch.indicators_looked_up

    def _judge_streaming(self, stamp: CycleStamp) -> None:
        """Classify the content_hashes streaming collectors produced since the
        previous cycle. Streaming rows aren't tied to a CollectionRun, so
        ``unjudged_all`` finds them."""
        if not stamp.settings.judge_on():
            return
        origin = BatchOrigin([], None, stamp.baseline, stamp.settings)
        for collector in self._judged_streams(stamp.settings):
            unjudged = self._unjudged_stream(collector)
            if unjudged:
                self._judge_stream(FindingBatch(collector, unjudged, origin))

    def _judged_streams(self, settings: CycleSettings) -> list[StreamingCollector]:
        # A disabled streaming collector keeps its worker running (workers
        # start once at boot) but is no longer judged.
        disabled = settings.disabled_collectors()
        return [
            collector
            for collector in self.config.streaming_collectors
            if collector.judge_enabled
            and collector.judge_fields
            and collector.name not in disabled
        ]

    def _unjudged_stream(self, collector: StreamingCollector) -> list[dict[str, Any]]:
        try:
            return self.config.sink.unjudged_all(collector)
        except HOST_FAILURES as exc:
            self._log.warning(
                "streaming-judge: unjudged_all(%s) failed: %s", collector.name, exc
            )
            return []

    def _judge_stream(self, batch: FindingBatch) -> None:
        name = batch.collector.name
        try:
            judged = self.plan.streaming_pipeline.process(batch)
            self.config.sink.write_judgments(judged.judgments, context=judged.context())
        except HOST_FAILURES:
            self._log.exception("streaming-judge failed for %s", name)
            return
        self._log.info(
            "streaming-judge collector=%s judged=%d", name, len(judged.judgments)
        )

    def _apply_feedback(self) -> None:
        try:
            applied = self.config.sink.apply_feedback()
        except HOST_FAILURES:
            self._log.exception("apply_feedback failed")
            return
        if applied:
            self._log.info("applied %d operator feedback correction(s)", applied)

    def _rotate(self) -> None:
        """Keep the DB under the size cap by pruning the oldest completed
        runs and their child rows."""
        cap = self.config.max_db_bytes
        if not cap:
            return
        stats = self.config.sink.prune_to_size(cap)
        if stats["runs_pruned"] or stats["events_pruned"]:
            self._log.info(
                "db_rotation: pruned runs=%d streaming_events=%d  "
                "%.1fMB → %.1fMB (cap %.0fMB)",
                stats["runs_pruned"],
                stats["events_pruned"],
                stats["bytes_before"] / BYTES_PER_MB,
                stats["bytes_after"] / BYTES_PER_MB,
                cap / BYTES_PER_MB,
            )


class CyclePlanner:
    """Assembles the finding stages and cycle steps the config turns on."""

    def __init__(self, config: RunnerConfig) -> None:
        self._config = config

    def plan(self, heartbeat: ProgressHeartbeat) -> CyclePlan:
        return CyclePlan(
            FindingPipeline(self._snapshot_stages(heartbeat)),
            FindingPipeline(self._streaming_stages()),
            tuple(self._cycle_steps()),
        )

    def _snapshot_stages(self, heartbeat: ProgressHeartbeat) -> list[FindingStage]:
        config, io = self._config, self._io()
        behavior = ProcessBehavior(io)
        stages: list[FindingStage] = []
        if config.enrichment_chain is not None:
            intel = ThreatIntel(config.enrichment_chain, IndicatorExtraction.default())
            stages.append(EvidenceStage(intel, heartbeat))
        stages += [
            BaselineStage(io),
            CorrelationStage(io, behavior),
            YaraContextStage(),
            JudgeStage(config.judge, io),
        ]
        stages += self._verify_stages()
        if config.investigator is not None:
            stages.append(InvestigateStage(config.investigator, io, behavior))
        return stages

    def _streaming_stages(self) -> list[FindingStage]:
        io = self._io()
        stages: list[FindingStage] = [
            BaselineStage(io),
            JudgeStage(self._config.judge, io),
        ]
        return stages + self._verify_stages()

    def _verify_stages(self) -> list[FindingStage]:
        verifier = self._config.verifier
        if verifier is None:
            return []
        return [VerifyStage(verifier, self._config.logger)]

    def _io(self) -> StepIO:
        return StepIO(self._config.sink, self._config.logger, self._config.clock)

    def _cycle_steps(self) -> list[CycleStep]:
        config = self._config
        io = self._io()
        steps: list[CycleStep] = []
        # Runs after touch_judgments, so the active-finding set is current.
        if config.narrator is not None:
            steps.append(NarrativeStep(io, config.narrator))
        steps += [RiskScoreStep(io), YaraStatusStep(io, config.snapshot_collectors)]
        if config.coverage is not None:
            steps.append(CoverageStep(io, config.coverage, config.identity))
        return steps


@dataclass(frozen=True)
class RunnerParts:
    cycle: CollectionCycle
    control: ControlLoop
    streaming: StreamingSupervisor


class Runner:
    """Coordinates the collection cycle, the control loop and the streaming
    workers. ``desktop.py`` and ``main.py`` only call the public methods."""

    def __init__(self, config: RunnerConfig, parts: RunnerParts) -> None:
        self.config = config
        self._parts = parts

    @classmethod
    def create(cls, config: RunnerConfig) -> Runner:
        sink = config.sink
        defaults = ControlDefaults(
            judge=not isinstance(config.judge, NullJudge),
            enrich=config.enrichment_chain is not None,
            verify=config.verifier is not None,
            investigate=config.investigator is not None,
        )
        settings = ControlSettings(sink, defaults)
        heartbeat = ProgressHeartbeat(sink, config.logger, config.clock)
        controls = CycleControls(settings, heartbeat, threading.Event())
        cycle = CollectionCycle(config, controls, CyclePlanner(config).plan(heartbeat))
        plane = cls._control_plane(config, controls.shutdown_event)
        control = ControlLoop(plane, settings, cycle.scan)
        return cls(config, RunnerParts(cycle, control, cls._streaming(config)))

    @classmethod
    def _control_plane(
        cls, config: RunnerConfig, shutdown_event: threading.Event
    ) -> ControlPlane:
        return ControlPlane(
            config.sink,
            shutdown_event,
            config.logger,
            config.max_db_bytes,
            clock=config.clock,
            identity=config.identity,
        )

    @classmethod
    def _streaming(cls, config: RunnerConfig) -> StreamingSupervisor:
        channel = StreamChannel(config.sink, config.identity.hostname, config.clock)
        policy = SupervisionPolicy.standard(config.logger)
        return StreamingSupervisor(channel, config.streaming_collectors, policy)

    @property
    def shutdown_event(self) -> threading.Event:
        return self._parts.cycle.controls.shutdown_event

    def request_shutdown(self) -> None:
        """Idempotent: safe to call from a signal handler."""
        self.shutdown_event.set()

    def setup(self) -> None:
        self.config.sink.setup()

    def start_streaming(self) -> None:
        self._parts.streaming.start()

    def stop_streaming(self) -> None:
        self._parts.streaming.stop()

    def run_once(self) -> tuple[str, int, int]:
        return self._parts.cycle.scan()

    def run_forever(self, interval: int) -> None:
        self._parts.control.run_forever(interval)
