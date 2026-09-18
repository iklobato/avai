"""Orchestrator: drives collectors against the sink each cycle."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from avai.enrichers import EnrichmentChain

from .collectors import SnapshotCollector, StreamingCollector
from .constants import DEFAULT_BASELINE_MIN_RUNS, LOG
from .control_loop import ControlLoop, ControlSettings, ProgressHeartbeat
from .coverage import YaraCoverageAssessor
from .cycle_steps import (
    CoverageStep,
    CycleStep,
    NarrativeStep,
    RiskScoreStep,
    YaraStatusStep,
)
from .finding_stages import (
    BaselineStage,
    CorrelationStage,
    EvidenceStage,
    FindingBatch,
    FindingPipeline,
    FindingStage,
    HostBaseline,
    InvestigateStage,
    JudgeStage,
    ProcessBehavior,
    VerifyStage,
    YaraContextStage,
)
from .investigator import UnknownFindingInvestigator
from .judge import Judge, NullJudge
from .narrator import IncidentNarrator
from .runtime import Digest
from .sink import Sink
from .streaming import StreamingSupervisor
from .verifier import MaliciousVerdictVerifier

_BYTES_PER_MB = 1024 * 1024


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


@dataclass
class CollectionCycle:
    """One scan: collect every snapshot collector, judge what's new
    (snapshot and streaming), then write the end-of-cycle reports."""

    config: RunnerConfig
    settings: ControlSettings
    heartbeat: ProgressHeartbeat
    snapshot_pipeline: FindingPipeline
    streaming_pipeline: FindingPipeline
    steps: list[CycleStep]
    shutdown_event: threading.Event

    def run(self) -> tuple[str, int, int]:
        sink = self.config.sink
        # Refresh the control cache so --once and the daemon loop both honour
        # disabled-collector / judge / enrich toggles set from the dashboard.
        self.settings.refresh()
        # Apply operator corrections before judging so this cycle's narrative
        # and risk reflect the fixed verdicts.
        self._apply_feedback()
        run_id, started = sink.start_run(socket.gethostname(), self.config.lookback_min)
        self.heartbeat.reset()
        # Measured once: it can't change mid-cycle (the current run isn't
        # completed yet), and every collector shares the same cutoff.
        baseline = HostBaseline.measure(sink, self.config.baseline_min_runs)
        ok, failed = self._collect_all(run_id, started, baseline)
        # No point starting a fresh round of LLM calls on the way out.
        if not self.shutdown_event.is_set():
            self._judge_streaming(baseline)
            for step in self.steps:
                step.run(run_id, started)
        sink.end_run(ok, failed)
        self._rotate()
        return run_id, ok, failed

    def _collect_all(
        self, run_id: str, started: str, baseline: HostBaseline
    ) -> tuple[int, int]:
        disabled = self.settings.disabled_collectors()
        ok = failed = 0
        for c in self.config.snapshot_collectors:
            # The first cycle judges every collector via the LLM, which can
            # take minutes; checking here lets Ctrl-C take effect mid-cycle.
            if self.shutdown_event.is_set():
                LOG.info("shutdown requested, stopping collector loop early")
                break
            if c.name in disabled:
                continue
            self.heartbeat.beat()
            try:
                self._collect(c, run_id, started, baseline)
                ok += 1
            except Exception as exc:
                failed += 1
                self.config.sink.write_error(c.name, exc)
                LOG.warning(
                    "collector=%s status=failed error=%s message=%s",
                    c.name,
                    type(exc).__name__,
                    str(exc)[:200],
                )
        return ok, failed

    def _collect(
        self, c: SnapshotCollector, run_id: str, started: str, baseline: HostBaseline
    ) -> None:
        sink = self.config.sink
        t0 = time.monotonic()
        rows = list(c.collect())
        for r in rows:
            r["run_id"] = run_id
            r["collected_at"] = started
            r["content_hash"] = Digest.of_row(r, c.judge_fields)
        sink.write(c.model, rows)
        collected_ms = int((time.monotonic() - t0) * 1000)

        judged = enriched = 0
        if c.judge_enabled and c.judge_fields:
            judged, enriched = self._judge_snapshot(c, rows, run_id, baseline)
            # Runs even with judging off, so already-recorded findings keep
            # an accurate status: the dashboard derives active/resolved by
            # comparing last_seen_at to the latest run.
            observed = [r["content_hash"] for r in rows if r.get("content_hash")]
            if observed:
                sink.touch_judgments(c.name, observed, started)

        LOG.info(
            "collector=%s rows=%d duration_ms=%d judged=%d enriched=%d",
            c.name,
            len(rows),
            collected_ms,
            judged,
            enriched,
        )

    def _judge_snapshot(
        self,
        c: SnapshotCollector,
        rows: list[dict],
        run_id: str,
        baseline: HostBaseline,
    ) -> tuple[int, int]:
        """Returns (judgments written, indicators looked up)."""
        unjudged = self.config.sink.unjudged(c)
        if not unjudged or not self.settings.judge_on():
            return 0, 0
        batch = FindingBatch(c, unjudged, rows, run_id, baseline)
        self.snapshot_pipeline.run(batch)
        self.config.sink.write_judgments(batch.judgments, context=batch.context())
        return len(batch.judgments), batch.indicators_looked_up

    def _judge_streaming(self, baseline: HostBaseline) -> None:
        """Classify the content_hashes streaming collectors produced since the
        previous cycle. Streaming rows aren't tied to a CollectionRun, so
        ``unjudged_all`` finds them."""
        if not self.settings.judge_on():
            return
        # A disabled streaming collector keeps its worker running (workers
        # start once at boot) but is no longer judged.
        disabled = self.settings.disabled_collectors()
        for c in self.config.streaming_collectors:
            if not (c.judge_enabled and c.judge_fields) or c.name in disabled:
                continue
            try:
                unjudged = self.config.sink.unjudged_all(c)
            except Exception as exc:
                LOG.warning("streaming-judge: unjudged_all(%s) failed: %s", c.name, exc)
                continue
            if unjudged:
                self._judge_stream(FindingBatch(c, unjudged, [], None, baseline))

    def _judge_stream(self, batch: FindingBatch) -> None:
        name = batch.collector.name
        try:
            self.streaming_pipeline.run(batch)
            self.config.sink.write_judgments(batch.judgments, context=batch.context())
        except Exception:
            LOG.exception("streaming-judge failed for %s", name)
            return
        LOG.info("streaming-judge collector=%s judged=%d", name, len(batch.judgments))

    def _apply_feedback(self) -> None:
        try:
            applied = self.config.sink.apply_feedback()
        except Exception:
            LOG.exception("apply_feedback failed")
            return
        if applied:
            LOG.info("applied %d operator feedback correction(s)", applied)

    def _rotate(self) -> None:
        """Keep the DB under the size cap by pruning the oldest completed
        runs and their child rows."""
        cap = self.config.max_db_bytes
        if not cap:
            return
        stats = self.config.sink.prune_to_size(cap)
        if stats["runs_pruned"] or stats["events_pruned"]:
            LOG.info(
                "db_rotation: pruned runs=%d auth_events=%d  "
                "%.1fMB → %.1fMB (cap %.0fMB)",
                stats["runs_pruned"],
                stats["events_pruned"],
                stats["bytes_before"] / _BYTES_PER_MB,
                stats["bytes_after"] / _BYTES_PER_MB,
                cap / _BYTES_PER_MB,
            )


class Runner:
    """Coordinates the collection cycle, the control loop and the streaming
    workers. ``desktop.py`` and ``main.py`` only call the public methods."""

    def __init__(self, config: RunnerConfig):
        self.config = config
        self.shutdown_event = threading.Event()
        settings = ControlSettings(
            config.sink,
            judge_default=not isinstance(config.judge, NullJudge),
            enrich_default=config.enrichment_chain is not None,
        )
        heartbeat = ProgressHeartbeat(config.sink)
        self._cycle = CollectionCycle(
            config=config,
            settings=settings,
            heartbeat=heartbeat,
            snapshot_pipeline=FindingPipeline(
                _snapshot_stages(config, settings, heartbeat)
            ),
            streaming_pipeline=FindingPipeline(_streaming_stages(config)),
            steps=_cycle_steps(config),
            shutdown_event=self.shutdown_event,
        )
        self._control = ControlLoop(
            config.sink,
            settings,
            self.run_once,
            config.max_db_bytes,
            self.shutdown_event,
        )
        self._streaming = StreamingSupervisor(config.sink, config.streaming_collectors)

    def request_shutdown(self) -> None:
        """Idempotent: safe to call from a signal handler."""
        self.shutdown_event.set()

    def setup(self) -> None:
        self.config.sink.setup()

    def start_streaming(self) -> None:
        self._streaming.start()

    def stop_streaming(self) -> None:
        self._streaming.stop()

    def run_once(self) -> tuple[str, int, int]:
        return self._cycle.run()

    def run_forever(self, interval: int) -> None:
        self._control.run_forever(interval)


def _snapshot_stages(
    config: RunnerConfig, settings: ControlSettings, heartbeat: ProgressHeartbeat
) -> list[FindingStage]:
    sink = config.sink
    behavior = ProcessBehavior(sink)
    stages: list[FindingStage] = []
    if config.enrichment_chain is not None:
        stages.append(EvidenceStage(config.enrichment_chain, settings, heartbeat))
    stages += [
        BaselineStage(sink),
        CorrelationStage(sink, behavior),
        YaraContextStage(),
        JudgeStage(config.judge, sink),
    ]
    if config.verifier is not None:
        stages.append(VerifyStage(config.verifier))
    if config.investigator is not None:
        stages.append(InvestigateStage(config.investigator, sink, behavior))
    return stages


def _streaming_stages(config: RunnerConfig) -> list[FindingStage]:
    stages: list[FindingStage] = [
        BaselineStage(config.sink),
        JudgeStage(config.judge, config.sink),
    ]
    if config.verifier is not None:
        stages.append(VerifyStage(config.verifier))
    return stages


def _cycle_steps(config: RunnerConfig) -> list[CycleStep]:
    sink = config.sink
    steps: list[CycleStep] = []
    # Runs after touch_judgments, so the active-finding set is current.
    if config.narrator is not None:
        steps.append(NarrativeStep(sink, config.narrator))
    steps += [RiskScoreStep(sink), YaraStatusStep(sink, config.snapshot_collectors)]
    if config.coverage is not None:
        steps.append(CoverageStep(sink, config.coverage))
    return steps
