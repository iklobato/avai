"""The per-collector finding pipeline: context stages add signals to each
unjudged entry, the judge classifies, and second-opinion stages revise the
verdicts. Each entry key (``evidence``, ``baseline``, ``related``,
``rule_meta``, ``matched_strings``) is written by exactly one stage."""

from __future__ import annotations

import bisect
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any, Protocol

from avai.enrichers import EnrichmentChain, IndicatorExtraction

from .collectors import Collector
from .control_loop import ControlSettings, ProgressHeartbeat
from .enums import BehaviorKind, FeedbackLabel, Verdict
from .failures import HOST_FAILURES
from .investigator import UnknownFindingInvestigator
from .judge import Judge, Judgment
from .sink import Sink
from .sink_stores import CorrelationWindow
from .slices import Slices
from .step_io import StepIO
from .verifier import MaliciousVerdictVerifier

# Minimum presence window (runs since first seen) before an artifact that
# misses runs is called "intermittent"; below this it's just freshly seen.
MIN_DRIFT_WINDOW = 3

# Bound second-pass LLM work per collector per cycle so a pathological batch
# can't fan out into unbounded verify / investigate calls.
MAX_VERIFY_PER_COLLECTOR = 10
MAX_INVESTIGATE_PER_COLLECTOR = 10

# How many of the host's other non-benign findings to hand the investigator
# as situational context.
HOST_CONTEXT_LIMIT = 15

# Per-kind caps on the behaviour attached to one artifact.
MAX_RELATED = 10
MAX_RELATED_DNS = 15

REASONING_CHARS = 500
LOGGED_REASON_CHARS = 120

# Only processes and launch items carry behaviour to correlate.
CORRELATED_COLLECTORS = (Slices.PROCESSES.name, Slices.LAUNCH_ITEMS.name)

# How an operator-feedback label reads in the ground-truth block fed to the
# judge, keyed by the raw stored label.
FEEDBACK_PHRASES = (
    (FeedbackLabel.FALSE_POSITIVE.value, "a FALSE POSITIVE (benign)"),
    (FeedbackLabel.CONFIRMED.value, "CONFIRMED malicious"),
)


@dataclass(frozen=True)
class HostBaseline:
    """How 'learned' this host is, measured once per cycle.

    ``established`` flips on after ``min_runs`` completed runs; ``cutoff_at``
    is the run timestamp that ends the learning window. An artifact first
    seen after the cutoff showed up on an already-baselined host: that's the
    novelty signal fed to the judge."""

    total_runs: int
    established: bool
    cutoff_at: str | None

    @classmethod
    def measure(cls, sink: Sink, min_runs: int) -> HostBaseline:
        total = sink.completed_run_count()
        established = total >= min_runs
        cutoff = sink.nth_run_started_at(min_runs) if established else None
        return cls(total_runs=total, established=established, cutoff_at=cutoff)

    def is_novel(self, first_seen: str) -> bool:
        return bool(
            self.established
            and self.cutoff_at is not None
            and first_seen > self.cutoff_at
        )


@dataclass(frozen=True)
class BatchOrigin:
    """Where a batch came from. ``rows`` are the collector's raw rows this
    cycle (empty for streaming), richer than the unjudged projection;
    ``run_id`` is None for streaming."""

    rows: list[dict[str, Any]]
    run_id: str | None
    baseline: HostBaseline


class FindingBatch:
    """One collector's unjudged entries on their way to a verdict. Stages
    add keys to the entries and replace ``judgments``."""

    def __init__(
        self, collector: Collector, entries: list[dict[str, Any]], origin: BatchOrigin
    ) -> None:
        self.collector = collector
        self.entries = entries
        self.origin = origin
        self.judgments: list[Judgment] = []
        self.indicators_looked_up = 0

    @property
    def rows(self) -> list[dict[str, Any]]:
        return self.origin.rows

    @property
    def run_id(self) -> str | None:
        return self.origin.run_id

    @property
    def baseline(self) -> HostBaseline:
        return self.origin.baseline

    def rows_by_hash(self) -> dict[str, dict[str, Any]]:
        """The first row that produced each content_hash."""
        by_hash: dict[str, dict[str, Any]] = {}
        for row in self.rows:
            content_hash = row.get("content_hash")
            if isinstance(content_hash, str) and content_hash:
                by_hash.setdefault(content_hash, row)
        return by_hash

    def entries_by_hash(self) -> dict[str, dict[str, Any]]:
        return {
            entry["content_hash"]: entry
            for entry in self.entries
            if entry.get("content_hash")
        }

    def context(self) -> dict[str, dict[str, Any]]:
        """The per-hash ``baseline`` + ``related`` signals, persisted with the
        verdict so the dashboard can show novelty and the process story."""
        signals = {
            entry.get("content_hash"): {
                key: entry[key] for key in ("baseline", "related") if entry.get(key)
            }
            for entry in self.entries
        }
        return {
            content_hash: parts
            for content_hash, parts in signals.items()
            if content_hash and parts
        }


class FindingStage(Protocol):
    def apply(self, batch: FindingBatch) -> None: ...


class FindingPipeline:
    """Runs its stages in order. The order is decided where the pipeline is
    built, so adding a stage never edits the cycle."""

    def __init__(self, stages: list[FindingStage]) -> None:
        self._stages = stages

    def process(self, batch: FindingBatch) -> None:
        for stage in self._stages:
            stage.apply(batch)


@dataclass(frozen=True)
class ThreatIntel:
    """Turns a collector row into indicators and looks each one up."""

    chain: EnrichmentChain
    extraction: IndicatorExtraction


class EvidenceStage:
    """Attach external threat-intel evidence to each entry as ``evidence``.

    Indicators come from the collector's rows (richer than the unjudged
    projection), mapped by content_hash so an entry's evidence is derived
    from one of the rows that produced it."""

    EVIDENCE_PRECISION = 2

    def __init__(
        self,
        intel: ThreatIntel,
        settings: ControlSettings,
        heartbeat: ProgressHeartbeat,
    ) -> None:
        self._intel = intel
        self._settings = settings
        self._heartbeat = heartbeat

    def apply(self, batch: FindingBatch) -> None:
        if not self._settings.enrich_on():
            return
        rows_by_hash = batch.rows_by_hash()
        for entry in batch.entries:
            # Each indicator is a serial, rate-limited HTTP call; keep proving
            # liveness to the dashboard as we go.
            self._heartbeat.beat()
            row = rows_by_hash.get(entry.get("content_hash"))
            evidence = [] if row is None else list(self._evidence(batch, row))
            if evidence:
                entry["evidence"] = evidence

    def _evidence(
        self, batch: FindingBatch, row: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        for indicator in self._intel.extraction.extract(batch.collector.name, row):
            batch.indicators_looked_up += 1
            yield from (
                {
                    "src": found.source,
                    "type": str(indicator.type),
                    "value": indicator.value,
                    "hint": str(found.verdict_hint),
                    "confidence": round(found.confidence, self.EVIDENCE_PRECISION),
                    "note": found.summary,
                }
                for found in self._intel.chain.enrich(indicator)
            )


class PresenceWindow:
    """Sizes one artifact's presence against every run start (including the
    in-progress run). An artifact present in fewer runs than have happened
    since it first appeared has come and gone: a sharper drift signal than
    novelty."""

    def __init__(self, timeline: list[str], host: HostBaseline) -> None:
        self._timeline = timeline
        self._host = host

    def describe(self, first_seen: str, times_seen: int) -> dict[str, Any]:
        timeline = self._timeline
        window = len(timeline) - bisect.bisect_left(timeline, first_seen)
        # Needs a few runs of window to tell flapping from freshly seen.
        intermittent = window >= MIN_DRIFT_WINDOW and times_seen < window
        return {
            "first_seen": first_seen,
            "times_seen": times_seen,
            "host_runs": self._host.total_runs,
            "baseline_established": self._host.established,
            "novel": self._host.is_novel(first_seen),
            "intermittent": intermittent,
        }


class BaselineStage:
    """Attach a ``baseline`` object so the judge weighs novelty against this
    host's learned normal instead of classifying every artifact in the
    absolute.

    ``first_seen`` comes from the rows table, not from when the artifact was
    first *judged*: the per-collector judge cap defers some entries across
    cycles, but an artifact present since run 1 still reads first_seen=run 1
    and is never mislabelled novel just because the judge got to it late."""

    def __init__(self, io: StepIO) -> None:
        self._io = io

    def apply(self, batch: FindingBatch) -> None:
        collector, sink = batch.collector, self._io.sink
        if not batch.entries or not collector.judge_fields:
            return
        hashes = list(batch.entries_by_hash())
        first_seen = self._io.read(
            f"baseline: first_seen_map({collector.name})",
            lambda: sink.first_seen_map(collector.model, hashes),
        )
        if first_seen is None:
            return
        timeline = self._io.read("baseline: run timeline fetch", sink.run_started_ats)
        presence = PresenceWindow(timeline or [], batch.baseline)
        for entry in batch.entries:
            seen = first_seen.get(entry.get("content_hash"))
            if seen is not None:
                entry["baseline"] = presence.describe(*seen)


@dataclass(frozen=True)
class ProcessLinks:
    """content_hash to the PIDs and process names an artifact ran as."""

    pids_by_hash: dict[str, set[int]]
    names_by_hash: dict[str, set[str]]

    def all_pids(self) -> list[int]:
        return sorted({pid for pids in self.pids_by_hash.values() for pid in pids})

    def all_names(self) -> list[str]:
        return sorted({name for names in self.names_by_hash.values() for name in names})

    def pids(self, content_hash: str | None) -> set[int]:
        return self.pids_by_hash.get(content_hash or "", set())

    def names(self, content_hash: str | None) -> set[str]:
        return self.names_by_hash.get(content_hash or "", set())


class BehaviorSummary:
    """The ``related`` behaviour object for one artifact, read from a
    correlation context and bounded per kind."""

    def __init__(self, context: dict[str, Any]) -> None:
        self._context = context

    def related(self, links: ProcessLinks, content_hash: str | None) -> dict[str, Any]:
        pids, names = links.pids(content_hash), links.names(content_hash)
        kinds = (
            ("listening_ports", self._by_pid(BehaviorKind.PORTS, pids)[:MAX_RELATED]),
            ("outbound_flows", self._by_pid(BehaviorKind.FLOWS, pids)[:MAX_RELATED]),
            (
                "remote_connections",
                self._by_pid(BehaviorKind.CONNS, pids)[:MAX_RELATED],
            ),
            ("dns_queries", self._by_name(names)[:MAX_RELATED_DNS]),
        )
        related: dict[str, Any] = {key: values for key, values in kinds if values}
        lineage = self._lineage(pids)
        if lineage is not None:
            related["exec_lineage"] = lineage
        return related

    def _lineage(self, pids: set[int]) -> Any | None:
        """The exec record of the first PID that has one."""
        execs = self._context[BehaviorKind.EXEC]
        found = [execs[pid] for pid in pids if pid in execs]
        return found[0] if found else None

    def _by_pid(self, kind: BehaviorKind, pids: set[int]) -> list[Any]:
        return [item for pid in pids for item in self._context[kind].get(pid, [])]

    def _by_name(self, names: set[str]) -> list[Any]:
        return [
            item
            for name in names
            for item in self._context[BehaviorKind.DNS].get(name, [])
        ]


class ProcessBehavior:
    """Resolves the PIDs and process names an artifact ran as."""

    def __init__(self, io: StepIO) -> None:
        self._io = io

    def links(
        self, collector_name: str, rows: list[dict[str, Any]], since: str | None
    ) -> ProcessLinks:
        """The links for a correlatable collector, or empty ones for anything
        else."""
        if collector_name == Slices.PROCESSES.name:
            return self._from_processes(rows)
        if collector_name == Slices.LAUNCH_ITEMS.name:
            return self._from_launch_items(rows, since)
        return ProcessLinks({}, {})

    def _from_processes(self, rows: list[dict[str, Any]]) -> ProcessLinks:
        pids: dict[str, set[int]] = {}
        names: dict[str, set[str]] = {}
        for row in rows:
            content_hash = row.get("content_hash")
            if not isinstance(content_hash, str) or not content_hash:
                continue
            if row.get("pid") is not None:
                pids.setdefault(content_hash, set()).add(row["pid"])
            if row.get("name"):
                names.setdefault(content_hash, set()).add(row["name"])
        return ProcessLinks(pids, names)

    def _from_launch_items(
        self, rows: list[dict[str, Any]], since: str | None
    ) -> ProcessLinks:
        """A launch item has no PID: resolve its ``program`` to the live
        process(es) running it, so a persistence entry is judged with the
        behaviour of what it spawns. Names carry the program basename so
        DNS-by-process-name correlation still applies."""
        programs = self._programs(rows)
        running = self._running(programs, since)
        pids = {
            content_hash: {pid for program in found for pid in running.get(program, ())}
            for content_hash, found in programs.items()
        }
        names = {
            content_hash: {program.rsplit("/", 1)[-1] for program in found}
            for content_hash, found in programs.items()
        }
        return ProcessLinks({key: value for key, value in pids.items() if value}, names)

    def _running(
        self, programs: dict[str, set[str]], since: str | None
    ) -> dict[str, list[int]]:
        everything = sorted(
            {program for found in programs.values() for program in found}
        )
        pids_for_exe = self._io.read(
            "correlation: pids_by_executable",
            lambda: self._io.sink.pids_by_executable(everything, since),
        )
        return pids_for_exe or {}

    def _programs(self, rows: list[dict[str, Any]]) -> dict[str, set[str]]:
        programs: dict[str, set[str]] = {}
        for row in rows:
            content_hash, program = row.get("content_hash"), row.get("program")
            if (
                isinstance(content_hash, str)
                and content_hash
                and isinstance(program, str)
                and program
            ):
                programs.setdefault(content_hash, set()).add(program)
        return programs


class CorrelationStage:
    """Attach a ``related`` object: the artifact's behaviour since the
    previous cycle, correlated by PID (DNS by process name), so the judge
    scores it *with* its behaviour. A novel binary that is also beaconing to
    a flagged IP is a far stronger signal than either row alone. Only
    processes and launch items are correlated; other collectors keep their
    own independent verdicts."""

    def __init__(self, io: StepIO, behavior: ProcessBehavior) -> None:
        self._io = io
        self._behavior = behavior

    def apply(self, batch: FindingBatch) -> None:
        name = batch.collector.name
        if not batch.entries or name not in CORRELATED_COLLECTORS:
            return
        try:
            # None is a valid answer here (no previous run), so this read is
            # guarded by hand instead of through StepIO.read.
            since = self._io.sink.prior_run_started_at(batch.run_id)
        except HOST_FAILURES as exc:
            self._io.logger.warning("correlation: prior_run(%s) failed: %s", name, exc)
            return
        self._correlate(batch, since)

    def _correlate(self, batch: FindingBatch, since: str | None) -> None:
        name = batch.collector.name
        links = self._behavior.links(name, batch.rows, since)
        pids, names = links.all_pids(), links.all_names()
        if not pids and not names:
            return
        context = self._io.read(
            f"correlation: context({name})",
            lambda: self._io.sink.correlation_context(
                pids, names, CorrelationWindow(since)
            ),
        )
        if context is None:
            return
        summary = BehaviorSummary(context)
        for entry in batch.entries:
            related = summary.related(links, entry.get("content_hash"))
            if related:
                entry["related"] = related


class JsonColumn:
    """A malformed JSON column must not break the judge wiring."""

    def parse(self, raw: object) -> Any | None:
        if not isinstance(raw, str) or not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None


class YaraContextStage:
    """Attach the matched rule's metadata (``rule_meta``) and a redacted
    sample of the matched bytes (``matched_strings``) to each file-scan
    entry, so the judge can triage false positives and attribute the rule.
    Both live on the rows but not in ``judge_fields``, so they don't affect
    the content_hash."""

    def apply(self, batch: FindingBatch) -> None:
        if batch.collector.name != Slices.FILE_SCAN.name or not batch.entries:
            return
        rows_by_hash = batch.rows_by_hash()
        for entry in batch.entries:
            row = rows_by_hash.get(entry.get("content_hash"))
            if row is not None:
                self._attach(entry, row)

    def _attach(self, entry: dict[str, Any], row: dict[str, Any]) -> None:
        meta = JsonColumn().parse(row.get("meta_json"))
        if isinstance(meta, dict) and meta:
            entry["rule_meta"] = meta
        strings = JsonColumn().parse(row.get("strings_json"))
        if isinstance(strings, list) and strings:
            entry["matched_strings"] = strings


class JudgeStage:
    """Classify the entries, with this host's operator feedback for the
    collector appended to the static hints as ground truth."""

    GROUND_TRUTH = (
        "\nOperator feedback for this host (ground truth: apply the same "
        "judgement to these and closely-matching artifacts):\n"
    )

    def __init__(self, judge: Judge, io: StepIO) -> None:
        self._judge = judge
        self._io = io

    def apply(self, batch: FindingBatch) -> None:
        collector = batch.collector
        hints = self._hints(collector.name, collector.judge_hints)
        batch.judgments = self._judge.judge(collector.name, hints, batch.entries)

    def _hints(self, collector_name: str, base_hints: str) -> str:
        examples = self._io.read(
            f"feedback_examples({collector_name})",
            lambda: self._io.sink.feedback_examples(collector_name),
        )
        if not examples:
            return base_hints
        lines = [self._line(example) for example in examples]
        return base_hints + self.GROUND_TRUTH + "\n".join(lines)

    def _line(self, example: dict[str, Any]) -> str:
        artifact = (example.get("artifact") or "").strip() or "(unnamed artifact)"
        label = example.get("label")
        phrase = dict(FEEDBACK_PHRASES).get(label, label)
        note = f" note: {example['note']}" if example.get("note") else ""
        return f'- "{artifact}" was marked {phrase} by the operator.{note}'


class VerifyStage:
    """Re-check each ``malicious`` verdict with an independent skeptic; a
    refuted one is downgraded to ``suspicious`` (still flagged for review,
    not asserted as an active threat)."""

    def __init__(
        self, verifier: MaliciousVerdictVerifier, logger: logging.Logger
    ) -> None:
        self._verifier = verifier
        self._logger = logger

    def apply(self, batch: FindingBatch) -> None:
        malicious = [
            index
            for index, judgment in enumerate(batch.judgments)
            if judgment.verdict == Verdict.MALICIOUS
        ][:MAX_VERIFY_PER_COLLECTOR]
        if not malicious:
            return
        entries = batch.entries_by_hash()
        revised = list(batch.judgments)
        for index in malicious:
            revised[index] = self._verify(batch.collector.name, revised[index], entries)
        batch.judgments = revised

    def _verify(
        self, collector: str, judgment: Judgment, entries: dict[str, dict[str, Any]]
    ) -> Judgment:
        entry = entries.get(judgment.content_hash, {})
        verdict = self._verifier.verify(self._finding(collector, judgment, entry))
        if not (verdict and verdict["refuted"]):
            return judgment
        reason = verdict["reasoning"]
        self._logger.info(
            "verifier downgraded collector=%s reason=%s",
            collector,
            reason[:LOGGED_REASON_CHARS],
        )
        note = f"[verifier downgraded malicious→suspicious] {reason} · original: {judgment.reasoning}"
        return replace(
            judgment, verdict=Verdict.SUSPICIOUS, reasoning=note[:REASONING_CHARS]
        )

    def _finding(
        self, collector: str, judgment: Judgment, entry: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "collector": collector,
            "verdict": str(judgment.verdict),
            "category": str(judgment.category),
            "reasoning": judgment.reasoning,
            **{key: value for key, value in entry.items() if key != "content_hash"},
        }


@dataclass(frozen=True)
class InvestigationBundle:
    """The context shared by every investigation in one batch, gathered once."""

    entries: dict[str, dict[str, Any]]
    links: ProcessLinks
    history: dict[str, Any]
    host_findings: list[dict[str, Any]]

    @classmethod
    def gather(
        cls, io: StepIO, behavior: ProcessBehavior, batch: FindingBatch
    ) -> InvestigationBundle:
        # Full history: since=None drops the previous-cycle time bound.
        links = behavior.links(batch.collector.name, batch.rows, None)
        pids, names = links.all_pids(), links.all_names()
        history = io.read(
            "investigate: full-history context",
            lambda: io.sink.correlation_context(pids, names, CorrelationWindow(None)),
        )
        host_findings = io.read(
            "investigate: host context",
            lambda: io.sink.recent_nonbenign(HOST_CONTEXT_LIMIT),
        )
        empty = {kind: {} for kind in BehaviorKind}
        return cls(
            batch.entries_by_hash(), links, history or empty, host_findings or []
        )

    def finding_for(self, judgment: Judgment) -> dict[str, Any]:
        content_hash = judgment.content_hash
        entry = self.entries.get(content_hash, {})
        finding = {key: value for key, value in entry.items() if key != "content_hash"}
        related_full = BehaviorSummary(self.history).related(self.links, content_hash)
        if related_full:
            finding["related_full"] = related_full
        others = [
            found
            for found in self.host_findings
            if found["content_hash"] != content_hash
        ]
        if others:
            finding["host_context"] = others
        return finding


class InvestigateStage:
    """Re-judge each ``unknown`` verdict with a deliberately gathered bundle:
    the artifact's FULL-HISTORY behaviour (not just the previous cycle) plus
    the host's other non-benign findings. A committed verdict replaces the
    unknown. Snapshot collectors only: their rows resolve the behaviour."""

    def __init__(
        self,
        investigator: UnknownFindingInvestigator,
        io: StepIO,
        behavior: ProcessBehavior,
    ) -> None:
        self._investigator = investigator
        self._io = io
        self._behavior = behavior

    def apply(self, batch: FindingBatch) -> None:
        unknown = [
            index
            for index, judgment in enumerate(batch.judgments)
            if judgment.verdict == Verdict.UNKNOWN
        ][:MAX_INVESTIGATE_PER_COLLECTOR]
        if not unknown:
            return
        # Gathered once, and only when there is an unknown to look at.
        bundle = InvestigationBundle.gather(self._io, self._behavior, batch)
        revised = list(batch.judgments)
        for index in unknown:
            revised[index] = self._investigate(
                batch.collector.name, revised[index], bundle
            )
        batch.judgments = revised

    def _investigate(
        self, collector: str, judgment: Judgment, bundle: InvestigationBundle
    ) -> Judgment:
        fresh = self._investigator.investigate(collector, bundle.finding_for(judgment))
        if not fresh or fresh["verdict"] == Verdict.UNKNOWN:
            return judgment
        self._io.logger.info(
            "investigator resolved collector=%s unknown→%s",
            collector,
            str(fresh["verdict"]),
        )
        return replace(
            judgment,
            verdict=fresh["verdict"],
            category=fresh["category"],
            confidence=fresh["confidence"],
            reasoning=f"[investigated] {fresh['reasoning']}"[:REASONING_CHARS],
            remediation=fresh["remediation"],
        )
