"""The per-collector finding pipeline: context stages add signals to each
unjudged entry, the judge classifies, and second-opinion stages revise the
verdicts. Each entry key (``evidence``, ``baseline``, ``related``,
``rule_meta``, ``matched_strings``) is written by exactly one stage."""

from __future__ import annotations

import bisect
import json
from dataclasses import dataclass, field, replace
from typing import Optional, Protocol

from avai.enrichers import EnrichmentChain, extract_indicators

from .collectors import Collector
from .constants import (
    _CORRELATED_COLLECTOR,
    _FILE_SCAN_COLLECTOR,
    _LAUNCH_ITEM_COLLECTOR,
    LOG,
)
from .control_loop import ControlSettings, ProgressHeartbeat
from .enums import FeedbackLabel, Verdict
from .investigator import UnknownFindingInvestigator
from .judge import Judge, Judgment
from .sink import Sink
from .verifier import MaliciousVerdictVerifier

# Minimum presence window (runs since first seen) before an artifact that
# misses runs is called "intermittent"; below this it's just freshly seen.
_MIN_DRIFT_WINDOW = 3

# Bound second-pass LLM work per collector per cycle so a pathological batch
# can't fan out into unbounded verify / investigate calls.
_MAX_VERIFY_PER_COLLECTOR = 10
_MAX_INVESTIGATE_PER_COLLECTOR = 10

# How many of the host's other non-benign findings to hand the investigator
# as situational context.
_HOST_CONTEXT_LIMIT = 15

# Per-kind caps on the behaviour attached to one artifact.
_MAX_RELATED = 10
_MAX_RELATED_DNS = 15

# How an operator-feedback label reads in the ground-truth block fed to the
# judge. Keyed by the raw stored label.
_FEEDBACK_PHRASE = {
    FeedbackLabel.FALSE_POSITIVE.value: "a FALSE POSITIVE (benign)",
    FeedbackLabel.CONFIRMED.value: "CONFIRMED malicious",
}

_EMPTY_CORRELATION = {"ports": {}, "flows": {}, "conns": {}, "dns": {}, "exec": {}}


@dataclass(frozen=True)
class HostBaseline:
    """How 'learned' this host is, measured once per cycle.

    ``established`` flips on after ``min_runs`` completed runs; ``cutoff_at``
    is the run timestamp that ends the learning window. An artifact first
    seen after the cutoff showed up on an already-baselined host: that's the
    novelty signal fed to the judge."""

    total_runs: int
    established: bool
    cutoff_at: Optional[str]

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


@dataclass
class FindingBatch:
    """One collector's unjudged entries on their way to a verdict. ``rows``
    are the collector's raw rows this cycle (empty for streaming), richer
    than the unjudged projection; ``run_id`` is None for streaming."""

    collector: Collector
    entries: list[dict]
    rows: list[dict]
    run_id: Optional[str]
    baseline: HostBaseline
    judgments: list[Judgment] = field(default_factory=list)
    indicators_looked_up: int = 0

    def rows_by_hash(self) -> dict[str, dict]:
        """The first row that produced each content_hash."""
        by_hash: dict[str, dict] = {}
        for row in self.rows:
            h = row.get("content_hash")
            if isinstance(h, str) and h and h not in by_hash:
                by_hash[h] = row
        return by_hash

    def entries_by_hash(self) -> dict[str, dict]:
        return {e["content_hash"]: e for e in self.entries if e.get("content_hash")}

    def context(self) -> dict[str, dict]:
        """The per-hash ``baseline`` + ``related`` signals, persisted with the
        verdict so the dashboard can show novelty and the process story."""
        ctx: dict[str, dict] = {}
        for entry in self.entries:
            h = entry.get("content_hash")
            if not h:
                continue
            parts = {k: entry[k] for k in ("baseline", "related") if entry.get(k)}
            if parts:
                ctx[h] = parts
        return ctx


class FindingStage(Protocol):
    def apply(self, batch: FindingBatch) -> None: ...


class FindingPipeline:
    """Runs its stages in order. The order is decided where the pipeline is
    built, so adding a stage never edits the cycle."""

    def __init__(self, stages: list[FindingStage]):
        self._stages = stages

    def run(self, batch: FindingBatch) -> None:
        for stage in self._stages:
            stage.apply(batch)


class EvidenceStage:
    """Attach external threat-intel evidence to each entry as ``evidence``.

    Indicators come from the collector's rows (richer than the unjudged
    projection), mapped by content_hash so an entry's evidence is derived
    from one of the rows that produced it."""

    def __init__(
        self,
        chain: EnrichmentChain,
        settings: ControlSettings,
        heartbeat: ProgressHeartbeat,
    ):
        self._chain = chain
        self._settings = settings
        self._heartbeat = heartbeat

    def apply(self, batch: FindingBatch) -> None:
        if not self._settings.enrich_on():
            return
        rows_by_hash = batch.rows_by_hash()
        for entry in batch.entries:
            # Each indicator is a serial, rate-limited HTTP call; a host with
            # many entries keeps this loop running well past the dashboard's
            # liveness window. Keep proving liveness as we go.
            self._heartbeat.beat()
            row = rows_by_hash.get(entry.get("content_hash"))
            if row is None:
                continue
            evidence = self._evidence(batch, row)
            if evidence:
                entry["evidence"] = evidence

    def _evidence(self, batch: FindingBatch, row: dict) -> list[dict]:
        found: list[dict] = []
        for indicator in extract_indicators(batch.collector.name, row):
            batch.indicators_looked_up += 1
            found.extend(
                {
                    "src": ev.source,
                    "type": str(indicator.type),
                    "value": indicator.value,
                    "hint": str(ev.verdict_hint),
                    "confidence": round(ev.confidence, 2),
                    "note": ev.summary,
                }
                for ev in self._chain.enrich(indicator)
            )
        return found


class BaselineStage:
    """Attach a ``baseline`` object so the judge weighs novelty against this
    host's learned normal instead of classifying every artifact in the
    absolute.

    ``first_seen`` comes from the rows table, not from when the artifact was
    first *judged*: the per-collector judge cap defers some entries across
    cycles, but an artifact present since run 1 still reads first_seen=run 1
    and is never mislabelled novel just because the judge got to it late."""

    def __init__(self, sink: Sink):
        self._sink = sink

    def apply(self, batch: FindingBatch) -> None:
        c = batch.collector
        if not batch.entries or not c.judge_fields:
            return
        hashes = [e["content_hash"] for e in batch.entries if e.get("content_hash")]
        try:
            first_seen = self._sink.first_seen_map(c.model, hashes)
        except Exception as exc:
            LOG.warning("baseline: first_seen_map(%s) failed: %s", c.name, exc)
            return
        timeline = self._timeline()
        for entry in batch.entries:
            seen = first_seen.get(entry.get("content_hash"))
            if seen is not None:
                entry["baseline"] = self._describe(batch.baseline, timeline, *seen)

    def _timeline(self) -> list[str]:
        """Every run start, including the in-progress run, to size each
        artifact's presence window."""
        try:
            return self._sink.run_started_ats()
        except Exception as exc:
            LOG.warning("baseline: run timeline fetch failed: %s", exc)
            return []

    @staticmethod
    def _describe(
        host: HostBaseline, timeline: list[str], first_seen: str, times_seen: int
    ) -> dict:
        # An artifact present in fewer runs than have happened since it first
        # appeared has come and gone: a sharper drift signal than novelty.
        window = (
            len(timeline) - bisect.bisect_left(timeline, first_seen) if timeline else 0
        )
        # Needs a few runs of window to tell flapping from freshly seen.
        intermittent = window >= _MIN_DRIFT_WINDOW and times_seen < window
        return {
            "first_seen": first_seen,
            "times_seen": times_seen,
            "host_runs": host.total_runs,
            "baseline_established": host.established,
            "novel": host.is_novel(first_seen),
            "intermittent": intermittent,
        }


class ProcessBehavior:
    """Resolves the PIDs and process names an artifact ran as, and reads what
    those processes did (ports, flows, connections, DNS, exec lineage)."""

    def __init__(self, sink: Sink):
        self._sink = sink

    def pids_and_names(
        self, collector_name: str, rows: list[dict], since: Optional[str]
    ) -> tuple[dict, dict]:
        """content_hash to (PIDs, names) for a correlatable collector, or two
        empty maps for anything else."""
        if collector_name == _CORRELATED_COLLECTOR:
            return self._from_processes(rows)
        if collector_name == _LAUNCH_ITEM_COLLECTOR:
            return self._from_launch_items(rows, since)
        return {}, {}

    @staticmethod
    def related(ctx: dict, pids: set, names: set) -> dict:
        """The ``related`` behaviour object for one artifact, bounded per
        kind."""
        related: dict = {}
        ports = [p for pid in pids for p in ctx["ports"].get(pid, [])]
        flows = [f for pid in pids for f in ctx["flows"].get(pid, [])]
        conns = [cc for pid in pids for cc in ctx["conns"].get(pid, [])]
        dns = [d for n in names for d in ctx["dns"].get(n, [])]
        execs = [ctx["exec"][pid] for pid in pids if pid in ctx["exec"]]
        if ports:
            related["listening_ports"] = ports[:_MAX_RELATED]
        if flows:
            related["outbound_flows"] = flows[:_MAX_RELATED]
        if conns:
            related["remote_connections"] = conns[:_MAX_RELATED]
        if dns:
            related["dns_queries"] = dns[:_MAX_RELATED_DNS]
        if execs:
            related["exec_lineage"] = execs[0]
        return related

    @staticmethod
    def _from_processes(rows: list[dict]) -> tuple[dict, dict]:
        pids_by_hash: dict[str, set] = {}
        names_by_hash: dict[str, set] = {}
        for r in rows:
            h = r.get("content_hash")
            if not isinstance(h, str) or not h:
                continue
            if r.get("pid") is not None:
                pids_by_hash.setdefault(h, set()).add(r["pid"])
            if r.get("name"):
                names_by_hash.setdefault(h, set()).add(r["name"])
        return pids_by_hash, names_by_hash

    def _from_launch_items(
        self, rows: list[dict], since: Optional[str]
    ) -> tuple[dict, dict]:
        """A launch item has no PID: resolve its ``program`` to the live
        process(es) running it, so a persistence entry is judged with the
        behaviour of what it spawns. Names carry the program basename so
        DNS-by-process-name correlation still applies."""
        programs_by_hash: dict[str, set] = {}
        for r in rows:
            h = r.get("content_hash")
            prog = r.get("program")
            if isinstance(h, str) and h and isinstance(prog, str) and prog:
                programs_by_hash.setdefault(h, set()).add(prog)
        all_programs = sorted({p for s in programs_by_hash.values() for p in s})
        try:
            pids_for_exe = self._sink.pids_by_executable(all_programs, since)
        except Exception as exc:
            LOG.warning("correlation: pids_by_executable failed: %s", exc)
            pids_for_exe = {}
        pids_by_hash: dict[str, set] = {}
        names_by_hash: dict[str, set] = {}
        for h, progs in programs_by_hash.items():
            for prog in progs:
                for pid in pids_for_exe.get(prog, ()):
                    pids_by_hash.setdefault(h, set()).add(pid)
                names_by_hash.setdefault(h, set()).add(prog.rsplit("/", 1)[-1])
        return pids_by_hash, names_by_hash


class CorrelationStage:
    """Attach a ``related`` object: the artifact's behaviour since the
    previous cycle, correlated by PID (DNS by process name), so the judge
    scores it *with* its behaviour. A novel binary that is also beaconing to
    a flagged IP is a far stronger signal than either row alone. Only
    processes and launch items are correlated; other collectors keep their
    own independent verdicts."""

    def __init__(self, sink: Sink, behavior: ProcessBehavior):
        self._sink = sink
        self._behavior = behavior

    def apply(self, batch: FindingBatch) -> None:
        name = batch.collector.name
        if not batch.entries or name not in (
            _CORRELATED_COLLECTOR,
            _LAUNCH_ITEM_COLLECTOR,
        ):
            return
        try:
            since = self._sink.prior_run_started_at(batch.run_id)
        except Exception as exc:
            LOG.warning("correlation: prior_run(%s) failed: %s", name, exc)
            return
        pids_by_hash, names_by_hash = self._behavior.pids_and_names(
            name, batch.rows, since
        )
        all_pids = sorted({p for s in pids_by_hash.values() for p in s})
        all_names = sorted({n for s in names_by_hash.values() for n in s})
        if not all_pids and not all_names:
            return
        try:
            ctx = self._sink.correlation_context(all_pids, all_names, since)
        except Exception as exc:
            LOG.warning("correlation: context(%s) failed: %s", name, exc)
            return
        for entry in batch.entries:
            h = entry.get("content_hash")
            related = self._behavior.related(
                ctx, pids_by_hash.get(h, set()), names_by_hash.get(h, set())
            )
            if related:
                entry["related"] = related


class YaraContextStage:
    """Attach the matched rule's metadata (``rule_meta``) and a redacted
    sample of the matched bytes (``matched_strings``) to each file-scan
    entry, so the judge can triage false positives and attribute the rule.
    Both live on the rows but not in ``judge_fields``, so they don't affect
    the content_hash."""

    def apply(self, batch: FindingBatch) -> None:
        if batch.collector.name != _FILE_SCAN_COLLECTOR or not batch.entries:
            return
        rows_by_hash = batch.rows_by_hash()
        for entry in batch.entries:
            row = rows_by_hash.get(entry.get("content_hash"))
            if row is None:
                continue
            meta = self._loads_or_none(row.get("meta_json"))
            if isinstance(meta, dict) and meta:
                entry["rule_meta"] = meta
            strings = self._loads_or_none(row.get("strings_json"))
            if isinstance(strings, list) and strings:
                entry["matched_strings"] = strings

    @staticmethod
    def _loads_or_none(raw):
        """A malformed JSON column must not break the judge wiring."""
        if not isinstance(raw, str) or not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None


class JudgeStage:
    """Classify the entries, with this host's operator feedback for the
    collector appended to the static hints as ground truth."""

    def __init__(self, judge: Judge, sink: Sink):
        self._judge = judge
        self._sink = sink

    def apply(self, batch: FindingBatch) -> None:
        c = batch.collector
        hints = self._hints(c.name, c.judge_hints)
        batch.judgments = self._judge.judge(c.name, hints, batch.entries)

    def _hints(self, collector_name: str, base_hints: str) -> str:
        try:
            examples = self._sink.feedback_examples(collector_name)
        except Exception as exc:
            LOG.warning("feedback_examples(%s) failed: %s", collector_name, exc)
            return base_hints
        if not examples:
            return base_hints
        lines = []
        for e in examples:
            artifact = (e.get("artifact") or "").strip() or "(unnamed artifact)"
            phrase = _FEEDBACK_PHRASE.get(e.get("label"), e.get("label"))
            note = f" note: {e['note']}" if e.get("note") else ""
            lines.append(f'- "{artifact}" was marked {phrase} by the operator.{note}')
        return base_hints + (
            "\nOperator feedback for this host (ground truth: apply the same "
            "judgement to these and closely-matching artifacts):\n" + "\n".join(lines)
        )


class VerifyStage:
    """Re-check each ``malicious`` verdict with an independent skeptic; a
    refuted one is downgraded to ``suspicious`` (still flagged for review,
    not asserted as an active threat)."""

    def __init__(self, verifier: MaliciousVerdictVerifier):
        self._verifier = verifier

    def apply(self, batch: FindingBatch) -> None:
        if not batch.judgments:
            return
        entries = batch.entries_by_hash()
        revised: list[Judgment] = []
        checked = 0
        for j in batch.judgments:
            if j.verdict != Verdict.MALICIOUS or checked >= _MAX_VERIFY_PER_COLLECTOR:
                revised.append(j)
                continue
            checked += 1
            revised.append(self._verify(batch.collector.name, j, entries))
        batch.judgments = revised

    def _verify(self, collector: str, j: Judgment, entries: dict) -> Judgment:
        entry = entries.get(j.content_hash, {})
        finding = {
            "collector": collector,
            "verdict": str(j.verdict),
            "category": str(j.category),
            "reasoning": j.reasoning,
            **{k: v for k, v in entry.items() if k != "content_hash"},
        }
        result = self._verifier.verify(finding)
        if not (result and result["refuted"]):
            return j
        LOG.info(
            "verifier downgraded collector=%s reason=%s",
            collector,
            result["reasoning"][:120],
        )
        return replace(
            j,
            verdict=Verdict.SUSPICIOUS,
            reasoning=(
                f"[verifier downgraded malicious→suspicious] "
                f"{result['reasoning']} · original: {j.reasoning}"
            )[:500],
        )


class InvestigateStage:
    """Re-judge each ``unknown`` verdict with a deliberately gathered bundle:
    the artifact's FULL-HISTORY behaviour (not just the previous cycle) plus
    the host's other non-benign findings. A committed verdict replaces the
    unknown. Snapshot collectors only: their rows resolve the behaviour."""

    def __init__(
        self,
        investigator: UnknownFindingInvestigator,
        sink: Sink,
        behavior: ProcessBehavior,
    ):
        self._investigator = investigator
        self._sink = sink
        self._behavior = behavior

    def apply(self, batch: FindingBatch) -> None:
        revised: list[Judgment] = []
        bundle: Optional[_InvestigationBundle] = None
        investigated = 0
        for j in batch.judgments:
            stop = investigated >= _MAX_INVESTIGATE_PER_COLLECTOR
            if j.verdict != Verdict.UNKNOWN or stop:
                revised.append(j)
                continue
            investigated += 1
            # Gathered once, and only when there is an unknown to look at.
            bundle = bundle or _InvestigationBundle.gather(
                self._sink, self._behavior, batch
            )
            revised.append(self._investigate(batch.collector.name, j, bundle))
        batch.judgments = revised

    def _investigate(
        self, collector: str, j: Judgment, bundle: _InvestigationBundle
    ) -> Judgment:
        result = self._investigator.investigate(collector, bundle.finding_for(j))
        if not result or result["verdict"] == Verdict.UNKNOWN:
            return j
        LOG.info(
            "investigator resolved collector=%s unknown→%s",
            collector,
            str(result["verdict"]),
        )
        return replace(
            j,
            verdict=result["verdict"],
            category=result["category"],
            confidence=result["confidence"],
            reasoning=f"[investigated] {result['reasoning']}"[:500],
            remediation=result["remediation"],
        )


@dataclass(frozen=True)
class _InvestigationBundle:
    """The context shared by every investigation in one batch, gathered once."""

    entries: dict[str, dict]
    pids_by_hash: dict
    names_by_hash: dict
    history: dict
    host_findings: list

    @classmethod
    def gather(
        cls, sink: Sink, behavior: ProcessBehavior, batch: FindingBatch
    ) -> _InvestigationBundle:
        # Full history: since=None drops the previous-cycle time bound.
        pids_by_hash, names_by_hash = behavior.pids_and_names(
            batch.collector.name, batch.rows, None
        )
        all_pids = sorted({p for s in pids_by_hash.values() for p in s})
        all_names = sorted({n for s in names_by_hash.values() for n in s})
        try:
            history = sink.correlation_context(all_pids, all_names, None)
        except Exception as exc:
            LOG.warning("investigate: full-history context failed: %s", exc)
            history = _EMPTY_CORRELATION
        try:
            host_findings = sink.recent_nonbenign(_HOST_CONTEXT_LIMIT)
        except Exception as exc:
            LOG.warning("investigate: host context failed: %s", exc)
            host_findings = []
        return cls(
            batch.entries_by_hash(), pids_by_hash, names_by_hash, history, host_findings
        )

    def finding_for(self, j: Judgment) -> dict:
        entry = self.entries.get(j.content_hash, {})
        finding = {k: v for k, v in entry.items() if k != "content_hash"}
        related_full = ProcessBehavior.related(
            self.history,
            self.pids_by_hash.get(j.content_hash, set()),
            self.names_by_hash.get(j.content_hash, set()),
        )
        if related_full:
            finding["related_full"] = related_full
        others = [h for h in self.host_findings if h["content_hash"] != j.content_hash]
        if others:
            finding["host_context"] = others
        return finding
