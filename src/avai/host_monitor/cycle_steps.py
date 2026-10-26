"""End-of-cycle reports, run once the cycle's verdicts are in. Every step is
best-effort: a failed report is logged and never fails the cycle."""

from __future__ import annotations

import json
import logging
import platform
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

from sqlalchemy.exc import SQLAlchemyError

from .collectors import SnapshotCollector
from .coverage import YaraCoverageAssessor
from .enums import Verdict
from .models import RiskScoreRow
from .narrator import IncidentNarrator
from .risk import RiskCounts, RiskScorer
from .runtime import Clock
from .sink import Sink

# What reading or writing a report can raise: database errors plus bad
# values in a stored row. Each is logged and the step skipped.
REPORT_FAILURES = (
    SQLAlchemyError,
    OSError,
    ValueError,
    LookupError,
    TypeError,
    AttributeError,
)

Value = TypeVar("Value")


class CycleStep(Protocol):
    def report(self, run_id: str, started: str) -> None: ...


@dataclass(frozen=True)
class StepIO:
    """Where a step reads and writes, and where its failures are logged."""

    sink: Sink
    logger: logging.Logger

    def read(self, label: str, action: Callable[[], Value]) -> Value | None:
        try:
            return action()
        except REPORT_FAILURES as exc:
            self.logger.warning("%s failed: %s", label, exc)
            return None

    def wrote(self, label: str, action: Callable[[], object]) -> bool:
        try:
            action()
        except REPORT_FAILURES as exc:
            self.logger.warning("%s failed: %s", label, exc)
            return False
        return True

    def matches(self, action: Callable[[], object], expected: str) -> bool:
        """An optimisation check: a failed read means "not the same"."""
        try:
            return action() == expected
        except REPORT_FAILURES:
            return False


class NarrativeStep:
    """Synthesise the active non-benign findings into one incident digest,
    only when that set changed since the last digest so an unchanged picture
    doesn't re-spend tokens."""

    def __init__(self, io: StepIO, narrator: IncidentNarrator) -> None:
        self._io = io
        self._narrator = narrator

    def report(self, run_id: str, started: str) -> None:
        findings = self._changed_findings(started)
        if not findings:
            return
        digest_reply = self._narrator.narrate(findings)
        if not digest_reply:
            return
        row = self._row(run_id, digest_reply, findings)
        if self._io.wrote(
            "narrative: write", lambda: self._io.sink.write_narrative(row)
        ):
            self._io.logger.info(
                "narrative written severity=%s findings=%d timeline=%d actions=%d",
                digest_reply["severity"],
                len(findings),
                len(digest_reply["timeline"]),
                len(digest_reply["actions"]),
            )

    def _changed_findings(self, started: str) -> list[dict[str, Any]] | None:
        sink = self._io.sink
        findings = self._io.read(
            "narrative: active_findings", lambda: sink.active_findings(started)
        )
        if not findings:
            return None
        digest = self._digest(findings)
        unchanged = self._io.matches(sink.latest_narrative_finding_hashes, digest)
        return None if unchanged else findings

    def _digest(self, findings: list[dict[str, Any]]) -> str:
        return json.dumps(sorted(finding["content_hash"] for finding in findings))

    def _row(
        self, run_id: str, digest_reply: dict[str, Any], findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "created_at": Clock().now_iso(),
            "run_id": run_id,
            "model": self._narrator.model,
            "severity": digest_reply["severity"],
            "headline": digest_reply["headline"],
            "summary": digest_reply["summary"],
            "timeline_json": json.dumps(digest_reply["timeline"]),
            "actions_json": json.dumps(digest_reply["actions"]),
            "finding_count": len(findings),
            "finding_hashes": self._digest(findings),
        }


class RiskExplanation:
    """Deterministic 'why it changed' from the driver diff against the
    previous run: accurate and free, with no LLM paraphrase to drift."""

    # How many added / resolved risk drivers the explanation names.
    MAX_DRIVERS_NAMED = 4

    def explain(self, score: dict[str, Any], prev: RiskScoreRow | None) -> str:
        if prev is None:
            return "Initial posture score for this host."
        delta = score["score"] - prev.score
        current = {driver["label"] for driver in score["drivers"]}
        previous = self._labels(prev.drivers_json)
        added, removed = sorted(current - previous), sorted(previous - current)
        if delta == 0 and not added and not removed:
            return "No change since the previous run."
        parts = [f"Score {'up' if delta >= 0 else 'down'} {abs(delta)}."]
        parts += self._named("New", added) + self._named("Resolved", removed)
        return " ".join(parts)

    def _labels(self, drivers_json: str | None) -> set[str]:
        try:
            return {driver["label"] for driver in json.loads(drivers_json or "[]")}
        except (ValueError, TypeError):
            return set()

    def _named(self, title: str, labels: list[str]) -> list[str]:
        if not labels:
            return []
        return [f"{title}: " + "; ".join(labels[: self.MAX_DRIVERS_NAMED]) + "."]


class RiskScoreStep:
    """Compute and store the deterministic host posture score, with a delta
    explanation against the previous score. Needs no LLM."""

    def __init__(self, io: StepIO) -> None:
        self._io = io

    def report(self, run_id: str, started: str) -> None:
        inputs = self._io.read(
            "risk: input gather", lambda: self._inputs(run_id, started)
        )
        if inputs is None:
            return
        score = RiskScorer().score(*inputs)
        row = self._row(run_id, score, self._io.sink.latest_risk_row())
        if self._io.wrote("risk: write", lambda: self._io.sink.write_risk_score(row)):
            self._io.logger.info(
                "risk score=%d grade=%s", score["score"], score["grade"]
            )

    def _row(
        self, run_id: str, score: dict[str, Any], prev: RiskScoreRow | None
    ) -> dict[str, Any]:
        return {
            "created_at": Clock().now_iso(),
            "run_id": run_id,
            "score": score["score"],
            "grade": score["grade"],
            "prev_score": prev.score if prev else None,
            "drivers_json": json.dumps(score["drivers"]),
            "explanation": RiskExplanation().explain(score, prev),
        }

    def _inputs(
        self, run_id: str, started: str
    ) -> tuple[dict[str, Any] | None, RiskCounts]:
        sink = self._io.sink
        verdicts = [finding["verdict"] for finding in sink.active_findings(started)]
        nopasswd, extra_uid0 = sink.privilege_risk_counts(run_id)
        counts = RiskCounts(
            verdicts.count(str(Verdict.MALICIOUS)),
            verdicts.count(str(Verdict.SUSPICIOUS)),
            nopasswd,
            extra_uid0,
        )
        return sink.system_integrity_row(run_id), counts


class YaraStatusStep:
    """Persist the file scanner's last compile summary (rules loaded, skipped,
    by source and category) so the read-only dashboard can show the ruleset."""

    def __init__(self, io: StepIO, collectors: list[SnapshotCollector]) -> None:
        self._io = io
        self._collectors = collectors

    def report(self, run_id: str, started: str) -> None:
        summaries = (
            collector.compile_stats
            for collector in self._collectors
            if getattr(collector, "compile_stats", None) is not None
        )
        stats = next(summaries, None)
        if stats is None:
            return
        self._io.wrote("yara_status: write", lambda: self._write(stats))

    def _write(self, stats: dict[str, Any]) -> None:
        self._io.sink.write_yara_status(stats)
        self._io.sink.write_yara_rules(stats.get("inventory") or [])


class CoverageStep:
    """Assess whether the loaded YARA ruleset covers this host's threat
    surface, only when the ruleset changed since the last assessment (it is
    static within a process, so this avoids re-spending tokens)."""

    def __init__(self, io: StepIO, assessor: YaraCoverageAssessor) -> None:
        self._io = io
        self._assessor = assessor

    def report(self, run_id: str, started: str) -> None:
        ruleset = self._changed_ruleset()
        host = None if ruleset is None else self._host(run_id)
        if ruleset is None or host is None:
            return
        assessment = self._assessor.assess(ruleset, host)
        if not assessment:
            return
        row = self._row(run_id, assessment, self._fingerprint(ruleset))
        sink = self._io.sink
        if self._io.wrote("coverage: write", lambda: sink.write_yara_coverage(row)):
            self._io.logger.info(
                "coverage posture=%s gaps=%d recommendations=%d",
                assessment["posture"],
                len(assessment["gaps"]),
                len(assessment["recommendations"]),
            )

    def _changed_ruleset(self) -> dict[str, Any] | None:
        sink = self._io.sink
        ruleset = self._io.read("coverage: read_yara_status", sink.read_yara_status)
        if not ruleset or not ruleset.get("rules_loaded"):
            return None
        fingerprint = self._fingerprint(ruleset)
        unchanged = self._io.matches(sink.latest_yara_coverage_fingerprint, fingerprint)
        return None if unchanged else ruleset

    def _host(self, run_id: str) -> dict[str, Any] | None:
        sink = self._io.sink
        host = self._io.read("coverage: profile", lambda: sink.coverage_profile(run_id))
        if host is None:
            return None
        return {**host, "platform": platform.system(), "hostname": socket.gethostname()}

    def _row(
        self, run_id: str, assessment: dict[str, Any], fingerprint: str
    ) -> dict[str, Any]:
        return {
            "created_at": Clock().now_iso(),
            "run_id": run_id,
            "model": self._assessor.model,
            "posture": assessment["posture"],
            "headline": assessment["headline"],
            "summary": assessment["summary"],
            "gaps_json": json.dumps(assessment["gaps"]),
            "recommendations_json": json.dumps(assessment["recommendations"]),
            "ruleset_fingerprint": fingerprint,
        }

    def _fingerprint(self, ruleset: dict[str, Any]) -> str:
        """Changes only when the rules actually change: rule count, per-source
        counts and the category set."""
        return json.dumps(
            {
                "rules": ruleset.get("rules_loaded"),
                "sources": sorted((ruleset.get("sources") or {}).items()),
                "cats": sorted((ruleset.get("by_category") or {}).keys()),
            },
            sort_keys=True,
        )
