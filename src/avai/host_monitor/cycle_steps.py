"""End-of-cycle reports, run once the cycle's verdicts are in. Every step is
best-effort: a failed report is logged and never fails the cycle."""

from __future__ import annotations

import json
import platform
import socket
from typing import Optional, Protocol

from .collectors import SnapshotCollector
from .constants import LOG
from .coverage import YaraCoverageAssessor
from .enums import Verdict
from .models import RiskScoreRow
from .narrator import IncidentNarrator
from .risk import compute_risk_score
from .runtime import Clock
from .sink import Sink

# How many added / resolved risk drivers the explanation names.
_MAX_DRIVERS_NAMED = 4


class CycleStep(Protocol):
    def run(self, run_id: str, started: str) -> None: ...


class NarrativeStep:
    """Synthesise the active non-benign findings into one incident digest,
    only when that set changed since the last digest so an unchanged picture
    doesn't re-spend tokens."""

    def __init__(self, sink: Sink, narrator: IncidentNarrator):
        self._sink = sink
        self._narrator = narrator

    def run(self, run_id: str, started: str) -> None:
        try:
            findings = self._sink.active_findings(started)
        except Exception as exc:
            LOG.warning("narrative: active_findings failed: %s", exc)
            return
        if not findings:
            return
        digest = json.dumps(sorted(f["content_hash"] for f in findings))
        if self._unchanged(digest):
            return
        result = self._narrator.narrate(findings)
        if not result:
            return
        try:
            self._sink.write_narrative(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "model": self._narrator.model,
                    "severity": result["severity"],
                    "headline": result["headline"],
                    "summary": result["summary"],
                    "timeline_json": json.dumps(result["timeline"]),
                    "actions_json": json.dumps(result["actions"]),
                    "finding_count": len(findings),
                    "finding_hashes": digest,
                }
            )
        except Exception as exc:
            LOG.warning("narrative: write failed: %s", exc)
            return
        LOG.info(
            "narrative written severity=%s findings=%d timeline=%d actions=%d",
            result["severity"],
            len(findings),
            len(result["timeline"]),
            len(result["actions"]),
        )

    def _unchanged(self, digest: str) -> bool:
        try:
            return self._sink.latest_narrative_finding_hashes() == digest
        except Exception:
            return False  # the comparison is an optimisation; generate anyway


class RiskScoreStep:
    """Compute and store the deterministic host posture score, with a delta
    explanation against the previous score. Needs no LLM."""

    def __init__(self, sink: Sink):
        self._sink = sink

    def run(self, run_id: str, started: str) -> None:
        try:
            findings = self._sink.active_findings(started)
            malicious = sum(
                1 for f in findings if f["verdict"] == str(Verdict.MALICIOUS)
            )
            suspicious = sum(
                1 for f in findings if f["verdict"] == str(Verdict.SUSPICIOUS)
            )
            integrity = self._sink.system_integrity_row(run_id)
            nopasswd, extra_uid0 = self._sink.privilege_risk_counts(run_id)
        except Exception as exc:
            LOG.warning("risk: input gather failed: %s", exc)
            return
        result = compute_risk_score(
            integrity, malicious, suspicious, nopasswd, extra_uid0
        )
        prev = self._sink.latest_risk_row()
        try:
            self._sink.write_risk_score(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "score": result["score"],
                    "grade": result["grade"],
                    "prev_score": prev.score if prev else None,
                    "drivers_json": json.dumps(result["drivers"]),
                    "explanation": self.explain(result, prev),
                }
            )
        except Exception as exc:
            LOG.warning("risk: write failed: %s", exc)
            return
        LOG.info("risk score=%d grade=%s", result["score"], result["grade"])

    @staticmethod
    def explain(result: dict, prev: Optional[RiskScoreRow]) -> str:
        """Deterministic 'why it changed' from the driver diff against the
        previous run: accurate and free, with no LLM paraphrase to drift."""
        if prev is None:
            return "Initial posture score for this host."
        delta = result["score"] - prev.score
        try:
            prev_labels = {d["label"] for d in json.loads(prev.drivers_json or "[]")}
        except (ValueError, TypeError):
            prev_labels = set()
        cur_labels = {d["label"] for d in result["drivers"]}
        added = sorted(cur_labels - prev_labels)
        removed = sorted(prev_labels - cur_labels)
        if delta == 0 and not added and not removed:
            return "No change since the previous run."
        parts = [f"Score {'up' if delta >= 0 else 'down'} {abs(delta)}."]
        if added:
            parts.append("New: " + "; ".join(added[:_MAX_DRIVERS_NAMED]) + ".")
        if removed:
            parts.append("Resolved: " + "; ".join(removed[:_MAX_DRIVERS_NAMED]) + ".")
        return " ".join(parts)


class YaraStatusStep:
    """Persist the file scanner's last compile summary (rules loaded, skipped,
    by source and category) so the read-only dashboard can show the ruleset."""

    def __init__(self, sink: Sink, collectors: list[SnapshotCollector]):
        self._sink = sink
        self._collectors = collectors

    def run(self, run_id: str, started: str) -> None:
        stats = next(
            (
                c.compile_stats
                for c in self._collectors
                if getattr(c, "compile_stats", None) is not None
            ),
            None,
        )
        if stats is None:
            return
        try:
            self._sink.write_yara_status(stats)
            self._sink.write_yara_rules(stats.get("inventory") or [])
        except Exception as exc:  # noqa: BLE001
            LOG.warning("yara_status: write failed: %s", exc)


class CoverageStep:
    """Assess whether the loaded YARA ruleset covers this host's threat
    surface, only when the ruleset changed since the last assessment (it is
    static within a process, so this avoids re-spending tokens)."""

    def __init__(self, sink: Sink, assessor: YaraCoverageAssessor):
        self._sink = sink
        self._assessor = assessor

    def run(self, run_id: str, started: str) -> None:
        try:
            ruleset = self._sink.read_yara_status()
        except Exception as exc:
            LOG.warning("coverage: read_yara_status failed: %s", exc)
            return
        if not ruleset or not ruleset.get("rules_loaded"):
            return
        fingerprint = self._fingerprint(ruleset)
        if self._unchanged(fingerprint):
            return
        try:
            host = self._sink.coverage_profile(run_id)
        except Exception as exc:
            LOG.warning("coverage: profile failed: %s", exc)
            return
        host["platform"] = platform.system()
        host["hostname"] = socket.gethostname()
        result = self._assessor.assess(ruleset, host)
        if not result:
            return
        try:
            self._sink.write_yara_coverage(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "model": self._assessor.model,
                    "posture": result["posture"],
                    "headline": result["headline"],
                    "summary": result["summary"],
                    "gaps_json": json.dumps(result["gaps"]),
                    "recommendations_json": json.dumps(result["recommendations"]),
                    "ruleset_fingerprint": fingerprint,
                }
            )
        except Exception as exc:
            LOG.warning("coverage: write failed: %s", exc)
            return
        LOG.info(
            "coverage posture=%s gaps=%d recommendations=%d",
            result["posture"],
            len(result["gaps"]),
            len(result["recommendations"]),
        )

    def _unchanged(self, fingerprint: str) -> bool:
        try:
            return self._sink.latest_yara_coverage_fingerprint() == fingerprint
        except Exception:
            return False  # the comparison is an optimisation; assess anyway

    @staticmethod
    def _fingerprint(ruleset: dict) -> str:
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
