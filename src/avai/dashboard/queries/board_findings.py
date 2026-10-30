"""One finding as the panels board explains it: what avai saw, what the
security databases said, how the AI decided, and the operator's answer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from avai.enrichers.cache import EnrichmentSchema
from avai.enrichers.indicators import IndicatorExtraction
from avai.host_monitor import Base, FeedbackLabel, FeedbackRow, Judgement
from avai.host_monitor.enums import Verdict

from .panel_reads import FindingSource, SchemaProbe

# The verifier and the investigator mark the reasoning they rewrite.
VERIFIER_PREFIX = "[verifier downgraded"
INVESTIGATOR_PREFIX = "[investigated]"
VERY_LIKELY = 0.9
LIKELY = 0.75


class CollectorLabels:
    """Each collector in everyday words, for people who never saw its name."""

    LABELS = {
        "processes": "running programs",
        "launch_items": "programs that start at login",
        "dns_queries": "web addresses it looks up",
        "file_scan": "files on disk",
        "network_flows": "network traffic",
        "network_connections": "network connections",
        "listening_ports": "open network ports",
        "hosts_file": "website address settings",
        "ssh_authorized_keys": "remote login keys",
        "ssh_known_hosts": "computers it logged into",
        "privilege_config": "admin permissions",
        "browser_extensions": "browser add-ons",
        "kernel_extensions": "system extensions",
        "system_extensions": "system extensions",
        "installed_apps": "installed apps",
        "quarantine_events": "downloaded files",
        "trusted_roots": "trusted certificates",
        "usb_devices": "USB devices",
        "setuid_files": "programs with admin powers",
        "auth_events": "logins",
        "process_exec_events": "program starts",
    }

    def of(self, collector: str) -> str:
        return self.LABELS.get(collector, collector.replace("_", " "))


class FeedbackLabels:
    """The operator's saved answer per finding, keyed like a judgement."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_keys(self, keys: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
        if not keys:
            return {}
        wanted = [
            and_(FeedbackRow.collector == collector, FeedbackRow.content_hash == digest)
            for collector, digest in keys
        ]
        statement = select(FeedbackRow).where(or_(*wanted))
        rows = self._session.execute(statement).scalars()
        return {(row.collector, row.content_hash): row.label for row in rows}


class EvidenceLookup:
    """Stored threat-intel answers for a set of indicators."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_values(self, values: list[str]) -> list[dict[str, Any]]:
        if (
            not values
            or "enrichment_evidence" not in SchemaProbe(self._session).tables()
        ):
            return []
        model = EnrichmentSchema(Base).model()
        statement = (
            select(model)
            .where(model.indicator_value.in_(values))
            .order_by(model.confidence.desc())
        )
        return [self._item(row) for row in self._session.execute(statement).scalars()]

    def _item(self, row: Any) -> dict[str, Any]:
        return {
            "source": row.source,
            "indicator": row.indicator_value,
            "hint": row.verdict_hint or "unknown",
            "confidence": row.confidence or 0.0,
            "summary": row.summary or "",
        }


class Certainty:
    def words(self, confidence: float) -> str:
        if confidence >= VERY_LIKELY:
            return "very likely"
        return "likely" if confidence >= LIKELY else "possible"


@dataclass(frozen=True)
class TrailInput:
    judgement: Judgement
    area: str
    evidence: list[dict[str, Any]]
    answer: str | None


class DecisionTrail:
    """The five steps behind a verdict, in plain words."""

    def steps(self, given: TrailInput) -> list[dict[str, str]]:
        judgement = given.judgement
        return [
            self._step(
                "Found",
                (judgement.created_at or "")[: len("YYYY-MM-DD")],
                self._found(given),
            ),
            self._lookups(given.evidence),
            self._step(
                "AI review",
                f"{judgement.verdict}, {Certainty().words(judgement.confidence or 0.0)}",
                ReasoningText().clean(judgement.reasoning),
            ),
            self._double_check(judgement),
            self._answer(given.answer),
        ]

    def _found(self, given: TrailInput) -> str:
        novel = " It had never seen it before." if given.judgement.novel else ""
        return f"avai noticed this while checking {given.area}.{novel}"

    def _lookups(self, evidence: list[dict[str, Any]]) -> dict[str, str]:
        if not evidence:
            detail = (
                "Security databases had no record of it, so the AI decided on its own."
            )
            return self._step("Online lookups", "nothing known", detail)
        detail = f"{len(evidence)} security database answers are shown above."
        return self._step("Online lookups", f"{len(evidence)} records", detail)

    def _double_check(self, judgement: Judgement) -> dict[str, str]:
        reasoning = judgement.reasoning or ""
        if reasoning.startswith(VERIFIER_PREFIX):
            detail = "A second AI argued it is less serious, so it was lowered to suspicious."
            return self._step("Double-check", "lowered", detail)
        if reasoning.startswith(INVESTIGATOR_PREFIX):
            detail = "The first answer was 'unknown', so a second AI looked deeper."
            return self._step("Double-check", "looked deeper", detail)
        if judgement.verdict == Verdict.MALICIOUS:
            detail = (
                "A second AI re-checks malicious findings. Its answer is not saved yet."
            )
            return self._step("Double-check", "not recorded", detail)
        detail = "Only malicious findings get a second check."
        return self._step("Double-check", "not needed", detail)

    def _answer(self, answer: str | None) -> dict[str, str]:
        detail = (
            "Tell avai if this is a real problem or normal for you. It learns from it."
        )
        return self._step("Your answer", AnswerWords().of(answer), detail)

    def _step(self, title: str, outcome: str, detail: str) -> dict[str, str]:
        return {"title": title, "outcome": outcome, "detail": detail}


class AnswerWords:
    WORDS = {
        FeedbackLabel.CONFIRMED.value: "real problem",
        FeedbackLabel.FALSE_POSITIVE.value: "normal for me",
    }

    def of(self, answer: str | None) -> str:
        return self.WORDS.get(answer or "", "waiting for you")


class ReasoningText:
    """The judge's reasoning without the markers later stages add."""

    def clean(self, reasoning: str | None) -> str:
        text = reasoning or ""
        if not text.startswith("["):
            return text
        closing = text.find("]")
        return text[closing + 1 :].strip() if closing >= 0 else text


class FindingInspector:
    """Everything the Inspect panel shows for one judged finding."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def detail(self, collector: str, content_hash: str) -> dict[str, Any] | None:
        judgement = self._session.get(Judgement, (content_hash, collector))
        if judgement is None:
            return None
        source_row, artifact = FindingSource(self._session).row_and_artifact(judgement)
        indicators = IndicatorExtraction.default().extract(collector, source_row)
        evidence = EvidenceLookup(self._session).for_values(
            [indicator.value for indicator in indicators]
        )
        answer = FeedbackLabels(self._session).for_keys([(collector, content_hash)])
        given = TrailInput(
            judgement,
            CollectorLabels().of(collector),
            evidence,
            answer.get((collector, content_hash)),
        )
        return FindingDetail(given, artifact).fields(DecisionTrail().steps(given))


@dataclass(frozen=True)
class FindingDetail:
    given: TrailInput
    artifact: str

    def fields(self, steps: list[dict[str, str]]) -> dict[str, Any]:
        judgement = self.given.judgement
        return {
            "kind": "finding",
            "collector": judgement.collector,
            "content_hash": judgement.content_hash,
            "verdict": judgement.verdict,
            "title": ReasoningText().clean(judgement.reasoning) or self.artifact,
            "area": self.given.area,
            "artifact": self.artifact,
            "seen": judgement.created_at,
            "novel": bool(judgement.novel),
            "fix": judgement.remediation or "",
            "model": judgement.model,
            "evidence": self.given.evidence,
            "answer": self.given.answer,
            "steps": steps,
        }
