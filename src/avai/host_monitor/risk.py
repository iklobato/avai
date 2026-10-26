"""Deterministic 0-100 host posture score (no LLM)."""

from __future__ import annotations

from dataclasses import dataclass
from operator import itemgetter
from typing import Any


@dataclass(frozen=True)
class RiskCounts:
    malicious: int = 0
    suspicious: int = 0
    nopasswd_sudoers: int = 0
    extra_uid0: int = 0


class RiskScorer:
    """Host posture score in [0, 100] with a letter grade and the list of
    point-costing ``drivers``. Pure: all inputs are plain values, so it is
    trivially testable and reproducible.

    Unknown integrity fields (NULL, e.g. a macOS-only field on Linux) are
    treated as "not a known weakness" and cost nothing, so a missing signal
    never silently tanks the score."""

    PERFECT_SCORE = 100
    GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))
    # Integrity fields that cost points when explicitly off:
    # (field, points, driver label).
    PROTECTIONS = (
        ("filevault_active", 15, "Disk encryption (FileVault) off"),
        ("firewall_global_state", 15, "Firewall off"),
        ("gatekeeper_assessments_enabled", 12, "Gatekeeper off"),
        ("firewall_stealth", 3, "Firewall stealth mode off"),
    )
    # Integrity fields that cost points when on.
    EXPOSURES = (
        ("remote_login_enabled", 10, "Remote login (SSH) enabled"),
        ("screen_sharing_enabled", 8, "Screen sharing enabled"),
        ("remote_management_enabled", 10, "Remote management enabled"),
    )
    # Points per counted item, and the cap for that count.
    MALICIOUS = (20, 40)
    SUSPICIOUS = (8, 24)
    NOPASSWD = (10, 20)
    UID0 = (15, 30)

    def score(
        self, integrity: dict[str, Any] | None, counts: RiskCounts
    ) -> dict[str, Any]:
        facts = integrity or {}
        drivers = [
            *self._protection_drivers(facts),
            *self._exposure_drivers(facts),
            *self._count_drivers(counts),
        ]
        drivers = [driver for driver in drivers if driver["points"] > 0]
        drivers.sort(key=itemgetter("points"), reverse=True)
        lost = sum(driver["points"] for driver in drivers)
        total = max(0, min(self.PERFECT_SCORE, self.PERFECT_SCORE - lost))
        return {"score": total, "grade": self.grade(total), "drivers": drivers}

    def grade(self, score: int) -> str:
        grades = (grade for threshold, grade in self.GRADES if score >= threshold)
        return next(grades, "F")

    def _protection_drivers(self, facts: dict[str, Any]) -> list[dict[str, Any]]:
        # None means unknown, which is free.
        return [
            {"label": label, "points": points}
            for field, points, label in self.PROTECTIONS
            if facts.get(field) is not None and not facts.get(field)
        ]

    def _exposure_drivers(self, facts: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"label": label, "points": points}
            for field, points, label in self.EXPOSURES
            if facts.get(field)
        ]

    def _count_drivers(self, counts: RiskCounts) -> list[dict[str, Any]]:
        counted = (
            (counts.malicious, self.MALICIOUS, "active malicious finding(s)"),
            (counts.suspicious, self.SUSPICIOUS, "active suspicious finding(s)"),
            (counts.nopasswd_sudoers, self.NOPASSWD, "NOPASSWD sudoers rule(s)"),
            (counts.extra_uid0, self.UID0, "extra uid-0 account(s)"),
        )
        return [
            {"label": f"{count} {label}", "points": min(count * each, cap)}
            for count, (each, cap), label in counted
        ]
