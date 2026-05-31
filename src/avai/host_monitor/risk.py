"""Deterministic 0-100 host posture score (no LLM)."""
from __future__ import annotations

from typing import Optional

from .constants import RISK_GRADES, RISK_WEIGHTS


def _risk_grade(score: int) -> str:
    for threshold, grade in RISK_GRADES:
        if score >= threshold:
            return grade
    return "F"


def compute_risk_score(
    integrity: Optional[dict],
    malicious: int,
    suspicious: int,
    nopasswd_sudoers: int,
    extra_uid0: int,
) -> dict:
    """Deterministic host posture score in [0, 100] with a letter grade and
    the list of point-costing ``drivers``. Pure function — all inputs are
    plain values so it is trivially testable and reproducible.

    Unknown integrity fields (NULL — e.g. a macOS-only field on Linux) are
    treated as "not a known weakness" and cost nothing, so a missing signal
    never silently tanks the score."""
    w = RISK_WEIGHTS
    score = 100
    drivers: list[dict] = []

    def penalise(points: int, label: str) -> None:
        nonlocal score
        if points > 0:
            score -= points
            drivers.append({"label": label, "points": points})

    integ = integrity or {}

    def is_off(key):  # explicitly false/0 — None means "unknown", skip
        v = integ.get(key)
        return v is not None and not v

    def is_on(key):
        return bool(integ.get(key))

    if is_off("filevault_active"):
        penalise(w["filevault_off"], "Disk encryption (FileVault) off")
    if is_off("firewall_global_state"):
        penalise(w["firewall_off"], "Firewall off")
    if is_off("gatekeeper_assessments_enabled"):
        penalise(w["gatekeeper_off"], "Gatekeeper off")
    if is_off("firewall_stealth"):
        penalise(w["stealth_off"], "Firewall stealth mode off")
    if is_on("remote_login_enabled"):
        penalise(w["ssh_on"], "Remote login (SSH) enabled")
    if is_on("screen_sharing_enabled"):
        penalise(w["screen_sharing_on"], "Screen sharing enabled")
    if is_on("remote_management_enabled"):
        penalise(w["remote_mgmt_on"], "Remote management enabled")

    if malicious > 0:
        penalise(
            min(malicious * w["malicious_each"], w["malicious_cap"]),
            f"{malicious} active malicious finding(s)",
        )
    if suspicious > 0:
        penalise(
            min(suspicious * w["suspicious_each"], w["suspicious_cap"]),
            f"{suspicious} active suspicious finding(s)",
        )
    if nopasswd_sudoers > 0:
        penalise(
            min(nopasswd_sudoers * w["nopasswd_each"], w["nopasswd_cap"]),
            f"{nopasswd_sudoers} NOPASSWD sudoers rule(s)",
        )
    if extra_uid0 > 0:
        penalise(
            min(extra_uid0 * w["uid0_each"], w["uid0_cap"]),
            f"{extra_uid0} extra uid-0 account(s)",
        )

    score = max(0, min(100, score))
    drivers.sort(key=lambda d: d["points"], reverse=True)
    return {"score": score, "grade": _risk_grade(score), "drivers": drivers}
