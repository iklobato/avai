"""Deterministic 0-100 host posture score (no LLM)."""
from __future__ import annotations

from typing import Optional

from .constants import RISK_GRADES, RISK_WEIGHTS


def _risk_grade(score: int) -> str:
    for threshold, grade in RISK_GRADES:
        if score >= threshold:
            return grade
    return "F"


# Integrity fields that cost points when explicitly off, and those that cost
# points when on: (field, RISK_WEIGHTS key, driver label).
_PROTECTIONS = (
    ("filevault_active", "filevault_off", "Disk encryption (FileVault) off"),
    ("firewall_global_state", "firewall_off", "Firewall off"),
    ("gatekeeper_assessments_enabled", "gatekeeper_off", "Gatekeeper off"),
    ("firewall_stealth", "stealth_off", "Firewall stealth mode off"),
)
_EXPOSURES = (
    ("remote_login_enabled", "ssh_on", "Remote login (SSH) enabled"),
    ("screen_sharing_enabled", "screen_sharing_on", "Screen sharing enabled"),
    ("remote_management_enabled", "remote_mgmt_on", "Remote management enabled"),
)


def compute_risk_score(
    integrity: Optional[dict],
    malicious: int,
    suspicious: int,
    nopasswd_sudoers: int,
    extra_uid0: int,
) -> dict:
    """Deterministic host posture score in [0, 100] with a letter grade and
    the list of point-costing ``drivers``. Pure function: all inputs are
    plain values so it is trivially testable and reproducible.

    Unknown integrity fields (NULL, e.g. a macOS-only field on Linux) are
    treated as "not a known weakness" and cost nothing, so a missing signal
    never silently tanks the score."""
    w = RISK_WEIGHTS
    integ = integrity or {}
    drivers: list[dict] = []

    def penalise(points: int, label: str) -> None:
        if points > 0:
            drivers.append({"label": label, "points": points})

    for field, weight, label in _PROTECTIONS:
        value = integ.get(field)
        if value is not None and not value:  # None means unknown: free
            penalise(w[weight], label)
    for field, weight, label in _EXPOSURES:
        if integ.get(field):
            penalise(w[weight], label)

    # (count, RISK_WEIGHTS prefix for <prefix>_each / <prefix>_cap, label)
    counted = (
        (malicious, "malicious", f"{malicious} active malicious finding(s)"),
        (suspicious, "suspicious", f"{suspicious} active suspicious finding(s)"),
        (nopasswd_sudoers, "nopasswd", f"{nopasswd_sudoers} NOPASSWD sudoers rule(s)"),
        (extra_uid0, "uid0", f"{extra_uid0} extra uid-0 account(s)"),
    )
    for count, prefix, label in counted:
        penalise(min(count * w[f"{prefix}_each"], w[f"{prefix}_cap"]), label)

    score = max(0, min(100, 100 - sum(d["points"] for d in drivers)))
    drivers.sort(key=lambda d: d["points"], reverse=True)
    return {"score": score, "grade": _risk_grade(score), "drivers": drivers}
