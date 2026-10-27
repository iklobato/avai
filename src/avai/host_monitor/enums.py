"""Typed categorical enums shared across the monitor."""

from __future__ import annotations

from enum import StrEnum


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

    @classmethod
    def worst_first(cls) -> tuple[Verdict, ...]:
        return (cls.MALICIOUS, cls.SUSPICIOUS, cls.UNKNOWN, cls.BENIGN)

    @classmethod
    def ranks(cls) -> dict[str, int]:
        """Each verdict's position, worst first (0 = malicious)."""
        return {verdict.value: rank for rank, verdict in enumerate(cls.worst_first())}

    @classmethod
    def flagged(cls) -> tuple[Verdict, ...]:
        """The verdicts that raise an alert."""
        return (cls.MALICIOUS, cls.SUSPICIOUS)


class IncidentSeverity(StrEnum):
    """How bad the narrator judges an incident, least severe first."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionPriority(StrEnum):
    """How soon a narrated remediation should run, most urgent first."""

    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoveragePosture(StrEnum):
    """How well the loaded YARA rules cover this host."""

    WELL_COVERED = "well_covered"
    PARTIAL = "partial"
    THIN = "thin"


class RiskGrade(StrEnum):
    """The posture score as a school letter grade."""

    EXCELLENT = "A"
    GOOD = "B"
    FAIR = "C"
    POOR = "D"
    FAILING = "F"


class ThreatCategory(StrEnum):
    NONE = "none"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    RECONNAISSANCE = "reconnaissance"


class MaintenanceCommand(StrEnum):
    """One-shot commands the dashboard queues and the monitor runs."""

    PRUNE = "prune"
    CLEAR = "clear"
    REJUDGE = "rejudge"
    RENARRATE = "renarrate"
    RESET_BASELINE = "reset_baseline"


class FeedbackLabel(StrEnum):
    """Operator correction on a finding, fed back into judging."""

    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


class LaunchScope(StrEnum):
    USER_AGENT = "user_agent"
    SYSTEM_AGENT = "system_agent"
    SYSTEM_DAEMON = "system_daemon"
    APPLE_AGENT = "apple_agent"
    APPLE_DAEMON = "apple_daemon"


class Browser(StrEnum):
    CHROME = "chrome"
    CHROME_BETA = "chrome_beta"
    CHROMIUM = "chromium"
    BRAVE = "brave"
    EDGE = "edge"
    ARC = "arc"
    VIVALDI = "vivaldi"
    FIREFOX = "firefox"
