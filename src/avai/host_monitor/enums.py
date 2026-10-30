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


class MonitorState(StrEnum):
    """What the monitor loop reports in its heartbeat."""

    PAUSED = "paused"
    RUNNING = "running"
    SCANNING = "scanning"


class PrivilegeKind(StrEnum):
    """What a privilege_config row describes."""

    SUDOERS = "sudoers"
    ACCOUNT = "account"
    GROUP = "group"


class BehaviorKind(StrEnum):
    """The kinds of process behaviour the judge sees as correlation context."""

    PORTS = "ports"
    FLOWS = "flows"
    CONNS = "conns"
    DNS = "dns"
    EXEC = "exec"


class VerifyOutcome(StrEnum):
    """What the skeptic second pass decided about a malicious verdict."""

    AGREED = "agreed"
    REFUTED = "refuted"
    FAILED = "failed"


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


class LinuxLaunchScope(StrEnum):
    """Where a Linux launch item comes from (systemd unit or cron entry)."""

    SYSTEM_SERVICE = "system_service"
    USER_SERVICE = "user_service"
    SYSTEM_TIMER = "system_timer"
    USER_TIMER = "user_timer"
    SYSTEM_CRONTAB = "system_crontab"
    SYSTEM_CRONTAB_D = "system_crontab_d"
    USER_CRONTAB = "user_crontab"


class LogLevel(StrEnum):
    """Syslog severities (RFC 5424), most severe first, so a member's
    position is its syslog PRIORITY number."""

    EMERG = "emerg"
    ALERT = "alert"
    CRIT = "crit"
    ERR = "err"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"

    @classmethod
    def from_priority(cls, priority: str) -> LogLevel | None:
        """The level of a journald PRIORITY ("0".."7"), None for anything else."""
        return {str(number): level for number, level in enumerate(cls)}.get(priority)

    @classmethod
    def errors(cls) -> frozenset[LogLevel]:
        return frozenset({cls.EMERG, cls.ALERT, cls.CRIT, cls.ERR})


class SelinuxMode(StrEnum):
    ENFORCING = "Enforcing"
    PERMISSIVE = "Permissive"
    UNKNOWN = "Unknown"

    @classmethod
    def from_flag(cls, flag: str) -> SelinuxMode:
        """The mode of /sys/fs/selinux/enforce ("0" or "1")."""
        return {"0": cls.PERMISSIVE, "1": cls.ENFORCING}.get(flag, cls.UNKNOWN)


class ScanSource(StrEnum):
    """Which bounded file set a YARA-scanned file came from."""

    BIN_DIRS = "bin_dirs"
    APP_BUNDLE = "app_bundle"
    DOWNLOADS = "downloads"


class YaraSkipReason(StrEnum):
    """Why a rules file was left out of the compiled ruleset."""

    NEEDS_CRYPTO = "needs crypto-enabled yara"
    OTHER = "other"


class DnsQueryType(StrEnum):
    """The dns_queries.qtype values avai writes itself; captured queries
    carry the wire type (A, AAAA, ...) as given."""

    DNS_OVER_HTTPS = "DoH"


class Browser(StrEnum):
    CHROME = "chrome"
    CHROME_BETA = "chrome_beta"
    CHROMIUM = "chromium"
    BRAVE = "brave"
    EDGE = "edge"
    ARC = "arc"
    VIVALDI = "vivaldi"
    FIREFOX = "firefox"
