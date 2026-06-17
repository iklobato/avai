"""Typed categorical enums shared across the monitor."""
from __future__ import annotations

from enum import StrEnum


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


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
