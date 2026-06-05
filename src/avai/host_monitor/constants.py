"""Defaults, tunables, pricing tables, and static data tables."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from .enums import Browser, LaunchScope

LOG = logging.getLogger("host_monitor")


_PKG_DIR = Path(__file__).resolve().parent.parent


DEFAULT_DB_PATH = Path.home() / ".avai" / "avai.db"


DEFAULT_INTERVAL = 300


DEFAULT_LOOKBACK_MIN = 6


DEFAULT_JUDGE_MODEL = "claude-haiku-4-5-20251001"


DEFAULT_JUDGE_BATCH = 20


DEFAULT_JUDGE_MAX_PER_COLLECTOR = 25


DEFAULT_JUDGE_TIMEOUT_S = 60


DEFAULT_BASELINE_MIN_RUNS = 12


_CORRELATED_COLLECTOR = "processes"


DEFAULT_NARRATIVE_MODEL = DEFAULT_JUDGE_MODEL


RISK_WEIGHTS = {
    "filevault_off": 15,
    "firewall_off": 15,
    "gatekeeper_off": 12,
    "stealth_off": 3,
    "ssh_on": 10,
    "screen_sharing_on": 8,
    "remote_mgmt_on": 10,
    "malicious_each": 20,
    "malicious_cap": 40,
    "suspicious_each": 8,
    "suspicious_cap": 24,
    "nopasswd_each": 10,
    "nopasswd_cap": 20,
    "uid0_each": 15,
    "uid0_cap": 30,
}


RISK_GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


MODEL_PRICING = {
    "haiku": (1.0, 5.0),
    "sonnet": (3.0, 15.0),
    "opus": (15.0, 75.0),
}


DEFAULT_PRICING = (1.0, 5.0)


DEFAULT_PROMPTS_PATH = _PKG_DIR / "prompts.toml"


WATCHED_FILES = [
    "~/.ssh/authorized_keys",
    "~/.ssh/known_hosts",
    "~/.ssh/config",
    "~/.ssh/id_rsa.pub",
    "~/.ssh/id_ed25519.pub",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.gitconfig",
    "~/.aws/credentials",
    "~/.aws/config",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/sudoers",
    "/etc/pam.d/sudo",
    "/etc/pam.d/login",
    "/etc/ssh/sshd_config",
]


LAUNCH_DIRS: list[tuple[LaunchScope, str]] = [
    (LaunchScope.USER_AGENT, "~/Library/LaunchAgents"),
    (LaunchScope.SYSTEM_AGENT, "/Library/LaunchAgents"),
    (LaunchScope.SYSTEM_DAEMON, "/Library/LaunchDaemons"),
    (LaunchScope.APPLE_AGENT, "/System/Library/LaunchAgents"),
    (LaunchScope.APPLE_DAEMON, "/System/Library/LaunchDaemons"),
]


BROWSER_PROFILES: dict[Browser, list[str]] = {
    Browser.CHROME: ["~/Library/Application Support/Google/Chrome"],
    Browser.CHROME_BETA: ["~/Library/Application Support/Google/Chrome Beta"],
    Browser.CHROMIUM: ["~/Library/Application Support/Chromium"],
    Browser.BRAVE: ["~/Library/Application Support/BraveSoftware/Brave-Browser"],
    Browser.EDGE: ["~/Library/Application Support/Microsoft Edge"],
    Browser.ARC: ["~/Library/Application Support/Arc/User Data"],
    Browser.VIVALDI: ["~/Library/Application Support/Vivaldi"],
    Browser.FIREFOX: ["~/Library/Application Support/Firefox"],
}


BROWSER_PROFILES_LINUX: dict[Browser, list[str]] = {
    Browser.CHROME: ["~/.config/google-chrome"],
    Browser.CHROMIUM: ["~/.config/chromium"],
    Browser.BRAVE: ["~/.config/BraveSoftware/Brave-Browser"],
    Browser.EDGE: ["~/.config/microsoft-edge"],
    Browser.VIVALDI: ["~/.config/vivaldi"],
    Browser.FIREFOX: ["~/.mozilla/firefox"],
}


WATCHED_FILES_LINUX = [
    "~/.ssh/authorized_keys",
    "~/.ssh/known_hosts",
    "~/.ssh/config",
    "~/.ssh/id_rsa.pub",
    "~/.ssh/id_ed25519.pub",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.gitconfig",
    "~/.aws/credentials",
    "~/.aws/config",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/crontab",
    "/etc/pam.d/sudo",
    "/etc/pam.d/login",
    "/etc/pam.d/su",
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
    "/root/.ssh/authorized_keys",
    "/root/.bashrc",
]


AUTH_LOG_PREDICATE = " OR ".join(
    [
        'subsystem == "com.apple.securityd"',
        'process == "sudo"',
        'process == "loginwindow"',
        'process == "authd"',
        'process == "sshd"',
        'process == "screensharingd"',
        'subsystem == "com.apple.TCC"',
        'subsystem == "com.apple.syspolicy"',
        'subsystem == "com.apple.opendirectoryd"',
    ]
)


APP_INFO_KEYS = (
    "CFBundleIdentifier",
    "CFBundleName",
    "CFBundleDisplayName",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "LSMinimumSystemVersion",
    "NSHumanReadableCopyright",
)


HOST_PREFIX = os.environ.get("HOST_PREFIX", "").rstrip("/")
