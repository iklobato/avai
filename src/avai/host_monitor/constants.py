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

# Collector whose findings carry YARA rule context (rule meta + matched
# strings) the Runner attaches to the judge payload for FP triage.
_FILE_SCAN_COLLECTOR = "file_scan"

# Persistence collector whose entries are correlated with the runtime
# behaviour of the process their program spawns (program → pid → story).
_LAUNCH_ITEM_COLLECTOR = "launch_items"


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


# --- File scanning (YARA) ---
# Bundled + user YARA rules live here; the FileScanCollector compiles
# every *.yar / *.yara found, once per process. Override via the env var.
YARA_RULES_DIR = Path(os.environ.get("AVAI_YARA_RULES_DIR", str(_PKG_DIR / "rules")))

# Skip files larger than this — YARA reads the whole file. On the measured
# target set (bin dirs + recent Downloads) p99 ≈ 9 MB, so 64 MB covers
# virtually every real binary while skipping multi-hundred-MB media / DMG
# outliers (observed max ≈ 372 MB). Large app executables are further
# bounded by the per-file match timeout below.
YARA_MAX_FILE_BYTES = 64 * 1024 * 1024

# Per-file match timeout (seconds): caps worst-case cost on a large binary
# so a single file can't stall the collection cycle.
YARA_MATCH_TIMEOUT_S = 30

# Hard cap on files scanned per cycle. The bounded target set measures
# ~1.3k files on a typical host; 5k is generous headroom and a runaway
# backstop (a home full of recent files can't blow out the cycle).
YARA_MAX_FILES_PER_CYCLE = 5000

# Only (re)scan Downloads modified within this window — freshly delivered
# payloads are the signal; re-hashing tens of thousands of old downloads
# every cycle is not (measured: 12 recent vs 72k total).
YARA_DOWNLOADS_RECENT_DAYS = 7

# When a rule matches, surface a bounded, redacted sample of the bytes that
# actually matched to the judge so it can tell a substantive hit (a real C2
# URL / mutex / command line) from a generic substring (a likely false
# positive). Caps keep binary blobs and pathological match counts out of the
# prompt and the DB. A broad hunting rule on a big binary can yield thousands
# of instances; 20 entries at 80 bytes each is enough context to triage.
YARA_MAX_MATCH_STRINGS = 20
YARA_MATCH_STRING_MAX_BYTES = 80

# Offline known-bad hash deny-list consumed by LocalHashDenylistEnricher:
# one hex digest (md5 / sha1 / sha256) per line, '#' comments allowed. An
# absent file ⇒ the enricher loads empty and simply gives no opinion.
HASH_DENYLIST_PATH = Path(
    os.environ.get("AVAI_HASH_DENYLIST", str(_PKG_DIR / "rules" / "hash_denylist.txt"))
)
