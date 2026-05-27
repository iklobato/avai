#!/usr/bin/env python3
"""host_monitor.py — macOS host security telemetry + LLM threat judge.

Architecture
------------
Five responsibilities, five abstractions:

  Collector  — one slice of host state. References a SQLAlchemy model
               (its table), and declares which fields form the
               LLM-judgeable content. Yields plain dict rows.

  Model      — SQLAlchemy ORM class for a collector table. Owns its
               schema (columns, indexes, types).

  Sink       — repository over a SQLAlchemy engine. Owns DDL bootstrap,
               run lifecycle, row writes, judgment writes, and "what is
               unjudged" lookups. No raw SQL.

  Judge      — classifies content as a security threat. ``LlmJudge``
               uses litellm; ``NullJudge`` is the no-op fallback.
               Verdicts and categories are typed (StrEnum).

  Runner     — orchestrates: per-collector transaction, error capture,
               content-hash injection, judge invocation, scheduling.

Each row gets a deterministic ``content_hash`` over the collector's
declared judgeable fields. Judgments are keyed by that hash, so the
same entity is sent to the LLM exactly once.

Every macOS data source is consumed in its structured form — JSON
output, plist via plistlib, SQLite via reflected ORM. No regex or
ad-hoc text parsing.

Requires: Python 3.11+, psutil, sqlalchemy, and (optional but
recommended) litellm + a provider API key (``ANTHROPIC_API_KEY``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import plistlib
import socket
import sqlite3
import subprocess
import sys
import time
import tomllib
import uuid
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from string import Template
from typing import Any, ClassVar, Iterable, Optional

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

try:
    from sqlalchemy import (
        Engine, MetaData, Table, create_engine, event, exists, select, update,
    )
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
except ImportError:
    sys.stderr.write("Required: pip install sqlalchemy>=2.0\n")
    sys.exit(2)

try:
    import litellm
    HAS_LITELLM = True
except ImportError:
    HAS_LITELLM = False


LOG = logging.getLogger("host_monitor")


# ============================================================================
# Defaults
# ============================================================================

_SCRIPT_DIR = Path(__file__).resolve().parent

DEFAULT_DB_PATH = _SCRIPT_DIR / "host_monitor.db"
DEFAULT_INTERVAL = 300
DEFAULT_LOOKBACK_MIN = 6

DEFAULT_JUDGE_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_JUDGE_BATCH = 20
DEFAULT_JUDGE_MAX_PER_COLLECTOR = 200

DEFAULT_PROMPTS_PATH = _SCRIPT_DIR / "host_monitor_prompts.toml"


# ============================================================================
# Enums — typed categoricals
# ============================================================================

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


class TccScope(StrEnum):
    USER = "user"
    SYSTEM = "system"


# ============================================================================
# Data configuration
# ============================================================================

WATCHED_FILES = [
    "~/.ssh/authorized_keys", "~/.ssh/known_hosts", "~/.ssh/config",
    "~/.ssh/id_rsa.pub", "~/.ssh/id_ed25519.pub",
    "~/.zshrc", "~/.zprofile", "~/.zshenv",
    "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.gitconfig", "~/.aws/credentials", "~/.aws/config",
    "/etc/hosts", "/etc/resolv.conf", "/etc/sudoers",
    "/etc/pam.d/sudo", "/etc/pam.d/login", "/etc/ssh/sshd_config",
]

LAUNCH_DIRS: list[tuple[LaunchScope, str]] = [
    (LaunchScope.USER_AGENT,    "~/Library/LaunchAgents"),
    (LaunchScope.SYSTEM_AGENT,  "/Library/LaunchAgents"),
    (LaunchScope.SYSTEM_DAEMON, "/Library/LaunchDaemons"),
    (LaunchScope.APPLE_AGENT,   "/System/Library/LaunchAgents"),
    (LaunchScope.APPLE_DAEMON,  "/System/Library/LaunchDaemons"),
]

BROWSER_PROFILES: dict[Browser, list[str]] = {
    Browser.CHROME:      ["~/Library/Application Support/Google/Chrome"],
    Browser.CHROME_BETA: ["~/Library/Application Support/Google/Chrome Beta"],
    Browser.CHROMIUM:    ["~/Library/Application Support/Chromium"],
    Browser.BRAVE:       ["~/Library/Application Support/BraveSoftware/Brave-Browser"],
    Browser.EDGE:        ["~/Library/Application Support/Microsoft Edge"],
    Browser.ARC:         ["~/Library/Application Support/Arc/User Data"],
    Browser.VIVALDI:     ["~/Library/Application Support/Vivaldi"],
    Browser.FIREFOX:     ["~/Library/Application Support/Firefox"],
}

TCC_SOURCES: list[tuple[TccScope, str]] = [
    (TccScope.USER,   "~/Library/Application Support/com.apple.TCC/TCC.db"),
    (TccScope.SYSTEM, "/Library/Application Support/com.apple.TCC/TCC.db"),
]

AUTH_LOG_PREDICATE = " OR ".join([
    'subsystem == "com.apple.securityd"',
    'process == "sudo"',
    'process == "loginwindow"',
    'process == "authd"',
    'process == "sshd"',
    'process == "screensharingd"',
    'subsystem == "com.apple.TCC"',
    'subsystem == "com.apple.syspolicy"',
    'subsystem == "com.apple.opendirectoryd"',
])

APP_INFO_KEYS = (
    "CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName",
    "CFBundleShortVersionString", "CFBundleVersion",
    "LSMinimumSystemVersion", "NSHumanReadableCopyright",
)


# ============================================================================
# Source helpers — wrap structured data sources
# ============================================================================

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def run_json(cmd: list[str], timeout: int = 60) -> Any:
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} rc={r.returncode}: "
                           f"{r.stderr.decode(errors='replace')[:200]}")
    return json.loads(r.stdout) if r.stdout else None


def run_ndjson(cmd: list[str], timeout: int = 180) -> Iterable[dict]:
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} rc={r.returncode}: "
                           f"{r.stderr.decode(errors='replace')[:200]}")
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def exit_code(cmd: list[str], timeout: int = 10) -> Optional[int]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        return r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def service_loaded(label: str) -> Optional[int]:
    code = exit_code(["launchctl", "list", label])
    return None if code is None else int(code == 0)


def sha256_file(path: Path, chunk: int = 65536) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def read_plist(path: Path) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    return data if isinstance(data, dict) else None


def jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def external_sqlite_rows(path: Path, table_name: str,
                         columns: list[str]) -> Iterable[dict]:
    """Reflect an external SQLite table and yield row dicts. No raw SQL."""
    url = f"sqlite:///file:{path}?mode=ro&uri=true"
    engine = create_engine(url)
    try:
        meta = MetaData()
        table = Table(table_name, meta, autoload_with=engine)
        stmt = select(*(table.c[c] for c in columns))
        with engine.connect() as conn:
            for row in conn.execute(stmt):
                yield dict(row._mapping)
    finally:
        engine.dispose()


def safe_psutil_connections() -> list:
    try:
        return psutil.net_connections(kind="inet")
    except psutil.AccessDenied as e:
        raise PermissionError(
            "psutil.net_connections requires root for full visibility"
        ) from e


def content_hash(row: dict, fields: Iterable[str]) -> Optional[str]:
    """Stable SHA-256 over the declared judgeable fields of a row."""
    keys = list(fields)
    if not keys:
        return None
    canonical = json.dumps(
        [row.get(k) for k in keys],
        ensure_ascii=False, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def coerce_enum(value: Any, enum_cls, default):
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default


# ============================================================================
# Prompt loading
# ============================================================================

@dataclass(frozen=True)
class Prompts:
    """All LLM-facing strings, loaded from an external TOML file.

    ``system`` is the fully-substituted system prompt (verdict /
    category lists already injected). ``user_template`` is a
    string.Template using ``$collector``, ``$hints``, ``$entries``.
    """
    system:           str
    user_template:    str
    collector_hints:  dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Prompts":
        with open(path, "rb") as f:
            data = tomllib.load(f)
        judge = data.get("judge") or {}
        raw_system = judge.get("system", "")
        system = Template(raw_system).safe_substitute(
            verdicts=" | ".join(str(v) for v in Verdict),
            categories=", ".join(str(c) for c in ThreatCategory),
        )
        return cls(
            system=system,
            user_template=judge.get("user_template", ""),
            collector_hints=dict(data.get("collector_hints") or {}),
        )

    def hint_for(self, collector_name: str) -> str:
        return self.collector_hints.get(collector_name, "")


# ============================================================================
# Judge layer
# ============================================================================

@dataclass(frozen=True)
class Judgment:
    content_hash: str
    collector:    str
    verdict:      Verdict
    category:     ThreatCategory
    confidence:   float
    reasoning:    str
    model:        str
    created_at:   str


class Judge(ABC):
    """Classifies entries as security threats."""

    @abstractmethod
    def judge(self, collector: str, hints: str,
              entries: list[dict]) -> list[Judgment]: ...


class NullJudge(Judge):
    def judge(self, collector, hints, entries):
        return []


class CompletionClient(ABC):
    """Strategy for issuing an LLM chat completion. Returns the raw
    response text — JSON parsing happens in the caller."""

    @abstractmethod
    def complete(self, *, model: str, system: str, user: str,
                 max_tokens: int, temperature: float) -> str: ...


class LitellmClient(CompletionClient):
    """Multi-provider completion via litellm. Uses ANTHROPIC_API_KEY /
    OPENAI_API_KEY / ... from the environment per litellm conventions."""

    def __init__(self):
        if not HAS_LITELLM:
            raise RuntimeError(
                "litellm is required for LitellmClient — pip install litellm"
            )

    def complete(self, *, model, system, user, max_tokens, temperature):
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content


class AnthropicOAuthClient(CompletionClient):
    """Anthropic completion via the OAuth Bearer flow used by Claude Code
    subscriptions. Reads ``CLAUDE_CODE_OAUTH_TOKEN`` from the environment
    and sends ``Authorization: Bearer <token>`` plus the OAuth beta
    header. Bypasses litellm because litellm sends ``x-api-key`` which
    is incompatible with OAuth tokens.

    The Claude Code OAuth scope requires the system prompt to start with
    the Claude Code identity line; otherwise the API returns an empty
    response. We prepend it transparently.
    """

    OAUTH_BETA_HEADER = "oauth-2025-04-20"
    SYSTEM_PROMPT_PREFIX = (
        "You are Claude Code, Anthropic's official CLI for Claude."
    )

    def __init__(self, oauth_token: str):
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK is required for OAuth auth — "
                "pip install anthropic"
            ) from e
        self._client = Anthropic(
            auth_token=oauth_token,
            default_headers={"anthropic-beta": self.OAUTH_BETA_HEADER},
        )

    def complete(self, *, model, system, user, max_tokens, temperature):
        # Strip litellm-style provider prefix if present.
        if "/" in model:
            model = model.split("/", 1)[1]
        full_system = f"{self.SYSTEM_PROMPT_PREFIX}\n\n{system}"
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=full_system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text if response.content else ""


def build_completion_client() -> CompletionClient:
    """Pick the right strategy from the environment.

    - ``CLAUDE_CODE_OAUTH_TOKEN`` set → ``AnthropicOAuthClient``
    - otherwise → ``LitellmClient`` (which itself reads
      ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` / ...)
    """
    oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    if oauth:
        return AnthropicOAuthClient(oauth)
    return LitellmClient()


class LlmJudge(Judge):
    """Threat judge backed by an LLM. Auth strategy is decided by
    ``build_completion_client()`` (OAuth → Anthropic SDK; API key →
    litellm). Prompts are injected via the ``Prompts`` object."""

    def __init__(self, prompts: Prompts,
                 model: str = DEFAULT_JUDGE_MODEL,
                 batch_size: int = DEFAULT_JUDGE_BATCH,
                 max_per_collector: int = DEFAULT_JUDGE_MAX_PER_COLLECTOR,
                 temperature: float = 0.0,
                 max_tokens: int = 4096,
                 client: Optional[CompletionClient] = None):
        self.prompts = prompts
        self.model = model
        self.batch_size = batch_size
        self.max_per_collector = max_per_collector
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._user_template = Template(prompts.user_template)
        self._client = client or build_completion_client()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def judge(self, collector, hints, entries):
        if not entries:
            return []
        if self.max_per_collector and len(entries) > self.max_per_collector:
            LOG.info("judge collector=%s capping entries %d -> %d",
                     collector, len(entries), self.max_per_collector)
            entries = entries[:self.max_per_collector]

        now = utcnow()
        results: list[Judgment] = []
        for batch in self._batches(entries):
            try:
                results.extend(self._call(collector, hints, batch, now))
            except Exception as exc:
                LOG.warning("judge batch failed collector=%s error=%s msg=%s",
                            collector, type(exc).__name__, str(exc)[:200])
        return results

    def _batches(self, entries):
        for i in range(0, len(entries), self.batch_size):
            yield entries[i:i + self.batch_size]

    def _call(self, collector, hints, batch, now):
        payload = [
            {"index": i, **{k: v for k, v in e.items()
                            if k != "content_hash" and v is not None}}
            for i, e in enumerate(batch)
        ]
        user = self._user_template.safe_substitute(
            collector=collector,
            hints=hints,
            entries=json.dumps(payload, ensure_ascii=False),
        )
        content = self._client.complete(
            model=self.model,
            system=self.prompts.system,
            user=user,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        parsed = json.loads(content)
        return list(self._parse(parsed, batch, collector, now))

    def _parse(self, parsed, batch, collector, now):
        for item in parsed.get("judgments", []) or []:
            idx = item.get("index")
            if not isinstance(idx, int) or not (0 <= idx < len(batch)):
                continue
            try:
                confidence = float(item.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            yield Judgment(
                content_hash=batch[idx]["content_hash"],
                collector=collector,
                verdict=coerce_enum(item.get("verdict"), Verdict, Verdict.UNKNOWN),
                category=coerce_enum(item.get("category"), ThreatCategory,
                                     ThreatCategory.NONE),
                confidence=max(0.0, min(1.0, confidence)),
                reasoning=str(item.get("reasoning") or "")[:500],
                model=self.model,
                created_at=now,
            )


# ============================================================================
# SQLAlchemy ORM — models = schema
# ============================================================================

class Base(DeclarativeBase):
    pass


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    run_id:            Mapped[str] = mapped_column(primary_key=True)
    started_at:        Mapped[str]
    finished_at:       Mapped[Optional[str]]
    hostname:          Mapped[str]
    collectors_ok:     Mapped[int] = mapped_column(default=0)
    collectors_failed: Mapped[int] = mapped_column(default=0)
    lookback_min:      Mapped[int]


class CollectorErrorRow(Base):
    __tablename__ = "collector_errors"
    id:          Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id:      Mapped[str] = mapped_column(index=True)
    collector:   Mapped[str]
    error_class: Mapped[Optional[str]]
    message:     Mapped[Optional[str]]
    occurred_at: Mapped[str]


class Judgement(Base):
    __tablename__ = "judgements"
    content_hash: Mapped[str] = mapped_column(primary_key=True)
    collector:    Mapped[str] = mapped_column(primary_key=True, index=True)
    verdict:      Mapped[str] = mapped_column(index=True)
    category:     Mapped[Optional[str]]
    confidence:   Mapped[Optional[float]]
    reasoning:    Mapped[Optional[str]]
    model:        Mapped[str]
    created_at:   Mapped[str]


class _RowBase(Base):
    """Common columns for every collector table."""
    __abstract__ = True
    id:           Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id:       Mapped[str] = mapped_column(index=True)
    collected_at: Mapped[str]
    content_hash: Mapped[Optional[str]] = mapped_column(index=True)


class ProcessRow(_RowBase):
    __tablename__ = "processes"
    pid:          Mapped[int]
    ppid:         Mapped[Optional[int]]
    name:         Mapped[Optional[str]] = mapped_column(index=True)
    exe:          Mapped[Optional[str]]
    cmdline_json: Mapped[Optional[str]]
    username:     Mapped[Optional[str]]
    uid:          Mapped[Optional[int]]
    status:       Mapped[Optional[str]]
    create_time:  Mapped[Optional[float]]
    cpu_percent:  Mapped[Optional[float]]
    memory_rss:   Mapped[Optional[int]]
    num_fds:      Mapped[Optional[int]]
    num_threads:  Mapped[Optional[int]]


class NetworkConnectionRow(_RowBase):
    __tablename__ = "network_connections"
    pid:        Mapped[Optional[int]]
    family:     Mapped[Optional[str]]
    type:       Mapped[Optional[str]]
    laddr_ip:   Mapped[Optional[str]]
    laddr_port: Mapped[Optional[int]]
    raddr_ip:   Mapped[Optional[str]] = mapped_column(index=True)
    raddr_port: Mapped[Optional[int]]
    status:     Mapped[Optional[str]]


class ListeningPortRow(_RowBase):
    __tablename__ = "listening_ports"
    pid:          Mapped[Optional[int]]
    process_name: Mapped[Optional[str]]
    family:       Mapped[Optional[str]]
    type:         Mapped[Optional[str]]
    laddr_ip:     Mapped[Optional[str]]
    laddr_port:   Mapped[Optional[int]]


class NetworkInterfaceRow(_RowBase):
    __tablename__ = "network_interfaces"
    name:           Mapped[str]
    is_up:          Mapped[Optional[int]]
    speed_mbps:     Mapped[Optional[int]]
    mtu:            Mapped[Optional[int]]
    bytes_sent:     Mapped[Optional[int]]
    bytes_recv:     Mapped[Optional[int]]
    packets_sent:   Mapped[Optional[int]]
    packets_recv:   Mapped[Optional[int]]
    errin:          Mapped[Optional[int]]
    errout:         Mapped[Optional[int]]
    dropin:         Mapped[Optional[int]]
    dropout:        Mapped[Optional[int]]
    addresses_json: Mapped[Optional[str]]


class UsbDeviceRow(_RowBase):
    __tablename__ = "usb_devices"
    name:          Mapped[Optional[str]]
    vendor_id:     Mapped[Optional[str]]
    product_id:    Mapped[Optional[str]]
    serial_number: Mapped[Optional[str]]
    manufacturer:  Mapped[Optional[str]]
    location_id:   Mapped[Optional[str]]
    speed:         Mapped[Optional[str]]
    raw_json:      Mapped[Optional[str]]


class BluetoothDeviceRow(_RowBase):
    __tablename__ = "bluetooth_devices"
    name:       Mapped[Optional[str]]
    address:    Mapped[Optional[str]]
    connected:  Mapped[Optional[int]]
    paired:     Mapped[Optional[int]]
    minor_type: Mapped[Optional[str]]
    raw_json:   Mapped[Optional[str]]


class WifiStateRow(_RowBase):
    __tablename__ = "wifi_state"
    interface: Mapped[Optional[str]]
    ssid:      Mapped[Optional[str]]
    bssid:     Mapped[Optional[str]]
    channel:   Mapped[Optional[str]]
    security:  Mapped[Optional[str]]
    raw_json:  Mapped[Optional[str]]


class LaunchItemRow(_RowBase):
    __tablename__ = "launch_items"
    scope:                        Mapped[str]
    path:                         Mapped[str] = mapped_column(index=True)
    label:                        Mapped[Optional[str]] = mapped_column(index=True)
    program:                      Mapped[Optional[str]]
    program_arguments_json:       Mapped[Optional[str]]
    run_at_load:                  Mapped[Optional[int]]
    keep_alive:                   Mapped[Optional[int]]
    start_interval:               Mapped[Optional[int]]
    start_calendar_interval_json: Mapped[Optional[str]]
    user_name:                    Mapped[Optional[str]]
    group_name:                   Mapped[Optional[str]]
    sha256:                       Mapped[Optional[str]]
    mtime:                        Mapped[Optional[float]]
    raw_json:                     Mapped[Optional[str]]


class TccPermissionRow(_RowBase):
    __tablename__ = "tcc_permissions"
    scope:         Mapped[str]
    service:       Mapped[Optional[str]]
    client:        Mapped[Optional[str]]
    client_type:   Mapped[Optional[int]]
    auth_value:    Mapped[Optional[int]]
    auth_reason:   Mapped[Optional[int]]
    last_modified: Mapped[Optional[int]]


class QuarantineEventRow(_RowBase):
    __tablename__ = "quarantine_events"
    event_id:        Mapped[Optional[str]]
    timestamp:       Mapped[Optional[float]]
    agent_bundle_id: Mapped[Optional[str]]
    agent_name:      Mapped[Optional[str]]
    origin_url:      Mapped[Optional[str]]
    data_url:        Mapped[Optional[str]]
    sender_name:     Mapped[Optional[str]]
    type_number:     Mapped[Optional[int]]


class BrowserExtensionRow(_RowBase):
    __tablename__ = "browser_extensions"
    browser:               Mapped[Optional[str]]
    profile:               Mapped[Optional[str]]
    extension_id:          Mapped[Optional[str]] = mapped_column(index=True)
    name:                  Mapped[Optional[str]]
    version:               Mapped[Optional[str]]
    permissions_json:      Mapped[Optional[str]]
    host_permissions_json: Mapped[Optional[str]]
    path:                  Mapped[Optional[str]]
    manifest_json:         Mapped[Optional[str]]


class SystemIntegrityRow(_RowBase):
    __tablename__ = "system_integrity"
    filevault_active:               Mapped[Optional[int]]
    firewall_global_state:          Mapped[Optional[int]]
    firewall_stealth:               Mapped[Optional[int]]
    firewall_logging:               Mapped[Optional[int]]
    gatekeeper_assessments_enabled: Mapped[Optional[int]]
    remote_login_enabled:           Mapped[Optional[int]]
    screen_sharing_enabled:         Mapped[Optional[int]]
    remote_management_enabled:      Mapped[Optional[int]]
    raw_json:                       Mapped[Optional[str]]


class AuthEventRow(_RowBase):
    __tablename__ = "auth_events"
    event_timestamp: Mapped[Optional[str]] = mapped_column(index=True)
    process:         Mapped[Optional[str]]
    subsystem:       Mapped[Optional[str]]
    category:        Mapped[Optional[str]]
    event_type:      Mapped[Optional[str]]
    event_message:   Mapped[Optional[str]]
    pid:             Mapped[Optional[int]]
    raw_json:        Mapped[Optional[str]]


class FileIntegrityRow(_RowBase):
    __tablename__ = "file_integrity"
    path:        Mapped[str] = mapped_column(index=True)
    sha256:      Mapped[Optional[str]]
    size:        Mapped[Optional[int]]
    mtime:       Mapped[Optional[float]]
    mode:        Mapped[Optional[int]]
    uid:         Mapped[Optional[int]]
    gid:         Mapped[Optional[int]]
    exists_flag: Mapped[Optional[int]]


class InstalledAppRow(_RowBase):
    __tablename__ = "installed_apps"
    path:      Mapped[str]
    bundle_id: Mapped[Optional[str]] = mapped_column(index=True)
    name:      Mapped[Optional[str]]
    version:   Mapped[Optional[str]]
    raw_json:  Mapped[Optional[str]]


# ============================================================================
# Core abstractions
# ============================================================================

class Collector(ABC):
    """One slice of host state. Subclasses point at a model and yield rows.

    Free-form text used to steer the LLM judge is injected per-instance
    via ``judge_hints`` (sourced from the external prompts TOML file).
    """

    name:           ClassVar[str]
    model:          ClassVar[type[_RowBase]]
    judge_enabled:  ClassVar[bool] = True
    judge_fields:   ClassVar[tuple[str, ...]] = ()

    def __init__(self, judge_hints: str = ""):
        self.judge_hints = judge_hints

    @property
    def table(self) -> str:
        return self.model.__tablename__

    @abstractmethod
    def collect(self) -> Iterable[dict]:
        """Yield row dicts for ``self.model``.

        ``run_id``, ``collected_at`` and ``content_hash`` are injected
        by the Runner — do not include them here.
        """


class Sink:
    """SQLAlchemy repository — owns schema, run lifecycle, writes, lookups."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.run_id: Optional[str] = None
        event.listen(engine, "connect", _set_sqlite_pragmas)

    def setup(self) -> None:
        Base.metadata.create_all(self.engine)

    def start_run(self, hostname: str, lookback_min: int) -> tuple[str, str]:
        run_id = str(uuid.uuid4())
        started = utcnow()
        with Session(self.engine) as session:
            session.add(CollectionRun(
                run_id=run_id, started_at=started,
                hostname=hostname, lookback_min=lookback_min,
            ))
            session.commit()
        self.run_id = run_id
        return run_id, started

    def end_run(self, ok: int, failed: int) -> None:
        with Session(self.engine) as session:
            session.execute(
                update(CollectionRun)
                .where(CollectionRun.run_id == self.run_id)
                .values(finished_at=utcnow(),
                        collectors_ok=ok, collectors_failed=failed)
            )
            session.commit()

    def write(self, model: type[_RowBase], rows: list[dict]) -> None:
        if not rows:
            return
        with Session(self.engine) as session:
            session.execute(sqlite_insert(model), rows)
            session.commit()

    def write_error(self, collector: str, exc: BaseException) -> None:
        with Session(self.engine) as session:
            session.add(CollectorErrorRow(
                run_id=self.run_id, collector=collector,
                error_class=type(exc).__name__,
                message=str(exc)[:1000],
                occurred_at=utcnow(),
            ))
            session.commit()

    def unjudged(self, collector: Collector) -> list[dict]:
        """Return one entry per distinct, unjudged content_hash for the
        current run (judge_fields drive what's selected)."""
        run_id = self.run_id
        if run_id is None or not collector.judge_fields:
            return []
        model = collector.model
        cols = [model.content_hash] + [getattr(model, f)
                                       for f in collector.judge_fields]
        stmt = (
            select(*cols).distinct()
            .where(model.run_id == run_id,
                   model.content_hash.is_not(None),
                   ~exists().where(
                       Judgement.content_hash == model.content_hash,
                       Judgement.collector == collector.name,
                   ))
        )
        col_names = ["content_hash"] + list(collector.judge_fields)
        with Session(self.engine) as session:
            return [
                {col_names[i]: row[i] for i in range(len(col_names))}
                for row in session.execute(stmt).all()
            ]

    def write_judgments(self, judgments: list[Judgment]) -> None:
        if not judgments:
            return
        rows = [
            {
                "content_hash": j.content_hash,
                "collector":    j.collector,
                "verdict":      str(j.verdict),
                "category":     str(j.category),
                "confidence":   j.confidence,
                "reasoning":    j.reasoning,
                "model":        j.model,
                "created_at":   j.created_at,
            }
            for j in judgments
        ]
        with Session(self.engine) as session:
            session.execute(
                sqlite_insert(Judgement).on_conflict_do_nothing(),
                rows,
            )
            session.commit()


def _set_sqlite_pragmas(dbapi_conn, _connection_record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


class Runner:
    """Drives collectors and the judge against a Sink."""

    def __init__(self, sink: Sink, collectors: list[Collector],
                 judge: Judge, lookback_min: int):
        self.sink = sink
        self.collectors = collectors
        self.judge = judge
        self.lookback_min = lookback_min

    def setup(self) -> None:
        self.sink.setup()

    def run_once(self) -> tuple[str, int, int]:
        run_id, started = self.sink.start_run(socket.gethostname(),
                                              self.lookback_min)
        ok = failed = 0
        for c in self.collectors:
            try:
                self._run_collector(c, run_id, started)
                ok += 1
            except Exception as exc:
                failed += 1
                self.sink.write_error(c.name, exc)
                LOG.warning("collector=%s status=failed error=%s message=%s",
                            c.name, type(exc).__name__, str(exc)[:200])
        self.sink.end_run(ok, failed)
        return run_id, ok, failed

    def _run_collector(self, c: Collector, run_id: str, started: str) -> None:
        t0 = time.monotonic()
        rows = list(c.collect())
        for r in rows:
            r["run_id"] = run_id
            r["collected_at"] = started
            r["content_hash"] = content_hash(r, c.judge_fields)
        self.sink.write(c.model, rows)
        collected_ms = int((time.monotonic() - t0) * 1000)

        judged = 0
        if c.judge_enabled and c.judge_fields:
            unjudged = self.sink.unjudged(c)
            if unjudged:
                judgments = self.judge.judge(c.name, c.judge_hints, unjudged)
                self.sink.write_judgments(judgments)
                judged = len(judgments)

        LOG.info("collector=%s rows=%d duration_ms=%d judged=%d",
                 c.name, len(rows), collected_ms, judged)

    def run_forever(self, interval: int) -> None:
        while True:
            t0 = time.monotonic()
            try:
                run_id, ok, failed = self.run_once()
                LOG.info("run complete run_id=%s ok=%d failed=%d",
                         run_id, ok, failed)
            except Exception:
                LOG.exception("run failed")
            sleep_for = max(0.0, interval - (time.monotonic() - t0))
            LOG.info("sleeping %.1fs", sleep_for)
            time.sleep(sleep_for)


# ============================================================================
# Strategies — pluggable readers for browser extensions
# ============================================================================

class BrowserExtensionReader(ABC):
    @abstractmethod
    def read(self, base: Path, browser: Browser) -> Iterable[dict]: ...


class ChromiumExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        try:
            profile_dirs = list(base.iterdir())
        except OSError:
            return
        for profile_dir in profile_dirs:
            ext_root = profile_dir / "Extensions"
            if not ext_root.is_dir():
                continue
            for ext_id_dir in ext_root.iterdir():
                if not ext_id_dir.is_dir():
                    continue
                for version_dir in ext_id_dir.iterdir():
                    manifest = version_dir / "manifest.json"
                    if not manifest.is_file():
                        continue
                    try:
                        m = json.loads(manifest.read_text(
                            encoding="utf-8", errors="replace"))
                    except (json.JSONDecodeError, OSError):
                        continue
                    yield {
                        "browser":               str(browser),
                        "profile":               profile_dir.name,
                        "extension_id":          ext_id_dir.name,
                        "name":                  m.get("name"),
                        "version":               m.get("version"),
                        "permissions_json":      json.dumps(m.get("permissions") or []),
                        "host_permissions_json": json.dumps(
                            m.get("host_permissions") or m.get("matches") or []),
                        "path":                  str(version_dir),
                        "manifest_json":         json.dumps(m),
                    }


class FirefoxExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        profiles_dir = base / "Profiles"
        if not profiles_dir.is_dir():
            return
        for profile_dir in profiles_dir.iterdir():
            ext_file = profile_dir / "extensions.json"
            if not ext_file.is_file():
                continue
            try:
                data = json.loads(ext_file.read_text(
                    encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            for addon in data.get("addons", []) or []:
                up = addon.get("userPermissions") or {}
                dl = addon.get("defaultLocale") or {}
                yield {
                    "browser":               str(browser),
                    "profile":               profile_dir.name,
                    "extension_id":          addon.get("id"),
                    "name":                  dl.get("name"),
                    "version":               addon.get("version"),
                    "permissions_json":      json.dumps(up.get("permissions") or []),
                    "host_permissions_json": json.dumps(up.get("origins") or []),
                    "path":                  addon.get("path"),
                    "manifest_json":         json.dumps(addon),
                }


# ============================================================================
# Concrete collectors
# ============================================================================

class ProcessCollector(Collector):
    name = "processes"
    model = ProcessRow
    judge_fields = ("name", "exe", "cmdline_json", "username")
    _ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "uids",
              "status", "create_time", "cpu_percent", "memory_info",
              "num_fds", "num_threads"]

    def collect(self):
        for p in psutil.process_iter(self._ATTRS, ad_value=None):
            info = p.info
            mem, uids = info.get("memory_info"), info.get("uids")
            yield {
                "pid":          info.get("pid"),
                "ppid":         info.get("ppid"),
                "name":         info.get("name"),
                "exe":          info.get("exe"),
                "cmdline_json": json.dumps(info.get("cmdline") or []),
                "username":     info.get("username"),
                "uid":          uids[0] if uids else None,
                "status":       info.get("status"),
                "create_time":  info.get("create_time"),
                "cpu_percent":  info.get("cpu_percent"),
                "memory_rss":   mem.rss if mem else None,
                "num_fds":      info.get("num_fds"),
                "num_threads":  info.get("num_threads"),
            }


class NetworkConnectionsCollector(Collector):
    name = "network_connections"
    model = NetworkConnectionRow
    judge_enabled = False  # too high churn; aggregate behaviourally instead

    def collect(self):
        for c in safe_psutil_connections():
            yield {
                "pid":        c.pid,
                "family":     c.family.name,
                "type":       c.type.name,
                "laddr_ip":   c.laddr.ip   if c.laddr else None,
                "laddr_port": c.laddr.port if c.laddr else None,
                "raddr_ip":   c.raddr.ip   if c.raddr else None,
                "raddr_port": c.raddr.port if c.raddr else None,
                "status":     c.status,
            }


class ListeningPortsCollector(Collector):
    name = "listening_ports"
    model = ListeningPortRow
    judge_fields = ("process_name", "family", "type", "laddr_ip", "laddr_port")

    def collect(self):
        names: dict[int, Optional[str]] = {}
        for c in safe_psutil_connections():
            if c.status != psutil.CONN_LISTEN:
                continue
            if c.pid is not None and c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[c.pid] = None
            yield {
                "pid":          c.pid,
                "process_name": names.get(c.pid) if c.pid else None,
                "family":       c.family.name,
                "type":         c.type.name,
                "laddr_ip":     c.laddr.ip   if c.laddr else None,
                "laddr_port":   c.laddr.port if c.laddr else None,
            }


class NetworkInterfacesCollector(Collector):
    name = "network_interfaces"
    model = NetworkInterfaceRow
    judge_enabled = False  # counters need behavioural analysis

    def collect(self):
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True)
        for name, addr_list in addrs.items():
            s, c = stats.get(name), counters.get(name)
            yield {
                "name":           name,
                "is_up":          int(s.isup) if s else None,
                "speed_mbps":     s.speed if s else None,
                "mtu":            s.mtu if s else None,
                "bytes_sent":     c.bytes_sent if c else None,
                "bytes_recv":     c.bytes_recv if c else None,
                "packets_sent":   c.packets_sent if c else None,
                "packets_recv":   c.packets_recv if c else None,
                "errin":          c.errin if c else None,
                "errout":         c.errout if c else None,
                "dropin":         c.dropin if c else None,
                "dropout":        c.dropout if c else None,
                "addresses_json": json.dumps([
                    {"family": a.family.name, "address": a.address,
                     "netmask": a.netmask, "broadcast": a.broadcast}
                    for a in addr_list
                ]),
            }


class UsbDevicesCollector(Collector):
    name = "usb_devices"
    model = UsbDeviceRow
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPUSBDataType"], timeout=30)
        root = data.get("SPUSBDataType", []) if isinstance(data, dict) else (data or [])
        yield from self._walk(root, None)

    def _walk(self, items, parent_location):
        for item in items or []:
            loc = item.get("location_id") or parent_location
            yield {
                "name":          item.get("_name"),
                "vendor_id":     item.get("vendor_id"),
                "product_id":    item.get("product_id"),
                "serial_number": item.get("serial_num"),
                "manufacturer":  item.get("manufacturer"),
                "location_id":   loc,
                "speed":         item.get("device_speed"),
                "raw_json":      json.dumps({k: jsonable(v)
                                             for k, v in item.items()
                                             if k != "_items"}),
            }
            yield from self._walk(item.get("_items"), loc)


class BluetoothCollector(Collector):
    name = "bluetooth_devices"
    model = BluetoothDeviceRow
    judge_fields = ("name", "address", "minor_type")
    _GROUPS = ("device_connected", "device_not_connected",
               "device_paired", "devices_list")
    _PAIRED_GROUPS = {"device_connected", "device_not_connected", "device_paired"}

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPBluetoothDataType"], timeout=30)
        sections = data.get("SPBluetoothDataType", []) if isinstance(data, dict) else (data or [])
        for section in sections:
            for group in self._GROUPS:
                for entry in section.get(group, []) or []:
                    if not isinstance(entry, dict):
                        continue
                    for dev_name, dev in entry.items():
                        if not isinstance(dev, dict):
                            continue
                        yield {
                            "name":       dev_name,
                            "address":    dev.get("device_address"),
                            "connected":  int(group == "device_connected"),
                            "paired":     int(group in self._PAIRED_GROUPS),
                            "minor_type": dev.get("device_minorType"),
                            "raw_json":   json.dumps(jsonable(dev)),
                        }


class WifiCollector(Collector):
    name = "wifi_state"
    model = WifiStateRow
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        data = run_json(["system_profiler", "-json", "SPAirPortDataType"], timeout=30)
        sections = data.get("SPAirPortDataType", []) if isinstance(data, dict) else (data or [])
        for entry in sections:
            for iface in entry.get("spairport_airport_interfaces", []) or []:
                cur = iface.get("spairport_current_network_information") or {}
                channel = cur.get("spairport_network_channel")
                yield {
                    "interface": iface.get("_name"),
                    "ssid":      cur.get("_name"),
                    "bssid":     cur.get("spairport_network_bssid"),
                    "channel":   str(channel) if channel is not None else None,
                    "security":  cur.get("spairport_security_mode"),
                    "raw_json":  json.dumps(jsonable(cur)),
                }


class LaunchItemsCollector(Collector):
    name = "launch_items"
    model = LaunchItemRow
    judge_fields = ("scope", "label", "program", "program_arguments_json",
                    "user_name", "run_at_load", "keep_alive")

    def collect(self):
        for scope, dir_str in LAUNCH_DIRS:
            d = expand(dir_str)
            if not d.is_dir():
                continue
            try:
                plists = list(d.glob("*.plist"))
            except PermissionError:
                continue
            for path in plists:
                row = self._row(scope, path)
                if row is not None:
                    yield row

    @staticmethod
    def _row(scope: LaunchScope, path: Path):
        data = read_plist(path)
        if data is None:
            return None
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        sci = data.get("StartCalendarInterval")
        return {
            "scope":                        str(scope),
            "path":                         str(path),
            "label":                        data.get("Label"),
            "program":                      data.get("Program"),
            "program_arguments_json":       json.dumps(jsonable(
                                                data.get("ProgramArguments") or [])),
            "run_at_load":                  int(bool(data.get("RunAtLoad"))),
            "keep_alive":                   int(bool(data.get("KeepAlive"))),
            "start_interval":               data.get("StartInterval"),
            "start_calendar_interval_json": json.dumps(jsonable(sci)) if sci is not None else None,
            "user_name":                    data.get("UserName"),
            "group_name":                   data.get("GroupName"),
            "sha256":                       sha256_file(path),
            "mtime":                        mtime,
            "raw_json":                     json.dumps(jsonable(data)),
        }


class TccCollector(Collector):
    name = "tcc_permissions"
    model = TccPermissionRow
    judge_fields = ("scope", "service", "client", "auth_value")
    _COLUMNS = ["service", "client", "client_type", "auth_value",
                "auth_reason", "last_modified"]

    def collect(self):
        errors: list[str] = []
        produced = False
        for scope, path_str in TCC_SOURCES:
            path = expand(path_str)
            if not path.exists():
                continue
            try:
                for row in external_sqlite_rows(path, "access", self._COLUMNS):
                    produced = True
                    yield {"scope": str(scope), **row}
            except Exception as e:
                errors.append(f"{scope.value}: {e}")
        if errors and not produced:
            raise PermissionError(
                "TCC.db unreadable (grant Full Disk Access): "
                + "; ".join(errors)
            )


class QuarantineCollector(Collector):
    name = "quarantine_events"
    model = QuarantineEventRow
    judge_fields = ("agent_bundle_id", "agent_name", "origin_url", "data_url")
    _COLUMN_MAP = {
        "LSQuarantineEventIdentifier":       "event_id",
        "LSQuarantineTimeStamp":             "timestamp",
        "LSQuarantineAgentBundleIdentifier": "agent_bundle_id",
        "LSQuarantineAgentName":             "agent_name",
        "LSQuarantineOriginURLString":       "origin_url",
        "LSQuarantineDataURLString":         "data_url",
        "LSQuarantineSenderName":            "sender_name",
        "LSQuarantineTypeNumber":            "type_number",
    }

    def collect(self):
        path = expand("~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        if not path.exists():
            return
        for row in external_sqlite_rows(path, "LSQuarantineEvent",
                                        list(self._COLUMN_MAP.keys())):
            yield {self._COLUMN_MAP[k]: v for k, v in row.items()}


class BrowserExtensionsCollector(Collector):
    name = "browser_extensions"
    model = BrowserExtensionRow
    judge_fields = ("browser", "extension_id", "name",
                    "permissions_json", "host_permissions_json")

    def __init__(self,
                 readers: Optional[dict[Browser, BrowserExtensionReader]] = None,
                 default_reader: Optional[BrowserExtensionReader] = None,
                 judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.readers = readers or {Browser.FIREFOX: FirefoxExtensionReader()}
        self.default_reader = default_reader or ChromiumExtensionReader()

    def collect(self):
        for browser, profiles in BROWSER_PROFILES.items():
            reader = self.readers.get(browser, self.default_reader)
            for base_str in profiles:
                base = expand(base_str)
                if not base.is_dir():
                    continue
                yield from reader.read(base, browser)


class SystemIntegrityCollector(Collector):
    name = "system_integrity"
    model = SystemIntegrityRow
    judge_fields = (
        "filevault_active", "firewall_global_state", "firewall_stealth",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled", "screen_sharing_enabled",
        "remote_management_enabled",
    )

    def collect(self):
        fv = exit_code(["fdesetup", "isactive"])
        gk = exit_code(["spctl", "--status"])
        alf = read_plist(Path("/Library/Preferences/com.apple.alf.plist")) or {}
        yield {
            "filevault_active":               None if fv is None else int(fv == 0),
            "firewall_global_state":          alf.get("globalstate"),
            "firewall_stealth":               int(bool(alf.get("stealthenabled")))
                                                if alf else None,
            "firewall_logging":               int(bool(alf.get("loggingenabled")))
                                                if alf else None,
            "gatekeeper_assessments_enabled": None if gk is None else int(gk == 0),
            "remote_login_enabled":           service_loaded("com.openssh.sshd"),
            "screen_sharing_enabled":         service_loaded("com.apple.screensharing"),
            "remote_management_enabled":      service_loaded("com.apple.RemoteDesktop.agent"),
            "raw_json":                       json.dumps({"alf": jsonable(alf)}),
        }


class AuthEventsCollector(Collector):
    name = "auth_events"
    model = AuthEventRow
    judge_enabled = False  # per-event judging is too noisy; aggregate later

    def __init__(self, lookback_min: int = DEFAULT_LOOKBACK_MIN,
                 predicate: str = AUTH_LOG_PREDICATE,
                 judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.lookback_min = lookback_min
        self.predicate = predicate

    def collect(self):
        cmd = ["log", "show", "--style", "ndjson",
               "--last", f"{self.lookback_min}m",
               "--info", "--predicate", self.predicate]
        for e in run_ndjson(cmd, timeout=180):
            yield {
                "event_timestamp": e.get("timestamp"),
                "process":         e.get("processImagePath"),
                "subsystem":       e.get("subsystem"),
                "category":        e.get("category"),
                "event_type":      e.get("eventType"),
                "event_message":   e.get("eventMessage"),
                "pid":             e.get("processID"),
                "raw_json":        json.dumps(e),
            }


class FileIntegrityCollector(Collector):
    name = "file_integrity"
    model = FileIntegrityRow
    judge_fields = ("path", "sha256", "exists_flag")

    def __init__(self, watched: Iterable[str] = WATCHED_FILES,
                 judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.watched = list(watched)

    def collect(self):
        for path_str in self.watched:
            p = expand(path_str)
            try:
                st = p.lstat()
            except FileNotFoundError:
                yield self._missing(p)
                continue
            except PermissionError:
                continue
            yield {
                "path":        str(p),
                "sha256":      sha256_file(p) if p.is_file() else None,
                "size":        st.st_size,
                "mtime":       st.st_mtime,
                "mode":        st.st_mode,
                "uid":         st.st_uid,
                "gid":         st.st_gid,
                "exists_flag": 1,
            }

    @staticmethod
    def _missing(p):
        return {"path": str(p), "sha256": None, "size": None, "mtime": None,
                "mode": None, "uid": None, "gid": None, "exists_flag": 0}


class InstalledAppsCollector(Collector):
    name = "installed_apps"
    model = InstalledAppRow
    judge_fields = ("bundle_id", "name", "path")

    def collect(self):
        for app_dir in (Path("/Applications"), expand("~/Applications")):
            if not app_dir.is_dir():
                continue
            try:
                apps = list(app_dir.glob("*.app"))
            except PermissionError:
                continue
            for app in apps:
                info = read_plist(app / "Contents" / "Info.plist") or {}
                yield {
                    "path":      str(app),
                    "bundle_id": info.get("CFBundleIdentifier"),
                    "name":      info.get("CFBundleName") or info.get("CFBundleDisplayName"),
                    "version":   info.get("CFBundleShortVersionString"),
                    "raw_json":  json.dumps(jsonable({
                        k: info.get(k) for k in APP_INFO_KEYS
                        if info.get(k) is not None
                    })),
                }


# ============================================================================
# Composition + entry point
# ============================================================================

def build_collectors(prompts: Prompts, lookback_min: int) -> list[Collector]:
    h = prompts.hint_for
    return [
        ProcessCollector(judge_hints=h("processes")),
        NetworkConnectionsCollector(judge_hints=h("network_connections")),
        ListeningPortsCollector(judge_hints=h("listening_ports")),
        NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
        UsbDevicesCollector(judge_hints=h("usb_devices")),
        BluetoothCollector(judge_hints=h("bluetooth_devices")),
        WifiCollector(judge_hints=h("wifi_state")),
        LaunchItemsCollector(judge_hints=h("launch_items")),
        TccCollector(judge_hints=h("tcc_permissions")),
        QuarantineCollector(judge_hints=h("quarantine_events")),
        BrowserExtensionsCollector(judge_hints=h("browser_extensions")),
        SystemIntegrityCollector(judge_hints=h("system_integrity")),
        AuthEventsCollector(lookback_min=lookback_min,
                            judge_hints=h("auth_events")),
        FileIntegrityCollector(judge_hints=h("file_integrity")),
        InstalledAppsCollector(judge_hints=h("installed_apps")),
    ]


def build_judge(args, prompts: Prompts) -> Judge:
    if args.no_judge:
        LOG.info("judge disabled (--no-judge)")
        return NullJudge()
    has_oauth = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY")
                       or os.environ.get("OPENAI_API_KEY"))
    if not has_oauth and not has_api_key:
        LOG.warning(
            "no LLM credentials in environment "
            "(CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY) — "
            "threat judging disabled"
        )
        return NullJudge()
    if not has_oauth and not HAS_LITELLM:
        LOG.warning("litellm not installed and no OAuth token; threat "
                    "judging disabled. pip install litellm")
        return NullJudge()
    try:
        judge = LlmJudge(
            prompts=prompts,
            model=args.judge_model,
            batch_size=args.judge_batch_size,
            max_per_collector=args.judge_max_per_collector,
        )
    except RuntimeError as exc:
        LOG.warning("LlmJudge unavailable (%s); falling back to NullJudge", exc)
        return NullJudge()
    LOG.info("judge auth_mode=%s model=%s", judge.auth_mode, judge.model)
    return judge


def main() -> int:
    parser = argparse.ArgumentParser(
        description="macOS host security telemetry + LLM threat judge"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help=f"SQLite database path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help="Seconds between cycles (default: 300)")
    parser.add_argument("--lookback-min", type=int, default=DEFAULT_LOOKBACK_MIN,
                        help="Minutes of unified-log history per run")
    parser.add_argument("--no-judge", action="store_true",
                        help="Disable the LLM threat judge")
    parser.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL,
                        help=f"litellm model id (default: {DEFAULT_JUDGE_MODEL})")
    parser.add_argument("--judge-batch-size", type=int,
                        default=DEFAULT_JUDGE_BATCH,
                        help=f"Entries per LLM call (default: {DEFAULT_JUDGE_BATCH})")
    parser.add_argument("--judge-max-per-collector", type=int,
                        default=DEFAULT_JUDGE_MAX_PER_COLLECTOR,
                        help="Cap of new entries judged per collector per run")
    parser.add_argument("--prompts-file", default=str(DEFAULT_PROMPTS_PATH),
                        help=f"Path to prompts TOML "
                             f"(default: {DEFAULT_PROMPTS_PATH})")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    prompts_path = Path(args.prompts_file).expanduser()
    prompts = Prompts.load(prompts_path)
    LOG.info("loaded prompts from %s (collector_hints=%d)",
             prompts_path, len(prompts.collector_hints))

    judge = build_judge(args, prompts)
    LOG.info("starting host_monitor db=%s interval=%ds lookback=%dm judge=%s",
             db_path, args.interval, args.lookback_min, type(judge).__name__)

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        sink = Sink(engine)
        runner = Runner(sink, build_collectors(prompts, args.lookback_min),
                        judge, args.lookback_min)
        runner.setup()

        if args.once:
            run_id, ok, failed = runner.run_once()
            LOG.info("run complete run_id=%s ok=%d failed=%d",
                     run_id, ok, failed)
            return 0

        try:
            runner.run_forever(args.interval)
        except KeyboardInterrupt:
            LOG.info("interrupted; exiting")
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
