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
import configparser
import hashlib
import json
import logging
import os
import plistlib
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
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
        Engine, MetaData, Table, asc, create_engine, delete, event, exists,
        func, inspect, select, text, update,
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

import platform as _platform

IS_MACOS = _platform.system() == "Darwin"
IS_LINUX = _platform.system() == "Linux"

_PKG_DIR = Path(__file__).resolve().parent

# Default database location: user's current working directory so the
# pip-installed `avai monitor` doesn't try to write into the read-only
# site-packages dir. Containerised invocations override via --db
# (compose passes --db /data/avai.db).
DEFAULT_DB_PATH = Path.cwd() / "avai.db"
DEFAULT_INTERVAL = 300
DEFAULT_LOOKBACK_MIN = 6

DEFAULT_JUDGE_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_JUDGE_BATCH = 20
DEFAULT_JUDGE_MAX_PER_COLLECTOR = 200

# Bundled inside the package — installed alongside this module.
DEFAULT_PROMPTS_PATH = _PKG_DIR / "prompts.toml"


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

# Linux equivalents — XDG paths under ~/.config + ~/.mozilla. Same
# browser_extensions logic; only the search roots change.
BROWSER_PROFILES_LINUX: dict[Browser, list[str]] = {
    Browser.CHROME:   ["~/.config/google-chrome"],
    Browser.CHROMIUM: ["~/.config/chromium"],
    Browser.BRAVE:    ["~/.config/BraveSoftware/Brave-Browser"],
    Browser.EDGE:     ["~/.config/microsoft-edge"],
    Browser.VIVALDI:  ["~/.config/vivaldi"],
    Browser.FIREFOX:  ["~/.mozilla/firefox"],
}

WATCHED_FILES_LINUX = [
    "~/.ssh/authorized_keys", "~/.ssh/known_hosts", "~/.ssh/config",
    "~/.ssh/id_rsa.pub", "~/.ssh/id_ed25519.pub",
    "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.zshrc", "~/.zprofile", "~/.zshenv",
    "~/.gitconfig", "~/.aws/credentials", "~/.aws/config",
    "/etc/hosts", "/etc/resolv.conf", "/etc/sudoers",
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/crontab",
    "/etc/pam.d/sudo", "/etc/pam.d/login", "/etc/pam.d/su",
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
    "/root/.ssh/authorized_keys",
    "/root/.bashrc",
]

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


# ---------------------------------------------------------------------------
# Host-path translation for container deployments.
#
# When the monitor runs in a Linux container that bind-mounts the host
# filesystem under /host (set via HOST_PREFIX=/host), absolute host
# paths a collector reads need to be translated:
#
#   "/etc/systemd/system" → "/host/etc/systemd/system"
#   "/sys/bus/usb/devices" → "/host/sys/bus/usb/devices"
#   "~/.config/google-chrome" → ["/host/home/alice/.config/google-chrome",
#                                "/host/home/bob/.config/google-chrome",
#                                "/host/root/.config/google-chrome"]
#
# Native (non-containerised) execution keeps HOST_PREFIX empty and the
# helpers are passthroughs.
# ---------------------------------------------------------------------------

HOST_PREFIX = os.environ.get("HOST_PREFIX", "").rstrip("/")


def host_path(p) -> Path:
    """Translate an absolute host path to its in-container location
    when HOST_PREFIX is set. Relative paths and the empty-prefix case
    are passthroughs."""
    p = p if isinstance(p, Path) else Path(p)
    if not HOST_PREFIX or not p.is_absolute():
        return p
    return Path(HOST_PREFIX + str(p))


def host_paths_for_home(template: str) -> list[Path]:
    """Expand a ``~/<rest>`` template into actual paths.

    Without HOST_PREFIX:
        ~/<rest> → [Path(os.path.expanduser(template))]

    With HOST_PREFIX (container mode):
        ~/<rest> → one entry per user home found under <prefix>/home/*
                   plus <prefix>/root for the rest.

    Absolute paths pass through ``host_path`` unchanged in count
    (always one path) so callers can flatten freely.
    """
    if not template.startswith("~/"):
        return [host_path(template)]
    rest = template[2:]
    if not HOST_PREFIX:
        return [Path(os.path.expanduser(template))]
    out: list[Path] = []
    home_root = Path(HOST_PREFIX) / "home"
    if home_root.is_dir():
        try:
            for user_dir in home_root.iterdir():
                if user_dir.is_dir():
                    out.append(user_dir / rest)
        except OSError:
            pass
    root_home = Path(HOST_PREFIX) / "root"
    if root_home.is_dir():
        out.append(root_home / rest)
    return out


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
    remediation:  str
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
    """Strategy for issuing an LLM chat completion that returns
    structured output matching a JSON schema. Returns a dict — no
    text-level JSON parsing happens in the caller."""

    @abstractmethod
    def complete_structured(self, *, model: str, system: str, user: str,
                            max_tokens: int, temperature: float,
                            schema: dict, schema_name: str) -> dict: ...


class LitellmClient(CompletionClient):
    """Multi-provider completion via litellm. Uses ANTHROPIC_API_KEY /
    OPENAI_API_KEY / ... from the environment per litellm conventions.
    Forces JSON output via ``response_format``."""

    def __init__(self):
        if not HAS_LITELLM:
            raise RuntimeError(
                "litellm is required for LitellmClient — pip install litellm"
            )

    def complete_structured(self, *, model, system, user, max_tokens,
                            temperature, schema, schema_name):
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
        return json.loads(response.choices[0].message.content)


class AnthropicOAuthClient(CompletionClient):
    """Anthropic completion via the OAuth Bearer flow used by Claude Code
    subscriptions. Reads ``CLAUDE_CODE_OAUTH_TOKEN`` from the environment
    and sends ``Authorization: Bearer <token>`` plus the OAuth beta
    header. Bypasses litellm because litellm sends ``x-api-key`` which
    is incompatible with OAuth tokens.

    The Claude Code OAuth scope requires the system prompt to start with
    the Claude Code identity line. Structured output is obtained via
    ``tool_use`` (not free-text JSON) so we never have to strip markdown
    fences or parse arbitrary text.
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

    def complete_structured(self, *, model, system, user, max_tokens,
                            temperature, schema, schema_name):
        # Strip litellm-style provider prefix if present.
        if "/" in model:
            model = model.split("/", 1)[1]
        full_system = f"{self.SYSTEM_PROMPT_PREFIX}\n\n{system}"
        tool = {
            "name": schema_name,
            "description": f"Submit results matching the {schema_name} schema.",
            "input_schema": schema,
        }
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=full_system,
            tools=[tool],
            tool_choice={"type": "tool", "name": schema_name},
            messages=[{"role": "user", "content": user}],
        )
        for block in response.content:
            if block.type == "tool_use" and block.name == schema_name:
                return dict(block.input)
        raise RuntimeError(
            f"OAuth response had no tool_use block (stop_reason="
            f"{response.stop_reason})"
        )


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
    litellm). Prompts are injected via the ``Prompts`` object.

    Structured output is enforced via the client's
    ``complete_structured`` — JSON-mode for litellm, tool_use for OAuth.
    Either way the caller receives a dict directly.
    """

    SCHEMA_NAME = "submit_judgments"

    @classmethod
    def _judgment_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {
                "judgments": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index":       {"type": "integer"},
                            "verdict":     {"type": "string",
                                            "enum": [str(v) for v in Verdict]},
                            "category":    {"type": "string",
                                            "enum": [str(c) for c in ThreatCategory]},
                            "confidence":  {"type": "number",
                                            "minimum": 0, "maximum": 1},
                            "reasoning":   {"type": "string"},
                            "remediation": {"type": "string"},
                        },
                        "required": ["index", "verdict", "category",
                                     "confidence", "reasoning", "remediation"],
                    },
                },
            },
            "required": ["judgments"],
        }

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
        self._schema = self._judgment_schema()

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
        parsed = self._client.complete_structured(
            model=self.model,
            system=self.prompts.system,
            user=user,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            schema=self._schema,
            schema_name=self.SCHEMA_NAME,
        )
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
                remediation=str(item.get("remediation") or "")[:2000],
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
    remediation:  Mapped[Optional[str]]
    model:        Mapped[str]
    created_at:   Mapped[str]
    # Most recent snapshot run timestamp at which this content_hash was
    # observed. Compared to the latest run's started_at to derive whether
    # the underlying artifact is still present ("active") or has gone
    # away ("resolved"). NULL until the next snapshot cycle touches it.
    last_seen_at: Mapped[Optional[str]] = mapped_column(index=True)


class StreamingSession(Base):
    """One row per StreamingWorker lifetime. Rows produced by a streaming
    collector reference this via ``run_id`` (same column as snapshot
    rows reference ``collection_runs.run_id`` — both are UUIDs, the
    foreign-key relationship is loose by design)."""
    __tablename__ = "streaming_sessions"
    run_id:      Mapped[str] = mapped_column(primary_key=True)
    collector:   Mapped[str] = mapped_column(index=True)
    hostname:    Mapped[str]
    started_at:  Mapped[str]
    finished_at: Mapped[Optional[str]]
    row_count:   Mapped[int] = mapped_column(default=0)


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


# ----- Phase 4: process exec, mounts, setuid files, macOS hardening -----

class ProcessExecRow(_RowBase):
    """One row per process exec event from eslogger (macOS) or
    auditd-via-journalctl (Linux). Same shape both sides so the
    dashboard treats them identically."""
    __tablename__ = "process_exec_events"
    event_timestamp: Mapped[Optional[str]] = mapped_column(index=True)
    event_type:      Mapped[Optional[str]]
    pid:             Mapped[Optional[int]]
    ppid:            Mapped[Optional[int]]
    uid:             Mapped[Optional[int]]
    username:        Mapped[Optional[str]]
    exe_path:        Mapped[Optional[str]] = mapped_column(index=True)
    exe_args_json:   Mapped[Optional[str]]
    parent_path:     Mapped[Optional[str]]
    signing_id:      Mapped[Optional[str]]
    raw_json:        Mapped[Optional[str]]


class MountRow(_RowBase):
    __tablename__ = "mounts"
    device:     Mapped[Optional[str]]
    mountpoint: Mapped[Optional[str]] = mapped_column(index=True)
    fstype:     Mapped[Optional[str]]
    opts:       Mapped[Optional[str]]
    raw_json:   Mapped[Optional[str]]


class SetuidFileRow(_RowBase):
    __tablename__ = "setuid_files"
    path:     Mapped[Optional[str]] = mapped_column(index=True)
    mode:     Mapped[Optional[int]]
    uid:      Mapped[Optional[int]]
    gid:      Mapped[Optional[int]]
    size:     Mapped[Optional[int]]
    mtime:    Mapped[Optional[float]]
    sha256:   Mapped[Optional[str]]
    setuid:   Mapped[Optional[int]]
    setgid:   Mapped[Optional[int]]
    raw_json: Mapped[Optional[str]]


class MdmProfileRow(_RowBase):
    __tablename__ = "mdm_profiles"
    identifier:    Mapped[Optional[str]] = mapped_column(index=True)
    display_name:  Mapped[Optional[str]]
    organization: Mapped[Optional[str]]
    description:   Mapped[Optional[str]]
    install_date:  Mapped[Optional[str]]
    profile_scope: Mapped[Optional[str]]
    is_supervised: Mapped[Optional[int]]
    raw_json:      Mapped[Optional[str]]


class KernelExtensionRow(_RowBase):
    __tablename__ = "kernel_extensions"
    bundle_id:  Mapped[Optional[str]] = mapped_column(index=True)
    name:       Mapped[Optional[str]]
    version:    Mapped[Optional[str]]
    path:       Mapped[Optional[str]]
    team_id:    Mapped[Optional[str]]
    signing_id: Mapped[Optional[str]]
    raw_json:   Mapped[Optional[str]]


class SystemExtensionRow(_RowBase):
    __tablename__ = "system_extensions"
    bundle_id:  Mapped[Optional[str]] = mapped_column(index=True)
    team_id:    Mapped[Optional[str]]
    version:    Mapped[Optional[str]]
    state:      Mapped[Optional[str]]
    categories: Mapped[Optional[str]]
    raw_json:   Mapped[Optional[str]]


# ============================================================================
# Core abstractions
# ============================================================================

class Collector(ABC):
    """Common base for any host-state collector. Subclass
    :class:`SnapshotCollector` (pull, per-cycle) or
    :class:`StreamingCollector` (push, long-lived) — not this directly.

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


class SnapshotCollector(Collector):
    """Pull model — the Runner calls :meth:`collect` once per cycle and
    materializes the result as a batch insert."""

    @abstractmethod
    def collect(self) -> Iterable[dict]:
        """Yield row dicts for ``self.model``.

        ``run_id``, ``collected_at`` and ``content_hash`` are injected
        by the Runner — do not include them here.
        """


class StreamingCollector(Collector):
    """Push model — the Runner starts :meth:`stream` once in a dedicated
    worker thread; the iterator yields rows as events arrive and only
    stops when ``stop_event`` is set or the stream ends.

    Streaming sources are time-series events (not state), so the default
    ``judge_enabled`` is ``False``; aggregate analysis is the right tool.
    """

    judge_enabled: ClassVar[bool] = False

    @abstractmethod
    def stream(self, stop_event: threading.Event) -> Iterable[dict]:
        """Yield row dicts continuously until ``stop_event`` is set.

        Implementations are responsible for terminating their underlying
        data source (subprocess, socket, filesystem watcher) when the
        event fires.
        """


class Sink:
    """SQLAlchemy repository — owns schema, run lifecycle, writes, lookups."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.run_id: Optional[str] = None
        event.listen(engine, "connect", _set_sqlite_pragmas)

    def setup(self) -> None:
        Base.metadata.create_all(self.engine)
        _migrate_add_columns(self.engine)

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
        return self._unjudged_select(collector, run_id_filter=run_id)

    def unjudged_all(self, collector: Collector) -> list[dict]:
        """Same as ``unjudged`` but with no run_id filter — used for
        streaming collectors whose rows accumulate continuously
        between snapshot runs. The Runner calls this once per cycle
        so the judge gets a chance to classify newly-streamed
        content_hashes."""
        if not collector.judge_fields:
            return []
        return self._unjudged_select(collector, run_id_filter=None)

    def _unjudged_select(self, collector: Collector,
                         run_id_filter: Optional[str]) -> list[dict]:
        model = collector.model
        cols = [model.content_hash] + [getattr(model, f)
                                       for f in collector.judge_fields]
        conditions = [
            model.content_hash.is_not(None),
            ~exists().where(
                Judgement.content_hash == model.content_hash,
                Judgement.collector == collector.name,
            ),
        ]
        if run_id_filter is not None:
            conditions.insert(0, model.run_id == run_id_filter)
        stmt = select(*cols).distinct().where(*conditions)
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
                "remediation":  j.remediation,
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

    def database_size_bytes(self) -> int:
        """Total on-disk bytes including the SQLite WAL/SHM sidecars."""
        url = str(self.engine.url)
        prefix = "sqlite:///"
        if not url.startswith(prefix):
            return 0
        base = Path(url[len(prefix):])
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(base) + suffix)
            if p.exists():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
        return total

    def database_live_bytes(self) -> int:
        """Estimate post-VACUUM database size from SQLite pragmas. Deletes
        only mark pages free; until VACUUM runs, the file size doesn't
        shrink. This estimate decreases immediately as we delete rows,
        so the prune loop has a meaningful stop condition."""
        with self.engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            page_count = conn.execute(text("PRAGMA page_count")).scalar() or 0
            page_size  = conn.execute(text("PRAGMA page_size")).scalar() or 0
            freelist   = conn.execute(text("PRAGMA freelist_count")).scalar() or 0
        return max(0, (page_count - freelist) * page_size)

    def prune_to_size(self, max_bytes: int) -> dict:
        """Delete oldest completed runs (and their child rows) plus the
        ``auth_events`` rows older than the oldest remaining run, until
        the database fits under ``max_bytes``. Always preserves at
        least one completed run so the dashboard stays useful.

        Returns ``{runs_pruned, events_pruned, bytes_before, bytes_after}``.
        """
        if max_bytes <= 0:
            return {"runs_pruned": 0, "events_pruned": 0,
                    "bytes_before": 0, "bytes_after": 0}

        bytes_before = self.database_size_bytes()
        if bytes_before <= max_bytes:
            return {"runs_pruned": 0, "events_pruned": 0,
                    "bytes_before": bytes_before,
                    "bytes_after": bytes_before}

        # All collector-row tables EXCEPT auth_events. Streaming events
        # aren't tied to a CollectionRun.run_id, so we trim them by
        # collected_at instead of by run_id.
        snapshot_models = [m for m in _RowBase.__subclasses__()
                           if m is not AuthEventRow]

        runs_pruned = 0
        events_pruned = 0

        with Session(self.engine) as session:
            # Use the post-VACUUM estimate (page_count - freelist) inside
            # the loop. SQLite deletes only mark pages free; the actual
            # file size doesn't shrink until VACUUM runs. database_live_bytes
            # decreases immediately after each delete, so the loop has a
            # meaningful stop condition.
            while self.database_live_bytes() > max_bytes:
                # Safety: never delete the only completed run on file.
                completed = session.execute(
                    select(func.count()).select_from(CollectionRun)
                    .where(CollectionRun.finished_at.is_not(None))
                ).scalar() or 0
                if completed <= 1:
                    LOG.warning("prune_to_size: only %d completed run(s) "
                                "left; cannot shrink further", completed)
                    break

                oldest = session.execute(
                    select(CollectionRun)
                    .where(CollectionRun.finished_at.is_not(None))
                    .order_by(asc(CollectionRun.started_at))
                    .limit(1)
                ).scalar_one_or_none()
                if oldest is None:
                    break

                for model in snapshot_models:
                    session.execute(
                        delete(model).where(model.run_id == oldest.run_id)
                    )
                session.execute(
                    delete(CollectorErrorRow)
                    .where(CollectorErrorRow.run_id == oldest.run_id)
                )
                session.execute(
                    delete(CollectionRun)
                    .where(CollectionRun.run_id == oldest.run_id)
                )
                runs_pruned += 1

                # Trim streaming events older than the new earliest run.
                new_earliest = session.execute(
                    select(CollectionRun.started_at)
                    .where(CollectionRun.finished_at.is_not(None))
                    .order_by(asc(CollectionRun.started_at))
                    .limit(1)
                ).scalar()
                if new_earliest:
                    result = session.execute(
                        delete(AuthEventRow)
                        .where(AuthEventRow.collected_at < new_earliest)
                    )
                    events_pruned += result.rowcount or 0
                    session.execute(
                        delete(StreamingSession)
                        .where(StreamingSession.finished_at < new_earliest)
                    )

                session.commit()

        # Always VACUUM when entering this function (file size was over
        # the cap). VACUUM cannot run inside a transaction, so use
        # AUTOCOMMIT isolation. Checkpoint the WAL before and after so
        # VACUUM sees committed pages and the final on-disk file
        # accurately reflects the post-prune state.
        try:
            with self.engine.connect() as conn:
                conn = conn.execution_options(isolation_level="AUTOCOMMIT")
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
                conn.execute(text("VACUUM"))
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        except Exception:
            LOG.exception("VACUUM failed; space not yet reclaimed")

        return {
            "runs_pruned":  runs_pruned,
            "events_pruned": events_pruned,
            "bytes_before": bytes_before,
            "bytes_after":  self.database_size_bytes(),
        }

    def touch_judgments(self, collector: str,
                        content_hashes: list[str], at: str) -> None:
        """Update ``last_seen_at`` for every judgment whose ``content_hash``
        was observed in the current snapshot cycle. Used to derive
        "active vs resolved" status without storing transitions
        explicitly: a judgment whose ``last_seen_at`` matches the latest
        run started_at is still present on the host; anything older
        (including NULL) means the underlying artifact has gone away."""
        if not content_hashes:
            return
        with Session(self.engine) as session:
            session.execute(
                update(Judgement)
                .where(Judgement.collector == collector)
                .where(Judgement.content_hash.in_(content_hashes))
                .values(last_seen_at=at)
            )
            session.commit()

    # -- streaming sessions -------------------------------------------------

    def start_streaming_session(self, collector: str, hostname: str) -> str:
        run_id = str(uuid.uuid4())
        with Session(self.engine) as session:
            session.add(StreamingSession(
                run_id=run_id, collector=collector, hostname=hostname,
                started_at=utcnow(),
            ))
            session.commit()
        return run_id

    def end_streaming_session(self, run_id: str, row_count: int) -> None:
        with Session(self.engine) as session:
            session.execute(
                update(StreamingSession)
                .where(StreamingSession.run_id == run_id)
                .values(finished_at=utcnow(), row_count=row_count)
            )
            session.commit()


def _set_sqlite_pragmas(dbapi_conn, _connection_record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def _migrate_add_columns(engine: Engine) -> None:
    """Idempotent forward-only migration: add any columns that exist on
    the ORM models but not yet on the live tables. SQLite supports
    ``ALTER TABLE ADD COLUMN`` (no ALTER COLUMN, no DROP COLUMN) so this
    handles the common case of adding a new optional field to a model.
    """
    inspector = inspect(engine)
    live_tables = set(inspector.get_table_names())
    for table in Base.metadata.tables.values():
        if table.name not in live_tables:
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            col_type = col.type.compile(engine.dialect)
            nullable = "" if col.nullable else " NOT NULL DEFAULT ''"
            with engine.begin() as conn:
                conn.execute(text(
                    f"ALTER TABLE {table.name} "
                    f"ADD COLUMN {col.name} {col_type}{nullable}"
                ))
            LOG.info("schema migration: added %s.%s", table.name, col.name)


# ============================================================================
# Streaming worker — drives one StreamingCollector in its own thread
# ============================================================================

class StreamingWorker:
    """Long-lived execution policy for a :class:`StreamingCollector`.

    Owns one OS thread, one ``StreamingSession`` row (its ``run_id``),
    and a small write buffer. Buffered rows are flushed when the buffer
    reaches ``batch_size`` *or* ``flush_interval_s`` has elapsed since
    the last flush, whichever comes first. ``stop()`` signals the
    collector to terminate its source and joins the thread.
    """

    def __init__(self, collector: StreamingCollector, sink: Sink,
                 hostname: str,
                 batch_size: int = 50,
                 flush_interval_s: float = 5.0,
                 join_timeout_s: float = 5.0):
        self.collector = collector
        self.sink = sink
        self.hostname = hostname
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.join_timeout_s = join_timeout_s
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.run_id: Optional[str] = None
        self._rows_written = 0

    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name=f"stream-{self.collector.name}",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=self.join_timeout_s)

    def _flush(self, buffer: list[dict]) -> None:
        if not buffer:
            return
        self.sink.write(self.collector.model, buffer)
        self._rows_written += len(buffer)
        buffer.clear()

    def _run(self) -> None:
        self.run_id = self.sink.start_streaming_session(
            self.collector.name, self.hostname,
        )
        LOG.info("streaming collector=%s run_id=%s started",
                 self.collector.name, self.run_id)
        buffer: list[dict] = []
        last_flush = time.monotonic()
        try:
            for row in self.collector.stream(self.stop_event):
                row["run_id"] = self.run_id
                row["collected_at"] = utcnow()
                row["content_hash"] = content_hash(row, self.collector.judge_fields)
                buffer.append(row)
                now = time.monotonic()
                if (len(buffer) >= self.batch_size
                        or (buffer and now - last_flush >= self.flush_interval_s)):
                    try:
                        self._flush(buffer)
                    except Exception:
                        LOG.exception("streaming flush failed collector=%s",
                                      self.collector.name)
                    last_flush = now
        except Exception:
            LOG.exception("streaming collector=%s crashed",
                          self.collector.name)
        finally:
            try:
                self._flush(buffer)
            except Exception:
                LOG.exception("streaming final flush failed collector=%s",
                              self.collector.name)
            try:
                self.sink.end_streaming_session(self.run_id, self._rows_written)
            except Exception:
                LOG.exception("end_streaming_session failed collector=%s",
                              self.collector.name)
            LOG.info("streaming collector=%s run_id=%s stopped rows=%d",
                     self.collector.name, self.run_id, self._rows_written)


class Runner:
    """Drives snapshot collectors (per-cycle) and streaming collectors
    (long-lived threads) against a Sink. Acts as a supervisor: starts
    streaming workers at boot, runs the snapshot loop on the main
    thread, and joins streaming workers on shutdown."""

    def __init__(self, sink: Sink,
                 snapshot_collectors: list[SnapshotCollector],
                 streaming_collectors: list[StreamingCollector],
                 judge: Judge, lookback_min: int,
                 max_db_bytes: int = 0):
        self.sink = sink
        self.snapshot_collectors = snapshot_collectors
        self.streaming_collectors = streaming_collectors
        self.judge = judge
        self.lookback_min = lookback_min
        self.max_db_bytes = max_db_bytes  # 0 = unlimited
        self._streaming_workers: list[StreamingWorker] = []
        self.shutdown_event = threading.Event()

    def request_shutdown(self) -> None:
        """Idempotent — safe to call from a signal handler."""
        self.shutdown_event.set()

    def setup(self) -> None:
        self.sink.setup()

    def start_streaming(self) -> None:
        if not self.streaming_collectors:
            return
        hostname = socket.gethostname()
        for c in self.streaming_collectors:
            worker = StreamingWorker(c, self.sink, hostname)
            worker.start()
            self._streaming_workers.append(worker)
        LOG.info("started %d streaming worker(s)", len(self._streaming_workers))

    def stop_streaming(self) -> None:
        for w in self._streaming_workers:
            w.stop()
        if self._streaming_workers:
            LOG.info("stopped %d streaming worker(s)", len(self._streaming_workers))
        self._streaming_workers.clear()

    def run_once(self) -> tuple[str, int, int]:
        run_id, started = self.sink.start_run(socket.gethostname(),
                                              self.lookback_min)
        ok = failed = 0
        for c in self.snapshot_collectors:
            try:
                self._run_collector(c, run_id, started)
                ok += 1
            except Exception as exc:
                failed += 1
                self.sink.write_error(c.name, exc)
                LOG.warning("collector=%s status=failed error=%s message=%s",
                            c.name, type(exc).__name__, str(exc)[:200])
        # Streaming collectors accumulate rows in background threads.
        # After the snapshot phase, give the LLM judge a chance to
        # classify any new content_hashes those streamers produced
        # since the previous cycle.
        self._judge_streaming_collectors()
        self.sink.end_run(ok, failed)

        # Rotation: keep the DB under the configured size cap by pruning
        # oldest completed runs and their child rows.
        if self.max_db_bytes:
            stats = self.sink.prune_to_size(self.max_db_bytes)
            if stats["runs_pruned"] or stats["events_pruned"]:
                LOG.info(
                    "db_rotation: pruned runs=%d auth_events=%d  "
                    "%.1fMB → %.1fMB (cap %.0fMB)",
                    stats["runs_pruned"], stats["events_pruned"],
                    stats["bytes_before"] / (1024 * 1024),
                    stats["bytes_after"]  / (1024 * 1024),
                    self.max_db_bytes / (1024 * 1024),
                )

        return run_id, ok, failed

    def _run_collector(self, c: SnapshotCollector, run_id: str,
                       started: str) -> None:
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
            # Mark every judgment whose hash was observed this cycle as
            # "still present". The dashboard derives active/resolved
            # status by comparing last_seen_at to the latest run.
            observed = [r["content_hash"] for r in rows
                        if r.get("content_hash")]
            if observed:
                self.sink.touch_judgments(c.name, observed, started)

        LOG.info("collector=%s rows=%d duration_ms=%d judged=%d",
                 c.name, len(rows), collected_ms, judged)

    def _judge_streaming_collectors(self) -> None:
        """Run the LLM judge against new content_hashes produced by
        streaming collectors since the previous cycle. Uses
        ``Sink.unjudged_all`` so streaming rows (which aren't tied to
        a CollectionRun.run_id) are still classified once each."""
        for c in self.streaming_collectors:
            if not (c.judge_enabled and c.judge_fields):
                continue
            try:
                unjudged = self.sink.unjudged_all(c)
            except Exception as exc:
                LOG.warning("streaming-judge: unjudged_all(%s) failed: %s",
                            c.name, exc)
                continue
            if not unjudged:
                continue
            try:
                judgments = self.judge.judge(c.name, c.judge_hints, unjudged)
                self.sink.write_judgments(judgments)
                LOG.info("streaming-judge collector=%s judged=%d",
                         c.name, len(judgments))
            except Exception:
                LOG.exception("streaming-judge failed for %s", c.name)

    def run_forever(self, interval: int) -> None:
        while not self.shutdown_event.is_set():
            t0 = time.monotonic()
            try:
                run_id, ok, failed = self.run_once()
                LOG.info("run complete run_id=%s ok=%d failed=%d",
                         run_id, ok, failed)
            except Exception:
                LOG.exception("run failed")
            sleep_for = max(0.0, interval - (time.monotonic() - t0))
            LOG.info("sleeping %.1fs", sleep_for)
            # Event-driven sleep: returns immediately when shutdown is
            # requested, without depending on signal-interrupting time.sleep
            # (which is unreliable when other threads exist).
            self.shutdown_event.wait(timeout=sleep_for)


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

class ProcessCollector(SnapshotCollector):
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


class NetworkConnectionsCollector(SnapshotCollector):
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


class ListeningPortsCollector(SnapshotCollector):
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


class NetworkInterfacesCollector(SnapshotCollector):
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


class UsbDevicesCollector(SnapshotCollector):
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


class BluetoothCollector(SnapshotCollector):
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


class WifiCollector(SnapshotCollector):
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


class LaunchItemsCollector(SnapshotCollector):
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


class TccCollector(SnapshotCollector):
    name = "tcc_permissions"
    model = TccPermissionRow
    judge_fields = ("scope", "service", "client", "auth_value")
    _COLUMNS = ["service", "client", "client_type", "auth_value",
                "auth_reason", "last_modified"]

    def collect(self):
        produced = False
        denied_scopes: list[str] = []
        other_errors: list[str] = []
        for scope, path_str in TCC_SOURCES:
            path = expand(path_str)
            if not path.exists():
                continue
            try:
                for row in external_sqlite_rows(path, "access", self._COLUMNS):
                    produced = True
                    yield {"scope": str(scope), **row}
            except Exception as e:
                # Use the underlying DBAPI error when SQLAlchemy wraps
                # one; the wrapped str() carries the verbose
                # "(Background on this error at: …)" footer that's
                # useless to a dashboard user.
                orig = getattr(e, "orig", e)
                msg = str(orig)
                if "authorization denied" in msg.lower():
                    denied_scopes.append(scope.value)
                else:
                    other_errors.append(f"{scope.value}: {msg}")
        if produced:
            return
        if denied_scopes:
            raise PermissionError(
                "TCC.db read denied for " + ", ".join(denied_scopes)
                + " — grant Full Disk Access to the running terminal/agent "
                "in System Settings → Privacy & Security → Full Disk Access."
            )
        if other_errors:
            raise PermissionError("TCC.db unreadable: " + "; ".join(other_errors))


class QuarantineCollector(SnapshotCollector):
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


class BrowserExtensionsCollector(SnapshotCollector):
    name = "browser_extensions"
    model = BrowserExtensionRow
    judge_fields = ("browser", "extension_id", "name",
                    "permissions_json", "host_permissions_json")

    def __init__(self,
                 readers: Optional[dict[Browser, BrowserExtensionReader]] = None,
                 default_reader: Optional[BrowserExtensionReader] = None,
                 judge_hints: str = "",
                 profiles: Optional[dict[Browser, list[str]]] = None):
        super().__init__(judge_hints=judge_hints)
        self.readers = readers or {Browser.FIREFOX: FirefoxExtensionReader()}
        self.default_reader = default_reader or ChromiumExtensionReader()
        # Per-platform search roots — caller supplies BROWSER_PROFILES
        # or BROWSER_PROFILES_LINUX. Defaults to the macOS layout.
        self.profiles = profiles or BROWSER_PROFILES

    def collect(self):
        for browser, profiles in self.profiles.items():
            reader = self.readers.get(browser, self.default_reader)
            for base_str in profiles:
                base = expand(base_str)
                if not base.is_dir():
                    continue
                yield from reader.read(base, browser)


class SystemIntegrityCollector(SnapshotCollector):
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


class AuthEventsCollector(StreamingCollector):
    """Tails the macOS unified log forever via ``log stream``. Each
    matching event is yielded as it arrives — no polling gaps."""

    name = "auth_events"
    model = AuthEventRow
    # judge_enabled is False by default for StreamingCollector

    def __init__(self, predicate: str = AUTH_LOG_PREDICATE,
                 judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.predicate = predicate

    def stream(self, stop_event: threading.Event):
        cmd = ["log", "stream", "--style", "ndjson", "--info",
               "--predicate", self.predicate]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        # Watchdog: when stop_event fires, terminate the subprocess,
        # which closes stdout and ends the read loop below.
        def _terminator():
            stop_event.wait()
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass

        threading.Thread(target=_terminator, daemon=True,
                         name="log-stream-killer").start()

        try:
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
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
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except ProcessLookupError:
                    pass


class FileIntegrityCollector(SnapshotCollector):
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


class InstalledAppsCollector(SnapshotCollector):
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


class LinuxInstalledAppsCollector(SnapshotCollector):
    """Linux equivalent of :class:`InstalledAppsCollector`. Sources:

    - ``dpkg -l`` (Debian / Ubuntu / derivatives): installed binary
      packages. Each yields one row tagged ``source='dpkg'``.
    - ``/usr/share/applications/*.desktop`` (XDG, universal): GUI app
      menu entries. Each yields one row tagged ``source='desktop'``.

    The ``bundle_id`` column holds the package name (dpkg) or the
    ``.desktop`` filename's stem (XDG), so the judge dedupes via a
    stable identifier in either case.
    """
    name = "installed_apps"
    model = InstalledAppRow
    judge_fields = ("bundle_id", "name", "path")

    _DPKG_FIELDS = ("Status", "Package", "Version", "Architecture",
                    "Description")

    def collect(self):
        yield from self._dpkg_rows()
        yield from self._desktop_rows()

    def _dpkg_rows(self):
        if not shutil.which("dpkg-query"):
            return
        # Tab-separated fixed-field output: no parsing of dpkg -l's
        # column-aligned text. dpkg-query -W -f gives us structured
        # output with a chosen delimiter.
        fmt = "${db:Status-Status}\t${Package}\t${Version}\t" \
              "${Architecture}\t${binary:Summary}\n"
        cmd = ["dpkg-query", "-W", "-f", fmt]
        # When containerised, --admindir points dpkg-query at the host's
        # package database rather than the container's.
        host_admindir = host_path("/var/lib/dpkg")
        if HOST_PREFIX and host_admindir.is_dir():
            cmd[1:1] = ["--admindir", str(host_admindir)]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            status, name, version, arch, summary = parts[0], parts[1], parts[2], parts[3], parts[4]
            if status != "installed":
                continue
            yield {
                "path":      f"dpkg:{name}",
                "bundle_id": name,
                "name":      name,
                "version":   version,
                "raw_json":  json.dumps({
                    "source": "dpkg",
                    "status": status,
                    "architecture": arch,
                    "summary": summary,
                }),
            }

    def _desktop_rows(self):
        # XDG desktop entries are simple INI files; configparser
        # handles them. We extract [Desktop Entry] Name / Exec /
        # Comment / Categories.
        roots: list[Path] = [
            host_path("/usr/share/applications"),
            host_path("/usr/local/share/applications"),
            host_path("/var/lib/flatpak/exports/share/applications"),
        ]
        roots.extend(host_paths_for_home("~/.local/share/applications"))
        roots.extend(host_paths_for_home(
            "~/.local/share/flatpak/exports/share/applications"))
        for root in roots:
            if not root.is_dir():
                continue
            try:
                entries = list(root.glob("*.desktop"))
            except PermissionError:
                continue
            for entry in entries:
                cp = configparser.ConfigParser(
                    interpolation=None, strict=False,
                )
                try:
                    cp.read(entry, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                if "Desktop Entry" not in cp:
                    continue
                sec = cp["Desktop Entry"]
                yield {
                    "path":      str(entry),
                    "bundle_id": entry.stem,
                    "name":      sec.get("Name"),
                    "version":   sec.get("Version"),
                    "raw_json":  json.dumps({
                        "source":     "desktop",
                        "exec":       sec.get("Exec"),
                        "comment":    sec.get("Comment"),
                        "categories": sec.get("Categories"),
                        "type":       sec.get("Type"),
                        "no_display": sec.get("NoDisplay") == "true",
                    }),
                }


class LinuxLaunchItemsCollector(SnapshotCollector):
    """Linux equivalent of :class:`LaunchItemsCollector`.

    Sources, all parsed structurally (no regex):

    - **systemd unit files** in (in this precedence order, first wins
      for duplicate names) ``/etc/systemd/system``,
      ``/run/systemd/system``, ``/lib/systemd/system``,
      ``/usr/lib/systemd/system``, ``~/.config/systemd/user``. Both
      ``.service`` and ``.timer`` units are read. INI format parsed
      via :mod:`configparser`. The ``[Unit] / [Service] / [Install] /
      [Timer]`` sections are captured verbatim in ``raw_json``;
      key fields land in the existing ``launch_items`` columns.

    - **cron entries** from ``/etc/crontab``, drop-in files in
      ``/etc/cron.d/*``, and per-user crontabs in ``/var/spool/cron``
      and ``/var/spool/cron/crontabs`` (root-readable). System-wide
      crontabs carry a user column (field 6); user crontabs don't.

    The ``scope`` column distinguishes sources:
    ``system_service`` / ``user_service`` / ``system_timer`` /
    ``user_timer`` / ``system_crontab`` / ``system_crontab_d`` /
    ``user_crontab``.
    """
    name = "launch_items"
    model = LaunchItemRow
    judge_fields = ("scope", "label", "program", "program_arguments_json",
                    "user_name", "run_at_load", "keep_alive")

    # (scope, directory, glob). Directories searched in this order;
    # later occurrences of the same unit filename are ignored (systemd
    # itself layers these dirs with /etc winning over /lib).
    _UNIT_DIRS = [
        ("system_service", "/etc/systemd/system",       "*.service"),
        ("system_service", "/run/systemd/system",       "*.service"),
        ("system_service", "/lib/systemd/system",       "*.service"),
        ("system_service", "/usr/lib/systemd/system",   "*.service"),
        ("user_service",   "~/.config/systemd/user",    "*.service"),
        ("system_timer",   "/etc/systemd/system",       "*.timer"),
        ("system_timer",   "/lib/systemd/system",       "*.timer"),
        ("system_timer",   "/usr/lib/systemd/system",   "*.timer"),
        ("user_timer",     "~/.config/systemd/user",    "*.timer"),
    ]

    _CRON_FILE     = ("system_crontab", Path("/etc/crontab"))
    _CRON_DROP_INS = [
        ("system_crontab_d", Path("/etc/cron.d")),
    ]
    _USER_CRONS    = [
        ("user_crontab", Path("/var/spool/cron")),
        ("user_crontab", Path("/var/spool/cron/crontabs")),
    ]

    _ALWAYS_RESTART = {"always", "on-failure", "on-success",
                       "on-abnormal", "on-abort", "on-watchdog"}

    def collect(self):
        # systemd units. Path translation honours HOST_PREFIX so the
        # container reads the host's /etc/systemd/system rather than
        # its own (empty) one.
        seen_units: set[str] = set()
        for scope, dir_str, pattern in self._UNIT_DIRS:
            d = host_paths_for_home(dir_str)[0]
            if not d.is_dir():
                continue
            try:
                paths = list(d.glob(pattern))
            except PermissionError:
                continue
            for path in paths:
                if path.name in seen_units:
                    continue
                seen_units.add(path.name)
                row = self._unit_row(scope, path)
                if row is not None:
                    yield row

        # /etc/crontab — single file, has-user-column form
        scope, p = self._CRON_FILE
        p = host_path(p)
        if p.is_file():
            yield from self._cron_rows(scope, p, has_user_col=True)

        # /etc/cron.d/* — drop-in files, has-user-column form
        for scope, d in self._CRON_DROP_INS:
            d = host_path(d)
            if not d.is_dir():
                continue
            try:
                files = list(d.iterdir())
            except PermissionError:
                continue
            for f in files:
                if not f.is_file() or f.name.startswith("."):
                    continue
                yield from self._cron_rows(scope, f, has_user_col=True)

        # /var/spool/cron* — per-user crontabs (no user column inside).
        # The filename IS the username.
        for scope, d in self._USER_CRONS:
            d = host_path(d)
            if not d.is_dir():
                continue
            try:
                files = list(d.iterdir())
            except PermissionError:
                continue
            for f in files:
                if not f.is_file() or f.name.startswith("."):
                    continue
                yield from self._cron_rows(scope, f, has_user_col=False,
                                           default_user=f.name)

    @staticmethod
    def _unit_row(scope: str, path: Path):
        cp = configparser.ConfigParser(
            interpolation=None, strict=False,
            inline_comment_prefixes=("#", ";"),
            comment_prefixes=("#", ";"),
        )
        try:
            cp.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        unit_sec    = dict(cp["Unit"])    if cp.has_section("Unit")    else {}
        service_sec = dict(cp["Service"]) if cp.has_section("Service") else {}
        install_sec = dict(cp["Install"]) if cp.has_section("Install") else {}
        timer_sec   = dict(cp["Timer"])   if cp.has_section("Timer")   else {}

        exec_start  = service_sec.get("ExecStart") or ""
        on_calendar = timer_sec.get("OnCalendar")

        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None

        try:
            args = shlex.split(exec_start) if exec_start else []
        except ValueError:
            args = [exec_start]

        return {
            "scope":                        scope,
            "path":                         str(path),
            "label":                        path.stem,
            "program":                      exec_start or on_calendar,
            "program_arguments_json":       json.dumps(args),
            "run_at_load":                  int(bool(install_sec.get("WantedBy"))),
            "keep_alive":                   int(
                service_sec.get("Restart", "no").strip()
                in LinuxLaunchItemsCollector._ALWAYS_RESTART
            ),
            "start_interval":               None,
            "start_calendar_interval_json": json.dumps(on_calendar)
                                            if on_calendar else None,
            "user_name":                    service_sec.get("User"),
            "group_name":                   service_sec.get("Group"),
            "sha256":                       sha256_file(path),
            "mtime":                        mtime,
            "raw_json":                     json.dumps({
                "unit":    unit_sec,
                "service": service_sec,
                "install": install_sec,
                "timer":   timer_sec,
            }),
        }

    @staticmethod
    def _cron_rows(scope: str, path: Path, has_user_col: bool,
                   default_user: Optional[str] = None):
        """Yield one row per executable crontab line.

        crontab(5) format:
          - 5 schedule fields + [user] + command  (system: /etc/crontab,
            /etc/cron.d)
          - 5 schedule fields + command           (user crontabs)
          - or a @keyword (e.g. ``@reboot``) replacing the schedule.
        Lines starting with ``#`` and blank lines are skipped.
        Environment-assignment lines (``KEY=value``) are also skipped —
        they're not jobs.
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        digest = sha256_file(path)

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # KEY=VALUE assignments aren't jobs.
            if "=" in line.split(None, 1)[0]:
                continue

            if line.startswith("@"):
                tokens = line.split(None, 2 if has_user_col else 1)
                need = 3 if has_user_col else 2
                if len(tokens) < need:
                    continue
                schedule = tokens[0]
                user     = tokens[1] if has_user_col else default_user
                command  = tokens[-1]
            else:
                # 5 schedule fields + optional user + command (which may
                # contain whitespace — preserve via maxsplit).
                need = 7 if has_user_col else 6
                tokens = line.split(None, need - 1)
                if len(tokens) < need:
                    continue
                schedule = " ".join(tokens[:5])
                user     = tokens[5] if has_user_col else default_user
                command  = tokens[-1]

            try:
                args = shlex.split(command)
            except ValueError:
                args = [command]

            yield {
                "scope":                        scope,
                "path":                         f"{path}:{lineno}",
                "label":                        f"cron:{path.name}:{lineno}",
                "program":                      command,
                "program_arguments_json":       json.dumps(args),
                "run_at_load":                  int(schedule == "@reboot"),
                "keep_alive":                   0,
                "start_interval":               None,
                "start_calendar_interval_json": json.dumps({"schedule": schedule}),
                "user_name":                    user,
                "group_name":                   None,
                "sha256":                       digest,
                "mtime":                        mtime,
                "raw_json":                     json.dumps({
                    "source":   "cron",
                    "schedule": schedule,
                    "user":     user,
                    "command":  command,
                    "line":     lineno,
                }),
            }


class LinuxAuthEventsCollector(StreamingCollector):
    """Linux equivalent of :class:`AuthEventsCollector` — tails
    ``journalctl -f --output=json`` filtered to security-relevant
    sources (auth+authpriv syslog facilities, sshd, systemd-logind,
    sudo, su, polkitd). Yields rows in the same shape as the macOS
    streaming collector so the dashboard treats them identically.

    The OR semantics across different journalctl matchers require
    inserting ``+`` between AND-groups; same-field matchers within a
    group OR by default.
    """
    name = "auth_events"
    model = AuthEventRow

    _MATCH_GROUPS = [
        ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"],  # auth + authpriv
        ["_SYSTEMD_UNIT=sshd.service"],
        ["_SYSTEMD_UNIT=systemd-logind.service"],
        ["_COMM=sudo"],
        ["_COMM=su"],
        ["_COMM=polkitd"],
        ["_COMM=login"],
    ]

    def __init__(self, judge_hints: str = "", priority: str = "info"):
        super().__init__(judge_hints=judge_hints)
        self.priority = priority

    def _cmd(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager",
               f"--priority={self.priority}"]
        # In container mode, point journalctl at the host's journal
        # directory rather than the container's empty one.
        if HOST_PREFIX:
            host_journal = host_path("/var/log/journal")
            if host_journal.is_dir():
                cmd.extend(["--directory", str(host_journal)])
        for i, group in enumerate(self._MATCH_GROUPS):
            if i > 0:
                cmd.append("+")
            cmd.extend(group)
        return cmd

    def stream(self, stop_event: threading.Event):
        proc = subprocess.Popen(
            self._cmd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        def _terminator():
            stop_event.wait()
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
        threading.Thread(target=_terminator, daemon=True,
                         name="journalctl-killer").start()

        try:
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield self._row_from_journal_event(e)
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except ProcessLookupError:
                    pass

    @staticmethod
    def _row_from_journal_event(e: dict) -> dict:
        # journalctl --output=json gives __REALTIME_TIMESTAMP in
        # microseconds since the epoch (as a string).
        ts_us = e.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass

        try:
            pid = int(e["_PID"]) if e.get("_PID") else None
        except (TypeError, ValueError):
            pid = None

        return {
            "event_timestamp": ts,
            "process":         e.get("_EXE") or e.get("_COMM"),
            "subsystem":       e.get("_SYSTEMD_UNIT") or "syslog",
            "category":        str(e.get("SYSLOG_FACILITY") or ""),
            "event_type":      f"priority={e.get('PRIORITY', '?')}",
            "event_message":   e.get("MESSAGE"),
            "pid":             pid,
            "raw_json":        json.dumps(e),
        }


# ----------------------------------------------------------------------------
# Phase 3: hardware + posture collectors for Linux
# ----------------------------------------------------------------------------

def _read_sysfs(path: Path, encoding: str = "utf-8") -> Optional[str]:
    """Read a sysfs/procfs attribute file. Returns the stripped string or
    None if unreadable. Doesn't raise on permission errors."""
    try:
        return path.read_text(encoding=encoding, errors="replace").strip()
    except (OSError, UnicodeError):
        return None


class LinuxUsbDevicesCollector(SnapshotCollector):
    """Linux equivalent of :class:`UsbDevicesCollector`.

    Walks ``/sys/bus/usb/devices`` and reads attribute files (kernel
    exposes the USB descriptors as plain-text files — no parsing
    needed, just :func:`Path.read_text`). Interface sub-nodes (those
    with a ``:`` in their name like ``1-1:1.0``) are skipped — we
    only want device-level entries.
    """
    name = "usb_devices"
    model = UsbDeviceRow
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    _ATTRS = ("idVendor", "idProduct", "manufacturer", "product",
              "serial", "speed", "bDeviceClass", "bDeviceProtocol",
              "bMaxPower", "version", "busnum", "devnum")

    def collect(self):
        root = host_path("/sys/bus/usb/devices")
        if not root.is_dir():
            return
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for dev in entries:
            # USB device nodes are named like "1-1", "2-1.2", "usb1".
            # Interfaces (which carry a colon) are sub-descriptors of
            # devices — skip them.
            if ":" in dev.name:
                continue
            if not dev.is_dir():
                continue
            attrs = {a: _read_sysfs(dev / a) for a in self._ATTRS}
            attrs = {k: v for k, v in attrs.items() if v is not None}
            if not attrs.get("idVendor") and not attrs.get("product"):
                # Empty entry (e.g. root hubs without descriptors).
                continue
            yield {
                "name":          attrs.get("product"),
                "vendor_id":     attrs.get("idVendor"),
                "product_id":    attrs.get("idProduct"),
                "serial_number": attrs.get("serial"),
                "manufacturer":  attrs.get("manufacturer"),
                "location_id":   dev.name,
                "speed":         attrs.get("speed"),
                "raw_json":      json.dumps(attrs),
            }


class LinuxBluetoothCollector(SnapshotCollector):
    """Linux equivalent of :class:`BluetoothCollector`.

    Walks ``/var/lib/bluetooth/<adapter_mac>/<device_mac>/info`` — the
    persistent state files BlueZ writes for every paired device. Each
    file is an INI document parsed by :mod:`configparser`. Presence
    in this directory means the device is paired; live connectivity
    requires D-Bus (deferred to a future phase) so ``connected`` is
    left as 0.

    Requires read access to ``/var/lib/bluetooth`` which is normally
    root-only — the monitor container runs as root.
    """
    name = "bluetooth_devices"
    model = BluetoothDeviceRow
    judge_fields = ("name", "address", "minor_type")

    def collect(self):
        root = host_path("/var/lib/bluetooth")
        if not root.is_dir():
            return
        try:
            adapters = list(root.iterdir())
        except PermissionError:
            return
        for adapter in adapters:
            if not adapter.is_dir():
                continue
            try:
                devices = list(adapter.iterdir())
            except PermissionError:
                continue
            for dev in devices:
                if not dev.is_dir():
                    continue
                info_file = dev / "info"
                if not info_file.is_file():
                    continue
                cp = configparser.ConfigParser(
                    interpolation=None, strict=False,
                    inline_comment_prefixes=("#", ";"),
                )
                try:
                    cp.read(info_file, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                general = dict(cp["General"]) if cp.has_section("General") else {}
                # BlueZ stores the MAC with underscores; restore colons.
                mac = dev.name.replace("_", ":")
                full = {sec: dict(cp[sec]) for sec in cp.sections()}
                yield {
                    "name":       general.get("Alias") or general.get("Name"),
                    "address":    mac,
                    "connected":  0,
                    "paired":     1,
                    "minor_type": general.get("Class"),
                    "raw_json":   json.dumps(full),
                }


class LinuxWifiCollector(SnapshotCollector):
    """Linux equivalent of :class:`WifiCollector`.

    Discovers wireless interfaces from sysfs (any net interface that
    has a ``wireless/`` subdirectory in ``/sys/class/net``). For each,
    asks ``iw dev <iface> link`` for the current connection details
    (SSID, BSSID, freq) — parsed line-by-line using ``key: value``
    structure, not regex. If ``iw`` isn't installed the interface is
    still emitted with empty fields so the dashboard can see it
    exists.
    """
    name = "wifi_state"
    model = WifiStateRow
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        # sysfs discovery via HOST_PREFIX; iw queries via netlink which
        # the host-network namespace (network_mode: host) already
        # exposes to the container.
        net = host_path("/sys/class/net")
        if not net.is_dir():
            return
        try:
            ifaces = list(net.iterdir())
        except OSError:
            return
        iw_available = shutil.which("iw") is not None
        for iface_dir in ifaces:
            if not (iface_dir / "wireless").is_dir():
                continue
            iface = iface_dir.name
            link = self._iw_link(iface) if iw_available else {}
            yield {
                "interface": iface,
                "ssid":      link.get("SSID"),
                "bssid":     link.get("BSSID"),
                "channel":   link.get("freq"),
                "security":  link.get("type"),
                "raw_json":  json.dumps(link),
            }

    @staticmethod
    def _iw_link(iface: str) -> dict:
        try:
            r = subprocess.run(
                ["iw", "dev", iface, "link"],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}
        if r.returncode != 0 or not r.stdout:
            return {}
        out: dict = {}
        for raw in r.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Connected to"):
                tokens = line.split()
                if len(tokens) >= 3:
                    out["BSSID"] = tokens[2]
                continue
            if line.startswith("Not connected"):
                out["connected"] = "no"
                continue
            key, sep, value = line.partition(":")
            if sep:
                out[key.strip()] = value.strip()
        return out


class LinuxSystemIntegrityCollector(SnapshotCollector):
    """Linux equivalent of :class:`SystemIntegrityCollector`.

    Maps Linux security posture into the existing ``system_integrity``
    row, preserving the macOS-shaped column names so the dashboard
    keeps rendering them:

    - ``filevault_active``          → any active dm-crypt (LUKS) mapping.
    - ``firewall_global_state``    → ``ufw`` OR ``firewalld`` active.
    - ``firewall_stealth``         → reserved (no clean Linux analog).
    - ``firewall_logging``         → reserved.
    - ``gatekeeper_assessments_*`` → SELinux in *Enforcing* mode OR
                                     AppArmor enabled.
    - ``remote_login_enabled``     → ``ssh.service`` / ``sshd.service``
                                     active.
    - ``screen_sharing_enabled``   → ``x11vnc`` / ``vncserver`` active.
    - ``remote_management_enabled``→ same as screen_sharing (no Linux
                                     equivalent to Apple Remote Desktop).

    Raw posture details (SELinux mode string, AppArmor enabled/loaded
    profiles, ufw / firewalld active flags, dm-crypt count, sshd /
    vnc systemd status) live in ``raw_json`` for the LLM judge.
    """
    name = "system_integrity"
    model = SystemIntegrityRow
    judge_fields = (
        "filevault_active", "firewall_global_state",
        "gatekeeper_assessments_enabled",
        "remote_login_enabled", "screen_sharing_enabled",
        "remote_management_enabled",
    )

    def collect(self):
        selinux  = self._selinux_state()
        apparmor = self._apparmor_state()
        ufw      = self._ufw_active()
        fwd      = self._service_active("firewalld")
        sshd     = (self._service_active("ssh")
                    or self._service_active("sshd"))
        vnc      = (self._service_active("x11vnc")
                    or self._service_active("vncserver")
                    or self._service_active("xrdp"))
        luks_n   = self._luks_count()

        raw = {
            "selinux":          selinux,
            "apparmor":         apparmor,
            "ufw_active":       ufw,
            "firewalld_active": fwd,
            "sshd_active":      sshd,
            "vnc_active":       vnc,
            "luks_mappings":    luks_n,
        }

        yield {
            "filevault_active":               int(luks_n > 0),
            "firewall_global_state":          int(ufw or fwd),
            "firewall_stealth":               None,
            "firewall_logging":               None,
            "gatekeeper_assessments_enabled": int(
                selinux == "Enforcing"
                or apparmor.get("enabled") is True
            ),
            "remote_login_enabled":           int(sshd),
            "screen_sharing_enabled":         int(vnc),
            "remote_management_enabled":      int(vnc),
            "raw_json":                       json.dumps(raw),
        }

    # ---- helpers ----------------------------------------------------

    @staticmethod
    def _selinux_state() -> Optional[str]:
        """Returns 'Enforcing' / 'Permissive' / None (not present)."""
        flag = _read_sysfs(host_path("/sys/fs/selinux/enforce"))
        if flag is None:
            return None
        return {"0": "Permissive", "1": "Enforcing"}.get(flag, "Unknown")

    @staticmethod
    def _apparmor_state() -> dict:
        enabled = _read_sysfs(host_path("/sys/module/apparmor/parameters/enabled"))
        return {"enabled": enabled == "Y"} if enabled is not None else {"enabled": False}

    @staticmethod
    def _ufw_active() -> bool:
        # /etc/ufw/ufw.conf is the canonical persistent state.
        conf = _read_sysfs(host_path("/etc/ufw/ufw.conf"))
        if conf is None:
            return False
        for line in conf.splitlines():
            if line.lstrip().startswith("ENABLED"):
                key, _, value = line.partition("=")
                if key.strip() == "ENABLED":
                    return value.strip().strip('"').lower() == "yes"
        return False

    @staticmethod
    def _service_active(unit: str) -> bool:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return r.stdout.strip() == "active"

    @staticmethod
    def _luks_count() -> int:
        if not shutil.which("dmsetup"):
            return 0
        try:
            r = subprocess.run(
                ["dmsetup", "ls", "--target", "crypt"],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except subprocess.TimeoutExpired:
            return 0
        if r.returncode != 0 or "No devices found" in r.stdout:
            return 0
        return sum(1 for line in r.stdout.splitlines() if line.strip())


# ----------------------------------------------------------------------------
# Phase 4 — cross-platform: mounts + setuid binaries
# ----------------------------------------------------------------------------

class MountsCollector(SnapshotCollector):
    """Cross-platform mount-table snapshot via ``psutil.disk_partitions``.

    Detects new mounts (an attacker shadowing ``/etc/passwd`` with a
    tmpfs is a classic rootkit move) and persistent device →
    mountpoint mappings. ``all=True`` keeps pseudo-filesystems
    (``proc``, ``sys``, ``tmpfs``, ``cgroup``, …) in the result —
    those are exactly what we want to watch for surprises.
    """
    name = "mounts"
    model = MountRow
    judge_fields = ("device", "mountpoint", "fstype", "opts")

    def collect(self):
        try:
            partitions = psutil.disk_partitions(all=True)
        except (psutil.AccessDenied, PermissionError):
            return
        for p in partitions:
            yield {
                "device":     p.device,
                "mountpoint": p.mountpoint,
                "fstype":     p.fstype,
                "opts":       p.opts,
                "raw_json":   json.dumps({
                    "device":     p.device,
                    "mountpoint": p.mountpoint,
                    "fstype":     p.fstype,
                    "opts":       p.opts,
                    "maxfile":    getattr(p, "maxfile", None),
                    "maxpath":    getattr(p, "maxpath", None),
                }),
            }


class SetuidFilesCollector(SnapshotCollector):
    """Enumerate setuid / setgid files in common executable directories.

    A *new* setuid binary on a system is one of the loudest signals
    of privilege-escalation persistence — and is invisible to most
    of the other collectors. The walk is bounded to typical bin /
    sbin / libexec dirs to keep cycle time short; a full ``/`` walk
    takes minutes on a populated host.

    Honors ``HOST_PREFIX`` on Linux so a container monitor walks the
    host's ``/usr/bin`` rather than its own.
    """
    name = "setuid_files"
    model = SetuidFileRow
    judge_fields = ("path", "uid", "setuid", "setgid")

    _BIN_DIRS_MACOS = (
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/usr/local/bin", "/usr/local/sbin", "/usr/libexec",
    )
    _BIN_DIRS_LINUX = (
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/usr/local/bin", "/usr/local/sbin",
        "/usr/libexec", "/opt",
    )

    def collect(self):
        bin_dirs = self._BIN_DIRS_LINUX if IS_LINUX else self._BIN_DIRS_MACOS
        for d in bin_dirs:
            base = host_path(d) if IS_LINUX else Path(d)
            if not base.is_dir():
                continue
            try:
                paths = list(base.rglob("*"))
            except (PermissionError, OSError):
                continue
            for path in paths:
                try:
                    if not path.is_file():
                        continue
                    st = path.lstat()
                except (PermissionError, OSError):
                    continue
                mode = st.st_mode
                setuid = bool(mode & 0o4000)
                setgid = bool(mode & 0o2000)
                if not (setuid or setgid):
                    continue
                yield {
                    "path":     str(path),
                    "mode":     mode,
                    "uid":      st.st_uid,
                    "gid":      st.st_gid,
                    "size":     st.st_size,
                    "mtime":    st.st_mtime,
                    "sha256":   sha256_file(path),
                    "setuid":   int(setuid),
                    "setgid":   int(setgid),
                    "raw_json": json.dumps({
                        "path":   str(path),
                        "mode":   oct(mode),
                        "setuid": setuid,
                        "setgid": setgid,
                    }),
                }


# ----------------------------------------------------------------------------
# Phase 4 — macOS-specific: MDM profiles, kernel + system extensions
# ----------------------------------------------------------------------------

class MdmProfilesCollector(SnapshotCollector):
    """macOS configuration profiles (MDM payloads). Unauthorized MDM
    enrollment is a major compromise vector — a malicious profile
    can install root CAs, push launch agents, configure VPNs, or
    restrict settings system-wide. ``system_profiler
    SPConfigurationProfileDataType`` gives us a structured (JSON)
    view of every installed profile."""
    name = "mdm_profiles"
    model = MdmProfileRow
    judge_fields = ("identifier", "display_name", "organization", "profile_scope")

    def collect(self):
        try:
            data = run_json(
                ["system_profiler", "-json", "SPConfigurationProfileDataType"],
                timeout=30,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        profiles = data.get("SPConfigurationProfileDataType", []) or []
        # The output structure is "list of nested groups, with profile
        # records under either _items or directly at the top level."
        for entry in self._walk(profiles):
            yield {
                "identifier":     entry.get("spconfigprofile_profile_identifier"),
                "display_name":   entry.get("_name") or entry.get(
                    "spconfigprofile_profile_display_name"),
                "organization":   entry.get("spconfigprofile_profile_organization"),
                "description":    entry.get("spconfigprofile_profile_description"),
                "install_date":   entry.get("spconfigprofile_install_date"),
                "profile_scope":  entry.get("spconfigprofile_profile_scope"),
                "is_supervised":  None,
                "raw_json":       json.dumps(jsonable(entry)),
            }

    @classmethod
    def _walk(cls, items):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            # A node is a profile if it has an identifier field, else
            # descend into _items.
            if item.get("spconfigprofile_profile_identifier"):
                yield item
            if "_items" in item:
                yield from cls._walk(item.get("_items"))


class KernelExtensionsCollector(SnapshotCollector):
    """macOS kernel extensions (kexts). Apple has deprecated them in
    favour of System Extensions, but third-party kexts can still
    load on older macOS or via legacy paths. Anything in ring 0 has
    full machine access — every loaded kext is high-signal.

    ``system_profiler -json SPExtensionsDataType`` is the structured
    source. It enumerates every installed kext (loaded or not),
    including the signing chain and notarisation state. The judge
    naturally ignores Apple-signed kexts and focuses on third-party
    ones via the prompt hints.
    """
    name = "kernel_extensions"
    model = KernelExtensionRow
    judge_fields = ("bundle_id", "name", "team_id")

    def collect(self):
        try:
            data = run_json(
                ["system_profiler", "-json", "SPExtensionsDataType"],
                timeout=60,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        for kext in data.get("SPExtensionsDataType", []) or []:
            if not isinstance(kext, dict):
                continue
            yield {
                "bundle_id":  kext.get("spext_bundleid"),
                "name":       kext.get("_name"),
                "version":    kext.get("spext_version"),
                "path":       kext.get("spext_path"),
                "team_id":    None,
                "signing_id": kext.get("spext_signed_by"),
                "raw_json":   json.dumps(jsonable({
                    k: v for k, v in kext.items()
                    if k in (
                        "_name", "spext_bundleid", "spext_version",
                        "spext_path", "spext_signed_by",
                        "spext_obtained_from", "spext_notarized",
                        "spext_loaded", "spext_loadable",
                        "spext_lastModified", "spext_hasAllDependencies",
                    )
                })),
            }


class SystemExtensionsCollector(SnapshotCollector):
    """macOS System Extensions — the post-Catalina replacement for
    kexts. Used by network filters (NEFilter), DriverKit
    (USB/serial), and endpoint-security extensions (ES).

    Source: ``/Library/SystemExtensions/db.plist`` — the LaunchServices
    plist that records every installed extension and its enabled /
    active state. Parsed via :mod:`plistlib`; no text scraping of
    ``systemextensionsctl list`` output.
    """
    name = "system_extensions"
    model = SystemExtensionRow
    judge_fields = ("bundle_id", "team_id")

    def collect(self):
        db = Path("/Library/SystemExtensions/db.plist")
        data = read_plist(db)
        if not data:
            return
        # The plist is a top-level dict with 'extensions' as the list
        # of every installed System Extension (one entry per ext,
        # regardless of activation state). 'bundleVersion' is a
        # nested dict carrying both CFBundleShortVersionString and
        # CFBundleVersion. 'categories' is a list of extension-point
        # identifiers (network_extension, endpoint_security, …).
        for ext in data.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            version = ext.get("bundleVersion")
            if isinstance(version, dict):
                version = (version.get("CFBundleShortVersionString")
                           or version.get("CFBundleVersion"))
            categories = ext.get("categories") or []
            yield {
                "bundle_id":  ext.get("identifier"),
                "team_id":    ext.get("teamID"),
                "version":    version,
                "state":      ext.get("state"),
                "categories": ",".join(categories) if categories else None,
                "raw_json":   json.dumps(jsonable(ext)),
            }


# ----------------------------------------------------------------------------
# Phase 4 — streaming: per-platform process exec events
# ----------------------------------------------------------------------------

class MacosProcessExecCollector(StreamingCollector):
    """Tails ``eslogger exec`` — Apple's Endpoint-Security CLI, shipped
    since macOS Ventura. Each ``exec(2)`` on the host emits one JSON
    object with the executing binary, args, parent, and signing
    information. Requires root (the binary itself enforces this).

    judge_enabled is True so the LLM evaluates each *unique*
    (exe_path, args, user, parent_path) combination — content_hash
    dedupe means a busy machine costs O(unique-binaries-run) LLM
    calls, not O(every-exec).
    """
    name = "process_exec_events"
    model = ProcessExecRow
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    _EVENTS = ("exec",)

    def stream(self, stop_event: threading.Event):
        cmd = ["eslogger", *self._EVENTS]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )

        def _terminator():
            stop_event.wait()
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
        threading.Thread(target=_terminator, daemon=True,
                         name="eslogger-killer").start()

        try:
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield self._row_from_eslogger_event(e)
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except ProcessLookupError:
                    pass

    @staticmethod
    def _row_from_eslogger_event(e: dict) -> dict:
        # eslogger emits ES events: { time, action_type, event,
        # process, ... } where event.exec.{target, args, ...}
        event_obj = e.get("event") or {}
        exec_evt = event_obj.get("exec") or {}
        target = exec_evt.get("target") or {}
        target_exe = (target.get("executable") or {}).get("path")
        args = exec_evt.get("args") or []
        parent = e.get("process") or {}
        parent_path = (parent.get("executable") or {}).get("path")
        target_token = target.get("audit_token") or {}
        parent_token = parent.get("audit_token") or {}
        return {
            "event_timestamp": e.get("time"),
            "event_type":      "exec",
            "pid":             target_token.get("pid"),
            "ppid":            parent_token.get("pid"),
            "uid":             target_token.get("ruid"),
            "username":        None,
            "exe_path":        target_exe,
            "exe_args_json":   json.dumps(args),
            "parent_path":     parent_path,
            "signing_id":      target.get("signing_id"),
            "raw_json":        json.dumps(e),
        }


class LinuxProcessExecCollector(StreamingCollector):
    """Tails the Linux audit subsystem for ``execve`` events via
    ``journalctl -f --output=json`` matchers on the audit type names.

    Requires ``auditd`` running on the host with the execve rule
    installed, e.g.::

        auditctl -a always,exit -F arch=b64 -S execve

    (most distros ship ``audit`` enabled by default for SECCOMP /
    PAM events; the execve rule is the additional configuration.)
    """
    name = "process_exec_events"
    model = ProcessExecRow
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    def _cmd(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager"]
        if HOST_PREFIX:
            host_journal = host_path("/var/log/journal")
            if host_journal.is_dir():
                cmd.extend(["--directory", str(host_journal)])
        cmd.extend(["_AUDIT_TYPE_NAME=EXECVE",
                    "+", "_AUDIT_TYPE_NAME=SYSCALL"])
        return cmd

    def stream(self, stop_event: threading.Event):
        proc = subprocess.Popen(
            self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )

        def _terminator():
            stop_event.wait()
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
        threading.Thread(target=_terminator, daemon=True,
                         name="journalctl-audit-killer").start()

        try:
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield self._row_from_audit_event(e)
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except ProcessLookupError:
                    pass

    @staticmethod
    def _row_from_audit_event(e: dict) -> dict:
        ts_us = e.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass
        try:
            pid = int(e["_PID"]) if e.get("_PID") else None
        except (TypeError, ValueError):
            pid = None
        try:
            uid = int(e["_UID"]) if e.get("_UID") else None
        except (TypeError, ValueError):
            uid = None
        # audit EXECVE messages carry the args as separate fields a0,
        # a1, ... in the structured message; SYSCALL records have
        # the exe= path and comm= name. The combined-record view is
        # typically captured under MESSAGE; we surface what's
        # available and dump the full event into raw_json so the
        # judge sees everything.
        return {
            "event_timestamp": ts,
            "event_type":      e.get("_AUDIT_TYPE_NAME") or "AUDIT",
            "pid":             pid,
            "ppid":            None,
            "uid":             uid,
            "username":        None,
            "exe_path":        e.get("EXE") or e.get("_EXE"),
            "exe_args_json":   None,
            "parent_path":     None,
            "signing_id":      None,
            "raw_json":        json.dumps(e),
        }


# ============================================================================
# Composition + entry point
# ============================================================================

def _build_macos_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
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
        FileIntegrityCollector(judge_hints=h("file_integrity")),
        InstalledAppsCollector(judge_hints=h("installed_apps")),
        # Phase 4 additions
        MountsCollector(judge_hints=h("mounts")),
        SetuidFilesCollector(judge_hints=h("setuid_files")),
        MdmProfilesCollector(judge_hints=h("mdm_profiles")),
        KernelExtensionsCollector(judge_hints=h("kernel_extensions")),
        SystemExtensionsCollector(judge_hints=h("system_extensions")),
    ]


def _build_linux_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
    """Linux snapshot collector set — full parity with the macOS set
    minus the two slices that have no Linux equivalent.

    Cross-platform via psutil: processes, network connections, listening
    ports, network interfaces.

    Same collector classes, Linux paths: file_integrity (WATCHED_FILES_LINUX),
    browser_extensions (BROWSER_PROFILES_LINUX).

    Linux-specific implementations:
      Phase 1 — installed_apps (dpkg-query + XDG .desktop)
      Phase 2 — launch_items (systemd unit files + cron entries)
      Phase 3 — usb_devices (sysfs walk), bluetooth_devices
                (/var/lib/bluetooth INI files), wifi_state (sysfs +
                `iw dev link`), system_integrity (SELinux + AppArmor
                + ufw / firewalld + sshd + vnc + LUKS).

    Dropped on Linux: tcc_permissions and quarantine_events (macOS-only
    concepts with no Linux analog).
    """
    h = prompts.hint_for

    # Expand watched-file templates through host_paths_for_home so that
    # ~/-prefixed entries become one path per user home found under
    # the container's bind-mounted /host/home (or the literal
    # expanduser path on a native install). Absolute /etc paths
    # become /host/etc paths automatically.
    watched: list[str] = []
    for tmpl in WATCHED_FILES_LINUX:
        for p in host_paths_for_home(tmpl):
            watched.append(str(p))

    # Same treatment for browser profile roots — one entry per
    # user_home/.config/<browser>.
    expanded_browser_profiles: dict[Browser, list[str]] = {}
    for browser, templates in BROWSER_PROFILES_LINUX.items():
        out: list[str] = []
        for tmpl in templates:
            for p in host_paths_for_home(tmpl):
                out.append(str(p))
        expanded_browser_profiles[browser] = out

    return [
        ProcessCollector(judge_hints=h("processes")),
        NetworkConnectionsCollector(judge_hints=h("network_connections")),
        ListeningPortsCollector(judge_hints=h("listening_ports")),
        NetworkInterfacesCollector(judge_hints=h("network_interfaces")),
        LinuxUsbDevicesCollector(judge_hints=h("usb_devices")),
        LinuxBluetoothCollector(judge_hints=h("bluetooth_devices")),
        LinuxWifiCollector(judge_hints=h("wifi_state")),
        LinuxLaunchItemsCollector(judge_hints=h("launch_items")),
        BrowserExtensionsCollector(
            judge_hints=h("browser_extensions"),
            profiles=expanded_browser_profiles,
        ),
        LinuxSystemIntegrityCollector(judge_hints=h("system_integrity")),
        FileIntegrityCollector(
            judge_hints=h("file_integrity"),
            watched=watched,
        ),
        LinuxInstalledAppsCollector(judge_hints=h("installed_apps")),
        # Phase 4 additions — cross-platform
        MountsCollector(judge_hints=h("mounts")),
        SetuidFilesCollector(judge_hints=h("setuid_files")),
    ]


def build_snapshot_collectors(prompts: Prompts) -> list[SnapshotCollector]:
    if IS_LINUX:
        return _build_linux_snapshot_collectors(prompts)
    return _build_macos_snapshot_collectors(prompts)


def build_streaming_collectors(prompts: Prompts) -> list[StreamingCollector]:
    h = prompts.hint_for
    if IS_LINUX:
        return [
            LinuxAuthEventsCollector(judge_hints=h("auth_events")),
            LinuxProcessExecCollector(judge_hints=h("process_exec_events")),
        ]
    return [
        AuthEventsCollector(judge_hints=h("auth_events")),
        MacosProcessExecCollector(judge_hints=h("process_exec_events")),
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
    parser.add_argument("--no-streaming", action="store_true",
                        help="Disable streaming collectors (e.g. auth_events)")
    parser.add_argument("--max-db-mb", type=int, default=1024,
                        help="Approximate database-size cap in megabytes. "
                             "After each cycle, oldest completed runs and "
                             "the auth_events older than the new earliest "
                             "run are deleted until the DB fits under the "
                             "cap, then VACUUM reclaims the space. Pass 0 "
                             "to disable rotation. Default: 1024 (1 GB).")
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

    # check_same_thread=False allows the connection pool to hand
    # connections to streaming-worker threads. SQLite serialises writes
    # internally, and WAL mode lets readers proceed in parallel.
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    try:
        sink = Sink(engine)
        snapshot_collectors = build_snapshot_collectors(prompts)
        streaming_collectors = (
            [] if args.no_streaming else build_streaming_collectors(prompts)
        )
        runner = Runner(sink, snapshot_collectors, streaming_collectors,
                        judge, args.lookback_min,
                        max_db_bytes=max(0, args.max_db_mb) * 1024 * 1024)
        runner.setup()

        if args.once:
            run_id, ok, failed = runner.run_once()
            LOG.info("run complete run_id=%s ok=%d failed=%d",
                     run_id, ok, failed)
            return 0

        # Install signal handlers so SIGINT/SIGTERM cleanly stop both
        # the snapshot loop and every streaming worker.
        def _handle_signal(signum, _frame):
            LOG.info("received signal %d; shutting down", signum)
            runner.request_shutdown()
        signal.signal(signal.SIGINT,  _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        runner.start_streaming()
        try:
            runner.run_forever(args.interval)
        finally:
            runner.stop_streaming()
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
