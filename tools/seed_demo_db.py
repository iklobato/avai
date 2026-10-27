#!/usr/bin/env python3
"""Seed the avai database with realistic synthetic data across ALL tables so
the dashboard is fully populated for a demo / dev run: no sudo, no real
system activity, no actual malware. Pure DB inserts.

Usage:
    python tools/seed_demo_db.py [--db ~/avai-local.db]

Intended for a fresh DB (delete the old one first). Idempotent-ish: it
creates the schema if missing and inserts a self-contained snapshot. The
snapshot rows live in ``demo_seed.json`` next to this file; timestamps there
are tokens (``$run_start:K``, ``$run_end:K``) resolved against "now", and
``$home:<path>`` resolves under the current user's home.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TextIO

from sqlalchemy import Engine, create_engine, insert
from sqlalchemy.orm import DeclarativeBase, Session

from avai.enrichers.cache import EnrichmentSchema
from avai.host_monitor import (
    AuthEventRow,
    Base,
    BluetoothDeviceRow,
    BrowserExtensionRow,
    CollectionRun,
    DiskUsageRow,
    DnsQueryRow,
    FileIntegrityRow,
    FileScanRow,
    HostResourceRow,
    HostsFileRow,
    IncidentNarrativeRow,
    InstalledAppRow,
    Judgement,
    KernelExtensionRow,
    LaunchItemRow,
    ListeningPortRow,
    MdmProfileRow,
    MountRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    NetworkInterfaceRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    ProcessRow,
    QuarantineEventRow,
    RiskScoreRow,
    SetuidFileRow,
    Sink,
    SshAuthorizedKeyRow,
    StreamingSession,
    SystemExtensionRow,
    SystemIntegrityRow,
    UsbDeviceRow,
    WifiStateRow,
    YaraStatusRow,
)

SEED_FILE = Path(__file__).with_name("demo_seed.json")
DEFAULT_DB = "~/avai-local.db"
BYTES_PER_MB = 1024 * 1024
DEMO_HOST = "demo-host.local"
DEMO_USER = "iklo"
DEMO_REMOTE_NET = "203.0.113"
SUMMARY_TABLES = (
    "collection_runs",
    "judgements",
    "incident_narratives",
    "risk_scores",
    "enrichment_evidence",
)


class DemoClock:
    """Run k (1 = newest) started ``k * RUN_SPACING`` before now."""

    RUN_SPACING = timedelta(minutes=4)
    RUN_DURATION = timedelta(seconds=28)

    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def iso(self, moment: datetime) -> str:
        return moment.replace(microsecond=0).isoformat()

    def run_start(self, run: int) -> str:
        return self.iso(self._start(run))

    def run_end(self, run: int) -> str:
        return self.iso(self._start(run) + self.RUN_DURATION)

    def _start(self, run: int) -> datetime:
        return self._now - self.RUN_SPACING * run


class SeedTokens:
    """Replaces ``$name:arg`` strings anywhere in a JSON value."""

    def __init__(self, clock: DemoClock, home: Path) -> None:
        self._clock = clock
        self._home = home

    def resolve(self, value: object) -> object:
        match value:
            case str():
                return self._text(value)
            case list():
                return [self.resolve(item) for item in value]
            case dict():
                return {key: self.resolve(item) for key, item in value.items()}
            case _:
                return value

    def _text(self, text: str) -> str:
        if not text.startswith("$"):
            return text
        name, _, argument = text[1:].partition(":")
        handlers = {
            "home": self._home_path,
            "run_start": self._run_start,
            "run_end": self._run_end,
        }
        return handlers[name](argument)

    def _home_path(self, relative: str) -> str:
        return str(self._home / relative)

    def _run_start(self, run: str) -> str:
        return self._clock.run_start(int(run))

    def _run_end(self, run: str) -> str:
        return self._clock.run_end(int(run))


class DemoModels:
    """The ORM classes ``demo_seed.json`` names, by class name."""

    MODELS = (
        AuthEventRow,
        BluetoothDeviceRow,
        BrowserExtensionRow,
        CollectionRun,
        DiskUsageRow,
        DnsQueryRow,
        FileIntegrityRow,
        FileScanRow,
        HostResourceRow,
        HostsFileRow,
        IncidentNarrativeRow,
        InstalledAppRow,
        Judgement,
        KernelExtensionRow,
        LaunchItemRow,
        ListeningPortRow,
        MdmProfileRow,
        MountRow,
        NetworkConnectionRow,
        NetworkFlowRow,
        NetworkInterfaceRow,
        PrivilegeConfigRow,
        ProcessExecRow,
        ProcessRow,
        QuarantineEventRow,
        RiskScoreRow,
        SetuidFileRow,
        SshAuthorizedKeyRow,
        StreamingSession,
        SystemExtensionRow,
        SystemIntegrityRow,
        UsbDeviceRow,
        WifiStateRow,
        YaraStatusRow,
    )

    def __init__(self, base: type[DeclarativeBase]) -> None:
        self._base = base

    def by_name(self) -> dict[str, type[DeclarativeBase]]:
        models = (*self.MODELS, EnrichmentSchema(self._base).model())
        return {model.__name__: model for model in models}


class DemoSnapshot:
    """Builds the ORM rows listed in the seed file, in file order (row ids
    follow that order)."""

    def __init__(self, models: DemoModels, tokens: SeedTokens) -> None:
        self._models = models
        self._tokens = tokens

    def rows(self, seed_file: Path) -> list[DeclarativeBase]:
        entries = json.loads(seed_file.read_text())["rows"]
        models = self._models.by_name()
        return [
            models[entry["model"]](**self._fields(entry["fields"])) for entry in entries
        ]

    def _fields(self, fields: dict[str, object]) -> dict[str, object]:
        resolved = self._tokens.resolve(fields)
        return {key: self._column(value) for key, value in resolved.items()}

    def _column(self, value: object) -> object:
        """Lists and objects are stored as JSON text columns."""
        if isinstance(value, (list, dict)):
            return json.dumps(value)
        return value


class DatabaseFile:
    SIDE_FILES = ("", "-wal", "-shm")

    def __init__(self, path: str) -> None:
        self._path = path

    def size_bytes(self) -> int:
        paths = (Path(self._path + suffix) for suffix in self.SIDE_FILES)
        return sum(path.stat().st_size for path in paths if path.exists())

    def size_mb(self) -> float:
        return self.size_bytes() / BYTES_PER_MB


@dataclass(frozen=True)
class BulkRun:
    run_id: str
    started_at: str


class BulkHistory:
    """Collection runs older than the demo snapshot, so the 'latest run'
    panels stay clean: bulk rows only add history and volume."""

    RUNS = 240
    START_OFFSET = timedelta(hours=3)
    RUN_STEP = timedelta(seconds=30)
    RUN_DURATION = timedelta(seconds=18)
    COLLECTORS_OK = 24
    LOOKBACK_MIN = 6

    def __init__(self, engine: Engine, clock: DemoClock) -> None:
        self._engine = engine
        self._clock = clock

    def write(self) -> list[BulkRun]:
        first = self._clock.now() - self.START_OFFSET
        runs = [
            self._run(index, first + self.RUN_STEP * index)
            for index in range(self.RUNS)
        ]
        with Session(self._engine) as session:
            session.add_all(runs)
            session.commit()
            return [BulkRun(run.run_id, run.started_at) for run in runs]

    def _run(self, index: int, started: datetime) -> CollectionRun:
        return CollectionRun(
            run_id=f"hist-{index}",
            started_at=self._clock.iso(started),
            finished_at=self._clock.iso(started + self.RUN_DURATION),
            hostname=DEMO_HOST,
            collectors_ok=self.COLLECTORS_OK,
            collectors_failed=0,
            lookback_min=self.LOOKBACK_MIN,
        )


class BulkStamp:
    """Where one bulk row sits: its run, its batch and its index."""

    PROCESS_NAMES = (
        "Google Chrome",
        "node",
        "python3.11",
        "Slack",
        "zoom.us",
        "Terminal",
        "ssh",
        "curl",
        "bash",
        "mDNSResponder",
        "WindowServer",
        "cfprefsd",
    )
    IPV4_OCTETS = 256

    def __init__(self, run: BulkRun, batch: int, index: int) -> None:
        self.run = run
        self.batch = batch
        self.index = index

    def process_name(self) -> str:
        return self.PROCESS_NAMES[self.index % len(self.PROCESS_NAMES)]

    def remote_ip(self) -> str:
        return f"{DEMO_REMOTE_NET}.{self.index % self.IPV4_OCTETS}"

    def common(self, hash_prefix: str) -> dict[str, object]:
        return {
            "run_id": self.run.run_id,
            "collected_at": self.run.started_at,
            "content_hash": f"{hash_prefix}{self.batch}_{self.index}",
        }


class BulkProcessRows:
    """Bulk ``processes`` and ``process_exec_events`` rows."""

    PID_BASE = 1000
    EXEC_PID_BASE = 2000
    CPU_SPREAD = 97
    CPU_DIVISOR = 3.0
    RSS_BASE = 5_000_000
    RSS_STEP = 13
    THREAD_SPREAD = 24
    DEMO_UID = 501

    def process(self, stamp: BulkStamp) -> dict[str, object]:
        name = stamp.process_name()
        return stamp.common("hp") | {
            "pid": self.PID_BASE + stamp.index,
            "ppid": 1,
            "name": name,
            "exe": f"/usr/bin/{name}",
            "cmdline_json": json.dumps([name, "--opt", str(stamp.index)]),
            "username": DEMO_USER,
            "cpu_percent": (stamp.index % self.CPU_SPREAD) / self.CPU_DIVISOR,
            "memory_rss": self.RSS_BASE + stamp.index * self.RSS_STEP,
            "num_threads": 1 + stamp.index % self.THREAD_SPREAD,
        }

    def process_exec(self, stamp: BulkStamp) -> dict[str, object]:
        name = stamp.process_name()
        return stamp.common("hx") | {
            "event_timestamp": stamp.run.started_at,
            "event_type": "exec",
            "pid": self.EXEC_PID_BASE + stamp.index,
            "ppid": 1,
            "uid": self.DEMO_UID,
            "username": DEMO_USER,
            "exe_path": f"/usr/bin/{name}",
            "exe_args_json": json.dumps([name, str(stamp.index)]),
            "parent_path": "/bin/zsh",
            "signing_id": "com.apple.x",
        }


class BulkNetworkRows:
    """Bulk ``network_connections``, ``dns_queries`` and ``auth_events``."""

    PID_BASE = 1000
    LOCAL_PORT_BASE = 40000
    LOCAL_PORT_SPREAD = 20000
    HTTPS_PORT = 443
    DNS_COUNT_SPREAD = 9
    AUTH_PID_BASE = 900
    AUTH_PID_SPREAD = 500
    RAW_BLOB_LENGTH = 48
    AUTH_PROCESSES = ("sudo", "sshd")

    def connection(self, stamp: BulkStamp) -> dict[str, object]:
        return stamp.common("hc") | {
            "pid": self.PID_BASE + stamp.index,
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "laddr_ip": "192.168.1.20",
            "laddr_port": self.LOCAL_PORT_BASE + stamp.index % self.LOCAL_PORT_SPREAD,
            "raddr_ip": stamp.remote_ip(),
            "raddr_port": self.HTTPS_PORT,
            "status": "ESTABLISHED",
        }

    def dns_query(self, stamp: BulkStamp) -> dict[str, object]:
        return stamp.common("hd") | {
            "iface": "en0",
            "qname": f"host{stamp.index}.cdn.example.com",
            "qtype": "A",
            "server_ip": "192.168.1.1",
            "process": stamp.process_name(),
            "count": 1 + stamp.index % self.DNS_COUNT_SPREAD,
            "first_seen": stamp.run.started_at,
            "last_seen": stamp.run.started_at,
        }

    def auth_event(self, stamp: BulkStamp) -> dict[str, object]:
        seq = f"{stamp.batch}_{stamp.index}"
        return stamp.common("ha") | {
            "event_timestamp": stamp.run.started_at,
            "process": self.AUTH_PROCESSES[stamp.index % len(self.AUTH_PROCESSES)],
            "subsystem": "com.apple.securityd",
            "category": "auth",
            "event_type": "failure",
            "event_message": (
                f"authentication failure {seq} for demo from {stamp.remote_ip()}"
            ),
            "pid": self.AUTH_PID_BASE + stamp.index % self.AUTH_PID_SPREAD,
            "raw_json": json.dumps(
                {"seq": stamp.index, "blob": "x" * self.RAW_BLOB_LENGTH}
            ),
        }


class BulkFiller:
    """Inserts batches of historical rows across the heavy time-series
    tables until the DB file reaches a target size."""

    BATCH_ROWS = 10000

    def __init__(self, engine: Engine, history: list[BulkRun]) -> None:
        self._engine = engine
        self._history = history

    def fill(self, database: DatabaseFile, target_bytes: int) -> int:
        batch = 0
        while database.size_bytes() < target_bytes:
            run = self._history[batch % len(self._history)]
            self._insert(run, batch)
            batch += 1
        return database.size_bytes()

    def _insert(self, run: BulkRun, batch: int) -> None:
        stamps = [BulkStamp(run, batch, index) for index in range(self.BATCH_ROWS)]
        with self._engine.begin() as conn:
            for model, build in self._tables():
                conn.execute(insert(model), [build(stamp) for stamp in stamps])

    def _tables(
        self,
    ) -> tuple[
        tuple[type[DeclarativeBase], Callable[[BulkStamp], dict[str, object]]], ...
    ]:
        processes, network = BulkProcessRows(), BulkNetworkRows()
        return (
            (ProcessRow, processes.process),
            (AuthEventRow, network.auth_event),
            (NetworkConnectionRow, network.connection),
            (DnsQueryRow, network.dns_query),
            (ProcessExecRow, processes.process_exec),
        )


class SeedReport:
    def __init__(self, out: TextIO, db_path: str) -> None:
        self._out = out
        self._db_path = db_path

    def write(self) -> None:
        size = DatabaseFile(self._db_path).size_mb()
        self._out.write(f"seeded {self._db_path} ({size:.1f} MB)\n")
        with closing(sqlite3.connect(self._db_path)) as connection:
            for table in SUMMARY_TABLES:
                query = f"select count(*) from {table}"
                count = connection.execute(query).fetchone()[0]
                self._out.write(f"  {count:>4}  {table}\n")
        self._out.write("done: start the dashboard to view.\n")


class DemoSeedCli:
    def __init__(self, out: TextIO) -> None:
        self._out = out

    @classmethod
    def main(cls) -> None:
        args = cls(sys.stdout).parser().parse_args()
        cls(sys.stdout).seed(args, datetime.now(timezone.utc).replace(microsecond=0))

    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Seed avai DB with demo data.")
        parser.add_argument("--db", default=os.path.expanduser(DEFAULT_DB))
        parser.add_argument(
            "--target-mb",
            type=float,
            default=0.0,
            help="If >0, bulk-fill historical rows until the DB is at least this "
            "many MB (the demo snapshot stays the latest run).",
        )
        return parser

    def seed(self, args: argparse.Namespace, now: datetime) -> None:
        engine = create_engine(
            f"sqlite:///{args.db}", connect_args={"check_same_thread": False}
        )
        Sink.create(engine).setup()  # create_all + enrichment model + migrate
        clock = DemoClock(now)
        tokens = SeedTokens(clock, Path.home())
        rows = DemoSnapshot(DemoModels(Base), tokens).rows(SEED_FILE)
        with Session(engine) as session:
            session.add_all(rows)
            session.commit()
        if args.target_mb > 0:
            self._bulk_fill(engine, clock, args)
        SeedReport(self._out, args.db).write()

    def _bulk_fill(
        self, engine: Engine, clock: DemoClock, args: argparse.Namespace
    ) -> None:
        self._out.write(f"bulk-filling to >= {args.target_mb:.0f} MB …\n")
        filler = BulkFiller(engine, BulkHistory(engine, clock).write())
        target = int(args.target_mb * BYTES_PER_MB)
        size = filler.fill(DatabaseFile(args.db), target)
        self._out.write(f"  reached {size / BYTES_PER_MB:.1f} MB\n")


if __name__ == "__main__":
    DemoSeedCli.main()
