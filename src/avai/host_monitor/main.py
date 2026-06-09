"""CLI entrypoint and argument parser for `avai monitor`."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from sqlalchemy import create_engine

from .constants import (
    DEFAULT_BASELINE_MIN_RUNS,
    DEFAULT_DB_PATH,
    DEFAULT_INTERVAL,
    DEFAULT_JUDGE_BATCH,
    DEFAULT_JUDGE_MAX_PER_COLLECTOR,
    DEFAULT_JUDGE_MODEL,
    DEFAULT_LOOKBACK_MIN,
    DEFAULT_NARRATIVE_MODEL,
    DEFAULT_PROMPTS_PATH,
    LOG,
)
from .hosts import HostFactory
from .judge import build_judge
from .models import Base
from .narrator import build_narrator
from .prompts import Prompts
from .runner import Runner
from .sink import Sink


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="avai — host security telemetry + LLM threat judge"
    )
    # Bare `avai monitor` uses ~/.avai/avai.db, a 300s interval, and a
    # 25-per-collector judge cap — no flags needed.
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help="Seconds between cycles (default: 300)",
    )
    parser.add_argument(
        "--lookback-min",
        type=int,
        default=DEFAULT_LOOKBACK_MIN,
        help="Minutes of unified-log history per run",
    )
    parser.add_argument(
        "--no-judge", action="store_true", help="Disable the LLM threat judge"
    )
    parser.add_argument(
        "--judge-model",
        default=DEFAULT_JUDGE_MODEL,
        help=f"litellm model id (default: {DEFAULT_JUDGE_MODEL})",
    )
    parser.add_argument(
        "--judge-batch-size",
        type=int,
        default=DEFAULT_JUDGE_BATCH,
        help=f"Entries per LLM call (default: {DEFAULT_JUDGE_BATCH})",
    )
    parser.add_argument(
        "--judge-max-per-collector",
        type=int,
        default=DEFAULT_JUDGE_MAX_PER_COLLECTOR,
        help="Cap of new entries judged per collector per run",
    )
    parser.add_argument(
        "--prompts-file",
        default=str(DEFAULT_PROMPTS_PATH),
        help=f"Path to prompts TOML " f"(default: {DEFAULT_PROMPTS_PATH})",
    )
    parser.add_argument(
        "--baseline-runs",
        type=int,
        default=DEFAULT_BASELINE_MIN_RUNS,
        help="Completed runs that establish the host baseline. Until this "
        "many runs exist the judge treats the host as still-being-learned "
        "(won't flag mere presence); after it, artifacts first seen post-"
        f"baseline are marked novel. Default: {DEFAULT_BASELINE_MIN_RUNS} "
        "(≈1 hour at the 300s interval).",
    )
    parser.add_argument(
        "--no-narrative",
        action="store_true",
        help="Disable the incident-narrative digest (the second-stage LLM "
        "that synthesises active findings into one attack-story).",
    )
    parser.add_argument(
        "--narrative-model",
        default=DEFAULT_NARRATIVE_MODEL,
        help=f"Model id for the incident narrator (default: "
        f"{DEFAULT_NARRATIVE_MODEL}, i.e. the judge model).",
    )
    parser.add_argument(
        "--no-streaming",
        action="store_true",
        help="Disable streaming collectors (e.g. auth_events)",
    )
    parser.add_argument(
        "--max-db-mb",
        type=int,
        default=1024,
        help="Approximate database-size cap in megabytes. "
        "After each cycle, oldest completed runs and "
        "the auth_events older than the new earliest "
        "run are deleted until the DB fits under the "
        "cap, then VACUUM reclaims the space. Pass 0 "
        "to disable rotation. Default: 1024 (1 GB).",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Disable the threat-intel enrichment chain "
        "(MalwareBazaar / VirusTotal / Shodan / "
        "URLhaus / abuse.ch / CISA KEV / OSV / NVD / "
        "AbuseIPDB / GreyNoise / Safe Browsing / "
        "PhishTank / GitHub Advisory / endoflife / "
        "crt.sh). Keyless sources always run; keyed "
        "sources only run when their env var is set.",
    )
    parser.add_argument(
        "--enrich-only",
        action="append",
        metavar="NAME",
        help="Limit enrichment to the named source(s). "
        "Pass once per source. Useful for debugging.",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    prompts_path = Path(args.prompts_file).expanduser()
    prompts = Prompts.load(prompts_path)
    LOG.info(
        "loaded prompts from %s (collector_hints=%d)",
        prompts_path,
        len(prompts.collector_hints),
    )

    judge = build_judge(args, prompts)
    narrator = build_narrator(args, prompts)
    LOG.info(
        "starting host_monitor db=%s interval=%ds lookback=%dm judge=%s narrator=%s",
        db_path,
        args.interval,
        args.lookback_min,
        type(judge).__name__,
        type(narrator).__name__ if narrator else "off",
    )

    # check_same_thread=False allows the connection pool to hand
    # connections to streaming-worker threads. SQLite serialises writes
    # internally, and WAL mode lets readers proceed in parallel.
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    try:
        sink = Sink(engine)
        host = HostFactory.create()
        snapshot_collectors = host.snapshot_collectors(prompts)
        streaming_collectors = (
            [] if args.no_streaming else host.streaming_collectors(prompts)
        )
        enrichment_chain = None
        if args.no_enrich:
            LOG.info("enrichment disabled (--no-enrich)")
        else:
            # Importing here keeps the `requests` dep out of the startup
            # path for `--no-enrich` smoke tests.
            from avai.enrichers import build_default_chain

            enrichment_chain = build_default_chain(
                engine,
                Base,
                enable=args.enrich_only,
            )
        runner = Runner(
            sink,
            snapshot_collectors,
            streaming_collectors,
            judge,
            args.lookback_min,
            max_db_bytes=max(0, args.max_db_mb) * 1024 * 1024,
            enrichment_chain=enrichment_chain,
            baseline_min_runs=max(1, args.baseline_runs),
            narrator=narrator,
        )
        runner.setup()
        # Seed the cooperative control row with this run's settings so the
        # dashboard reflects reality (no-op if it already exists).
        sink.ensure_control_row(
            interval=args.interval,
            judge_enabled=not args.no_judge,
            enrich_enabled=not args.no_enrich,
        )

        if args.once:
            run_id, ok, failed = runner.run_once()
            LOG.info("run complete run_id=%s ok=%d failed=%d", run_id, ok, failed)
            return 0

        # Install signal handlers so SIGINT/SIGTERM cleanly stop both
        # the snapshot loop and every streaming worker. First signal =
        # graceful (let the current collector finish, then stop). Second
        # signal = force-quit immediately — a guaranteed escape hatch so
        # Ctrl-C is never swallowed during a long LLM-judging cycle.
        _signal_count = {"n": 0}

        def _handle_signal(signum, _frame):
            _signal_count["n"] += 1
            if _signal_count["n"] >= 2:
                LOG.warning("second signal — forcing immediate exit")
                os._exit(130)
            LOG.warning(
                "received signal %d; stopping after the current step "
                "(press Ctrl-C again to force-quit now)",
                signum,
            )
            runner.request_shutdown()

        signal.signal(signal.SIGINT, _handle_signal)
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
