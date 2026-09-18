"""CLI entrypoint and argument parser for `avai monitor`."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine

from avai.enrichers import build_default_chain

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
from .coverage import YaraCoverageAssessor
from .hosts import HostFactory
from .investigator import UnknownFindingInvestigator
from .judge import Judge, LlmJudge, NullJudge
from .llm import CompletionClient, LlmCredentials
from .models import Base
from .narrator import IncidentNarrator
from .prompts import Prompts
from .runner import Runner, RunnerConfig
from .sink import Sink
from .verifier import MaliciousVerdictVerifier


def _has_prompt(system: str, stage: str) -> bool:
    if not system:
        LOG.warning("%s prompt missing from prompts file; %s disabled", stage, stage)
    return bool(system)


@dataclass(frozen=True)
class LlmStages:
    """Every LLM stage, sharing one completion client. A stage stays off (the
    judge a NullJudge) when its flag, its prompt, or the credentials say so."""

    judge: Judge
    narrator: Optional[IncidentNarrator] = None
    coverage: Optional[YaraCoverageAssessor] = None
    verifier: Optional[MaliciousVerdictVerifier] = None
    investigator: Optional[UnknownFindingInvestigator] = None

    @classmethod
    def build(cls, args, prompts: Prompts, credentials: LlmCredentials) -> LlmStages:
        if not credentials.can_call():
            LOG.warning(
                "no usable LLM credentials (CLAUDE_CODE_OAUTH_TOKEN, or "
                "ANTHROPIC_API_KEY / OPENAI_API_KEY with litellm installed); "
                "LLM stages disabled"
            )
            return cls(judge=NullJudge())
        try:
            client = credentials.client()
        except RuntimeError as exc:
            LOG.warning("LLM client unavailable (%s); LLM stages disabled", exc)
            return cls(judge=NullJudge())
        LOG.info("llm client=%s", type(client).__name__)
        return cls(
            judge=cls._judge(args, prompts, client),
            # A digest is only meaningful when judging runs.
            narrator=(
                IncidentNarrator(prompts, client, args.narrative_model)
                if not (args.no_narrative or args.no_judge)
                and _has_prompt(prompts.narrator_system, "narrator")
                else None
            ),
            coverage=(
                YaraCoverageAssessor(prompts, client, args.narrative_model)
                if not args.no_coverage
                and _has_prompt(prompts.coverage_system, "coverage")
                else None
            ),
            verifier=(
                MaliciousVerdictVerifier(prompts, client, args.judge_model)
                if not args.no_verify
                and _has_prompt(prompts.verifier_system, "verifier")
                else None
            ),
            investigator=(
                UnknownFindingInvestigator(prompts, client, args.judge_model)
                if not args.no_investigate
                and _has_prompt(prompts.investigator_system, "investigator")
                else None
            ),
        )

    @staticmethod
    def _judge(args, prompts: Prompts, client: CompletionClient) -> Judge:
        if args.no_judge:
            LOG.info("judge disabled (--no-judge)")
            return NullJudge()
        return LlmJudge(
            prompts,
            client,
            args.judge_model,
            args.judge_batch_size,
            args.judge_max_per_collector,
        )


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
        help=f"Path to prompts TOML (default: {DEFAULT_PROMPTS_PATH})",
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
        "--no-coverage",
        action="store_true",
        help="Disable the YARA ruleset-coverage assessment (the second-stage "
        "LLM that judges whether the loaded rules cover this host's threat "
        "surface). Uses --narrative-model.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable the malicious-verdict verifier (the skeptic second pass "
        "that downgrades unsupported malicious verdicts to suspicious). Uses "
        "--judge-model.",
    )
    parser.add_argument(
        "--no-investigate",
        action="store_true",
        help="Disable the unknown-finding investigator (the deep second pass "
        "that re-judges unknown verdicts with full-history context). Uses "
        "--judge-model.",
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


def build_runner(args) -> "tuple[Runner, object]":
    """Wire a fully-configured Runner (collectors, judge, sink, seeded control
    row) from parsed args, without signal handlers or running the loop.

    Shared by the CLI ``main()`` and the in-process desktop app (which runs the
    monitor in a thread, no subprocess). Returns ``(runner, engine)``; the
    caller drives ``start_streaming`` / ``run_forever`` and disposes the engine.
    """
    # The monitor often runs as root while the dashboard runs unprivileged;
    # both write the same SQLite file. A group-friendly umask makes the DB dir
    # and the files SQLite creates (db, -wal, -shm) group-writable so a
    # same-group dashboard can write the control_state row. _relax_db_permissions
    # fixes already-existing files; this covers ones created from here on.
    os.umask(0o002)
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    prompts_path = Path(args.prompts_file).expanduser()
    prompts = Prompts.load(prompts_path)
    LOG.info(
        "loaded prompts from %s (collector_hints=%d)",
        prompts_path,
        len(prompts.collector_hints),
    )

    llm = LlmStages.build(args, prompts, LlmCredentials.from_env(os.environ))
    LOG.info(
        "starting host_monitor db=%s interval=%ds lookback=%dm judge=%s "
        "narrator=%s coverage=%s verify=%s investigate=%s",
        db_path,
        args.interval,
        args.lookback_min,
        type(llm.judge).__name__,
        type(llm.narrator).__name__ if llm.narrator else "off",
        type(llm.coverage).__name__ if llm.coverage else "off",
        type(llm.verifier).__name__ if llm.verifier else "off",
        type(llm.investigator).__name__ if llm.investigator else "off",
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
            enrichment_chain = build_default_chain(
                engine,
                Base,
                enable=args.enrich_only,
            )
        runner = Runner(
            RunnerConfig(
                sink,
                snapshot_collectors,
                streaming_collectors,
                llm.judge,
                args.lookback_min,
                max_db_bytes=max(0, args.max_db_mb) * 1024 * 1024,
                enrichment_chain=enrichment_chain,
                baseline_min_runs=max(1, args.baseline_runs),
                narrator=llm.narrator,
                coverage=llm.coverage,
                verifier=llm.verifier,
                investigator=llm.investigator,
            )
        )
        runner.setup()
        # Seed the cooperative control row with this run's settings so the
        # dashboard reflects reality (no-op if it already exists).
        sink.ensure_control_row(
            interval=args.interval,
            judge_enabled=not args.no_judge,
            enrich_enabled=not args.no_enrich,
        )
        return runner, engine
    except Exception:
        engine.dispose()
        raise


def main() -> int:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime

    runner, engine = build_runner(args)
    try:
        if args.once:
            run_id, ok, failed = runner.run_once()
            LOG.info("run complete run_id=%s ok=%d failed=%d", run_id, ok, failed)
            return 0

        # Install signal handlers so SIGINT/SIGTERM cleanly stop both
        # the snapshot loop and every streaming worker. First signal =
        # graceful (let the current collector finish, then stop). Second
        # signal = force-quit immediately, a guaranteed escape hatch so
        # Ctrl-C is never swallowed during a long LLM-judging cycle.
        _signal_count = {"n": 0}

        def _handle_signal(signum, _frame):
            _signal_count["n"] += 1
            if _signal_count["n"] >= 2:
                LOG.warning("second signal, forcing immediate exit")
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
