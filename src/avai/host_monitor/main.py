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
from types import FrameType

from sqlalchemy import Engine, create_engine

from avai.enrichers import (
    ChainBuilder,
    ChainRequest,
    EnricherCatalog,
    EnrichmentChain,
    EvidenceCache,
)
from avai.enrichers.http import HttpClient

from .collectors import SnapshotCollector, StreamingCollector
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
    LOGGER_NAME,
)
from .coverage import YaraCoverageAssessor
from .hosts import HostFactory
from .investigator import UnknownFindingInvestigator
from .judge import Judge, JudgeSettings, LlmJudge, NullJudge
from .llm import LlmCredentials, LlmSession
from .models import Base
from .narrator import IncidentNarrator
from .prompts import Prompts
from .runner import Runner, RunnerConfig
from .sink import Sink
from .sink_admin import ControlSeed
from .verifier import MaliciousVerdictVerifier

BYTES_PER_MB = 1024 * 1024
DEFAULT_MAX_DB_MB = 1024
# A group-friendly umask keeps the DB files SQLite creates group-writable.
GROUP_WRITABLE_UMASK = 0o002


@dataclass(frozen=True)
class LlmStages:
    """Every LLM stage, sharing one completion client. A stage stays off (the
    judge a NullJudge) when its flag, its prompt, or the credentials say so."""

    judge: Judge
    narrator: IncidentNarrator | None = None
    coverage: YaraCoverageAssessor | None = None
    verifier: MaliciousVerdictVerifier | None = None
    investigator: UnknownFindingInvestigator | None = None


class LlmStageBuilder:
    """Builds the LLM stages the parsed flags and the prompts file allow."""

    def __init__(self, args: argparse.Namespace, logger: logging.Logger) -> None:
        self._args = args
        self._logger = logger

    def build(self, prompts: Prompts, credentials: LlmCredentials) -> LlmStages:
        session = self._session(credentials)
        if session is None:
            return LlmStages(judge=NullJudge())
        return LlmStages(
            judge=self._judge(prompts, session),
            narrator=self._narrator(prompts, session),
            coverage=self._coverage(prompts, session),
            verifier=self._verifier(prompts, session),
            investigator=self._investigator(prompts, session),
        )

    def _session(self, credentials: LlmCredentials) -> LlmSession | None:
        if not credentials.can_call():
            self._logger.warning(
                "no usable LLM credentials (CLAUDE_CODE_OAUTH_TOKEN, or "
                "ANTHROPIC_API_KEY / OPENAI_API_KEY); LLM stages disabled"
            )
            return None
        try:
            client = credentials.client()
        except RuntimeError as exc:
            self._logger.warning(
                "LLM client unavailable (%s); LLM stages disabled", exc
            )
            return None
        self._logger.info("llm client=%s", type(client).__name__)
        return LlmSession(client, self._logger)

    def _judge(self, prompts: Prompts, session: LlmSession) -> Judge:
        args = self._args
        if args.no_judge:
            self._logger.info("judge disabled (--no-judge)")
            return NullJudge()
        settings = JudgeSettings(
            args.judge_model, args.judge_batch_size, args.judge_max_per_collector
        )
        return LlmJudge.create(prompts, session, settings)

    def _narrator(
        self, prompts: Prompts, session: LlmSession
    ) -> IncidentNarrator | None:
        # A digest is only meaningful when judging runs.
        wanted = not (self._args.no_narrative or self._args.no_judge)
        if not (wanted and self._has_prompt(prompts.narrator_system, "narrator")):
            return None
        return IncidentNarrator.create(prompts, session, self._args.narrative_model)

    def _coverage(
        self, prompts: Prompts, session: LlmSession
    ) -> YaraCoverageAssessor | None:
        if self._args.no_coverage or not self._has_prompt(
            prompts.coverage_system, "coverage"
        ):
            return None
        return YaraCoverageAssessor.create(prompts, session, self._args.narrative_model)

    def _verifier(
        self, prompts: Prompts, session: LlmSession
    ) -> MaliciousVerdictVerifier | None:
        if self._args.no_verify or not self._has_prompt(
            prompts.verifier_system, "verifier"
        ):
            return None
        return MaliciousVerdictVerifier.create(prompts, session, self._args.judge_model)

    def _investigator(
        self, prompts: Prompts, session: LlmSession
    ) -> UnknownFindingInvestigator | None:
        if self._args.no_investigate or not self._has_prompt(
            prompts.investigator_system, "investigator"
        ):
            return None
        return UnknownFindingInvestigator.create(
            prompts, session, self._args.judge_model
        )

    def _has_prompt(self, system: str, stage: str) -> bool:
        if not system:
            self._logger.warning(
                "%s prompt missing from prompts file; %s disabled", stage, stage
            )
        return bool(system)


class MonitorArgs:
    """The ``avai monitor`` argument parser. Bare ``avai monitor`` uses
    ~/.avai/avai.db, a 300s interval and a 25-per-collector judge cap."""

    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="avai: host security telemetry + LLM threat judge"
        )
        self._add_cycle(parser)
        self._add_judge(parser)
        self._add_stages(parser)
        self._add_storage(parser)
        self._add_enrichment(parser)
        parser.add_argument("--verbose", action="store_true")
        return parser

    def _add_cycle(self, parser: argparse.ArgumentParser) -> None:
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

    def _add_judge(self, parser: argparse.ArgumentParser) -> None:
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
        self._add_prompts(parser)

    def _add_prompts(self, parser: argparse.ArgumentParser) -> None:
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
        self._add_baseline(parser)

    def _add_baseline(self, parser: argparse.ArgumentParser) -> None:
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

    def _add_stages(self, parser: argparse.ArgumentParser) -> None:
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
        self._add_second_opinions(parser)

    def _add_second_opinions(self, parser: argparse.ArgumentParser) -> None:
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
        self._add_investigator(parser)

    def _add_investigator(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-investigate",
            action="store_true",
            help="Disable the unknown-finding investigator (the deep second pass "
            "that re-judges unknown verdicts with full-history context). Uses "
            "--judge-model.",
        )

    def _add_storage(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-streaming",
            action="store_true",
            help="Disable streaming collectors (e.g. auth_events)",
        )
        parser.add_argument(
            "--max-db-mb",
            type=int,
            default=DEFAULT_MAX_DB_MB,
            help="Approximate database-size cap in megabytes. "
            "After each cycle, oldest completed runs and "
            "the auth_events older than the new earliest "
            "run are deleted until the DB fits under the "
            "cap, then VACUUM reclaims the space. Pass 0 "
            "to disable rotation. Default: 1024 (1 GB).",
        )

    def _add_enrichment(self, parser: argparse.ArgumentParser) -> None:
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


class MonitorWiring:
    """Wires a fully-configured Runner (collectors, judge, sink, seeded
    control row) from parsed args, without signal handlers or the loop.

    Shared by ``avai monitor`` and the in-process desktop app (which runs the
    monitor on a thread). ``build`` returns ``(runner, engine)``; the caller
    drives ``start_streaming`` / ``run_forever`` and disposes the engine.
    """

    def __init__(self, args: argparse.Namespace, logger: logging.Logger) -> None:
        self._args = args
        self._logger = logger

    def build(self) -> tuple[Runner, Engine]:
        db_path = self._prepare_db()
        prompts = self._prompts()
        credentials = LlmCredentials.from_env(os.environ)
        llm = LlmStageBuilder(self._args, self._logger).build(prompts, credentials)
        self._log_start(db_path, llm)
        # check_same_thread=False lets the pool hand connections to the
        # streaming-worker threads; SQLite serialises writes and WAL lets
        # readers proceed in parallel.
        engine = create_engine(
            f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
        )
        built = False
        try:
            runner = self._runner(engine, prompts, llm)
            built = True
            return runner, engine
        finally:
            if not built:
                engine.dispose()

    def _prepare_db(self) -> Path:
        # The monitor often runs as root while the dashboard runs
        # unprivileged and both write the same SQLite file; the umask covers
        # the files SQLite creates from here on.
        os.umask(GROUP_WRITABLE_UMASK)
        db_path = Path(self._args.db).expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return db_path

    def _prompts(self) -> Prompts:
        prompts_path = Path(self._args.prompts_file).expanduser()
        prompts = Prompts.load(prompts_path)
        self._logger.info(
            "loaded prompts from %s (collector_hints=%d)",
            prompts_path,
            len(prompts.collector_hints),
        )
        return prompts

    def _log_start(self, db_path: Path, llm: LlmStages) -> None:
        stages = (llm.narrator, llm.coverage, llm.verifier, llm.investigator)
        names = [type(stage).__name__ if stage else "off" for stage in stages]
        self._logger.info(
            "starting host_monitor db=%s interval=%ds lookback=%dm judge=%s "
            "narrator=%s coverage=%s verify=%s investigate=%s",
            db_path,
            self._args.interval,
            self._args.lookback_min,
            type(llm.judge).__name__,
            *names,
        )

    def _runner(self, engine: Engine, prompts: Prompts, llm: LlmStages) -> Runner:
        args = self._args
        sink = Sink.create(engine)
        runner = Runner.create(self._config(sink, prompts, llm))
        runner.setup()
        # Seed the control row with this run's settings (no-op if it exists).
        seed = ControlSeed(args.interval, not args.no_judge, not args.no_enrich)
        sink.ensure_control_row(seed)
        return runner

    def _config(self, sink: Sink, prompts: Prompts, llm: LlmStages) -> RunnerConfig:
        args = self._args
        snapshot, streaming = self._collectors(prompts)
        return RunnerConfig(
            sink,
            snapshot,
            streaming,
            llm.judge,
            args.lookback_min,
            max_db_bytes=max(0, args.max_db_mb) * BYTES_PER_MB,
            enrichment_chain=self._enrichment(sink.engine),
            baseline_min_runs=max(1, args.baseline_runs),
            narrator=llm.narrator,
            coverage=llm.coverage,
            verifier=llm.verifier,
            investigator=llm.investigator,
            logger=self._logger,
        )

    def _collectors(
        self, prompts: Prompts
    ) -> tuple[list[SnapshotCollector], list[StreamingCollector]]:
        host = HostFactory(self._logger).create()
        snapshot = host.snapshot_collectors(prompts)
        if self._args.no_streaming:
            return snapshot, []
        return snapshot, host.streaming_collectors(prompts)

    def _enrichment(self, engine: Engine) -> EnrichmentChain | None:
        if self._args.no_enrich:
            self._logger.info("enrichment disabled (--no-enrich)")
            return None
        logger = logging.getLogger("avai.enrichers")
        builder = ChainBuilder(
            EnricherCatalog.of_sources(logger), HttpClient.create(logger), logger
        )
        only = self._args.enrich_only
        request = ChainRequest(dict(os.environ), frozenset(only) if only else None)
        return builder.build(EvidenceCache.on_base(engine, Base), request)


class ShutdownSignals:
    """SIGINT/SIGTERM stop the snapshot loop and every streaming worker. The
    first signal is graceful (the current collector finishes); the second
    force-quits, so Ctrl-C is never swallowed during a long judging cycle."""

    FORCE_QUIT_SIGNALS = 2
    FORCED_EXIT_CODE = 130

    def __init__(self, runner: Runner, logger: logging.Logger) -> None:
        self._runner = runner
        self._logger = logger
        self._received = 0

    def install(self) -> None:
        signal.signal(signal.SIGINT, self.on_signal)
        signal.signal(signal.SIGTERM, self.on_signal)

    def on_signal(self, signum: int, _frame: FrameType | None) -> None:
        self._received += 1
        if self._received >= self.FORCE_QUIT_SIGNALS:
            self._logger.warning("second signal, forcing immediate exit")
            os._exit(self.FORCED_EXIT_CODE)
        self._logger.warning(
            "received signal %d; stopping after the current step "
            "(press Ctrl-C again to force-quit now)",
            signum,
        )
        self._runner.request_shutdown()


class MonitorApp:
    """``avai monitor``: one cycle with ``--once``, else the daemon loop."""

    def __init__(self, runner: Runner, logger: logging.Logger) -> None:
        self._runner = runner
        self._logger = logger

    @classmethod
    def main(cls) -> int:
        args = MonitorArgs().parser().parse_args()
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(asctime)sZ %(levelname)s %(message)s",
        )
        logging.Formatter.converter = time.gmtime
        logger = logging.getLogger(LOGGER_NAME)
        runner, engine = MonitorWiring(args, logger).build()
        try:
            return cls(runner, logger).serve(args)
        finally:
            engine.dispose()

    def serve(self, args: argparse.Namespace) -> int:
        if args.once:
            run_id, ok, failed = self._runner.run_once()
            self._logger.info(
                "run complete run_id=%s ok=%d failed=%d", run_id, ok, failed
            )
            return 0
        ShutdownSignals(self._runner, self._logger).install()
        self._runner.start_streaming()
        try:
            self._runner.run_forever(args.interval)
        finally:
            self._runner.stop_streaming()
        return 0


if __name__ == "__main__":
    sys.exit(MonitorApp.main())
