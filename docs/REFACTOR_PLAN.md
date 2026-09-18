# Refactor plan: object orientation, SOLID, YAGNI

Goal: make the codebase aggressively object oriented and SOLID while
deleting everything nobody uses. Every phase ships as one PR, keeps behaviour
identical (except the one bug fix called out in Phase 2), and leaves ruff and
the full test suite green.

This replaces the 2026-05-31 plan from commit `8ca219c`. That plan split
`host_monitor.py` and `dashboard.py` into packages and has been carried out:
neither file exists any more, and the later `refactor/os-abstraction` work
added the Host and runtime layers. One of its anti-goals is reversed on
purpose, following the new request for aggressive OO and SOLID: it said to add
no new abstractions, and Phases 2 to 6 here add value objects, pipeline stages
and parameter objects. Each one replaces measured duplication or complexity.

Its other anti-goals still hold: `Sink` stays one class (decided 2026-09-17),
no DI container, no plugin discovery for collectors, and no interface with one
implementation.

Decisions taken 2026-09-17: "YARN" in the request means YAGNI; `Sink` is not
split; the unused scan-root catalog is deleted; Phases 0 and 1 run first.

Baseline measured on `dev` at `7af815d`, 2026-09-17:

| Measure | Value |
|---|---|
| Tests | 897 passed in 59 s |
| Line coverage | 83% total; `collectors.py` 65%, `desktop.py` 46%, `runtime/probes.py` 61% |
| Functions over mccabe 10 | 12 (worst: `LinuxLaunchItemsCollector.collect` 19, `FileScanCollector._targets` 18, `queries.listening_ports` 18) |
| Functions with more than 5 parameters | 15 (`Runner.__init__` 12, `StreamingWorker.__init__` 10, `queries.findings` 10) |
| Magic-value comparisons (PLR2004) | 74 |
| Classes over 15 methods or 300 lines | `Sink` 49 methods / 1028 lines, `Runner` 40 methods / 1005 lines |
| Functions of 100+ lines | 11 (5 of them in `dashboard/queries.py`, 150 to 193 lines each) |
| `isinstance` / `hasattr` / `getattr` calls | 42 in `collectors.py`, 27 in `indicators.py`, 14 in `queries.py`, 11 in `runner.py` |
| `os.environ` reads outside a composition root | 30 across 10 modules |
| Slice identity (`name`, `model`, `judge_fields`) declared more than once | 8 slices, 3 copies each |

## Rules for every phase

- **Tests first.** A module under 80% coverage gets characterization tests
  before it moves. Those tests pin today's output, even where it looks wrong.
- **The facade is the compatibility seam.** 103 test imports use
  `from avai.host_monitor import ...`. Code moves behind the facade and the
  facade keeps its exports until Phase 10, so tests stay stable while the
  internals change.
- **The DB schema is a contract.** No migration in this plan. The monitor and
  the dashboard can be different versions against the same file.
- **Ruff ratchet.** Phase 0 turns on `C901` (max 10), `PLR0913` (max 5) and
  `PLR2004`, with a per-file ignore list of today's offenders. Each phase
  deletes its entries from that list. Nothing new can be added to it.
- **What "aggressive" does not mean.** No DI container, no new dependency, no
  interface with one implementation unless it is an I/O seam (subprocess,
  filesystem, network, clock, DB) that a test fake already uses. The existing
  Strategy parsers, enrichment sources and supervision protocols already
  follow SOLID and stay as they are.
- **Branching.** One branch per phase (`refactor/p<N>-<topic>`), each
  stacked on the previous one and rooted at `dev`, because `main` is 10+
  merges behind `dev`. Never commit to `dev` or `main` directly.

## Phase 0: guardrails (no production change)

- Enable the ruff ratchet above in `pyproject.toml`.
- Add a layering test (plain pytest plus `ast`, no new dependency) that fails
  when a lower layer imports a higher one: `runtime` imports only `constants`
  and `enums`; collectors never import `hosts`, `sink`, the LLM stages or
  orchestration; `sink` never imports collectors or `hosts` at runtime;
  `host_monitor` never imports the dashboard, desktop or CLI; the dashboard
  never imports collectors, `hosts`, the LLM stages or orchestration (it may
  use `Sink.setup()`); enrichers import nothing from `host_monitor` except
  `constants`.
- Cover the one dashboard route no test hit (`/fragments/auth-events`).
  The other 37 routes and `Runner.run_once` (96 runner tests) are already
  covered, so no stored HTML or DB snapshot is committed. A snapshot of the
  code's own output would only restate it.

Acceptance: the suite is green with the new tests, and ruff passes with the
ignore list in place.

Done on `refactor/p0-guardrails`: ruff ratchet (38 files frozen, a new magic
value in `src/` is rejected), `tests/test_layering.py` (6 rules, proven to
catch an injected dashboard-to-runner import and a function-level
runtime-to-sink import), and the auth-events tests.

## Phase 1: YAGNI, delete what nothing uses

Each item below was checked with a word-level reference count over `src/`,
`tests/` and `templates/`.

| Remove | Evidence |
|---|---|
| `EnrichmentChain.enrich_many` | no caller, no test |
| `EvidenceCache.for_indicator` | no caller, no test |
| `EnrichmentChain.reset_stats` | called only by one test |
| `HostsTable.is_managed` | called only by tests |
| `runtime.ServiceProbe` | only re-exported, never called |
| `runtime.WindowsScmServiceManager` | only re-exported, never wired into `WindowsHost` |
| `dashboard/__init__.py` re-exports of 20 route functions | Flask dispatches routes by URL, and nothing imports the handlers |
| Function-level `avai.enrichers` imports in `main.build_runner` and `Runner._enrich_entries` | meant to keep `requests` out of `--no-enrich` runs, but `Sink.setup()` already loads it on every boot (checked: `'requests' in sys.modules` is true after `setup()`). They become normal top-level imports |
| `file_scanner/` package (`ScanRootCatalog` and 9 related types) | added in `36e1a70`, never wired into `FileScanCollector`, used only by `tests/test_scan_roots.py`. Recoverable from git if scan planning is picked up again |

Acceptance: the listed symbols are gone, their test-only callers are removed or
rewritten against public behaviour, and the suite is green.

Done on `refactor/p1-yagni` in five commits, one per row group: `src/` is 392 lines
smaller and `tests/` 186 lines smaller. 889 tests pass (the drop from 901 is the 11 deleted
scan-root tests plus `test_reset_stats_clears`). The `is_managed` assertions now
check public behaviour: a removed mapping no longer resolves, and removing the
mapping leaves a hand-added entry alone. `docs/ARCHITECTURE.md` was updated to
match, and all 22 of its Mermaid diagrams still parse.

## Phase 2: one source of truth per telemetry slice (DRY, OCP, and a bug fix)

Problem: the string name of a slice, its ORM model and its `judge_fields` are
repeated in each OS variant. The same string is repeated again as a key in the
dashboard's `COLLECTOR_MODELS`, `_STREAMING_COLLECTORS`, the enrichment
`EXTRACTORS` table, `prompts.toml` hints and three constants. The copies have
already drifted: `COLLECTOR_MODELS` is missing `trusted_roots`,
`injection_env`, `kernel_modules` and `ssh_known_hosts`, so the dashboard
cannot show their source row, count them, toggle them or accept feedback on
them.

- Add a frozen value object `Slice(name, model, judge_fields, judge_enabled,
  streaming)` and a `SliceCatalog` that holds every slice exactly once.
- Each collector class points at its slice (`slice = SLICES.usb_devices`), and
  `Collector.name`, `model` and `judge_fields` become properties read from it.
- The dashboard derives `COLLECTOR_MODELS` and `_STREAMING_COLLECTORS` from the
  catalog. `EXTRACTORS` and the prompt hints are validated against it.
- Add catalog tests: every `_RowBase` model has exactly one slice, every
  judged slice has a prompt hint, and every extractor key is a real slice.

Acceptance: slice identity is declared once per slice, the four missing
slices appear in the dashboard, a regression test proves feedback is accepted
for `trusted_roots`, and the existing dashboard tests stay green.

## Phase 3: LLM stages (SRP, DRY, DIP)

Problem: `build_judge`, `build_verifier`, `build_investigator`,
`build_narrator` and `build_coverage_assessor` each re-read the same three env
vars and repeat the same credential rule. Each stage then builds its own
`CompletionClient`. `complete_structured` takes 7 parameters.

- Add a value object `LlmCredentials.from_env()`. It is read once, in the
  composition root, and answers `can_call()` and `client()`.
- Build one `CompletionClient` and inject it into every stage. This is the
  same `client=` seam the tests already use with `_FakeClient`.
- Add `StructuredLlmStage` as a small Template Method base. It holds the
  prompt pair, the schema and the client, with `call(payload) -> dict | None`.
  `MaliciousVerdictVerifier`, `UnknownFindingInvestigator`,
  `IncidentNarrator`, `YaraCoverageAssessor` and `LlmJudge` keep their public
  methods and delegate the call.
- Add `LlmStages.build(args, prompts, credentials)`, which returns all five
  stages or `None`/`NullJudge`, and replaces the five `build_*` functions.
- Add a `CompletionRequest` parameter object in place of the 7 arguments.

Acceptance: `os.environ` is read in no LLM module, one client instance is
shared by every stage, and the credential rule has one implementation and one
table-driven test.

## Phase 4: split `Runner` (SRP, OCP, primitive obsession)

Today `Runner` owns the control loop, maintenance commands, the cycle, seven
finding-enrichment steps, four end-of-cycle reports and the streaming
workers. It passes loose dicts whose keys (`evidence`, `baseline`, `related`,
`rule_meta`, `matched_strings`) are added by different methods.

| New type | Takes over |
|---|---|
| `Finding` (dataclass) and `FindingBatch` | the entry dicts. Typed fields, plus `to_prompt()` at the LLM edge |
| `FindingStage` protocol with one class per step: `EvidenceStage`, `BaselineStage`, `CorrelationStage`, `YaraContextStage`, `JudgeStage`, `VerifyStage`, `InvestigateStage` | `_enrich_entries`, `_annotate_baseline`, `_attach_correlation` and its three pid-map helpers, `_attach_yara_context`, the judge call, `_verify_judgments`, `_investigate_unknowns` |
| `FindingPipeline(stages)` | the middle of `_run_collector`. The stage order is built in the composition root, so a new stage never edits the Runner |
| `CycleStep` protocol: `NarrativeStep`, `RiskScoreStep`, `YaraStatusStep`, `CoverageStep` | the four `_generate_*` / `_write_*` methods and their "skip if unchanged" fingerprints |
| `MaintenanceCommand` enum with an `apply(repos)` method | the `if cmd == ...` chain in `_dispatch_command` |
| `ControlLoop` | `run_forever`, `_refresh_control`, the heartbeats and the scan-now handling |
| `StreamingSupervisor` | `start_streaming` and `stop_streaming` |
| `RunnerConfig` (dataclass) | the 12-argument `Runner.__init__` |
| `SupervisionPolicy` (dataclass) | the 10-argument `StreamingWorker.__init__` (backoff, sleeper, listener, batch size, flush interval, healthy reset) |

Before any move, add characterization tests for the Runner branches the
suite does not reach today (coverage 76%).

`Runner` stays as the thin coordinator of `CollectionCycle`, `ControlLoop` and
`StreamingSupervisor`, so `desktop.py` and `main.py` keep calling the same
three methods.

Acceptance: no class in `runner.py` or its new modules exceeds 15 methods or
300 lines, the characterization tests stay green, and each stage has its own
unit test with a fake collaborator.

## Phase 5: dropped

The `Sink` split into repositories was dropped on 2026-09-17. `Sink` keeps
its 49 methods. Its two worst methods are still simplified where they are:
`correlation_context` (mccabe 15) gets one private method per signal, and
`prune_to_size` (122 lines) gets one private method per table group. Both
get characterization tests first (`tests/test_sink_rotation.py` already
covers pruning; correlation needs its own).

## Phase 6: dashboard (SRP, DIP, parameter objects)

- Replace the module-level `app` and its 5 env reads with
  `create_app(DashboardConfig)`. `serve.py` and `desktop.py` call the factory.
- Split routes into three Blueprints: fragments, api and control.
- Turn `queries.py` (2774 lines of module functions tied to `current_app`)
  into query classes per panel: `FindingsQueries`, `NetworkQueries`,
  `VulnerabilityQueries`, `LogQueries`, `AuthEventQueries`, `PostureQueries`,
  `ResourceQueries` and `CollectionQueries`. Each is built with a session
  factory and never touches Flask.
- Break each 150 to 193 line function into select, map and aggregate methods.
- Add parameter objects `Page(page, per_page)` and `FindingFilter(verdict,
  status, collector, category, q, sort)` in place of the 6 to 10 argument
  signatures.

Before the first move, render every route against a DB seeded by
`tools/seed_demo_db.py` and keep that HTML locally (not committed). After the
phase, render again and diff, with timestamps normalized first.

Acceptance: the before/after HTML diff is empty, no function in
`dashboard/` is over mccabe 10 or 60 lines, and query classes are tested
without a Flask app.

## Phase 7: collectors (SRP, DIP, magic values)

Characterization tests come first. `collectors.py` is at 65% coverage and is
3362 lines long.

- Split `collectors.py` into a `collectors/` package by area: network,
  devices, persistence, integrity, files and streams. The facade keeps
  exports stable.
- Inject collaborators instead of building them inline: 6 `CommandRunner()`
  calls and 14 direct `psutil.` calls move behind the existing
  `CommandRunner`, `SystemMetrics` and `PsutilConnections` seams, wired by the
  Host composition roots as the newer collectors already are.
- Extract `YaraRulesetCompiler` from `_compile_yara_rules` (96 lines). Split
  `LinuxLaunchItemsCollector.collect` (mccabe 19) and `_cron_rows` (80 lines)
  into systemd and cron readers.
- `FileScanCollector._targets` (mccabe 18): split it into the three target
  sources it already walks (privileged bin dirs, app executables, recent
  Downloads), with the per-cycle cap applied once.
- Turn the 74 magic comparisons into named constants or enum members.

Acceptance: coverage for the collector package is at least 80%, no function
exceeds mccabe 10, and zero `CommandRunner()` or `psutil.` calls remain inside
collector classes.

## Phase 8: enrichment and indicators (small)

- Split `EnrichmentChain.enrich` (mccabe 13, 73 lines) into cache lookup,
  fetch and forward-chain methods. Per-source counters become a
  `SourceStats` object.
- Replace the 10 elif chains and 27 type checks in `indicators.py` with a
  single `_safe_loads` result type plus small helpers.
- Simplify `OSVEnricher._fetch` (mccabe 12).

## Phase 9: entry points and configuration (OCP, DIP)

- `cli.main` (88 lines of `if cmd ==`): a `{name: Command}` table with a
  `run(argv)` method per subcommand. Aliases become table entries.
- `HostFactory.create`: a `{system: HostClass}` table instead of three string
  compares.
- `host_monitor.main.build_runner` becomes the single composition root. It
  builds `LlmCredentials`, the repositories, the pipeline and the steps from a
  `MonitorSettings` object parsed once from argv and env.

Acceptance: `os.environ` is read only in `desktop.py`, `main.py`,
`serve.py` and `create_app`.

## Phase 10: trim the facades

- Point tests at the real modules and shrink `host_monitor/__init__.py` (334
  lines) and `dashboard/__init__.py` (260 lines) to the names a caller outside
  the package actually uses.
- Empty the ruff ignore list and delete it.

Acceptance: the ignore list is gone, the layering test is green, coverage is
at least 85%, and `docs/ARCHITECTURE.md` is regenerated.

## Order and why

`0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10`

- Deleting code comes before moving it, so nothing dead gets refactored.
- The slice catalog comes before the Runner, because the Runner, dashboard,
  extractors and prompts all key on slice names.
- The LLM stages come before the Runner, because the Phase 4 pipeline stages
  wrap them.
- The dashboard and collectors are independent of each other and are kept
  sequential to hold three open fronts at most.

Not measured yet: the size of each PR, and whether Phase 4's extra
indirection changes cycle wall time. Phase 4 should time `run_once` before
and after on this Mac.
