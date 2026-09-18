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

Done on `refactor/p2-slice-catalog`, with two changes from the design above:

- `judge_fields` (and `judge_enabled`) stay on the collector class. They
  really differ by OS: Windows `process_exec_events` judges `username` where
  macOS and Linux judge `uid`, and only macOS `system_integrity` judges
  `firewall_stealth`. A `Slice` is `(name, model, streaming)`.
- The catalog is a module (`host_monitor/slices.py`: one constant per slice
  plus `ALL`), not a `SliceCatalog` class. Nothing needed an instance.

The dashboard's `COLLECTOR_MODELS` and `_STREAMING_COLLECTORS` are built from
it, which adds the four missing slices. The feedback regression test covers
all four, and it fails on the old map. `tests/test_slices.py` checks the catalog
against the row models, collector classes, prompt hints and extractor keys,
and each check was seen to fail when its rule was broken. 898 tests pass.

Left open: `DISPLAY_FIELDS` is still hand-kept and lacks 15 slices, and the
slice names repeated in `constants.py` were not touched.

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

Done on `refactor/p3-llm-stages`, with two changes from the design above:

- No `StructuredLlmStage` base class. Each stage holds a `StructuredCall`
  (its fixed `CompletionRequest` plus the client) and delegates to it. The
  stages keep `judge`, `verify`, `investigate`, `narrate` and `assess`.
- `LlmStages` lives in `main.py`, the composition root. Putting it in
  `llm.py` would make `llm.py` import the stages that import it.

Credentials are read from `os.environ` once, in `build_runner`, and
`LlmCredentials` is the only place the rule lives. One client is built and
passed to every stage, and the stages now require it. The one `os.environ`
touch left in an LLM module is `llm.py` setting `LITELLM_LOG` to quiet
litellm on import; it reads no credentials. The `temperature` and
`max_tokens` arguments nobody passed became class constants, `auth_mode` is
gone (`LlmStages.build` logs the client type once), and `judge.py` no longer
needs its `PLR0913` exemption. The OAuth token is kept out of the repr.

Behaviour changes: with no usable credentials there is now one warning,
"LLM stages disabled", instead of a judge-only warning, even under
`--no-judge`. The stage flags are read as `args.no_verify` and so on,
not through `getattr` defaults. The facade drops `build_judge`,
`build_narrator` and `build_completion_client` and adds `LlmStages`,
`LlmCredentials` and `CompletionRequest`.

`tests/test_judge_auth.py` holds the table-driven credential test and the
`LlmStages.build` wiring tests. Five deliberate breaks were each seen to
turn a test red: ignoring litellm, preferring the API key over OAuth, a
second client for one stage, the token in the repr, and a narrator under
`--no-judge`. 910 tests pass.

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

Done on `refactor/p4-runner` in three commits: 23 characterization tests
through the public `Runner` API only (`tests/test_runner_cycle.py`), then
`SupervisionPolicy`, then the split. `runner.py` went from 1058 lines to 331;
the largest class is now `CollectionCycle` (8 methods, 167 lines). Changes
from the design above:

- No `Finding` dataclass. The entries stay dicts, but each key is now written
  by exactly one stage, and `FindingBatch` carries the rest (collector, rows,
  run id, `HostBaseline`, judgments). A typed `Finding` would have touched
  every judge prompt for no behaviour gain.
- The stage and step lists are built in `runner.py` (`_snapshot_stages`,
  `_streaming_stages`, `_cycle_steps`), not in `main.py`: `RunnerConfig`
  already holds everything they need, and `main.py` stays unchanged.
  A disabled verifier or investigator means the stage is left out, not a
  None check inside it.
- `MaintenanceCommand.apply(sink, max_db_bytes)`, since there are no
  repositories (Phase 5 was dropped).
- Extra small types: `ControlSettings` (the control row read once per cycle,
  with the startup defaults), `ProgressHeartbeat`, `HostBaseline`,
  `ProcessBehavior` (the pid maps shared by correlation and investigation)
  and `_InvestigationBundle`.
- The sleeper stays a separate `StreamingWorker` argument, since its default
  needs the worker's own stop event.
- `runner.config` is public (the desktop test reads the collector lists).

Behaviour changes: two log or prompt strings lost their em dash (the
shutdown log line and the feedback hint text), and a failure in the
streaming baseline step is now caught with the rest of that collector's
judging instead of escaping the cycle.

Coverage on the full suite: `runner.py` 96%, `control_loop.py` 97%,
`finding_stages.py` 91%, `streaming.py` 92%, `cycle_steps.py` 77% (the
narrator and coverage error branches). Timing on a synthetic 200-row cycle,
old and new run alternately: median 25 to 27 ms before, 25 to 29 ms after,
inside the spread. Three deliberate breaks (verify cap, investigate cap,
feedback from another collector) each turned a test red. 940 tests pass.
`test_runtime.py::test_exit_code_returns_code` can time out when the suite
runs under coverage (a child Python takes over 10 s to start there); it is
not touched by this phase.

## Phase 5: dropped

The `Sink` split into repositories was dropped on 2026-09-17. `Sink` keeps
its 49 methods. Its two worst methods are still simplified where they are:
`correlation_context` (mccabe 15) gets one private method per signal, and
`prune_to_size` (122 lines) gets one private method per table group. Both
get characterization tests first (`tests/test_sink_rotation.py` already
covers pruning; correlation needs its own).

Done on `refactor/p5-sink` in three commits: characterization tests (13 new
in `tests/test_sink_correlation.py`, 8 more in `test_sink_rotation.py`), a
bug fix, then the split. Five deliberate breaks (the DNS cap, the keep-one-run
guard, error-row deletion, the `since` bound, the null remote address filter)
each turned a test red before the split.

The bug: `prune_to_size` trimmed only `auth_events` by date and deleted every
other collector table by `CollectionRun` run id. `process_exec_events` rows
carry a streaming session's run id, so no prune ever reached them. On a host
with `--max-db-mb` they grew without a bound while the loop deleted
collection runs to make room, and they outlived their deleted
`StreamingSession` rows. Every streaming slice is now trimmed by
`collected_at`, taken from the slice catalog. `events_pruned` counts both
tables and the rotation log says `streaming_events=` instead of
`auth_events=`. Proven with a regression test that failed first
(0 events pruned instead of 20); I did not measure how large the table is
on a real host.

One change from the design: the per-signal and per-table-group helpers are
module-level functions taking the session, not private `Sink` methods, since
none of them needs `self`. `Sink` gained only `_vacuum` (50 methods).
`correlation_context` lost its copied group-and-cap loop (`_capped`), and
`sink.py` no longer needs its `C901` exemption. 962 tests pass.

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

Done on `refactor/p6-dashboard` in six commits: the app factory and
blueprints, the `queries` split, two bug fixes, the filter objects, and the
last long function. `app.py` went from 976 lines to 63 and `queries.py`
(2719 lines) became 14 modules; the largest is `common.py` at 342. No
function in `dashboard/` is over mccabe 10 or 60 lines, and both ruff
ignores for the dashboard are gone from `pyproject.toml`. Every GET route
(times 56 query strings) and every POST was rendered against a fixed
`tools/seed_demo_db.py` DB in three setups (plain, desktop open mode, token):
4542 captured responses, byte-identical to the commit before each refactor.
Changes from the design above:

- Functions per panel module, not query classes. Each function already takes
  a `Session` and nothing else, so a class per panel would only have held
  the session. The layering test now fails if `dashboard.queries*` or
  `dashboard.control` imports Flask, `dashboard.app` or `dashboard.routes`.
- `FindingFilter` holds verdict, collector, category, search and status;
  `sort` and `order` stay separate arguments since they are not filters.
  `RowFilter(verdict, q)` and `LogFilter(source, level, q)` were added for
  the other panels, `PersistencePages` for the three persistence tables, and
  `VerdictTable` replaces `_collector_rows_with_verdict` (its `limit`
  argument, never passed by a caller, is now a per-table constant).
- Control writes go through `ControlStore(engine)`, built once in
  `create_app` next to the read-only engine (`db.py`). `DashboardServices`
  holds both in `app.extensions`.
- `desktop.py` still sets `AVAI_CONTROL_OPEN` and `AVAI_APP_MODE` in the
  environment and calls `DashboardConfig.from_env`; moving that is Phase 9.
- The package facade lost `_paginate`, `_collector_rows_with_verdict` and
  `_prior_run` (no caller outside the package). `prior_run` now lives in
  `queries.collection`, so no route module runs SQL itself.

Two bugs found by the HTML diff, each fixed in its own commit with a test
that failed first:

- A page past the end (`?page=99`) showed the last page's rows but echoed
  page 99, so the row numbers and the prev/next links were wrong. Panels now
  return the page they actually served (`Page.within`).
- In `network_flows` and `listening_ports` the loop variable `verdict`
  shadowed the verdict filter, so picking a verdict filtered on whatever the
  last row had. The flows and ports tabs now filter on the picked verdict.

Behaviour changes besides those: a `raw_json` or evidence value that parses
to something other than a JSON object now reads as empty in
`system_integrity` and `vulnerabilities` instead of raising.

Coverage of `avai.dashboard` on the full suite is 93% (`db.py` 62%, the
query log hook). New tests: `tests/test_dashboard_paging.py` (`Page`),
`tests/test_dashboard_filters.py` (the three filters) and
`TestDashboardConfigFromEnv`. Deliberate breaks of the verdict filter, the
case-insensitive search, the finding status, the Linux posture branch and
`prior_run` each turned a test red. One mutant survives by design: making the
findings search case-sensitive changes nothing, because SQLite `LIKE`
already ignores ASCII case. Em dashes already in moved user-facing strings
(`routes/control.py`, `serve.py`) were left as they are. 987 tests pass.

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

Done on `refactor/p7-collectors` in six commits: characterization tests,
the package split, the injection, `YaraRulesetCompiler` with the file-scan
target split, the Linux launch-item readers, and the named magic values. The
53 characterization tests (`tests/test_collectors_characterization.py`)
patch `subprocess`, `shutil.which` and `psutil` on the global modules, so
they run unchanged across every move; they took `collectors.py` from 64% to
90% line coverage before anything moved. The split commit only moved code
(the AST of every class and function is identical). `collectors.py` (3301
lines) is now 11 modules; the largest is `persistence.py` at 538. No
function in the package is over mccabe 10, nothing in it calls `psutil` or
`subprocess` directly, and the C901/PLR2004 ignores for `collectors/*.py`,
`net_collectors.py`, `exposure_collectors.py` and
`persistence_collectors.py` are gone from `pyproject.toml`. Changes from the
design above:

- The collaborators are optional constructor arguments (`runner`,
  `connections`, `metrics`, `disks`) that default to a fresh instance, the
  pattern the security controls already used. So `CommandRunner()` still
  appears once in the `__init__` of each of the 13 collectors that shell
  out, as that default; none builds one per call any more, and the Linux
  and macOS hosts pass their own runner. Tests build collectors with no
  arguments.
- Eight direct `subprocess.run` calls that the plan did not list (tcpdump
  twice, spctl, dpkg-query, iw, systemctl, dmsetup, journalctl) also go
  through the runner, since `runtime/command_runner.py` documents it as the
  one subprocess seam. That took one new method, `CommandRunner.capture`,
  which returns stdout, stderr and a `timed_out` flag and keeps partial
  output on timeout (tcpdump stops at its time cap on a quiet link).
- New seam methods: `PsutilConnections.listening` and `process_name`,
  `SystemMetrics.process_table` and the three `net_if_*`/`net_io_counters`
  readers, and `DiskMetrics.mount_table` (every mount, pseudo filesystems
  included, unlike the container-aware `partitions`).
- `_compile_yara_rules` left the facade; `avai rules` and the tests call
  `YaraRulesetCompiler(rules_dir).compile()`.
- `_cron_rows(scope, path, has_user_col, default_user)` became
  `CronJob.parse(line, owner)`: the owner of a per-user crontab replaces
  the boolean flag, since only those files lack a user column.
- The magic-value count covered this area only: 7 in the package and 15 in
  the three source-injected modules. The rest of the "74" is Phase 10.

Behaviour changes: when `spctl --status` times out, whatever it printed
before the cap is now read instead of giving None, and the journalctl
timeout warning now names the timeout instead of repeating the exception.
`FileScanCollector` no longer pulls one extra target past the per-cycle cap
(no row changes).

Coverage of `avai.host_monitor.collectors` on the full suite is 92%
(`streams.py` 86% is the lowest). New tests beyond the characterization
file: the compile summary, the namespace suffix for a repeated file stem,
target dedup and the cap across sources (`test_file_scan.py`), cron
discovery across every source (`test_collectors.py`),
`CommandRunner.capture`, the Windows session parser and the ndp state
fallback, which had no test. 34 deliberate breaks across the four
refactor commits each turned a test red. One more stayed green at first:
dropping the `KEY=value` check in the cron parser, because the old env-line
test used lines too short to pass the field count anyway; a new test with a
long `MAILTO=` line now catches it. The first version of the capture
timeout test used a real child process with a 1 s cap and failed once under
a loaded full run; it now fakes `TimeoutExpired`. 1054 tests pass.

## Phase 8: enrichment and indicators (small)

- Split `EnrichmentChain.enrich` (mccabe 13, 73 lines) into cache lookup,
  fetch and forward-chain methods. Per-source counters become a
  `SourceStats` object.
- Replace the 10 elif chains and 27 type checks in `indicators.py` with a
  single `_safe_loads` result type plus small helpers.
- Simplify `OSVEnricher._fetch` (mccabe 12).

Done on `refactor/p8-enrichment` in three commits, one per bullet. The
largest function in `chain.py`, `indicators.py` and `sources/osv.py` is now
mccabe 5, and their three entries are gone from the ruff ignores
(`indicators.py` keeps none: its only magic value, the sha256 hex length, is
named).

- `EnrichmentChain.enrich` is now `_lookup` (cache, then fetch), `_fetch`
  (the three guarded failure paths) and `_forward_chain`; the id discovery
  is a generator capped with `islice` instead of a `break` in a nested loop.
  `SourceStats` is a dataclass and `stats()` keeps its dict shape. Nothing
  in production reads `stats()` (only three test files do; the per-cycle
  log that used it went away in `3bf0760`), so it is a candidate to delete
  or to wire back into the cycle summary.
- `indicators.py` did not need a `_safe_loads` result type: it has one
  caller. The 10 elif chains were host classification repeated in nine
  extractors, and they disagreed on privacy. `_public_host_type` classifies
  once and `_host_indicators` yields the host when it is a kind the
  extractor asks for. The four hash-a-file extractors share
  `_file_hash_indicators`, and the identical `FileIntegrityExtractor` and
  `FileScanExtractor` became one `RecordedDigestExtractor`. elif went from
  10 to 1 and `isinstance` from 26 to 20; the rest guard `row.get()` values
  from collector rows, which is the input edge.
- `OSVEnricher._fetch` is split into `_vuln_by_id` and `_vulns_for_package`
  plus a module `_advisory_ids`; the separate 404 branch folded into the
  non-OK one (both returned None), and `HTTPStatus.OK` replaces the bare
  200. The other sources still compare against literal status codes; that
  is Phase 10.

Behaviour change: `proxy_config`, `login_sessions` and `dns_resolvers`
used to emit private IPv6 addresses (`fe80::1`, `::1`) and
`quarantine_events` a private IPv4 download host, all sent on to
threat-intel sources. Their docstrings say public only; now no extractor
emits a private, loopback or link-local address. I did not measure how
often that happened on a real host.

New tests: a forward-chain test (dedup, case, prefix filter, cap), a
35-row table of what each host-classifying extractor yields (30 rows pass
on the old code; the 5 private-address rows fail on it), and 9 OSV tests
(query payload, empty name, non-OK status on both paths, id dedup and the
five-vuln cap) that pass on the old code. 30 deliberate breaks turned a
test red. Two stayed green: dropping `.upper()` in the forward chain, until
the test used a lower-case id with no upper-case twin; and dropping the
`context` an extractor attaches to a host indicator. Nothing outside tests
reads `Indicator.context`, so that one changes no output; it is dead data,
not a missing test.

Coverage of `avai.enrichers` on the full suite is 94% (`chain.py` 96%,
`indicators.py` 93%, `osv.py` 100%). 1099 tests pass.

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

Done on `refactor/p9-entrypoints` in four commits. Acceptance is not met
as written; what is left and why is below.

- `cli.main` looks the subcommand up in a `_COMMANDS` table of `_run_*`
  functions, one per command, aliases as extra keys. Plain functions, not
  a `Command` class: each has one method and no state.
- `HostFactory.create` keeps its three `if` branches. A `{system: class}`
  table needs the classes imported by name (`importlib` plus `getattr`) to
  stay lazy, which loses the static import and type check for no gain:
  adding a platform is one edit either way. It gained a Windows test.
- `build_runner` was already the composition root. `MonitorSettings` was
  not built: the argparse namespace is already parsed once, and a
  dataclass copy of its 20 fields would have no second source to justify
  it.
- Nine keyed enricher sources read their key through `env_token()`
  instead of their own `os.environ.get`, so each env var name lives only
  in `requires_token`. Full injection of the keys (registry passes them
  in) was not done: the sources have four construction shapes (keyless,
  keyed, optional key, and the path-based local deny-list) that the
  registry bridges with signature inspection, and a common constructor
  contract would be more code than the reads it removes.
- `desktop._start_dashboard` passes `DashboardConfig.from_env` an overlay
  instead of writing `AVAI_CONTROL_OPEN` and `AVAI_APP_MODE` into the
  process environment. `ANTHROPIC_API_KEY` stays a `setdefault`, because
  litellm reads the key from the process environment itself.

`os.environ` is still read outside the entry points in: `Enricher.env_token`
and `NvdEnricher.__init__` (source keys, above); `constants.py`
(`HOST_PREFIX`, `AVAI_YARA_RULES_DIR`, `AVAI_HASH_DENYLIST`, read at
import and used across the collectors, so moving them means threading
three values through every host and collector); `hostsfile.py`
(`SystemRoot`, a Windows fact, not configuration); `llm.py` (a
`setdefault` of `LITELLM_LOG`, which has to happen before litellm is
imported); and `DashboardConfig.from_env`'s default argument.

Behaviour change: the desktop app no longer sets the two dashboard
variables in its own environment; before, they also leaked into every
test that ran after `test_dashboard_serves_in_process`.

New tests: the `app` aliases, `install-hosts` (install, remove,
unchanged, the permission hint, other errors), `migrate`, the dashboard
argv passthrough, HostFactory on Windows, the desktop overlay (fails on
the old code), NVD's optional key header and rate lane, and a test that
every keyed source sends the key from its env var. That last one closes
a real gap: blanking any of the nine keys left the suite green before
it. 19 deliberate breaks (8 in `cli`, 9 source keys, 2 in NVD) turned a
test red.

`cli.py` coverage went from 62% to 98%. 1122 tests pass; line coverage
of the whole `avai` package on the full suite is 92%.

## Phase 10: trim the facades

- Point tests at the real modules and shrink `host_monitor/__init__.py` (334
  lines) and `dashboard/__init__.py` (260 lines) to the names a caller outside
  the package actually uses.
- Empty the ruff ignore list and delete it.

Acceptance: the ignore list is gone, the layering test is green, coverage is
at least 85%, and `docs/ARCHITECTURE.md` is regenerated.

Done on `refactor/p10-facades` in seven commits.

- The last 22 `PLR2004` entries went by naming each value: `HTTPStatus`
  members in the enrichment sources and `http.py`, `CVSS_CRITICAL` and
  `CVSS_HIGH` in `enrichers/base.py` (shared by NVD and GitHub Advisory),
  the AbuseIPDB and VirusTotal verdict thresholds, the field counts in the
  host parsers, `_MAX_HOSTNAME_LEN` and `_FORCE_QUIT_SIGNALS`. PhishTank's
  509 stays a named constant, because `HTTPStatus` has no member for it.
  No behaviour change.
- `compute_risk_score` (mccabe 16) reads the seven integrity fields from
  two tables and the four counted findings from one loop over their
  `RISK_WEIGHTS` prefix. A new test pins every driver, its points and
  their order, and it passes on the old code. The `count > 0` guard was
  an equivalent mutant (a zero count gives zero points, which `penalise`
  already skips) and is gone. The other 6 deliberate breaks turned the
  test red, and so did dropping `points > 0` once the count guard was
  gone.
- `JsonLineStreamSource.stream` (mccabe 11) only wires three module
  functions: the stop watchdog, the line decoder and the terminate/kill
  shutdown. The blank-line check was an equivalent mutant (`json.loads`
  rejects an empty line, and the decoder already skips that) and is gone.
  4 new shutdown tests; 7 deliberate breaks turned a test red.
- That emptied the `src/` ignore list. `pyproject.toml` keeps the rules
  and the exemption for tests, tools, scripts and packaging, which compare
  against literal expected values by design.
- Every test imports from the submodule that defines the name (127 import
  statements across 21 files). `host_monitor/__init__.py` went from 161
  exported names to 44 (the ORM rows the dashboard and
  `tools/seed_demo_db.py` read, `Sink`, `FeedbackLabel`, `main`,
  `DEFAULT_DB_PATH`) and from 328 lines to 103. `dashboard/__init__.py`
  went from 86 names to 4 (`create_app`, `DashboardConfig`, `main`,
  `_ensure_db_exists`) and from 214 lines to 19. The entry points still
  load the same 81 `avai` modules, so PyInstaller's static import walk
  finds everything it found before.

Deviation: `_ensure_db_exists` keeps its leading underscore while the
desktop app imports it through the facade. Making it public means renaming
it in 20 test lines and the docs, which is a rename for its own sake.

Found on the way: under `pytest-cov` with a subpackage target
(`--cov=avai.host_monitor.runtime`), every child Python a test starts
takes about 29 s to boot, and two `CommandRunner` tests with a 10 s
timeout fail. With `--cov=avai` the same child takes about 1 s. It is a
measurement artifact, not a code bug: measure with `--cov=avai` and read
the subpackage rows.

The layering test is green. 1127 tests pass; line coverage of the whole
`avai` package on the full suite is 92% (floor 85%). `ruff check` passes
on `src`, `tests` and `tools`. The appendix of `docs/ARCHITECTURE.md` is
regenerated from the code (122 modules, 0 mismatches).

## Follow-up: dead enrichment data

Phase 8 found two things nothing in production read, and both are gone on
`refactor/p11-dead-code`:

- `EnrichmentChain.stats()` and its `SourceStats` counters. Only tests
  called it (four files). The tests that also checked a failing source is
  skipped keep that check through the evidence list; the enrichment-off
  test now checks the source got no call (dropping the `enrich_on` gate
  turns it red); and a new test covers a plain `EnricherError`, which no
  test raised before (making that branch re-raise turns it red).
- `Indicator.context`. Nine extractor sites filled it and nothing read it.
  Dedup in `extract_indicators` keys on `(type, value)`, not on the
  dataclass equality that `context` took part in, so no output changes.

1124 tests pass; line coverage of the whole package is still 92%.

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
