# avai: project knowledge for agents

Read this first. It is the working state of the project: how to run it, how the
code is laid out, the rules it follows, what was done, what was decided and why,
what is still open, and what to watch. Last updated 2026-10-27 (UTC).

Deeper material:

- `docs/ARCHITECTURE.md`: the long design write-up (older than the refactor below; module names may have moved).
- `docs/REFACTOR_PLAN.md`: the 2026-09-17 OO/SOLID plan. Done; kept for history.
- `README.md`: the user-facing feature list and install steps.

## 1. What avai is

A host security monitor. `avai monitor` runs about 37 collectors per cycle on
macOS (fewer on Linux and Windows): processes, sockets, persistence, launch
items, browser extensions, file integrity, YARA file scan, auth and exec event
streams, and more. New rows are enriched by up to 19 threat-intel sources (18
online APIs plus a local hash deny-list, `enrichers/sources/`) and
judged by an LLM (malicious / suspicious / unknown / benign). Everything lands in
one SQLite file (default `~/.avai/avai.db`). `avai dashboard` is a read-only
Flask + HTMX page on that file (default port 8765). `avai app` wraps both in a
desktop window.

- Package: `avai-monitor` on PyPI, current release 0.10.0 (2026-10-27): https://pypi.org/project/avai-monitor/0.10.0/
- Docker image: `iklob1/avai` on Docker Hub, https://hub.docker.com/r/iklob1/avai
- Repo: https://github.com/iklobato/avai
- Branches: `main` is released, `dev` is the integration branch. Never commit to
  either; open a branch and a PR into `dev`.

## 2. Commands

Run every command from the repo root.

| What | Command |
|---|---|
| Tests (local lock) | `timeout 500 env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run --frozen pytest -q -p no:cacheprovider tests` |
| Tests with CI versions | add `--with "sqlalchemy==2.1.6" --with "alembic==1.20.1"` after `--frozen` |
| Lint | `uv run --frozen ruff check src tests` |
| Format one file | `uv run --frozen black -q <file>` (never black a whole test file: it rewrites untouched lines) |
| Coverage | add `--cov=avai` (never a subpackage target, see 7.2) |
| Install the `avai` command from this checkout | `uv tool install --editable /Users/iklo/scripts/avai --force` (puts `avai` in `~/.local/bin`, which comes before the old pyenv `avai` on PATH; run `rehash` in zsh after) |
| Safe local run (no root, separate DB, no Sentry, no LLM judging) | `AVAI_TELEMETRY=0 avai monitor --db /tmp/x/live.db --interval 120 --no-judge --judge-model gpt-4o-mini > live.log 2>&1 &` |
| Dashboard on that DB | `AVAI_TELEMETRY=0 avai dashboard --db /tmp/x/live.db --port 8799` (8765 may already be taken by a real dashboard) |
| Stop the monitor cleanly | `kill -TERM <pid>`; it finishes the current step first (can take up to about 2 minutes while `file_scan` runs) |

`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` is required: an auto-loaded plugin in the
global Python crashes pytest with `numpy.dtype size changed`.

## 3. Code map

```
src/avai/
  cli.py              `avai` entry point (monitor, dashboard, app, install-hosts, ...)
  observability.py    Sentry setup (on by default, see section 6)
  errors.py           AvaiError, the base of every own exception
  host_monitor/
    main.py           monitor composition root: MonitorArgs, LlmStageBuilder, ShutdownSignals, MonitorApp
    options.py        MonitorOptions: every CLI flag as a frozen pydantic model
    runner.py         one cycle: collect, store, judge, report steps
    control_loop.py   the daemon loop; CycleSettings is a frozen per-cycle snapshot of the control row
    collectors/       one class per collector (network.py, file_scan.py, software.py, ...)
    hosts/            per-OS assembly of collectors (portable.py has the psutil ones)
    runtime/          thin seams over the OS: probes.py (psutil), command_runner.py (subprocess with timeouts), host_paths.py, clock
    finding_stages.py enrichment, correlation, judging pipeline over a frozen FindingBatch
    llm.py            completion clients (Anthropic OAuth, litellm), StructuredCall
    judge.py, narrator.py, coverage.py, verifier.py, investigator.py   the LLM stages
    sink*.py          Sink: one facade over six stores (runs, behavior, judgments, reports, retention, control)
    models.py         SQLAlchemy tables; migrations live in src/avai/migrations (alembic)
  enrichers/          threat-intel sources (sources/*.py), HttpClient (http.py), EnrichmentChain (chain.py)
  dashboard/          Flask app, routes/, queries/ (one panel class per fragment)
  rules/              YARA rules: eicar.yar + vendor/signature-base (gitignored, see 7.5)
tests/                about 1240 tests, all offline
```

Where things are wired: `host_monitor/main.py` (`MonitorWiring`) and
`hosts/*.py` build every object. Everything else gets its collaborators
injected.

## 4. Rules the code follows

All Python here follows `~/.claude/code-imutatble-rules.md`. In short: every
function lives in a class, `__init__` only assigns, collaborators are injected,
at most 3 params, methods of at most 20 lines, no `elif`, Enum instead of loose
strings, own exceptions, no magic numbers, type hints everywhere.

- A hook (`~/.claude/hooks/immutable-rules-check.py`) blocks any NEW violation
  against HEAD after every edit. Old violations do not block. Fix the code; do
  not dodge the hook.
- Status: 0 findings on `src`, `scripts`, `tools`, `packaging`. `tests/` still
  has 2685 old findings (measured on 872cd3d), mostly example numbers in
  asserts. They are accepted debt; the hook stops new ones.
- Tests: a hand-written fake for any I/O (no MagicMock for HTTP or files), a
  regression test that fails before every bug fix, assert the full error.
- Never add `subprocess` calls in new code (use `os.system` + `shlex`), except
  inside `runtime/command_runner.py`, which keeps subprocess on purpose (see 5.3).
- No new dependencies without asking the maintainer.
- Commits, PR text and code are plain, simple English with no em dash.

## 5. What was done

### 5.1 Refactor to the immutable rules: PR https://github.com/iklobato/avai/pull/39 (merged into `dev` 2026-10-27, released in 0.10.0)

- Part 1 brought the mechanical rule scan to 0 on `src`, `scripts`, `tools`, `packaging`.
- Part 2 covered the judgment rules:
  - one `AvaiError` base;
  - Enums for verdicts, statuses, sort keys and similar categories;
  - injected clock, host paths, command runner and HTTP transport;
  - pydantic models for CLI options, LLM replies, all 18 threat-intel replies and the prompts TOML;
  - no hidden state: frozen batches, `Completion` carries token usage, the run log has no "current run", frozen cycle settings;
  - dead code deleted.
- Real bugs fixed on the way:
  - 15 threat-intel sources read a 401/5xx as "no opinion" with no log. Now only a 404 means "nothing found", anything else raises `EnricherError` and is logged.
  - The run log could send errors to the wrong run.
  - The `install-hosts` sudo hint now shows on a real permission error.
  - A flaky streaming test is fixed.
  - The macOS collectors no longer crash when the host has no home directory.
- Checks:
  - 1230 tests passed.
  - CI green: https://github.com/iklobato/avai/actions/runs/40447936513
  - All 403 dashboard routes render the same bytes as before, except the intended changes.
  - 124 canned threat-intel replies give the same evidence as before.

### 5.2 Sentry fixes: PR https://github.com/iklobato/avai/pull/40 (merged into `dev` 2026-10-27, released in 0.10.0)

| Commit | Sentry issue | Cause | Fix |
|---|---|---|---|
| d2796b6 | AVAI-CLI-H https://iklobato.sentry.io/issues/7814025955/ | `--narrative-model` defaulted to a fixed Claude model, not to `--judge-model` as its help said. With only `OPENAI_API_KEY`, coverage and narrator failed every cycle ("Missing Anthropic API Key"). | `options.py`: no `--narrative-model` now means the judge model. |
| 3518b97 | AVAI-CLI-B https://iklobato.sentry.io/issues/7808928942/ (2980 events) | macOS denies `psutil.net_connections` without root, so `listening_ports` and `network_connections` failed every cycle. | `PsutilConnections.visible()` falls back to each process's own table (`OwnedSocket`). Yes/no port checks (`PsutilPortInspector`) still use the full table only and say "unknown" without root. psutil floor is now 6.0. |
| b427846 | AVAI-CLI-G https://iklobato.sentry.io/issues/7813804025/ (474 events) | 95 signature-base files need a yara built with OpenSSL; each logged a warning per start. 13 of them (`pe.number_of_signatures`) were also misfiled as "other". | `CryptoHint.OPENSSL_FIELDS` knows that field; crypto skips log at debug plus one info summary. Other broken rule files still warn. |
| 1be6229 | AVAI-CLI-D https://iklobato.sentry.io/issues/7808943981/ | A normal SIGTERM stop was logged as a warning. | Info now; the second signal (force quit) stays a warning. |

Left as is, on purpose (the warning is right, the cause is the user's machine):

- AVAI-CLI-E https://iklobato.sentry.io/issues/7811239265/: no LLM key on that machine.
- AVAI-CLI-F https://iklobato.sentry.io/issues/7811415337/: crt.sh read timeout; the client already retries.
- AVAI-CLI-C https://iklobato.sentry.io/issues/7808936825/: that Ollama model can't return structured output.

Checks on PR 40:

- 1238 tests passed, also with the CI versions.
- CI green: https://github.com/iklobato/avai/actions/runs/40497980678
- A live run on the maintainer's Mac, without root, on 2026-10-27 (section 8).

### 5.3 Decisions to know before changing code

Each one says what it costs if it turns out wrong.

- `Sink` stays one facade over its six stores. Cost: callers see more methods than they need.
- Collector rows stay `dict` keyed by ORM column names. The SQLAlchemy model is the one schema per table. Cost: about 489 `dict` annotations.
- `HOST_FAILURES`, `STREAM_FAILURES` and `SOURCE_FAILURES` still catch `TypeError` and `AttributeError`, so one odd value from an OS tool cannot stop the monitor. Cost: a real programming bug in a collector is logged instead of crashing.
- `CommandRunner` keeps `subprocess`: every call has a timeout, and `os.system` has none. A stuck `tcpdump` would hang the cycle.
- OS tool JSON (system_profiler, eslogger, PowerShell) is read with `.get()` and is not modeled in pydantic.
- The dashboard env config keeps `EnvToggle` (no pydantic-settings dependency).
- `SchemaProbe` keeps a class-level 30 s cache of table names and hands out frozensets.
- `StepIO.read` returns None on failure.
- `SystemProfiler` (devices) and `ProfilerReport` (software) stay separate because they have different error contracts.
- `AVAI_APP_MODE` turns on only for 1/true/yes/on.
- The unprivileged socket view (5.2) is partial. Collectors use it; any yes/no answer must use `PsutilConnections.inet()` and handle `PermissionError`.

### 5.4 How a release works (first used for 0.10.0, 2026-10-27)

1. Branch `release/vX.Y.Z` from `dev`. Bump `version` in `pyproject.toml` and `__version__` in `src/avai/__init__.py`, run `uv lock`, and add a `CHANGELOG.md` entry.
2. Open a PR into `main` and merge it once CI is green (example: https://github.com/iklobato/avai/pull/41).
3. Push an annotated tag: `git tag -a vX.Y.Z <main merge sha> -m "..."` then `git push origin vX.Y.Z`. The tag starts three workflows:
   - `publish.yml` uploads the wheel and sdist to PyPI. It uses trusted publishing, so no token is stored anywhere. The publisher (owner `iklobato`, repo `avai`, workflow `publish.yml`, no environment) was added on PyPI on 2026-10-27. Before that every tag failed with `invalid-publisher`, which is why 0.9.x never reached PyPI.
   - `docker.yml` (new in 0.10.0) pushes `iklob1/avai:X.Y.Z` and `:latest` for `linux/amd64` and `linux/arm64`. It uses the repo secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, set on 2026-10-27. Before that the image was pushed by hand and stopped at 0.8.0, amd64 only.
   - `release.yml` builds the desktop installers and attaches them to the GitHub Release. The macOS job fails until the signing secrets exist (see `packaging/README.md`).

   Result for v0.10.0:
   - PyPI: published (wheel and sdist; the wheel holds 750 `.yar` files).
   - Docker Hub: `0.10.0` and `latest` for amd64 and arm64, both started and checked.
   - GitHub Release https://github.com/iklobato/avai/releases/tag/v0.10.0: Windows `.exe` and Linux `.deb` attached; the macOS job failed at signing as expected.
4. Bring `main` back into `dev` (the release branch commits exist only on `main` otherwise).

Known noise: GitGuardian flags a "Generic Password" in an old commit of `tests/test_home_lookup.py` (incident https://dashboard.gitguardian.com/workspace/697954/incidents/17490324). It was the variable name `passwd` for the stdlib `pwd` module, renamed since. No secret was ever there. The maintainer resolved the incident in the GitGuardian dashboard on 2026-10-27. If the check goes red again on a range with commit 8a6193b, it is the same false positive.

The Docker image installs `tcpdump`, `iproute2` and `p11-kit` since 0.10.0. Without them 7 collectors failed every cycle in the container. In a local build of 0.10.0 the first cycle ended `ok=35 failed=0`.

## 6. Sentry

- Org `iklobato`, project `avai-cli`.
- The DSN is bundled in `observability.py`, so reporting is on by default.
- `LoggingIntegration(event_level=WARNING)` turns every `LOG.warning` into an issue.
- Users turn it off with `AVAI_TELEMETRY=0` or an empty `SENTRY_DSN`.
- So a warning is a statement that something is wrong. Expected, documented outcomes log at info. Use `AVAI_TELEMETRY=0` for local test runs.
- Read issues with `python3 ~/.claude/skills/sentry/sentry_api.py issues iklobato avai-cli --json` (needs `SENTRY_TOKEN`, read scopes). Use `issue iklobato AVAI-CLI-X --json` for the latest event.
- Issues stay "unresolved" until a release with the fixes ships and the events stop. Nobody marked them resolved by hand.

## 7. Environment gotchas

1. **pytest plugin crash:** set `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` (see section 2).
2. **Coverage:** use `--cov=avai`. A subpackage target (`--cov=avai.host_monitor.runtime`) makes each child python take about 29 s to start, and the real-subprocess tests time out.
3. **CI ignores `uv.lock`:** it runs `pip install -e ".[dev]"`, so it gets the newest deps (SQLAlchemy 2.1.6, alembic 1.20.1 on 2026-10-26).
   - Run the suite with those versions before pushing.
   - Read file paths from `engine.url.database`, never by slicing `str(engine.url)`. SQLAlchemy 2.1 percent-encodes the path.
4. **sudo changes the DB:** `sudo avai monitor` uses `/root/.avai/avai.db`, a different file from the user dashboard's. Pass `--db /home/<user>/.avai/avai.db` and the full path to the binary.
5. **YARA pack:** `src/avai/rules/vendor/` is gitignored but force-included in the wheel (`[tool.hatch.build] artifacts`). The machine that builds a release must fetch it first with `python scripts/update_rules.py`. The `publish` and `docker` workflows both have a "Fetch the YARA pack" step for this. Without it, only EICAR ships. The 0.10.0 wheel on PyPI was checked: it holds 750 `.yar` files.
6. **Stock yara has no crypto:** the PyPI yara-python wheel has no OpenSSL. 95 of 751 signature-base files are skipped (`pe.imphash`, `pe.number_of_signatures`, `hash.*`). That leaves 5292 rules from 656 files. Expected; see `src/avai/rules/NOTICE`.
7. **Windows:** has no `pwd` module. Tests that patch it use `pytest.importorskip("pwd")`.
8. **Two `avai` installs on the maintainer's Mac:**
   - The editable uv tool in `~/.local/bin` is the one used now.
   - An old pyenv 3.11.7 install (0.7.3 metadata, editable from this repo) is still there, shadowed on PATH.

## 8. Live run, 2026-10-27, maintainer's Mac, no root

Setup:

- Code: branch `fix/sentry-errors`, installed as the editable uv tool.
- Flags: `--no-judge --judge-model gpt-4o-mini --interval 120`.
- Separate DB, `AVAI_TELEMETRY=0`.
- Only `OPENAI_API_KEY` set.

| Check | Result |
|---|---|
| Cycles | 19 since the restart at 13:03 UTC, every one `ok=37 failed=0` |
| WARNING / ERROR / Traceback lines | 0 |
| `listening_ports` / `network_connections` | 14 to 19 rows / 130 to 199 rows each cycle (were failing before) |
| YARA | one info line: `skipped 95 rule files that need a crypto-enabled yara`; 5292 rules loaded |
| Coverage stage with gpt-4o-mini | `coverage posture=partial gaps=3 recommendations=3`. It runs only when the ruleset fingerprint changes, so once per new ruleset. |
| SIGTERM | `INFO received signal 15; ...`, then a clean exit with code 0 after about 70 s (waited for `file_scan`) |
| Dashboard | all 18 fragments return 200 |
| YARA hit | `/usr/local/bin/masscan`, rule `hacktool_multi_masscan` (a port scanner the user installed; a true positive) |
| Memory | about 490 MB at start, 506 MB after 56 min: flat |
| DB size | grows about 16 MB per cycle (432 MB after 56 min); `auth_events` is most of it (88.6 of 144 MB when measured) |
| Cycle time | about 2.3 to 3.7 min. `file_scan` takes 106 to 160 s (377 s when the host load average was 46). `kernel_extensions` runs `system_profiler SPExtensionsDataType` at about 95% CPU for 10 to 23 s. |

Not covered by that run: root mode, the LLM judge, enrichment against live APIs,
Linux and Windows hosts, a PyInstaller build, and sending to Sentry.

## 9. Open work and next steps

Not done, and worth a separate decision:
   - **avai logs its own noise.** Found in the 2026-10-27 run, 79 min, 31 cycles:
     - Every cycle, `kernel_extensions` runs `system_profiler -json SPExtensionsDataType`.
     - That makes macOS `securityd` log exactly 4048 `MacOS error: -67062` lines (process `/usr/sbin/system_profiler`, category `security_exception`). Each run of the child is a new pid.
     - The `auth_events` stream stores them: 133,584 of 289,685 rows (46%). `auth_events` is 424 MB of the about 600 MB DB.
     - Fix options: run `kernel_extensions` less often (it also costs about 12 s of 95% CPU per cycle), and/or drop auth events whose pid is a child avai itself started.
     - Decision 2026-10-27 (maintainer): leave it as is for now; no code change. Revisit if DB size or CPU becomes a complaint.
   - `file_scan` takes about 128 s per cycle on average, 85% of the cycle time (cycle median 135 s). That also makes a graceful stop slow. Options: a smaller per-cycle cap, or skipping files whose mtime and size did not change.
   - Snapshot collectors store their full list every cycle: `launch_items` (842 rows) used 37 MB and `kernel_extensions` (843 rows) used 22 MB in 31 cycles. Storing only changes would cut this.
   - The DB grew about 600 MB in 79 min. The 1024 MB cap (`--max-db-mb`) prunes old runs. Pruning was not reached in the test, so it is still unchecked.
   - `process_exec_events` ends at once with `rows=0` without root (no warning). Root is probably needed (eslogger); confirm and say so in the dashboard.
   - The test-suite debt: 2685 mechanical findings in `tests/`.
   - Untested: the Linux and Windows collectors on real machines, and the socket fallback outside macOS. psutil's docs say only macOS and AIX need root for the system table.

## 10. What to monitor now that 0.10.0 is out

- Sentry `avai-cli`:
  - AVAI-CLI-B, G, H and D should get no new events with release `avai@0.10.0`. If one does, the fix did not reach that path.
  - Three `avai@0.10.0` events on 2026-10-27 around 14:44 UTC came from a local Docker smoke test run without `AVAI_TELEMETRY=0` ("no usable LLM credentials" and two "tcpdump not found"). They are test noise, not users.
  - E, F and C can keep coming; they come from machine setup.
- Any new `collector=... status=failed` warning: it is a new Sentry issue, read it.
- DB size against `--max-db-mb` on long runs. Look for `db_rotation: pruned` lines in the monitor log.
- Cycle time (`run complete` timestamps) and `file_scan duration_ms`.
- Monitor memory (RSS). It was flat at about 500 MB over an hour; a steady climb would be a leak.
