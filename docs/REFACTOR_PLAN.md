# Refactor plan — split the two God-modules, change nothing else

**Goal:** make the code easier to read and maintain by fixing the *one* real
SOLID violation in this codebase — module-level SRP. `host_monitor.py` (6,138
lines) and `dashboard.py` (2,599 lines) each do many unrelated jobs in one file.

**This is a pure structural refactor. Zero behavior change.**

## Principles (and the tension, resolved)

The brief was "aggressive SOLID + perfect patterns" *and* "keep it extremely
simple, avoid all overengineering." Those pull in opposite directions, so the
stance here is explicit:

- The architecture is **already good**. The patterns that belong here are
  already present — Strategy (`BrowserExtensionReader`, `IndicatorExtractor`,
  `CompletionClient`), Chain-of-Responsibility (`EnrichmentChain`), Template
  Method (`Enricher`, `Collector`), Registry (`discover_enricher_classes`),
  Factory (`build_*`), and constructor DI (`Runner`).
- So this refactor **adds no new patterns and no new abstractions.** It only
  *moves code into files*, applying SRP at the module level.
- The `enrichers/` package is exemplary — **do not touch it.**

## Anti-goals (do NOT do these — they are the overengineering to avoid)

- ❌ No repository / Unit-of-Work layer over SQLAlchemy. Models are the data
  layer; `Sink` is the single write gateway. That's enough.
- ❌ No splitting `Sink` into per-table repositories. It's large but cohesive.
- ❌ No DI container/framework. Constructor injection is already correct.
- ❌ No plugin-discovery for collectors. Two platforms → an explicit list is
  clearer than magic.
- ❌ No new interface that would have exactly one implementation.

## The safety contract: the facade

Every test, plus `dashboard.py` and `migrations/env.py`, imports
`from avai.host_monitor import X`. **66 distinct symbols** are imported this way
(including privates: `_build_parser`, `_payload_bytes`, `coerce_enum`).

→ `host_monitor/` becomes a **package** whose `__init__.py` re-exports all 66.
Nothing outside the package changes. If the facade is complete, the existing
test suite is the regression net and passes **untouched**.

---

## Phase 1 — `host_monitor.py` → `host_monitor/` package

The file already has comment-banner sections that map 1:1 to submodules.
Layered so imports flow one direction only (no cycles):

```
constants/enums/shell  →  models  →  prompts/risk/judge/narrator  →  sink
   →  collectors  →  streaming  →  runner  →  main
```

### Module map

| New file | Symbols moved in |
|---|---|
| `constants.py` | `DEFAULT_DB_PATH`, `DEFAULT_PROMPTS_PATH`, `DEFAULT_BASELINE_MIN_RUNS`, `_CORRELATED_COLLECTOR`, `WATCHED_FILES`, `WATCHED_FILES_LINUX`, `AUTH_LOG_PREDICATE`, `IS_MACOS`, `IS_LINUX`, `HOST_PREFIX`, LLM-timeout + risk-weight constants |
| `enums.py` | `Verdict`, `ThreatCategory`, `LaunchScope`, `Browser` |
| `shell.py` | `run_json`, `run_ndjson`, `exit_code`, `service_loaded`, `process_running`, `sha256_file`, `read_plist`, `jsonable`, `external_sqlite_rows`, `safe_psutil_connections`, `content_hash`, `coerce_enum`, `expand`, `host_path`, `host_paths_for_home`, `utcnow`, `_read_sysfs`, `_ssh_fingerprint` |
| `prompts.py` | `Prompts` |
| `models.py` | `Base`, `_RowBase`, `CollectionRun`, `CollectorErrorRow`, `Judgement`, `IncidentNarrativeRow`, `RiskScoreRow`, `StreamingSession`, **all `*Row` models** (~25) |
| `risk.py` | `compute_risk_score`, `_risk_grade` |
| `judge.py` | `Judgment`, `Judge`, `NullJudge`, `LlmJudge`, `CompletionClient`, `LitellmClient`, `AnthropicOAuthClient`, `build_completion_client`, `build_judge`, `estimate_cost` |
| `narrator.py` | `IncidentNarrator`, `build_narrator` |
| `sink.py` | `Sink`, `_set_sqlite_pragmas`, `_migrate_add_columns` |
| `collectors/base.py` | `Collector`, `SnapshotCollector`, `StreamingCollector`, `BrowserExtensionReader`, `ChromiumExtensionReader`, `FirefoxExtensionReader`, `ProcessConnectionResolver`, `_payload_bytes` |
| `collectors/macos.py` | macOS-only collectors (`ProcessCollector`, `NetworkFlowsCollector`, `DnsQueriesCollector`, `AuthEventsCollector`, `MacosProcessExecCollector`, `MdmProfilesCollector`, …) |
| `collectors/linux.py` | the `Linux*` collectors |
| `collectors/common.py` | cross-platform collectors (`MountsCollector`, `SetuidFilesCollector`, `SshAuthorizedKeysCollector`, `HostsFileCollector`, `PrivilegeConfigCollector`, `FileIntegrityCollector`) |
| `collectors/build.py` | `build_snapshot_collectors`, `build_streaming_collectors`, `_build_macos_*`, `_build_linux_*` (platform dispatch) |
| `streaming.py` | `StreamingWorker` |
| `runner.py` | `Runner` |
| `main.py` | `main`, `_build_parser`, signal handling |
| `__init__.py` | **facade** — re-export the 66 symbols below + `main` |

> Pragmatic option: if splitting `collectors/` four ways feels fussy, a single
> `collectors.py` (~2.4k lines) is an acceptable simpler stop. Don't agonize.

### The facade `__init__.py`

```python
"""avai.host_monitor — facade. Public API unchanged after the package split.

Everything tests / dashboard / migrations import from `avai.host_monitor`
is re-exported here, so no caller changes. Submodules hold the real code.
"""
from .constants import *          # noqa: F401,F403
from .enums import Verdict, ThreatCategory, LaunchScope, Browser  # noqa: F401
from .shell import (              # noqa: F401
    content_hash, coerce_enum, host_path, host_paths_for_home, utcnow,
)
from .models import *             # noqa: F401,F403  (Base, all *Row, Judgement, …)
from .prompts import Prompts, DEFAULT_PROMPTS_PATH   # noqa: F401
from .risk import compute_risk_score                 # noqa: F401
from .judge import (              # noqa: F401
    Judgment, Judge, NullJudge, LlmJudge,
    build_completion_client, build_judge, estimate_cost,
)
from .narrator import IncidentNarrator               # noqa: F401
from .sink import Sink                                # noqa: F401
from .collectors.base import (    # noqa: F401
    ChromiumExtensionReader, FirefoxExtensionReader,
    ProcessConnectionResolver, _payload_bytes,
)
from .collectors.macos import NetworkFlowsCollector, DnsQueriesCollector  # noqa: F401
from .collectors.linux import LinuxLaunchItemsCollector                   # noqa: F401
from .collectors.common import (  # noqa: F401
    SshAuthorizedKeysCollector, HostsFileCollector, PrivilegeConfigCollector,
)
from .collectors.build import build_snapshot_collectors  # noqa: F401
from .streaming import StreamingWorker                    # noqa: F401
from .runner import Runner                                # noqa: F401
from .main import main, _build_parser                     # noqa: F401
```

**Care item:** keep the enricher-chain import lazy inside `runner`/`main`
(as it is today) so `--no-enrich` never pulls in `requests`.

### Ordered, verifiable steps (one commit each)

Move bottom-up so each step compiles against already-moved modules:

1. `constants.py`, `enums.py`, `shell.py` (leaf modules, no internal deps)
2. `models.py`
3. `risk.py`, `judge.py`, `narrator.py`
4. `sink.py`
5. `collectors/` (base → macos/linux/common → build)
6. `streaming.py`, `runner.py`, `main.py`
7. Replace `host_monitor.py` with `host_monitor/__init__.py` facade; delete the old file.

**After every step:** `pytest -q && ruff check src tests`. The suite must stay
green the whole way — if a symbol is missing from the facade, a test import
fails immediately and tells you exactly which one.

---

## Phase 2 — `dashboard.py` → `dashboard/` package (the MVC seam)

The one place a clear SRP split genuinely helps: separate the controller, the
data access, and the presentation. Routes shrink to 2–3 lines each.

| New file | Holds |
|---|---|
| `queries.py` | all read functions — `latest_run`, `findings`, `network_flows`, `listening_ports`, `dns_queries`, `vulnerabilities`, `persistence_tampering`, `auth_events_aggregated`, `system_integrity`, `verdict_counts`, `verdict_timeseries`, `new_alerts`, + the `_engine`/`_session`/`_attach_ip_enrichment` data helpers |
| `format.py` | presentation helpers — `render_markdown`, `_relative_time`, `_datetime_fmt`, `_pretty_json`, `_human_bytes`, `_flag_emoji`, `_sparkline_points`, `_geo_*`, `_addr_scope`, `_cmdline_str`, `_paginate`, `_parse_json_*` |
| `app.py` | Flask `app` + the `@app.route` handlers (thin: call query → `render_template`) |
| `serve.py` | `main`, `_build_parser`, `_serve`, `_open_browser`, `_ensure_db_exists` |
| `__init__.py` | re-export `app`, `main` |

Same discipline: pure moves, `pytest` + `ruff` green after each commit.

---

## Authoritative facade export set (Phase 1)

These 66 symbols are imported from `avai.host_monitor` somewhere in
`src/` or `tests/`. The facade **must** export all of them (verified by grep):

```
AuthEventRow, Base, BluetoothDeviceRow, Browser, BrowserExtensionRow,
ChromiumExtensionReader, CollectionRun, CollectorErrorRow,
DEFAULT_BASELINE_MIN_RUNS, DEFAULT_PROMPTS_PATH, DnsQueriesCollector,
DnsQueryRow, FileIntegrityRow, FirefoxExtensionReader, HostsFileCollector,
HostsFileRow, IncidentNarrativeRow, IncidentNarrator, InstalledAppRow,
Judgement, Judgment, KernelExtensionRow, LaunchItemRow,
LinuxLaunchItemsCollector, ListeningPortRow, LlmJudge, MdmProfileRow,
MountRow, NetworkConnectionRow, NetworkFlowRow, NetworkFlowsCollector,
NetworkInterfaceRow, NullJudge, PrivilegeConfigCollector, PrivilegeConfigRow,
ProcessConnectionResolver, ProcessExecRow, ProcessRow, Prompts,
QuarantineEventRow, RiskScoreRow, Runner, SetuidFileRow, Sink,
SshAuthorizedKeyRow, SshAuthorizedKeysCollector, StreamingWorker,
SystemExtensionRow, SystemIntegrityRow, ThreatCategory, UsbDeviceRow,
Verdict, WifiStateRow, _build_parser, _payload_bytes, build_completion_client,
build_judge, build_snapshot_collectors, coerce_enum, compute_risk_score,
content_hash, estimate_cost, host_path, host_paths_for_home, utcnow
```

> Re-confirm with this command before declaring the facade complete:
> ```
> python3 - <<'PY'
> import re, pathlib
> roots = ["src/avai/dashboard.py","src/avai/cli.py","src/avai/__init__.py",
>          "src/avai/migrations/env.py", *map(str, pathlib.Path("tests").glob("*.py"))]
> pat = re.compile(r"from avai\.host_monitor import\s+(\([^)]*\)|[^\n]+)")
> syms=set()
> for f in roots:
>     for m in pat.finditer(pathlib.Path(f).read_text()):
>         for s in m.group(1).strip("() \n").split(","):
>             s=s.split(" as ")[0].strip()
>             if s and not s.startswith("#"): syms.add(s)
> print(len(syms)); print("\n".join(sorted(syms)))
> PY
> ```

---

## Verification & rollback

- **Per-commit gate:** `pytest -q && ruff check src tests` (add `mypy`/`pyright`
  if configured). Never commit on red.
- **Behavioral smoke test** after Phase 1: `avai monitor --once --no-enrich`
  and `avai dashboard` both start cleanly.
- **Rollback:** each step is one mechanical commit → `git revert` any single
  step in isolation.

## Sequencing note

Decided: execute **on the current `release/0.1.0` branch** (per your call). Be
aware it carries a large pile of uncommitted release work — commit that first
so the refactor commits stay cleanly separated and individually revertable.
Recommended order: Phase 1, stop and review (tests green), then Phase 2.
