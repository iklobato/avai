# Dashboard redesign plan: the Panels board

Status (2026-10-30, nothing merged yet): step 1 on branch `feat/panels-board` (PR https://github.com/iklobato/avai/pull/44); step 2 on branch `feat/panels-board-phase2`, stacked on it. Steps 3 and 4 not started.

How step 2 was built:
- Migration `0013_board_phase2` adds `judgements.remediation_plain`, `judgements.verify_outcome`, `control_state.verify_enabled`, `control_state.investigate_enabled`, `control_state.capabilities_json`.
- `remediation_plain` is optional in the judge's reply (decision 2026-10-30): a model that skips it still answers, and Inspect falls back to `remediation`.
- The Double-check switch only turns off what the monitor built at start (decision 2026-10-30); if it started without the second passes, the card says to restart.
- Telemetry stays an env var read at start: the Setup panel shows it, it has no switch yet.

How step 1 differs from the map below:
- Board fragments live under `/board/*` (`routes/board.py`, `routes/board_panels.py`), not in `/fragments/*`.
  The old page and its fragments stay untouched at `/classic`, so nothing in section 3.8 needed a change.
- The Activity charts and the program-start list are HTML fragments (`/board/rates` every 15 s,
  `/board/exec-feed` every 5 s), not the JSON endpoints in 3.5. Same queries, one less client renderer.
- Host, Network and Collection are one fragment per row (`/board/host`, `/board/network`, `/board/collection`).
  The CPU line and load sparkline are drawn server side as SVG; `/api/chart/resources` is unchanged.
- System fonts replace Inter Tight and JetBrains Mono: the CSP allows no font CDN.
- Setup shows only what the DB knows: no Double-check switch, no Change AI, Give access or Add keys
  (they need 4.2 and 4.4). The Alerts switch works (browser only).
- The program-start list marks unsigned programs; it does not yet mark ones that match a finding.
- Zero-count verdict tiles are drawn neutral, not red or orange.

Design reference: the exported mockup `E · Panels board (chosen) · Tweaks monitor live offline-html/Panels.dc.html`
(canvas https://claude.ai/artifact/QAfV9JZ2SUHZh8xAKDKR3A, board E). Treat it as a mockup: copy its
colors, sizes and layout, not its markup. Its numbers come from a copy of the maintainer's
`~/.avai/avai.db` taken 2026-10-29.

## 1. Facts that shape the plan

| Fact | Where | What it means for the board |
|---|---|---|
| The monitor writes `control_state.last_seen_at` about every 3 s; "alive" means seen in the last 120 s | `dashboard/control.py` `MonitorLiveness`, `MONITOR_LIVENESS_WINDOW_S = 120` | The offline banner and the Live/Stale chip can be exact today. |
| Streaming rows (`process_exec_events`, `auth_events`) are flushed to SQLite every 5 s or per batch | `host_monitor/streaming.py:40` `flush_interval_s: float = 5.0` | "Process starts (live)" and the per-minute charts can be live with plain 5 s polling. No SSE or websocket needed. |
| Snapshot collectors (CPU, ports, flows, DNS, persistence) and LLM judging run once per cycle, 300 s by default | `host_monitor/constants.py` `DEFAULT_INTERVAL = 300` | Those panels change at most once per cycle. Polling them faster than 30 to 60 s buys nothing. |
| The dashboard reads through a read-only engine; its only writes are `control_state` and `feedback` | `dashboard/control.py` module docstring | Every new write (settings, toggles) goes through `ControlStore`, behind `TokenGate`. |
| Both `event_timestamp` columns are indexed | `.indexes process_exec_events`, `.indexes auth_events` on the DB copy | Per-minute counts over the last 20 minutes are cheap. |
| Without root, `process_exec_events` stops at once with `rows=0`; 46% of `auth_events` rows were avai's own `system_profiler` noise in the 2026-10-27 run | `docs/KNOWLEDGE.md` section 9 | The exec feed is empty for a non-root monitor: the panel must say "needs Full access", not show an empty list. The auth per-minute chart counts avai's own noise unless those rows are filtered. |
| The verifier only stores a result when it refutes a verdict (reasoning starts `[verifier downgraded malicious→suspicious]`); the investigator marks its result with `[investigated]` | `host_monitor/finding_stages.py:593` and `:718` | "Double-check: agreed" is NOT in the DB today. See 4.1. |

## 2. Approach

Keep the current stack: Flask views + Jinja fragments + HTMX + Chart.js, all vendored, no build step.
Each board panel is one fragment with its own `hx-trigger="load, every Ns"`. JSON stays only for
charts and the two live feeds. Reason: it is the existing pattern (`routes/fragments.py`), it needs no
new dependency, and every query below already returns plain dicts the templates can render.

Interactive parts of the mockup map to HTMX like this:
- Row collapse, the Setup panel open/closed, "Show command": client-side, state in `localStorage`.
- Selecting a finding: `hx-get` the Inspect fragment, which also swaps "How avai decided" with `hx-swap-oob`.
- Real problem / This is normal: `hx-post` to the existing feedback route, swap the row.
- Ask avai: `hx-post` returns the two new chat bubbles.

Status legend in the tables: **R** = reuse as is, **C** = exists, needs a change, **N** = new.

## 3. Endpoint map

### 3.1 Top bar and offline banner

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /` | C | New page shell: top bar, 5 collapsible rows, empty panels with their `hx-get` | `templates/dashboard.html` (rewritten) | once |
| `GET /fragments/topbar` | N | hostname; monitor state (`running`/`scanning`/`paused`/offline), pid, heartbeat age, interval; Setup badge count; bell count; banner when offline | `RunQueries.latest_run()` → `collection_runs.hostname`; `ControlReader().read()` → `control_state.status, paused, pid, last_seen_at, current_interval`; `MonitorLiveness.alive()`; bell = `len(VerdictQueries.new_alerts(since))` | 5 s |
| `GET /api/notifications/new?since=` | R | `{since, now, items: [{content_hash, collector, verdict, category, confidence, reasoning, remediation, created_at, artifact}]}` | `VerdictQueries.new_alerts()` → `judgements` where verdict in malicious/suspicious and `created_at > since`, newest 50 | 15 s |

`since` stays in `localStorage` as today, so "Mark all seen" is client-side only.

### 3.2 Setup and privacy

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /fragments/setup` | N | 6 cards (Monitor, AI review, Double-check, Full access, Online lookups, Alerts) with state and the control each shows; the "What leaves this computer" rows | see the card table below | 60 s |
| `POST /control/pause`, `/control/resume`, `/control/scan-now` | R | re-rendered card | `ControlStore` → `control_state` | on click |
| `POST /control/settings` | C | re-rendered card | add `verify`, `investigate` to `SettingsChange` → new columns (4.2) | on click |

Card by card:

| Card | Shows | Source today | Missing |
|---|---|---|---|
| Monitor | Running / Stopped, "every 5 minutes", Pause or Start | `control_state` + `MonitorLiveness` | **Start** when the process is gone: the dashboard cannot start the monitor. v1 links to the start steps. |
| AI review | On / Off, model name | `control_state.judge_enabled`; model = `judgements.model` of the newest row | Whether an API key is set lives only in the monitor process. Needs 4.2. **Change AI** needs a settings design (4.4). |
| Double-check | On / Off switch | nothing: `--no-verify` / `--no-investigate` are CLI flags | 4.2 columns + `CycleSettings` support. |
| Full access | Given / Not given | latest run's `collector_errors` with `error_class = 'PermissionError'` (2 rows on the DB copy: `network_connections`, `listening_ports`) | **Give access** needs a privileged helper (4.4). v1 shows steps. |
| Online lookups | "N on · M more" | sources that returned data: `select distinct source from enrichment_evidence` (8 on the DB copy) | Which sources are on and which lack a key: 4.2 capabilities (key names only, never values). |
| Alerts | Pop-up and sound switch | browser only: `localStorage` + Notification API, as today | nothing |

Privacy rows: "The AI service" = `count(*)` and `sum(cost_usd)` over `judgements` (12 rows, $0.00111 on the
DB copy); "Security databases" = `count(distinct source)` over `enrichment_evidence`; "avai error reports"
= telemetry on/off, which needs 4.2 (today it is the `AVAI_TELEMETRY` env var of each process).

### 3.3 Row "Threats"

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /fragments/threat-stats` | N | active count per verdict (4 tiles); posture score and grade; top 3 vulnerabilities; AI cost total, judged count, model | tiles: `FindingsPanel.findings()` with `FindingFilter(verdict=v, status=ACTIVE)` and `Page(1, 1)`, read `total` (same as `TriageFragment._active`, extended to unknown and benign); posture: `ReportQueries.latest_risk()` → `risk_scores.score, grade`; vulns: `VulnerabilitiesPanel.vulnerabilities(VulnQuery(page=Page(1, 3)))` → `software, severity, cvss, cves, kev, eol`; cost: new `VerdictQueries.cost_total()` and `latest_model()` over `judgements` | 30 s |
| `GET /fragments/alerts` | N | "New since your last visit" list | same as `/api/notifications/new`; client sends `since` with `hx-vals` | 15 s |
| `GET /fragments/changes` | N | per collector `{name, before, after, delta}` for the persistence-surface collectors; active findings with `novel = 1` | `RowCounts.for_runs(latest, previous)` → `{name, rows, delta, is_new}` (`RunQueries.latest_run()` and `prior_run()`); novel: `judgements.novel` with the active filter | 60 s |
| `GET /fragments/incident` | C | headline, severity, summary, actions `{priority, title, command, detail}` | `ReportQueries.latest_narrative()` → `incident_narratives.headline, severity, summary, actions_json, finding_count, created_at, model`. Template change only: the command hides behind "Show command". | 60 s |
| `GET /fragments/findings` | C | rows `{verdict, collector, plain area, reasoning, confidence, novel, content_hash, feedback label}` | `FindingsPanel.findings()` (unchanged query) + new: left join `feedback` on `(content_hash, collector)` for the saved answer; plain area from a new constant map `CollectorLabels` (collector → "programs that start at login") | 60 s and after feedback |
| `POST /feedback/<collector>/<content_hash>/<label>` | C | the updated table row | `ControlStore.record_feedback()` → `feedback` (labels `confirmed`, `false_positive`). Change: return the row fragment, not the "recorded" span. | on click |
| `GET /fragments/inspect/<collector>/<content_hash>` | N | Inspect panel + "How avai decided" (out of band): judgement fields; artifact; "What to do"; command; online-lookup rows `{source, verdict_hint, confidence, summary}`; trail Found → Online lookups → AI review → Double-check → Your answer | `judgements` row by key; `FindingSource.row_and_artifact()` → source row + label; evidence: `IndicatorExtraction.default().extract(collector, source_row)` then `enrichment_evidence` where `(indicator_type, indicator_value)` match; trail: `created_at`, `novel`, evidence count, `verdict`, `confidence`, `model`, verifier (4.1), `feedback.label` | on select |
| `GET /fragments/inspect/vuln?software=` | N | the same panel for a vulnerable package | the `VulnerabilitiesPanel` row + `enrichment_evidence` for the package and its CVEs (sources `osv`, `nvd`, `cisa_kev`, `github_advisory`, `endoflife`) | on select |
| `POST /api/ask` | N | two chat bubbles (question, answer) | an LLM call with the Inspect data as context (4.3) | on send |

### 3.4 Row "Host"

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /fragments/host` | C | memory %, swap %, CPU %, load 1/5/15, uptime, core count, per-core %, disks `{mountpoint, percent, total}` | `ResourceQueries.host_resources(latest)` → `host_resources.*` + `cpu_per_core_json`; `ResourceQueries.disk_usage(latest)` → `disk_usage.mountpoint, percent, total, used` | 30 s |
| `GET /api/chart/resources` | C | `{labels, cpu, mem, swap, load}` | `ResourceQueries.resource_trend()` → `host_resources.collected_at, cpu_percent, mem_percent, swap_percent`; add `load_1` for the load sparkline | 30 s |

### 3.5 Row "Activity"

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /api/activity/rate?stream=exec\|auth&minutes=20` | N | `[{minute, count}]` | `process_exec_events` or `auth_events`, `group by substr(event_timestamp, 1, 16)` where `event_timestamp >= now - 20 min` (indexed) | 15 s |
| `GET /api/activity/exec?after=<id>` | N | newest rows `{id, event_timestamp, exe_path, signing_id, pid, ppid, username, unsigned, flagged}`, at most 50 | `process_exec_events`; `unsigned` = empty `signing_id`; `flagged` = `exe_path` matches the artifact of an active `processes` finding | 5 s |
| (both feeds above) | | Empty-state rule: with no exec rows in the last cycle and Full access missing, show "needs Full access" (see section 1). | | |
| `GET /fragments/listening-ports` | C | `{process, pid, port, proto, addrs, scope, exposed, verdict}` | `PortsPanel.ports(PortQuery())` (unchanged); compact template | 60 s |

### 3.6 Row "Network and settings"

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /fragments/network-flows` | C | top 4 destinations `{dst_ip, ports, bytes, packets, process, hostname, geo}` | `FlowsPanel.flows(FlowQuery())` → `network_flows` + `IpEnrichment` over `enrichment_evidence`; compact template | 60 s |
| `GET /fragments/dns-queries` | C | `{qname, qtype, count, level, verdict}` | `DnsPanel.queries(DnsQuery())` → `dns_queries`; compact template | 60 s |
| `GET /fragments/sysint` | R | 8 checks `{label, enabled, active}` | `IntegrityPosture.for_run(latest)` → `system_integrity` (macOS columns or Linux `raw_json`) | 60 s |

### 3.7 Row "Collection health"

| Endpoint | St | Returns | Data source | Refresh |
|---|---|---|---|---|
| `GET /fragments/collection` | C | last 8 runs `{started_at, duration, collectors_ok, collectors_failed}`; top 8 row counts; YARA `{rules_loaded, files_loaded, files_skipped}`; failing collectors `{collector, error_class}` | `RunQueries.recent_runs()` → `collection_runs`; `RowCounts.for_runs()`; `YaraPanels.status()` → `yara_status`; `RunQueries.collector_errors(latest)` → `collector_errors` | 60 s |

### 3.8 Leaving the board

These stay registered (detail pages later; the route render tests keep passing) but the board no longer
loads them: `/fragments/triage`, `/header-meta`, `/overview`, `/risk`, `/verdicts`, `/posture`,
`/control`, `/log-summary`, `/logs`, `/network` and its tabs `/network-topology`, `/network-exposure`,
`/persistence`, `/file-scan`, `/auth-events`, `/errors`, `/row-counts`, `/runs`, and `/api/chart/verdicts`.
Collector on/off and maintenance commands (`/control/collector/...`, `/control/maintenance/...`) move to
a settings page.

## 4. Backend work the board needs

### 4.1 Store the verifier result (needed for "Double-check: agreed")
- Add `judgements.verify_outcome` (`agreed` / `refuted` / `failed` / NULL = not checked) with an alembic migration.
- `VerifyStage._verify` writes `agreed` when the skeptic does not refute, `refuted` when it does.
- Until then, Inspect can only show "refuted" (reasoning prefix) and "investigated" (`[investigated]` prefix), never "agreed".

### 4.2 Monitor capabilities and new toggles
- The monitor writes a snapshot at start into a new `control_state.capabilities_json`: judge model, narrative model,
  verify on, investigate on, enrichment sources enabled, sources skipped for a missing key (names like
  `VT_API_KEY`, never values), running as root, telemetry on.
- New columns `control_state.verify_enabled`, `investigate_enabled`; `CycleSettings` reads them like `judge_enabled`.
- Telemetry on/off persisted the same way, read by both processes at start.

### 4.3 Ask avai
- `POST /api/ask {collector, content_hash, question}` behind `TokenGate`.
- Needs an LLM client in the dashboard process (reuse `host_monitor/llm.py` and a new prompt in the prompts TOML),
  a per-minute limit, and cost recorded like `judgements.cost_usd`.
- Context sent to the LLM: the Inspect data only. It goes to the "What leaves this computer" list.

### 4.4 Actions that change the machine (not in v1)
"Fix it for me", "Fix it", "Give access", "Start", "Change AI" and adding API keys. Each one runs commands
or stores secrets, so each needs its own design and a security review (confirmation step, privilege
helper, keys in the macOS Keychain and not in SQLite). v1 shows the command with Copy and links to steps.

### 4.5 Plain language
- `CollectorLabels`: one map in the dashboard, collector name → everyday words. No DB change.
- A plain "What to do" sentence per finding is not in the DB (`remediation` is a command or a technical
  line). Options: add `remediation_plain` to the judge's reply schema plus a column, or show `remediation` as is.

## 5. Order of work

1. **Board on existing data** (no migration): shell, top bar, threat-stats, alerts, changes, incident, findings with
   saved feedback, inspect with online lookups, host, activity feeds, ports, flows, DNS, sysint, collection.
   Setup shows what existing data allows (monitor, model, full access, sources that returned data).
2. **Migrations**: 4.1, 4.2 and `remediation_plain` (4.5), then finish the Setup cards, the "Double-check" step and the plain "What to do".
3. **Ask avai** (4.3).
4. **Actions** (4.4), each behind its own review.

Decisions (maintainer, 2026-10-30):
- The verdict tiles count **active** findings only (0 malicious on the DB copy today; all 12 judgements are
  resolved). The mockup's 4/7/0/1 were all-time counts.
- The judge writes the plain "What to do": add `remediation_plain` to the judge's reply schema and a
  `judgements.remediation_plain` column. This joins step 2. Until it lands, Inspect shows `remediation`.
- Ask avai is **not** in the first release. It stays step 3.
- `/classic` (the previous page) is removed in the next release. Cost: the details the board does not
  show yet (logs, persistence lists, YARA matches, auth events, network topology and exposure, collector
  on/off, maintenance commands) go with it unless they get board panels first. The findings panel links
  to `/classic` for the full list; that link has to change in the same release.

## 6. Not verified

- Return shapes come from reading the code on 2026-10-30, not from running each endpoint.
- The DB facts (8 sources, 12 judgements, $0.00111, 2 PermissionError rows) come from the copy taken 2026-10-29.
- I did not measure query times for the per-minute and exec feeds on a big DB (the copy is 322 MB with 107 465 `auth_events` rows).
