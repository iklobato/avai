"""Orchestrator: drives collectors against the sink each cycle."""

from __future__ import annotations

import bisect
import json
import os
import platform
import socket
import threading
import time
from dataclasses import replace
from typing import Optional

from .collectors import Collector, SnapshotCollector, StreamingCollector
from .constants import (
    _CORRELATED_COLLECTOR,
    _FILE_SCAN_COLLECTOR,
    _LAUNCH_ITEM_COLLECTOR,
    DEFAULT_BASELINE_MIN_RUNS,
    LOG,
)
from .enums import FeedbackLabel, Verdict
from .judge import Judge, NullJudge
from .narrator import IncidentNarrator
from .risk import compute_risk_score
from .runtime import Clock, Digest
from .sink import Sink
from .streaming import StreamingWorker

# Minimum presence window (runs since first seen) before an artifact that
# misses runs is called "intermittent" — below this it's just freshly seen.
_MIN_DRIFT_WINDOW = 3

# Bound second-pass LLM work per collector per cycle so a pathological batch
# can't fan out into unbounded verify / investigate calls.
_MAX_VERIFY_PER_COLLECTOR = 10
_MAX_INVESTIGATE_PER_COLLECTOR = 10

# How many of the host's other non-benign findings to hand the investigator
# as situational context.
_HOST_CONTEXT_LIMIT = 15

# How an operator-feedback label reads in the ground-truth block fed to the
# judge. Keyed by the raw stored label.
_FEEDBACK_PHRASE = {
    FeedbackLabel.FALSE_POSITIVE.value: "a FALSE POSITIVE (benign)",
    FeedbackLabel.CONFIRMED.value: "CONFIRMED malicious",
}


class Runner:
    """Drives snapshot collectors (per-cycle) and streaming collectors
    (long-lived threads) against a Sink. Acts as a supervisor: starts
    streaming workers at boot, runs the snapshot loop on the main
    thread, and joins streaming workers on shutdown."""

    def __init__(
        self,
        sink: Sink,
        snapshot_collectors: list[SnapshotCollector],
        streaming_collectors: list[StreamingCollector],
        judge: Judge,
        lookback_min: int,
        max_db_bytes: int = 0,
        enrichment_chain=None,
        baseline_min_runs: int = DEFAULT_BASELINE_MIN_RUNS,
        narrator: "Optional[IncidentNarrator]" = None,
        coverage=None,
        verifier=None,
        investigator=None,
    ):
        self.sink = sink
        self.snapshot_collectors = snapshot_collectors
        self.streaming_collectors = streaming_collectors
        self.judge = judge
        self.lookback_min = lookback_min
        self.max_db_bytes = max_db_bytes  # 0 = unlimited
        self.baseline_min_runs = baseline_min_runs
        # Optional second-stage incident-digest LLM. None ⇒ disabled.
        self.narrator = narrator
        # Optional second-stage YARA ruleset-coverage assessor. None ⇒ disabled.
        self.coverage = coverage
        # Optional skeptic that re-checks malicious verdicts. None ⇒ disabled.
        self.verifier = verifier
        # Optional deep re-judge for unknown findings. None ⇒ disabled.
        self.investigator = investigator
        self._streaming_workers: list[StreamingWorker] = []
        self.shutdown_event = threading.Event()
        # Optional threat-intel enrichment between collection and judging.
        # None ⇒ disabled (no API calls, no schema rows). Lazily imported
        # so the enrichers package's `requests` dep is only needed when
        # enrichment is on.
        self._enrichment_chain = enrichment_chain
        # Cooperative control plane (see models.ControlState). The dashboard
        # writes intent to the control row; we refresh this cache each cycle
        # and obey. Defaults below are what "None" (unset) in the row means.
        self._control: dict = {}
        self._default_judge_on = not isinstance(judge, NullJudge)
        self._default_enrich_on = enrichment_chain is not None

    def request_shutdown(self) -> None:
        """Idempotent — safe to call from a signal handler."""
        self.shutdown_event.set()

    # ----- cooperative control: read the row, derive effective settings -----

    def _refresh_control(self) -> dict:
        self._control = self.sink.read_control() or {}
        return self._control

    def _disabled_collectors(self) -> set[str]:
        raw = self._control.get("disabled_collectors")
        return {s.strip() for s in raw.split(",") if s.strip()} if raw else set()

    def _judge_on(self) -> bool:
        v = self._control.get("judge_enabled")
        return self._default_judge_on if v is None else bool(v)

    def _enrich_on(self) -> bool:
        v = self._control.get("enrich_enabled")
        return self._default_enrich_on if v is None else bool(v)

    def _heartbeat(self, status: str, current_interval: int) -> None:
        try:
            self.sink.write_heartbeat(
                pid=os.getpid(), status=status, current_interval=current_interval
            )
        except Exception:
            LOG.exception("heartbeat write failed")

    def _run_pending_command(self, ctrl: dict) -> None:
        """Execute a one-shot maintenance command if a new nonce is present,
        then acknowledge it. Best-effort: a failed command must not kill the
        loop."""
        nonce = ctrl.get("command_nonce", 0)
        if nonce == ctrl.get("command_applied", 0):
            return
        cmd = ctrl.get("command")
        try:
            result = self._dispatch_command(cmd)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("control command %s failed", cmd)
            result = f"error: {type(exc).__name__}: {str(exc)[:120]}"
        self.sink.ack_command(nonce, result)
        LOG.info("control command applied: %s -> %s", cmd, result)

    def _dispatch_command(self, cmd: Optional[str]) -> str:
        if cmd == "prune":
            stats = self.sink.prune_to_size(self.max_db_bytes or 0)
            return f"pruned runs={stats['runs_pruned']} events={stats['events_pruned']}"
        if cmd == "clear":
            return f"cleared {self.sink.clear_data()} rows"
        if cmd == "rejudge":
            return f"cleared {self.sink.clear_judgements()} judgements"
        if cmd == "renarrate":
            return f"cleared {self.sink.clear_narratives()} narratives"
        if cmd == "reset_baseline":
            return f"reset baseline ({self.sink.reset_baseline()} runs dropped)"
        return f"unknown command: {cmd}"

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
        # Refresh the control cache so --once and the daemon loop both honour
        # disabled-collector / judge / enrich toggles set from the dashboard.
        self._refresh_control()
        # Apply any operator corrections before judging so this cycle's
        # narrative / risk reflect the fixed verdicts.
        self._apply_feedback()
        run_id, started = self.sink.start_run(socket.gethostname(), self.lookback_min)
        # Snapshot the host's baseline state once: it can't change mid-cycle
        # (the current run isn't completed yet), and every collector shares
        # the same cutoff.
        host_baseline = self._host_baseline()
        disabled = self._disabled_collectors()
        ok = failed = 0
        for c in self.snapshot_collectors:
            # Honour a shutdown request mid-cycle. The first cycle judges
            # every collector via the LLM, which can take minutes; without
            # this check Ctrl-C wouldn't take effect until the whole cycle
            # finished (the loop is the long pole, not run_forever).
            if self.shutdown_event.is_set():
                LOG.info("shutdown requested — stopping collector loop early")
                break
            if c.name in disabled:
                continue
            try:
                self._run_collector(c, run_id, started, host_baseline)
                ok += 1
            except Exception as exc:
                failed += 1
                self.sink.write_error(c.name, exc)
                LOG.warning(
                    "collector=%s status=failed error=%s message=%s",
                    c.name,
                    type(exc).__name__,
                    str(exc)[:200],
                )
        # Streaming collectors accumulate rows in background threads.
        # After the snapshot phase, give the LLM judge a chance to
        # classify any new content_hashes those streamers produced
        # since the previous cycle. Skip if we're shutting down — no
        # point starting a fresh round of LLM calls on the way out.
        if not self.shutdown_event.is_set():
            self._judge_streaming_collectors(host_baseline)
            # With this cycle's verdicts in and last_seen_at touched, the
            # active-finding set is current — synthesise the incident digest.
            if self.narrator is not None:
                self._generate_narrative(run_id, started)
            # Deterministic posture score — always computed (no LLM needed).
            self._generate_risk_score(run_id, started)
            # Persist the file scanner's ruleset summary for the dashboard.
            self._write_yara_status()
            # Assess whether the loaded ruleset covers this host (LLM, opt-in).
            if self.coverage is not None:
                self._generate_coverage(run_id, started)
        self.sink.end_run(ok, failed)

        # Rotation: keep the DB under the configured size cap by pruning
        # oldest completed runs and their child rows.
        if self.max_db_bytes:
            stats = self.sink.prune_to_size(self.max_db_bytes)
            if stats["runs_pruned"] or stats["events_pruned"]:
                LOG.info(
                    "db_rotation: pruned runs=%d auth_events=%d  "
                    "%.1fMB → %.1fMB (cap %.0fMB)",
                    stats["runs_pruned"],
                    stats["events_pruned"],
                    stats["bytes_before"] / (1024 * 1024),
                    stats["bytes_after"] / (1024 * 1024),
                    self.max_db_bytes / (1024 * 1024),
                )

        return run_id, ok, failed

    def _host_baseline(self) -> dict:
        """Snapshot of how 'learned' this host is, computed once per cycle.

        ``established`` flips on after ``baseline_min_runs`` completed runs;
        ``cutoff_at`` is the run timestamp that ends the learning window.
        An artifact whose first appearance post-dates the cutoff showed up
        on an already-baselined host — that's the novelty signal fed to the
        judge."""
        total = self.sink.completed_run_count()
        established = total >= self.baseline_min_runs
        cutoff = (
            self.sink.nth_run_started_at(self.baseline_min_runs)
            if established
            else None
        )
        return {"total_runs": total, "established": established, "cutoff_at": cutoff}

    def _annotate_baseline(
        self, c: Collector, unjudged: list[dict], host_baseline: dict
    ) -> None:
        """Attach a ``baseline`` object to each unjudged entry in-place so
        the judge can weigh novelty against this host's learned-normal
        instead of classifying every artifact in the absolute.

        Computing ``first_seen`` from the rows table (not from when the
        artifact was first *judged*) is deliberate: the per-collector judge
        cap defers some entries across cycles, but an artifact present since
        run 1 still reads first_seen=run 1 and so is never mislabelled
        novel just because the judge got to it late."""
        if not unjudged or not c.judge_fields:
            return
        hashes = [e["content_hash"] for e in unjudged if e.get("content_hash")]
        try:
            fs_map = self.sink.first_seen_map(c.model, hashes)
        except Exception as exc:
            LOG.warning("baseline: first_seen_map(%s) failed: %s", c.name, exc)
            return
        cutoff = host_baseline["cutoff_at"]
        established = host_baseline["established"]
        # Run timeline (incl. the in-progress run) to size each artifact's
        # presence window — how many runs have happened since it first
        # appeared. Fetched once; an artifact present in fewer runs than its
        # window has come and gone (intermittent), a sharper drift signal than
        # the novelty bit alone.
        try:
            timeline = self.sink.run_started_ats()
        except Exception as exc:
            LOG.warning("baseline: run timeline fetch failed: %s", exc)
            timeline = []
        for entry in unjudged:
            seen = fs_map.get(entry.get("content_hash"))
            if seen is None:
                continue
            first_seen, times_seen = seen
            novel = bool(established and cutoff is not None and first_seen > cutoff)
            window = (
                len(timeline) - bisect.bisect_left(timeline, first_seen)
                if timeline
                else 0
            )
            # Needs at least a few runs of window to distinguish flapping from
            # a freshly-seen artifact.
            intermittent = window >= _MIN_DRIFT_WINDOW and times_seen < window
            entry["baseline"] = {
                "first_seen": first_seen,
                "times_seen": times_seen,
                "host_runs": host_baseline["total_runs"],
                "baseline_established": established,
                "novel": novel,
                "intermittent": intermittent,
            }

    def _attach_correlation(
        self, c: Collector, unjudged: list[dict], rows: list[dict], run_id: str
    ) -> None:
        """Attach a ``related`` object — the artifact's listening ports,
        outbound flows, remote connections, DNS queries and exec lineage,
        correlated by PID (DNS by process name) — so the judge scores it
        *with its behaviour* instead of in isolation. A novel binary (or a
        launch item) that is also beaconing to a flagged IP is a far stronger
        signal than either row alone.

        Correlated collectors:
        - ``processes``: PID/name come straight from the collector's rows.
        - ``launch_items``: the unjudged entry has no PID, so we resolve each
          item's ``program`` to the live process(es) running it, then use
          those PIDs.
        Other collectors keep their own independent verdicts."""
        if not unjudged or c.name not in (
            _CORRELATED_COLLECTOR,
            _LAUNCH_ITEM_COLLECTOR,
        ):
            return
        try:
            since = self.sink.prior_run_started_at(run_id)
        except Exception as exc:
            LOG.warning("correlation: prior_run(%s) failed: %s", c.name, exc)
            return
        pids_by_hash, names_by_hash = self._behavior_pid_map(c, rows, since)
        all_pids = sorted({p for s in pids_by_hash.values() for p in s})
        all_names = sorted({n for s in names_by_hash.values() for n in s})
        if not all_pids and not all_names:
            return
        try:
            ctx = self.sink.correlation_context(all_pids, all_names, since)
        except Exception as exc:
            LOG.warning("correlation: context(%s) failed: %s", c.name, exc)
            return
        for entry in unjudged:
            h = entry.get("content_hash")
            related = self._related_from_ctx(
                ctx, pids_by_hash.get(h, set()), names_by_hash.get(h, set())
            )
            if related:
                entry["related"] = related

    def _behavior_pid_map(
        self, c: Collector, rows: list[dict], since: Optional[str]
    ) -> tuple[dict, dict]:
        """content_hash → (PIDs, names) for a correlatable collector, or two
        empty maps for anything else. Dispatches on the collector instead of
        branching at each call site."""
        if c.name == _CORRELATED_COLLECTOR:
            return self._process_pid_map(rows)
        if c.name == _LAUNCH_ITEM_COLLECTOR:
            return self._launch_item_pid_map(rows, since)
        return {}, {}

    @staticmethod
    def _related_from_ctx(ctx: dict, pids: set, names: set) -> dict:
        """Assemble the ``related`` behaviour object for one artifact from a
        correlation context, bounded per kind. Shared by per-cycle correlation
        and the investigator's full-history bundle."""
        related: dict = {}
        ports = [p for pid in pids for p in ctx["ports"].get(pid, [])]
        flows = [f for pid in pids for f in ctx["flows"].get(pid, [])]
        conns = [cc for pid in pids for cc in ctx["conns"].get(pid, [])]
        dns = [d for n in names for d in ctx["dns"].get(n, [])]
        execs = [ctx["exec"][pid] for pid in pids if pid in ctx["exec"]]
        if ports:
            related["listening_ports"] = ports[:10]
        if flows:
            related["outbound_flows"] = flows[:10]
        if conns:
            related["remote_connections"] = conns[:10]
        if dns:
            related["dns_queries"] = dns[:15]
        if execs:
            related["exec_lineage"] = execs[0]
        return related

    @staticmethod
    def _process_pid_map(rows: list[dict]) -> tuple[dict, dict]:
        """content_hash → (PIDs, names) from the processes rows' own
        pid/name fields."""
        pids_by_hash: dict[str, set] = {}
        names_by_hash: dict[str, set] = {}
        for r in rows:
            h = r.get("content_hash")
            if not isinstance(h, str) or not h:
                continue
            if r.get("pid") is not None:
                pids_by_hash.setdefault(h, set()).add(r["pid"])
            if r.get("name"):
                names_by_hash.setdefault(h, set()).add(r["name"])
        return pids_by_hash, names_by_hash

    def _launch_item_pid_map(
        self, rows: list[dict], since: Optional[str]
    ) -> tuple[dict, dict]:
        """content_hash → (PIDs, names) for launch items: resolve each item's
        ``program`` to the live process(es) running it (via the process
        snapshot at/after ``since``), so a persistence entry is judged with
        the behaviour of the process it spawns. names carry the program
        basename so DNS-by-process-name correlation still applies."""
        programs_by_hash: dict[str, set] = {}
        for r in rows:
            h = r.get("content_hash")
            prog = r.get("program")
            if isinstance(h, str) and h and isinstance(prog, str) and prog:
                programs_by_hash.setdefault(h, set()).add(prog)
        all_programs = sorted({p for s in programs_by_hash.values() for p in s})
        try:
            pids_for_exe = self.sink.pids_by_executable(all_programs, since)
        except Exception as exc:
            LOG.warning("correlation: pids_by_executable failed: %s", exc)
            pids_for_exe = {}
        pids_by_hash: dict[str, set] = {}
        names_by_hash: dict[str, set] = {}
        for h, progs in programs_by_hash.items():
            for prog in progs:
                for pid in pids_for_exe.get(prog, ()):
                    pids_by_hash.setdefault(h, set()).add(pid)
                names_by_hash.setdefault(h, set()).add(prog.rsplit("/", 1)[-1])
        return pids_by_hash, names_by_hash

    def _attach_yara_context(
        self, c: Collector, unjudged: list[dict], rows: list[dict]
    ) -> None:
        """Attach the matched rule's own metadata and a redacted sample of
        the matched bytes to each ``file_scan`` entry in-place, so the judge
        can triage false positives and attribute the rule instead of seeing
        only the rule name + tags.

        Both fields live on the collector ``rows`` but not in ``judge_fields``
        (so they don't affect the content_hash); we map content_hash → row
        exactly as ``_enrich_entries`` maps evidence, then surface ``meta_json``
        as ``rule_meta`` and ``strings_json`` as ``matched_strings``."""
        if c.name != _FILE_SCAN_COLLECTOR or not unjudged:
            return
        rows_by_hash: dict[str, dict] = {}
        for r in rows:
            h = r.get("content_hash")
            if isinstance(h, str) and h and h not in rows_by_hash:
                rows_by_hash[h] = r
        for entry in unjudged:
            row = rows_by_hash.get(entry.get("content_hash"))
            if row is None:
                continue
            meta = self._loads_or_none(row.get("meta_json"))
            if isinstance(meta, dict) and meta:
                entry["rule_meta"] = meta
            strings = self._loads_or_none(row.get("strings_json"))
            if isinstance(strings, list) and strings:
                entry["matched_strings"] = strings

    @staticmethod
    def _loads_or_none(raw):
        """Parse a JSON column value, returning None on absence/garbage so a
        malformed row can't break the judge wiring."""
        if not isinstance(raw, str) or not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _judgment_context(unjudged: list[dict]) -> dict:
        """Collect the per-hash ``baseline`` + ``related`` signals from the
        judged entries so ``write_judgments`` can persist them alongside the
        verdict (the dashboard then surfaces novelty + the process story on
        each finding)."""
        ctx: dict[str, dict] = {}
        for e in unjudged:
            h = e.get("content_hash")
            if not h:
                continue
            parts = {}
            if e.get("baseline"):
                parts["baseline"] = e["baseline"]
            if e.get("related"):
                parts["related"] = e["related"]
            if parts:
                ctx[h] = parts
        return ctx

    def _verify_judgments(
        self, collector: str, judgments: list, unjudged: list[dict]
    ) -> list:
        """Re-check each ``malicious`` verdict with the independent skeptic; a
        refuted verdict is downgraded to ``suspicious`` (still flagged for
        review, not asserted as an active threat). No-op without a verifier;
        bounded per collector so a batch of malicious can't fan out."""
        if self.verifier is None or not judgments:
            return judgments
        by_hash = {e.get("content_hash"): e for e in unjudged if e.get("content_hash")}
        out: list = []
        checked = 0
        for j in judgments:
            if j.verdict != Verdict.MALICIOUS or checked >= _MAX_VERIFY_PER_COLLECTOR:
                out.append(j)
                continue
            checked += 1
            entry = by_hash.get(j.content_hash, {})
            finding = {
                "collector": collector,
                "verdict": str(j.verdict),
                "category": str(j.category),
                "reasoning": j.reasoning,
                **{k: v for k, v in entry.items() if k != "content_hash"},
            }
            result = self.verifier.verify(finding)
            if result and result["refuted"]:
                out.append(
                    replace(
                        j,
                        verdict=Verdict.SUSPICIOUS,
                        reasoning=(
                            f"[verifier downgraded malicious→suspicious] "
                            f"{result['reasoning']} · original: {j.reasoning}"
                        )[:500],
                    )
                )
                LOG.info(
                    "verifier downgraded collector=%s reason=%s",
                    collector,
                    result["reasoning"][:120],
                )
            else:
                out.append(j)
        return out

    def _apply_feedback(self) -> None:
        """Pin operator corrections onto their findings' verdicts. Best-effort
        — a feedback failure must not stop the cycle."""
        try:
            n = self.sink.apply_feedback()
        except Exception:
            LOG.exception("apply_feedback failed")
            return
        if n:
            LOG.info("applied %d operator feedback correction(s)", n)

    def _judge_hints(self, collector_name: str, base_hints: str) -> str:
        """Append this host's recent operator feedback for the collector to
        the static hints as ground-truth examples, so the judge classifies
        matching artifacts the same way. Returns the base hints unchanged when
        there's no feedback."""
        try:
            examples = self.sink.feedback_examples(collector_name)
        except Exception as exc:
            LOG.warning("feedback_examples(%s) failed: %s", collector_name, exc)
            return base_hints
        if not examples:
            return base_hints
        lines = []
        for e in examples:
            artifact = (e.get("artifact") or "").strip() or "(unnamed artifact)"
            phrase = _FEEDBACK_PHRASE.get(e.get("label"), e.get("label"))
            note = f" note: {e['note']}" if e.get("note") else ""
            lines.append(f'- "{artifact}" was marked {phrase} by the operator.{note}')
        return base_hints + (
            "\nOperator feedback for this host (ground truth — apply the same "
            "judgement to these and closely-matching artifacts):\n" + "\n".join(lines)
        )

    def _investigate_unknowns(
        self, c: Collector, judgments: list, unjudged: list[dict], rows: list[dict]
    ) -> list:
        """Re-judge each ``unknown`` verdict with a richer, deliberately
        gathered bundle: the artifact's FULL-HISTORY correlated behaviour (not
        just the previous cycle) plus the host's other non-benign findings.
        A committed verdict replaces the unknown. No-op without an
        investigator; bounded per collector. Snapshot collectors only — their
        ``rows`` are needed to resolve behaviour."""
        if self.investigator is None or not judgments:
            return judgments
        by_hash = {e.get("content_hash"): e for e in unjudged if e.get("content_hash")}
        # Full history: since=None drops the previous-cycle time bound.
        pids_by_hash, names_by_hash = self._behavior_pid_map(c, rows, None)
        all_pids = sorted({p for s in pids_by_hash.values() for p in s})
        all_names = sorted({n for s in names_by_hash.values() for n in s})
        ctx = None
        host_context: list = []
        out: list = []
        investigated = 0
        for j in judgments:
            stop = investigated >= _MAX_INVESTIGATE_PER_COLLECTOR
            if j.verdict != Verdict.UNKNOWN or stop:
                out.append(j)
                continue
            investigated += 1
            if ctx is None:  # gather the shared context once, on first unknown
                ctx = self._full_history_context(all_pids, all_names)
                host_context = self._host_context()
            entry = by_hash.get(j.content_hash, {})
            finding = {k: v for k, v in entry.items() if k != "content_hash"}
            related_full = self._related_from_ctx(
                ctx,
                pids_by_hash.get(j.content_hash, set()),
                names_by_hash.get(j.content_hash, set()),
            )
            if related_full:
                finding["related_full"] = related_full
            others = [h for h in host_context if h["content_hash"] != j.content_hash]
            if others:
                finding["host_context"] = others
            result = self.investigator.investigate(c.name, finding)
            if result and result["verdict"] != Verdict.UNKNOWN:
                out.append(
                    replace(
                        j,
                        verdict=result["verdict"],
                        category=result["category"],
                        confidence=result["confidence"],
                        reasoning=f"[investigated] {result['reasoning']}"[:500],
                        remediation=result["remediation"],
                    )
                )
                LOG.info(
                    "investigator resolved collector=%s unknown→%s",
                    c.name,
                    str(result["verdict"]),
                )
            else:
                out.append(j)
        return out

    def _full_history_context(self, pids: list, names: list) -> dict:
        """Correlation context over all retained history (since=None)."""
        try:
            return self.sink.correlation_context(pids, names, None)
        except Exception as exc:
            LOG.warning("investigate: full-history context failed: %s", exc)
            return {"ports": {}, "flows": {}, "conns": {}, "dns": {}, "exec": {}}

    def _host_context(self) -> list:
        try:
            return self.sink.recent_nonbenign(_HOST_CONTEXT_LIMIT)
        except Exception as exc:
            LOG.warning("investigate: host context failed: %s", exc)
            return []

    def _run_collector(
        self, c: SnapshotCollector, run_id: str, started: str, host_baseline: dict
    ) -> None:
        t0 = time.monotonic()
        rows = list(c.collect())
        for r in rows:
            r["run_id"] = run_id
            r["collected_at"] = started
            r["content_hash"] = Digest.of_row(r, c.judge_fields)
        self.sink.write(c.model, rows)
        collected_ms = int((time.monotonic() - t0) * 1000)

        judged = 0
        enriched_indicators = 0
        if c.judge_enabled and c.judge_fields:
            unjudged = self.sink.unjudged(c)
            # Judging (and its enrichment) is gated by the live control
            # toggle; touch_judgments still runs below so already-recorded
            # findings keep an accurate active/resolved status.
            if unjudged and self._judge_on():
                enriched_indicators = self._enrich_entries(c, unjudged, rows)
                self._annotate_baseline(c, unjudged, host_baseline)
                self._attach_correlation(c, unjudged, rows, run_id)
                self._attach_yara_context(c, unjudged, rows)
                hints = self._judge_hints(c.name, c.judge_hints)
                judgments = self.judge.judge(c.name, hints, unjudged)
                judgments = self._verify_judgments(c.name, judgments, unjudged)
                judgments = self._investigate_unknowns(c, judgments, unjudged, rows)
                self.sink.write_judgments(
                    judgments, context=self._judgment_context(unjudged)
                )
                judged = len(judgments)
            # Mark every judgment whose hash was observed this cycle as
            # "still present". The dashboard derives active/resolved
            # status by comparing last_seen_at to the latest run.
            observed = [r["content_hash"] for r in rows if r.get("content_hash")]
            if observed:
                self.sink.touch_judgments(c.name, observed, started)

        LOG.info(
            "collector=%s rows=%d duration_ms=%d judged=%d enriched=%d",
            c.name,
            len(rows),
            collected_ms,
            judged,
            enriched_indicators,
        )

    def _enrich_entries(
        self, c: SnapshotCollector, unjudged: list[dict], rows: list[dict]
    ) -> int:
        """Attach external threat-intel evidence to each unjudged entry
        in-place by adding an ``evidence`` key.

        Indicators come from the collector's ``rows`` (richer than the
        unjudged projection); we map by ``content_hash`` so an entry's
        evidence is derived from one of the rows that produced it.
        Returns the count of distinct indicators looked up — used only
        for the per-collector log line.
        """
        chain = self._enrichment_chain
        if chain is None or not self._enrich_on():
            return 0
        from avai.enrichers import extract_indicators

        rows_by_hash: dict[str, dict] = {}
        for r in rows:
            h = r.get("content_hash")
            if isinstance(h, str) and h and h not in rows_by_hash:
                rows_by_hash[h] = r

        total = 0
        for entry in unjudged:
            h = entry.get("content_hash")
            row = rows_by_hash.get(h) if isinstance(h, str) else None
            if row is None:
                continue
            indicators = extract_indicators(c.name, row)
            if not indicators:
                continue
            ev_dicts: list[dict] = []
            for ind in indicators:
                total += 1
                for ev in chain.enrich(ind):
                    ev_dicts.append(
                        {
                            "src": ev.source,
                            "type": str(ind.type),
                            "value": ind.value,
                            "hint": str(ev.verdict_hint),
                            "confidence": round(ev.confidence, 2),
                            "note": ev.summary,
                        }
                    )
            if ev_dicts:
                entry["evidence"] = ev_dicts
        return total

    def _judge_streaming_collectors(self, host_baseline: dict) -> None:
        """Run the LLM judge against new content_hashes produced by
        streaming collectors since the previous cycle. Uses
        ``Sink.unjudged_all`` so streaming rows (which aren't tied to
        a CollectionRun.run_id) are still classified once each."""
        if not self._judge_on():
            return
        disabled = self._disabled_collectors()
        for c in self.streaming_collectors:
            if not (c.judge_enabled and c.judge_fields):
                continue
            # A disabled streaming collector keeps its background worker
            # running (workers start once at boot) but is no longer judged.
            if c.name in disabled:
                continue
            try:
                unjudged = self.sink.unjudged_all(c)
            except Exception as exc:
                LOG.warning("streaming-judge: unjudged_all(%s) failed: %s", c.name, exc)
                continue
            if not unjudged:
                continue
            self._annotate_baseline(c, unjudged, host_baseline)
            try:
                hints = self._judge_hints(c.name, c.judge_hints)
                judgments = self.judge.judge(c.name, hints, unjudged)
                judgments = self._verify_judgments(c.name, judgments, unjudged)
                self.sink.write_judgments(
                    judgments, context=self._judgment_context(unjudged)
                )
                LOG.info(
                    "streaming-judge collector=%s judged=%d", c.name, len(judgments)
                )
            except Exception:
                LOG.exception("streaming-judge failed for %s", c.name)

    def _generate_narrative(self, run_id: str, started: str) -> None:
        """Synthesise the active non-benign findings into one incident
        digest and store it — but only when the active-finding set has
        changed since the last narrative, so we don't re-spend tokens on
        an unchanged picture. Never raises (best-effort, post-judge)."""
        try:
            findings = self.sink.active_findings(started)
        except Exception as exc:
            LOG.warning("narrative: active_findings failed: %s", exc)
            return
        if not findings:
            return
        digest = json.dumps(sorted(f["content_hash"] for f in findings))
        try:
            if self.sink.latest_narrative_finding_hashes() == digest:
                return  # nothing changed since the last digest
        except Exception:
            pass  # comparison is an optimisation; fall through and generate
        result = self.narrator.narrate(findings)
        if not result:
            return
        try:
            self.sink.write_narrative(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "model": self.narrator.model,
                    "severity": result["severity"],
                    "headline": result["headline"],
                    "summary": result["summary"],
                    "timeline_json": json.dumps(result["timeline"]),
                    "actions_json": json.dumps(result["actions"]),
                    "finding_count": len(findings),
                    "finding_hashes": digest,
                }
            )
            LOG.info(
                "narrative written severity=%s findings=%d timeline=%d actions=%d",
                result["severity"],
                len(findings),
                len(result["timeline"]),
                len(result["actions"]),
            )
        except Exception as exc:
            LOG.warning("narrative: write failed: %s", exc)

    def _generate_risk_score(self, run_id: str, started: str) -> None:
        """Compute and store the deterministic host posture score for this
        run, with a delta explanation vs the previous score. Best-effort —
        never raises."""
        try:
            findings = self.sink.active_findings(started)
            malicious = sum(
                1 for f in findings if f["verdict"] == str(Verdict.MALICIOUS)
            )
            suspicious = sum(
                1 for f in findings if f["verdict"] == str(Verdict.SUSPICIOUS)
            )
            integrity = self.sink.system_integrity_row(run_id)
            nopasswd, extra_uid0 = self.sink.privilege_risk_counts(run_id)
        except Exception as exc:
            LOG.warning("risk: input gather failed: %s", exc)
            return
        result = compute_risk_score(
            integrity, malicious, suspicious, nopasswd, extra_uid0
        )
        prev = self.sink.latest_risk_row()
        try:
            self.sink.write_risk_score(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "score": result["score"],
                    "grade": result["grade"],
                    "prev_score": prev.score if prev else None,
                    "drivers_json": json.dumps(result["drivers"]),
                    "explanation": self._risk_explanation(result, prev),
                }
            )
            LOG.info("risk score=%d grade=%s", result["score"], result["grade"])
        except Exception as exc:
            LOG.warning("risk: write failed: %s", exc)

    def _write_yara_status(self) -> None:
        """Persist the file scanner's last compile summary (rules loaded /
        skipped / by source / category) so the read-only dashboard can show
        the ruleset. Best-effort — never raises."""
        stats = next(
            (
                c.compile_stats
                for c in self.snapshot_collectors
                if getattr(c, "compile_stats", None) is not None
            ),
            None,
        )
        if stats is None:
            return
        try:
            self.sink.write_yara_status(stats)
            self.sink.write_yara_rules(stats.get("inventory") or [])
        except Exception as exc:  # noqa: BLE001
            LOG.warning("yara_status: write failed: %s", exc)

    def _generate_coverage(self, run_id: str, started: str) -> None:
        """Assess whether the loaded YARA ruleset covers this host's threat
        surface and store the result — but only when the ruleset has changed
        since the last assessment, so we don't re-spend tokens on a ruleset
        that's static within a process. Never raises (best-effort)."""
        try:
            ruleset = self.sink.read_yara_status()
        except Exception as exc:
            LOG.warning("coverage: read_yara_status failed: %s", exc)
            return
        if not ruleset or not ruleset.get("rules_loaded"):
            return
        fingerprint = self._ruleset_fingerprint(ruleset)
        try:
            if self.sink.latest_yara_coverage_fingerprint() == fingerprint:
                return  # ruleset unchanged since the last assessment
        except Exception:
            pass  # comparison is an optimisation; fall through and assess
        try:
            host = self.sink.coverage_profile(run_id)
        except Exception as exc:
            LOG.warning("coverage: profile failed: %s", exc)
            return
        host["platform"] = platform.system()
        host["hostname"] = socket.gethostname()
        result = self.coverage.assess(ruleset, host)
        if not result:
            return
        try:
            self.sink.write_yara_coverage(
                {
                    "created_at": Clock().now_iso(),
                    "run_id": run_id,
                    "model": self.coverage.model,
                    "posture": result["posture"],
                    "headline": result["headline"],
                    "summary": result["summary"],
                    "gaps_json": json.dumps(result["gaps"]),
                    "recommendations_json": json.dumps(result["recommendations"]),
                    "ruleset_fingerprint": fingerprint,
                }
            )
            LOG.info(
                "coverage posture=%s gaps=%d recommendations=%d",
                result["posture"],
                len(result["gaps"]),
                len(result["recommendations"]),
            )
        except Exception as exc:
            LOG.warning("coverage: write failed: %s", exc)

    @staticmethod
    def _ruleset_fingerprint(ruleset: dict) -> str:
        """Stable signature of the loaded ruleset — its rule count, per-source
        counts, and category set. Changes only when the rules actually change,
        gating regeneration of the (token-costing) coverage assessment."""
        return json.dumps(
            {
                "rules": ruleset.get("rules_loaded"),
                "sources": sorted((ruleset.get("sources") or {}).items()),
                "cats": sorted((ruleset.get("by_category") or {}).keys()),
            },
            sort_keys=True,
        )

    @staticmethod
    def _risk_explanation(result: dict, prev) -> str:
        """Deterministic 'why it changed' from the driver diff vs the
        previous run — accurate and free (no LLM paraphrase to drift)."""
        if prev is None:
            return "Initial posture score for this host."
        delta = result["score"] - prev.score
        try:
            prev_labels = {d["label"] for d in json.loads(prev.drivers_json or "[]")}
        except (ValueError, TypeError):
            prev_labels = set()
        cur_labels = {d["label"] for d in result["drivers"]}
        added = [lbl for lbl in cur_labels if lbl not in prev_labels]
        removed = [lbl for lbl in prev_labels if lbl not in cur_labels]
        if delta == 0 and not added and not removed:
            return "No change since the previous run."
        parts = [f"Score {'up' if delta >= 0 else 'down'} {abs(delta)}."]
        if added:
            parts.append("New: " + "; ".join(sorted(added)[:4]) + ".")
        if removed:
            parts.append("Resolved: " + "; ".join(sorted(removed)[:4]) + ".")
        return " ".join(parts)

    # How often the loop wakes to poll the control row. Bounds the latency
    # of pause / resume / scan-now / maintenance commands (the dashboard
    # can't signal us directly — there is no IPC, only the shared DB).
    _CONTROL_POLL_SECONDS = 3.0

    def run_forever(self, interval: int) -> None:
        # Scan immediately on the first tick, then every effective interval.
        next_scan = time.monotonic()
        while not self.shutdown_event.is_set():
            ctrl = self._refresh_control()
            self._run_pending_command(ctrl)  # one-shot maintenance, even if paused
            effective = ctrl.get("interval_override") or interval
            paused = bool(ctrl.get("paused"))
            scan_now = ctrl.get("scan_now_nonce", 0) != ctrl.get("scan_now_applied", 0)

            if scan_now or (time.monotonic() >= next_scan and not paused):
                if scan_now:
                    # Scan-now runs one cycle even while paused.
                    self.sink.ack_scan_now(ctrl["scan_now_nonce"])
                self._heartbeat("scanning", effective)
                t0 = time.monotonic()
                try:
                    run_id, ok, failed = self.run_once()
                    LOG.info(
                        "run complete run_id=%s ok=%d failed=%d", run_id, ok, failed
                    )
                except Exception:
                    LOG.exception("run failed")
                next_scan = t0 + effective
            else:
                self._heartbeat("paused" if paused else "running", effective)

            # Short poll-sleep (still backed by shutdown_event so SIGINT/SIGTERM
            # stay responsive within one poll interval).
            self.shutdown_event.wait(timeout=self._CONTROL_POLL_SECONDS)
