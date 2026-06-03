"""Orchestrator: drives collectors against the sink each cycle."""
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Optional

from .enums import Verdict
from .constants import DEFAULT_BASELINE_MIN_RUNS, LOG, _CORRELATED_COLLECTOR
from .runtime import Clock, Digest
from .risk import compute_risk_score
from .judge import Judge
from .narrator import IncidentNarrator
from .sink import Sink
from .collectors import Collector, SnapshotCollector, StreamingCollector
from .streaming import StreamingWorker


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
        self._streaming_workers: list[StreamingWorker] = []
        self.shutdown_event = threading.Event()
        # Optional threat-intel enrichment between collection and judging.
        # None ⇒ disabled (no API calls, no schema rows). Lazily imported
        # so the enrichers package's `requests` dep is only needed when
        # enrichment is on.
        self._enrichment_chain = enrichment_chain

    def request_shutdown(self) -> None:
        """Idempotent — safe to call from a signal handler."""
        self.shutdown_event.set()

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
        run_id, started = self.sink.start_run(socket.gethostname(), self.lookback_min)
        # Snapshot the host's baseline state once: it can't change mid-cycle
        # (the current run isn't completed yet), and every collector shares
        # the same cutoff.
        host_baseline = self._host_baseline()
        ok = failed = 0
        for c in self.snapshot_collectors:
            # Honour a shutdown request mid-cycle. The first cycle judges
            # every collector via the LLM, which can take minutes; without
            # this check Ctrl-C wouldn't take effect until the whole cycle
            # finished (the loop is the long pole, not run_forever).
            if self.shutdown_event.is_set():
                LOG.info("shutdown requested — stopping collector loop early")
                break
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
        for entry in unjudged:
            seen = fs_map.get(entry.get("content_hash"))
            if seen is None:
                continue
            first_seen, times_seen = seen
            novel = bool(established and cutoff is not None and first_seen > cutoff)
            entry["baseline"] = {
                "first_seen": first_seen,
                "times_seen": times_seen,
                "host_runs": host_baseline["total_runs"],
                "baseline_established": established,
                "novel": novel,
            }

    def _attach_correlation(
        self, c: Collector, unjudged: list[dict], rows: list[dict], run_id: str
    ) -> None:
        """Attach a ``related`` object to each ``processes`` entry in-place:
        the process's listening ports, outbound flows, remote connections,
        DNS queries and exec lineage, correlated by PID (DNS by process
        name). This lets the judge score the process *with its behaviour*
        instead of in isolation — a novel binary that is also beaconing to
        a flagged IP is a far stronger signal than either row alone.

        Only the ``processes`` collector is correlated; flows/DNS keep their
        own independent verdicts. The unjudged projection has no PID (its
        content_hash is over name/exe/cmdline/username), so we map
        content_hash → PIDs/names via the full ``rows``, exactly as
        ``_enrich_entries`` maps evidence."""
        if c.name != _CORRELATED_COLLECTOR or not unjudged:
            return
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
        all_pids = sorted({p for s in pids_by_hash.values() for p in s})
        all_names = sorted({n for s in names_by_hash.values() for n in s})
        try:
            since = self.sink.prior_run_started_at(run_id)
            ctx = self.sink.correlation_context(all_pids, all_names, since)
        except Exception as exc:
            LOG.warning("correlation: context(%s) failed: %s", c.name, exc)
            return
        for entry in unjudged:
            h = entry.get("content_hash")
            pids = pids_by_hash.get(h, set())
            names = names_by_hash.get(h, set())
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
            if related:
                entry["related"] = related

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
            if unjudged:
                enriched_indicators = self._enrich_entries(c, unjudged, rows)
                self._annotate_baseline(c, unjudged, host_baseline)
                self._attach_correlation(c, unjudged, rows, run_id)
                judgments = self.judge.judge(c.name, c.judge_hints, unjudged)
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
        if chain is None:
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
        for c in self.streaming_collectors:
            if not (c.judge_enabled and c.judge_fields):
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
                judgments = self.judge.judge(c.name, c.judge_hints, unjudged)
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

    def run_forever(self, interval: int) -> None:
        while not self.shutdown_event.is_set():
            t0 = time.monotonic()
            try:
                run_id, ok, failed = self.run_once()
                LOG.info("run complete run_id=%s ok=%d failed=%d", run_id, ok, failed)
            except Exception:
                LOG.exception("run failed")
            sleep_for = max(0.0, interval - (time.monotonic() - t0))
            LOG.info("sleeping %.1fs", sleep_for)
            # Event-driven sleep: returns immediately when shutdown is
            # requested, without depending on signal-interrupting time.sleep
            # (which is unreliable when other threads exist).
            self.shutdown_event.wait(timeout=sleep_for)
