"""Cross-cutting integration tests.

These exercise the seams *between* components where the high-value
bugs hide — places where a unit test on either side would pass but
the contract between them could silently break:

  1. Enrichment evidence actually reaching the LLM prompt (the entire
     point of the enrichment feature).
  2. content_hash stability across dict insertion order (dedup
     correctness depends on it).
  3. A judged finding flowing end-to-end into the dashboard's findings
     query + verdict chart, with the active/resolved + filter logic.
  4. VirusTotal indicator → API path mapping (real encoding logic).
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.host_monitor import (
    CollectionRun,
    Judgment,
    LlmJudge,
    Prompts,
    Sink,
    ThreatCategory,
    Verdict,
    content_hash,
    utcnow,
)


# ===========================================================================
# 1. Enrichment evidence must reach the LLM prompt
# ===========================================================================

class _CapturingClient:
    """Captures the `user` prompt the judge sends; returns no judgments."""
    def __init__(self):
        self.user_prompts: list[str] = []

    def complete_structured(self, *, user, **kw):
        self.user_prompts.append(user)
        return {"judgments": []}


@pytest.fixture
def judge_prompts():
    return Prompts(
        system="analyst",
        user_template="Source: $collector\nHints: $hints\nEntries:\n$entries",
        collector_hints={},
    )


class TestEvidenceReachesPrompt:
    """The enrichment layer is worthless if the evidence it gathers
    never makes it into the prompt the model sees. The Runner attaches
    an ``evidence`` key to each entry; the judge must serialise it into
    the user message verbatim."""

    def test_evidence_field_is_serialised_into_user_prompt(self, judge_prompts):
        client = _CapturingClient()
        judge = LlmJudge(prompts=judge_prompts, model="m",
                         batch_size=20, max_per_collector=0, client=client)
        entry = {
            "content_hash": "a" * 64,
            "name": "suspicious.bin",
            "evidence": [
                {"src": "virustotal", "hint": "malicious",
                 "confidence": 0.95, "note": "38/72 engines flagged"},
                {"src": "malware_bazaar", "hint": "malicious",
                 "confidence": 0.95, "note": "family=AsyncRAT"},
            ],
        }
        judge.judge("processes", "hint", [entry])

        assert len(client.user_prompts) == 1
        prompt = client.user_prompts[0]
        # The model must see both the source names and the human notes.
        assert "virustotal" in prompt
        assert "malware_bazaar" in prompt
        assert "38/72 engines flagged" in prompt
        assert "family=AsyncRAT" in prompt

    def test_content_hash_is_stripped_from_prompt(self, judge_prompts):
        # content_hash is internal plumbing — sending it to the model
        # wastes tokens and could bias it. _call must drop it.
        client = _CapturingClient()
        judge = LlmJudge(prompts=judge_prompts, model="m",
                         batch_size=20, max_per_collector=0, client=client)
        judge.judge("processes", "h",
                    [{"content_hash": "deadbeef" * 8, "name": "x"}])
        assert "deadbeef" not in client.user_prompts[0]

    def test_none_valued_fields_are_omitted_from_prompt(self, judge_prompts):
        client = _CapturingClient()
        judge = LlmJudge(prompts=judge_prompts, model="m",
                         batch_size=20, max_per_collector=0, client=client)
        judge.judge("processes", "h",
                    [{"content_hash": "a", "name": "x", "exe": None}])
        # The null exe should not appear as `"exe": null` noise.
        assert '"exe"' not in client.user_prompts[0]

    def test_index_is_injected_for_result_mapping(self, judge_prompts):
        # The model maps results back by integer index; every entry in
        # the payload must carry one.
        client = _CapturingClient()
        judge = LlmJudge(prompts=judge_prompts, model="m",
                         batch_size=20, max_per_collector=0, client=client)
        judge.judge("processes", "h",
                    [{"content_hash": "a", "name": "x"},
                     {"content_hash": "b", "name": "y"}])
        payload = json.loads(
            client.user_prompts[0].split("Entries:\n", 1)[1])
        assert [item["index"] for item in payload] == [0, 1]


# ===========================================================================
# 2. content_hash stability — dedup correctness depends on this
# ===========================================================================

class TestContentHashStability:
    def test_insertion_order_does_not_change_hash(self):
        # The same logical row built with keys in a different order must
        # hash identically — otherwise the same artifact dedups as two,
        # and the judge re-bills it every cycle.
        a = content_hash({"name": "x", "exe": "/bin/x", "user": "root"},
                         ["name", "exe", "user"])
        b = content_hash({"user": "root", "exe": "/bin/x", "name": "x"},
                         ["name", "exe", "user"])
        assert a == b

    def test_field_subset_order_in_judge_fields_matters(self):
        # The judge_fields tuple defines the canonical order. Reordering
        # *it* is a deliberate schema change and SHOULD change the hash
        # (documents that judge_fields order is part of the contract).
        a = content_hash({"a": 1, "b": 2}, ["a", "b"])
        b = content_hash({"a": 1, "b": 2}, ["b", "a"])
        assert a != b

    def test_extra_unjudged_keys_do_not_affect_hash(self):
        base = content_hash({"name": "x"}, ["name"])
        noisy = content_hash({"name": "x", "pid": 4321, "cpu": 0.5}, ["name"])
        assert base == noisy


# ===========================================================================
# 3. A judged finding flows into the dashboard end-to-end
# ===========================================================================

@pytest.fixture
def seeded_dashboard(tmp_path):
    """A dashboard bound to a DB containing one active malicious finding
    and one benign one, with a latest run so active/resolved resolves."""
    from avai.dashboard import app, _ensure_db_exists

    db = tmp_path / "seeded.db"
    _ensure_db_exists(str(db))
    engine = create_engine(f"sqlite:///{db}")
    sink = Sink(engine)
    sink.setup()

    run_id, started = sink.start_run("host", 5)
    sink.end_run(ok=1, failed=0)

    # One malicious (active), one benign — both seen this run.
    for h, verdict, cat, reason in [
        ("m" * 64, Verdict.MALICIOUS, ThreatCategory.PERSISTENCE,
         "launchagent drops from /tmp"),
        ("b" * 64, Verdict.BENIGN, ThreatCategory.NONE, "signed apple binary"),
    ]:
        sink.write_judgments([Judgment(
            content_hash=h, collector="launch_items",
            verdict=verdict, category=cat, confidence=0.9,
            reasoning=reason, remediation="x", model="m",
            created_at=started,
        )])
        sink.touch_judgments("launch_items", [h], started)

    # The dashboard opens the DB with ``immutable=1``, which reads only
    # the main file and ignores the -wal. Committed-but-uncheckpointed
    # rows would be invisible. In production the long-running monitor
    # checkpoints continuously; here we force one so the read-only
    # dashboard sees the seeded rows. (This mirrors the real WAL
    # interaction documented in dashboard._engine.)
    from sqlalchemy import text
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    engine.dispose()

    app.config.update(TESTING=True, DB_PATH=str(db))
    with app.test_client() as c:
        yield c


class TestFindingFlowsToDashboard:
    def test_malicious_finding_appears_in_findings_fragment(self, seeded_dashboard):
        r = seeded_dashboard.get("/fragments/findings")
        assert r.status_code == 200
        html = r.data.decode()
        # The malicious finding's reasoning must render.
        assert "launchagent drops from /tmp" in html

    def test_benign_excluded_by_default(self, seeded_dashboard):
        r = seeded_dashboard.get("/fragments/findings")
        html = r.data.decode()
        # Default findings view excludes benign — the benign reasoning
        # must NOT be present.
        assert "signed apple binary" not in html

    def test_verdict_filter_narrows(self, seeded_dashboard):
        # Explicitly filtering to benign surfaces it.
        r = seeded_dashboard.get("/fragments/findings?verdict=benign")
        html = r.data.decode()
        assert "signed apple binary" in html
        assert "launchagent drops from /tmp" not in html

    def test_chart_counts_seeded_judgements(self, seeded_dashboard):
        r = seeded_dashboard.get("/api/chart/verdicts")
        body = r.get_json()
        # Both judgements were created in this hour → the datasets must
        # carry a non-zero count for malicious and benign somewhere.
        assert sum(body["datasets"]["malicious"]) == 1
        assert sum(body["datasets"]["benign"]) == 1

    def test_notifications_surface_malicious(self, seeded_dashboard):
        # since far in the past → the malicious judgement is "new".
        r = seeded_dashboard.get(
            "/api/notifications/new?since=2000-01-01T00:00:00+00:00")
        body = r.get_json()
        verdicts = {item["verdict"] for item in body["items"]}
        assert "malicious" in verdicts
        # benign must never raise a notification.
        assert "benign" not in verdicts


# ===========================================================================
# 4. VirusTotal indicator → API path mapping
# ===========================================================================

class TestVirusTotalPathMapping:
    def test_hash_maps_to_files_endpoint(self):
        from avai.enrichers.sources.virustotal import _path_for
        from avai.enrichers.base import Indicator, IndicatorType
        p = _path_for(Indicator(IndicatorType.SHA256, "a" * 64))
        assert p == "/files/" + "a" * 64

    def test_ip_maps_to_ip_addresses_endpoint(self):
        from avai.enrichers.sources.virustotal import _path_for
        from avai.enrichers.base import Indicator, IndicatorType
        p = _path_for(Indicator(IndicatorType.IPV4, "8.8.8.8"))
        assert p == "/ip_addresses/8.8.8.8"

    def test_domain_maps_to_domains_endpoint(self):
        from avai.enrichers.sources.virustotal import _path_for
        from avai.enrichers.base import Indicator, IndicatorType
        p = _path_for(Indicator(IndicatorType.DOMAIN, "evil.test"))
        assert p == "/domains/evil.test"

    def test_url_is_base64url_without_padding(self):
        # VT's URL endpoint ID is base64url(url) with '=' padding
        # stripped. A wrong encoding silently 404s every URL lookup.
        import base64
        from avai.enrichers.sources.virustotal import _path_for
        from avai.enrichers.base import Indicator, IndicatorType
        url = "https://evil.test/path?x=1"
        p = _path_for(Indicator(IndicatorType.URL, url))
        expected = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        assert p == f"/urls/{expected}"
        assert "=" not in p  # padding must be stripped
