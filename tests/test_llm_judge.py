"""Tests for ``LlmJudge`` — batch dispatch, structured-output parsing,
prompt template substitution, and graceful handling of malformed
model output.

The completion client is replaced by a fake that returns a canned
``parsed`` dict, so these tests are network- and provider-free.
"""

from __future__ import annotations

import pytest

from avai.host_monitor import LlmJudge, Prompts, ThreatCategory, Verdict


class _FakeClient:
    """Stand-in for CompletionClient. Records every call; returns a
    configured parsed dict (the framework normally receives this from
    JSON-mode or tool_use)."""

    def __init__(
        self, parsed=None, parsed_per_call=None, raise_exc: Exception | None = None
    ):
        self.calls: list[dict] = []
        self._parsed = parsed
        self._queue = list(parsed_per_call or [])
        self._raise = raise_exc

    def complete_structured(self, **kw):
        self.calls.append(kw)
        if self._raise is not None:
            raise self._raise
        if self._queue:
            return self._queue.pop(0)
        return self._parsed or {"judgments": []}


@pytest.fixture
def prompts():
    return Prompts(
        system="you are an analyst — verdicts: $verdicts",
        user_template="Source: $collector\nHints: $hints\nEntries:\n$entries",
        collector_hints={},
    )


def _judge(prompts, client=None, **kwargs):
    """Build an LlmJudge wired to ``client`` — no real LLM, no network."""
    return LlmJudge(
        prompts=prompts,
        model="test-model",
        batch_size=20,
        max_per_collector=0,  # no cap
        client=client or _FakeClient(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_returns_judgments_for_each_index(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "malicious",
                        "category": "persistence",
                        "confidence": 0.9,
                        "reasoning": "bad",
                        "remediation": "remove it",
                    },
                    {
                        "index": 1,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 0.99,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge(
            "processes",
            "h",
            [{"content_hash": "a", "name": "x"}, {"content_hash": "b", "name": "y"}],
        )
        assert len(result) == 2
        assert {j.verdict for j in result} == {Verdict.MALICIOUS, Verdict.BENIGN}
        # Mapping by index → content_hash preserved.
        by_h = {j.content_hash: j for j in result}
        assert by_h["a"].verdict is Verdict.MALICIOUS
        assert by_h["b"].verdict is Verdict.BENIGN

    def test_empty_input_returns_empty_without_calling_llm(self, prompts):
        client = _FakeClient()
        judge = _judge(prompts, client)
        assert judge.judge("processes", "", []) == []
        assert client.calls == []

    def test_call_cost_attributed_evenly_across_batch(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 0.9,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                    {
                        "index": 1,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 0.9,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )
        # default tier ($1/M in, $5/M out): 1000 in ($0.001) + 200 out
        # ($0.001) = $0.002, split across 2 entries → $0.001 each.
        client.last_usage = {"input": 1000, "output": 200}
        judge = _judge(prompts, client)  # model "test-model" → default tier
        result = judge.judge(
            "processes", "", [{"content_hash": "a"}, {"content_hash": "b"}]
        )
        assert all(j.cost_usd == pytest.approx(0.001) for j in result)

    def test_cost_zero_when_usage_unavailable(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 0.9,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )  # _FakeClient never sets last_usage
        judge = _judge(prompts, client)
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert result[0].cost_usd == 0.0

    def test_user_template_is_substituted(self, prompts):
        client = _FakeClient()
        judge = _judge(prompts, client)
        judge.judge("processes", "be careful", [{"content_hash": "a", "name": "x"}])
        user_text = client.calls[0]["user"]
        assert "Source: processes" in user_text
        assert "Hints: be careful" in user_text
        # entries should be JSON-serialised.
        assert '"name": "x"' in user_text or '"name":"x"' in user_text


# ---------------------------------------------------------------------------
# Defensive parsing — malformed model output must not crash
# ---------------------------------------------------------------------------


class TestParsingDefensiveness:
    def test_missing_judgments_key_returns_empty(self, prompts):
        client = _FakeClient(parsed={})  # no 'judgments'
        judge = _judge(prompts, client)
        assert judge.judge("processes", "", [{"content_hash": "a"}]) == []

    def test_judgment_index_out_of_range_is_skipped(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 5,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.0,
                        "reasoning": "x",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        # Only one entry → index 5 is invalid; nothing produced.
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert result == []

    def test_judgment_index_negative_is_skipped(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": -1,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.0,
                        "reasoning": "x",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        assert judge.judge("processes", "", [{"content_hash": "a"}]) == []

    def test_judgment_with_non_integer_index_is_skipped(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": "0",
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.0,
                        "reasoning": "x",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        assert judge.judge("processes", "", [{"content_hash": "a"}]) == []

    def test_invalid_verdict_value_falls_back_to_unknown(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "spicy",
                        "category": "none",
                        "confidence": 0.5,
                        "reasoning": "?",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert result[0].verdict is Verdict.UNKNOWN

    def test_invalid_category_value_falls_back_to_none(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "fake-cat",
                        "confidence": 1.0,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert result[0].category is ThreatCategory.NONE

    def test_non_numeric_confidence_defaults_to_zero(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": "high",
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert result[0].confidence == 0.0

    def test_confidence_is_clamped_to_zero_one(self, prompts):
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.5,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                    {
                        "index": 1,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": -0.5,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge(
            "processes", "", [{"content_hash": "a"}, {"content_hash": "b"}]
        )
        assert result[0].confidence == 1.0
        assert result[1].confidence == 0.0

    def test_reasoning_is_truncated_to_500_chars(self, prompts):
        long = "x" * 1000
        client = _FakeClient(
            parsed={
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.0,
                        "reasoning": long,
                        "remediation": "",
                    },
                ]
            }
        )
        judge = _judge(prompts, client)
        result = judge.judge("processes", "", [{"content_hash": "a"}])
        assert len(result[0].reasoning) == 500


# ---------------------------------------------------------------------------
# Batching + per-collector cap
# ---------------------------------------------------------------------------


class TestBatching:
    def test_splits_into_batches_of_batch_size(self, prompts):
        client = _FakeClient(parsed={"judgments": []})
        judge = LlmJudge(
            prompts=prompts, model="m", batch_size=3, max_per_collector=0, client=client
        )
        entries = [{"content_hash": f"h{i}", "name": str(i)} for i in range(10)]
        judge.judge("processes", "", entries)
        # 10 items / 3 batch size → 4 calls (3+3+3+1).
        assert len(client.calls) == 4

    def test_caps_entries_to_max_per_collector(self, prompts):
        client = _FakeClient(parsed={"judgments": []})
        judge = LlmJudge(
            prompts=prompts,
            model="m",
            batch_size=20,
            max_per_collector=3,
            client=client,
        )
        entries = [{"content_hash": f"h{i}"} for i in range(10)]
        judge.judge("processes", "", entries)
        # All 3 capped entries fit in one batch.
        assert len(client.calls) == 1


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    def test_one_failing_batch_does_not_abort_later_batches(self, prompts):
        # First call raises, second returns one judgment. The judge
        # must keep going past the first failure.
        results_per_call = [
            Exception("boom"),
            {
                "judgments": [
                    {
                        "index": 0,
                        "verdict": "benign",
                        "category": "none",
                        "confidence": 1.0,
                        "reasoning": "ok",
                        "remediation": "",
                    },
                ]
            },
        ]
        calls_made: list[dict] = []

        def fake_complete(**kw):
            calls_made.append(kw)
            r = results_per_call.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        client = type("C", (), {"complete_structured": staticmethod(fake_complete)})()
        judge = LlmJudge(
            prompts=prompts, model="m", batch_size=1, max_per_collector=0, client=client
        )
        entries = [{"content_hash": "a"}, {"content_hash": "b"}]
        result = judge.judge("processes", "", entries)
        # Two batches dispatched.
        assert len(calls_made) == 2
        # One produced a judgment.
        assert len(result) == 1
        assert result[0].content_hash == "b"
