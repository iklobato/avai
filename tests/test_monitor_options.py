"""MonitorOptions: the parsed ``avai monitor`` flags, checked at the edge."""

from __future__ import annotations

import argparse

import pytest
from pydantic import ValidationError

from avai.host_monitor.constants import DEFAULT_BASELINE_MIN_RUNS, DEFAULT_INTERVAL
from avai.host_monitor.main import DEFAULT_MAX_DB_MB, MonitorArgs
from avai.host_monitor.options import MonitorOptions


class TestMonitorOptions:
    def test_bare_command_gives_the_documented_defaults(self) -> None:
        options = MonitorArgs().options([])

        assert (options.interval, options.max_db_mb, options.baseline_runs) == (
            DEFAULT_INTERVAL,
            DEFAULT_MAX_DB_MB,
            DEFAULT_BASELINE_MIN_RUNS,
        )
        assert options.enrich_only is None
        assert options.once is False

    def test_negative_db_cap_means_no_cap(self) -> None:
        options = MonitorArgs().options(["--max-db-mb", "-5"])

        assert options.max_db_mb == 0

    def test_baseline_needs_at_least_one_run(self) -> None:
        options = MonitorArgs().options(["--baseline-runs", "0"])

        assert options.baseline_runs == 1

    def test_repeated_enrich_only_is_kept_in_order(self) -> None:
        options = MonitorArgs().options(
            ["--enrich-only", "osv", "--enrich-only", "nvd"]
        )

        assert options.enrich_only == ("osv", "nvd")

    def test_narrative_model_follows_the_judge_model(self) -> None:
        # Only an OpenAI key set: the coverage and narrative stages must not
        # fall back to a Claude model the key cannot call.
        options = MonitorArgs().options(["--judge-model", "gpt-4o-mini"])

        assert options.narrative_model == "gpt-4o-mini"

    def test_an_explicit_narrative_model_wins(self) -> None:
        options = MonitorArgs().options(
            ["--judge-model", "gpt-4o-mini", "--narrative-model", "gpt-4o"]
        )

        assert (options.judge_model, options.narrative_model) == (
            "gpt-4o-mini",
            "gpt-4o",
        )

    def test_an_unknown_field_is_rejected(self) -> None:
        parsed = MonitorArgs().parser().parse_args([])
        parsed.surprise = True

        with pytest.raises(ValidationError) as excinfo:
            MonitorOptions.from_namespace(parsed)

        assert excinfo.value.errors()[0]["loc"] == ("surprise",)
        assert excinfo.value.errors()[0]["type"] == "extra_forbidden"

    def test_options_are_read_only(self) -> None:
        options = MonitorOptions.from_namespace(MonitorArgs().parser().parse_args([]))

        with pytest.raises(ValidationError):
            options.interval = DEFAULT_INTERVAL + 1  # type: ignore[misc]  # frozen

    def test_a_wrong_type_is_rejected(self) -> None:
        parsed = argparse.Namespace(**vars(MonitorArgs().parser().parse_args([])))
        parsed.interval = "soon"

        with pytest.raises(ValidationError) as excinfo:
            MonitorOptions.from_namespace(parsed)

        assert excinfo.value.errors()[0]["loc"] == ("interval",)
