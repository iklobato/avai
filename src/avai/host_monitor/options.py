"""The ``avai monitor`` options, checked once where they come in."""

from __future__ import annotations

import argparse

from pydantic import BaseModel, ConfigDict, field_validator

MIN_BASELINE_RUNS = 1


class MonitorOptions(BaseModel):
    """Every ``avai monitor`` flag, typed. Built from the parsed command line
    by :meth:`from_namespace`; the rest of the monitor reads only this."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    db: str
    once: bool
    interval: int
    lookback_min: int
    no_judge: bool
    judge_model: str
    judge_batch_size: int
    judge_max_per_collector: int
    prompts_file: str
    baseline_runs: int
    no_narrative: bool
    narrative_model: str
    no_coverage: bool
    no_verify: bool
    no_investigate: bool
    no_streaming: bool
    max_db_mb: int
    no_enrich: bool
    enrich_only: tuple[str, ...] | None
    verbose: bool

    @classmethod
    def from_namespace(cls, parsed: argparse.Namespace) -> MonitorOptions:
        return cls.model_validate(vars(parsed))

    @field_validator("max_db_mb")
    @classmethod
    def _no_negative_cap(cls, value: int) -> int:
        """A negative cap means "no cap", the same as 0."""
        return max(0, value)

    @field_validator("baseline_runs")
    @classmethod
    def _at_least_one_run(cls, value: int) -> int:
        """The baseline needs at least one completed run."""
        return max(MIN_BASELINE_RUNS, value)
