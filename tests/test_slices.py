"""The slice catalog is the one place a telemetry table is named.

These tests keep every other table keyed by slice name (collectors, prompt
hints, enrichment extractors) in step with it.
"""

from __future__ import annotations

from collections import Counter

from avai.enrichers.indicators import EXTRACTORS
from avai.host_monitor import (
    collectors,
    exposure_collectors,
    net_collectors,
    persistence_collectors,
    slices,
)
from avai.host_monitor.collectors import Collector, StreamingCollector
from avai.host_monitor.constants import DEFAULT_PROMPTS_PATH
from avai.host_monitor.hosts import windows
from avai.host_monitor.models import _RowBase
from avai.host_monitor.prompts import Prompts

_COLLECTOR_MODULES = (
    collectors,
    net_collectors,
    exposure_collectors,
    persistence_collectors,
    windows,
)
SLICE_NAMES = {s.name for s in slices.ALL}


def _collector_classes() -> set[type[Collector]]:
    return {
        value
        for module in _COLLECTOR_MODULES
        for value in vars(module).values()
        if isinstance(value, type)
        and issubclass(value, Collector)
        and "slice" in vars(value)
    }


def _row_models() -> set[type[_RowBase]]:
    found, stack = set(), [_RowBase]
    while stack:
        for sub in stack.pop().__subclasses__():
            found.add(sub)
            stack.append(sub)
    return found


def test_every_row_model_has_exactly_one_slice():
    per_model = Counter(s.model for s in slices.ALL)

    assert set(per_model) == _row_models()
    assert max(per_model.values()) == 1
    assert len(SLICE_NAMES) == len(slices.ALL)


def test_every_slice_is_written_by_a_collector_and_only_catalogued_ones():
    written = {cls.slice for cls in _collector_classes()}

    assert written == set(slices.ALL)


def test_streaming_flag_matches_the_collector_kind():
    mismatched = [
        cls.__name__
        for cls in _collector_classes()
        if cls.slice.streaming != issubclass(cls, StreamingCollector)
    ]

    assert mismatched == []


def test_every_judged_collector_has_a_prompt_hint():
    hints = Prompts.load(DEFAULT_PROMPTS_PATH).collector_hints
    unhinted = sorted(
        cls.slice.name
        for cls in _collector_classes()
        if cls.judge_enabled and cls.judge_fields and cls.slice.name not in hints
    )

    assert unhinted == []
    assert set(hints) <= SLICE_NAMES


def test_extractor_keys_are_catalogued_slices():
    assert set(EXTRACTORS) <= SLICE_NAMES
