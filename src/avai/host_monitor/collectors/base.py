"""The collector contract: snapshot and streaming collectors and the slice
they fill."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import ClassVar, Iterable

from .. import slices
from ..models import _RowBase


class Collector(ABC):
    """Common base for any host-state collector. Subclass
    :class:`SnapshotCollector` (pull, per-cycle) or
    :class:`StreamingCollector` (push, long-lived) — not this directly.

    Free-form text used to steer the LLM judge is injected per-instance
    via ``judge_hints`` (sourced from the external prompts TOML file).
    """

    slice: ClassVar[slices.Slice]
    judge_enabled: ClassVar[bool] = True
    judge_fields: ClassVar[tuple[str, ...]] = ()

    def __init__(self, judge_hints: str = ""):
        self.judge_hints = judge_hints

    @property
    def name(self) -> str:
        return self.slice.name

    @property
    def model(self) -> type[_RowBase]:
        return self.slice.model

    @property
    def table(self) -> str:
        return self.model.__tablename__


class SnapshotCollector(Collector):
    """Pull model — the Runner calls :meth:`collect` once per cycle and
    materializes the result as a batch insert."""

    @abstractmethod
    def collect(self) -> Iterable[dict]:
        """Yield row dicts for ``self.model``.

        ``run_id``, ``collected_at`` and ``content_hash`` are injected
        by the Runner — do not include them here.
        """


class StreamingCollector(Collector):
    """Push model — the Runner starts :meth:`stream` once in a dedicated
    worker thread; the iterator yields rows as events arrive and only
    stops when ``stop_event`` is set or the stream ends.

    Streaming sources are time-series events (not state), so the default
    ``judge_enabled`` is ``False``; aggregate analysis is the right tool.
    """

    judge_enabled: ClassVar[bool] = False

    @abstractmethod
    def stream(self, stop_event: threading.Event) -> Iterable[dict]:
        """Yield row dicts continuously until ``stop_event`` is set.

        Implementations are responsible for terminating their underlying
        data source (subprocess, socket, filesystem watcher) when the
        event fires.
        """
