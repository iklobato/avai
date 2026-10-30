"""What the monitor runs with, written to the control row at every start so
the dashboard's Setup panel can tell the person what is on and what is
missing. Only names are stored: never a key, token or other secret value."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass

from avai.enrichers.chain import EnrichmentChain
from avai.enrichers.registry import EnricherCatalog
from avai.observability import SentryReporting

ROOT_UID = 0


@dataclass(frozen=True)
class SourceGap:
    """A threat-intel source that stayed off because its key is not set."""

    name: str
    key: str


@dataclass(frozen=True)
class MonitorCapabilities:
    judge_model: str | None
    verify: bool
    investigate: bool
    sources_on: tuple[str, ...]
    sources_missing_key: tuple[SourceGap, ...]
    as_root: bool
    telemetry_on: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class RootCheck:
    def is_root(self) -> bool:
        # Windows has no geteuid; there the question does not apply.
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == ROOT_UID)


class SourceCoverage:
    """Which catalog sources are on, and which need a key to turn on."""

    def __init__(self, catalog: EnricherCatalog) -> None:
        self._catalog = catalog

    def on(self, chain: EnrichmentChain | None) -> tuple[str, ...]:
        return tuple(chain.sources) if chain else ()

    def missing_key(self, chain: EnrichmentChain | None) -> tuple[SourceGap, ...]:
        running = set(self.on(chain))
        return tuple(
            SourceGap(source.name, source.requires_token)
            for source in self._catalog.classes()
            if source.requires_token and source.name not in running
        )


@dataclass(frozen=True)
class StageFlags:
    """Which LLM stages the monitor built at start."""

    judge_model: str | None
    verify: bool
    investigate: bool


class CapabilitiesProbe:
    def __init__(self, coverage: SourceCoverage, environ: Mapping[str, str]) -> None:
        self._coverage = coverage
        self._environ = environ

    def probe(
        self, stages: StageFlags, chain: EnrichmentChain | None
    ) -> MonitorCapabilities:
        return MonitorCapabilities(
            judge_model=stages.judge_model,
            verify=stages.verify,
            investigate=stages.investigate,
            sources_on=self._coverage.on(chain),
            sources_missing_key=self._coverage.missing_key(chain),
            as_root=RootCheck().is_root(),
            telemetry_on=SentryReporting(self._environ).dsn() is not None,
        )
