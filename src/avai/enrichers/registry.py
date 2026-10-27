"""Factory: build the default :class:`EnrichmentChain` from the
environment.

Walks every concrete :class:`Enricher` subclass under
``avai.enrichers.sources``, calls its ``create()`` factory, drops
any that return ``None`` (gate condition not met — usually a missing
API key), and constructs the chain with the surviving instances and
a single shared :class:`HttpClient`.

No source module is referenced by name here; new sources land by
dropping a file in ``sources/`` that subclasses :class:`Enricher`.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Mapping
from dataclasses import dataclass
from types import ModuleType

from avai.enrichers import sources
from avai.enrichers.base import Enricher
from avai.enrichers.cache import EvidenceCache
from avai.enrichers.chain import SOURCE_FAILURES, EnrichmentChain
from avai.enrichers.http import HttpClient


class EnricherCatalog:
    """Every concrete :class:`Enricher` subclass defined in a package.
    Order is alphabetical by module name → stable across runs."""

    def __init__(self, package: ModuleType, logger: logging.Logger) -> None:
        self._package = package
        self._logger = logger

    @classmethod
    def of_sources(cls, logger: logging.Logger) -> EnricherCatalog:
        return cls(sources, logger)

    def classes(self) -> list[type[Enricher]]:
        return [
            member
            for module in self._modules()
            for member in self._enrichers_in(module)
        ]

    def _modules(self) -> list[ModuleType]:
        modules: list[ModuleType] = []
        for module_info in pkgutil.iter_modules(self._package.__path__):
            name = f"{self._package.__name__}.{module_info.name}"
            try:
                modules.append(importlib.import_module(name))
            except ImportError as exc:
                self._logger.warning(
                    "enricher module %s failed to import: %s", module_info.name, exc
                )
        return modules

    def _enrichers_in(self, module: ModuleType) -> list[type[Enricher]]:
        return [
            member
            for _, member in inspect.getmembers(module, inspect.isclass)
            if issubclass(member, Enricher)
            and member is not Enricher
            and not inspect.isabstract(member)
            and member.__module__ == module.__name__
        ]


@dataclass(frozen=True)
class ChainRequest:
    """What to build the chain from: the environment that gates keyed
    sources, and an optional allow-list of enricher names (still subject
    to the env gate)."""

    env: Mapping[str, str]
    enable: frozenset[str] | None = None

    def allows(self, enricher_cls: type[Enricher]) -> bool:
        return self.enable is None or enricher_cls.name in self.enable


class ChainBuilder:
    """Builds an :class:`EnrichmentChain` with every enricher whose env
    gate is satisfied, all sharing one HTTP client."""

    def __init__(
        self, catalog: EnricherCatalog, http: HttpClient, logger: logging.Logger
    ) -> None:
        self._catalog = catalog
        self._http = http
        self._logger = logger

    def build(self, cache: EvidenceCache, request: ChainRequest) -> EnrichmentChain:
        enrichers = [
            enricher
            for enricher_cls in self._catalog.classes()
            if request.allows(enricher_cls)
            for enricher in [self._instantiate(enricher_cls, request.env)]
            if enricher is not None
        ]
        self._logger.info(
            "enrichment chain built with %d source(s): %s",
            len(enrichers),
            [enricher.name for enricher in enrichers],
        )
        return EnrichmentChain(enrichers, cache, self._logger)

    def _instantiate(
        self, enricher_cls: type[Enricher], env: Mapping[str, str]
    ) -> Enricher | None:
        try:
            enricher = enricher_cls.create(self._http, env)
        except SOURCE_FAILURES as exc:
            self._logger.warning(
                "enricher %s failed to initialise: %s", enricher_cls.name, exc
            )
            return None
        self._log_outcome(enricher_cls, enricher)
        return enricher

    def _log_outcome(
        self, enricher_cls: type[Enricher], enricher: Enricher | None
    ) -> None:
        if enricher is None:
            self._logger.info(
                "enricher disabled (token missing): %s (set $%s to enable)",
                enricher_cls.name,
                enricher_cls.requires_token,
            )
            return
        self._logger.info(
            "enricher enabled: %s (types=%s)",
            enricher_cls.name,
            sorted(str(kind) for kind in enricher_cls.supports_types),
        )
