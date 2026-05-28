"""Factory: build the default :class:`EnrichmentChain` from the
environment.

Walks every concrete :class:`Enricher` subclass under
``avai.enrichers.sources``, calls its ``from_env()`` factory, drops
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
from typing import Iterable

from sqlalchemy import Engine

from avai.enrichers.base import Enricher
from avai.enrichers.cache import EvidenceCache
from avai.enrichers.chain import EnrichmentChain
from avai.enrichers.http import HttpClient

LOG = logging.getLogger("avai.enrichers.registry")


def discover_enricher_classes() -> list[type[Enricher]]:
    """Walk ``avai.enrichers.sources`` and return every concrete
    :class:`Enricher` subclass found there. Order is alphabetical by
    module name → stable across runs."""
    import avai.enrichers.sources as pkg

    classes: list[type[Enricher]] = []
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        try:
            module = importlib.import_module(
                f"{pkg.__name__}.{mod_info.name}")
        except Exception as exc:  # noqa: BLE001
            LOG.warning("enricher module %s failed to import: %s",
                        mod_info.name, exc)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, Enricher)
                    and obj is not Enricher
                    and not inspect.isabstract(obj)
                    and obj.__module__ == module.__name__):
                classes.append(obj)
    return classes


def build_default_chain(engine: Engine, base_cls,
                        http: HttpClient | None = None,
                        *,
                        enable: Iterable[str] | None = None,
                        ) -> EnrichmentChain:
    """Build an :class:`EnrichmentChain` with every enricher whose
    env gate is satisfied.

    Parameters:
        engine: shared SQLAlchemy engine (same DB as the monitor).
        base_cls: SQLAlchemy ``DeclarativeBase`` from host_monitor.
        http: optional shared client; one is created if absent.
        enable: optional explicit allow-list of enricher names; if
            given, only those are registered (still subject to env gate).
    """
    cache = EvidenceCache(engine, base_cls)
    http_client = http or HttpClient()
    enrichers: list[Enricher] = []
    allow = set(enable) if enable is not None else None

    for cls in discover_enricher_classes():
        if allow is not None and cls.name not in allow:
            continue
        token = cls.env_token()
        if token is None:
            LOG.info("enricher disabled (token missing): %s "
                     "(set $%s to enable)", cls.name, cls.requires_token)
            continue
        try:
            # Prefer constructing with the shared HttpClient if the
            # subclass accepts one; fall back to its no-arg factory.
            sig = inspect.signature(cls.__init__)
            if "http" in sig.parameters:
                instance = cls(http=http_client)
            else:
                instance = cls.from_env()
        except Exception as exc:  # noqa: BLE001
            LOG.warning("enricher %s failed to initialise: %s", cls.name, exc)
            continue
        if instance is None:
            continue
        enrichers.append(instance)
        LOG.info("enricher enabled: %s (types=%s)",
                 cls.name, sorted(str(t) for t in cls.supports_types))

    LOG.info("enrichment chain built with %d source(s): %s",
             len(enrichers), [e.name for e in enrichers])
    return EnrichmentChain(enrichers, cache)
