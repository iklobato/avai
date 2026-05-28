"""Concrete enrichers. Each module owns one external source.

The :mod:`avai.enrichers.registry` discovers everything in this package
at runtime — no manual list to maintain. Adding a source means dropping
a new module next to these and inheriting from :class:`Enricher`.
"""
