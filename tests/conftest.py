"""Shared pytest fixtures.

Error reporting is on by default in production (see avai.observability), which
means any test that drives the CLI or the monitor would otherwise initialize
the real bundled Sentry DSN and send events over the network. Disable
telemetry for the whole suite so tests stay offline and deterministic. Tests
that exercise the reporting path itself manage AVAI_TELEMETRY explicitly and
patch sentry_sdk.init, so they are unaffected.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_telemetry(monkeypatch):
    monkeypatch.setenv("AVAI_TELEMETRY", "0")
