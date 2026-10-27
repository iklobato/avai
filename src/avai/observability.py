"""Sentry error reporting, enabled by default so failures users hit in the
wild are visible centrally.

Reporting is ON out of the box via a bundled DSN. A Sentry DSN is a public,
client-side identifier (it ships inside released apps by design), not a
secret. Users can point it elsewhere with ``SENTRY_DSN`` (the variable the
Sentry SDK reads natively) or turn reporting off with ``AVAI_TELEMETRY=0``
(matching avai's ``AVAI_*`` toggle convention) or an empty ``SENTRY_DSN``.

Coverage is intentionally broad: unhandled exceptions (main thread and the
monitor's worker threads) are captured by the SDK automatically, and the
logging integration is configured so ``LOG.warning`` and above become Sentry
issues — that includes both the hard ``LOG.exception`` failures and the
tolerated per-step degradations in the monitor loop. PII (request headers,
client IP) is left off because avai handles sensitive host-security telemetry.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration

from . import __version__

# Values that turn the AVAI_TELEMETRY toggle off; unset means on.
TELEMETRY_OFF_VALUES = frozenset({"", "0", "false", "no", "off"})


class SentryReporting:
    """Starts Sentry for this process unless the operator opted out."""

    # Bundled so reporting works for every install without setup. Override via
    # SENTRY_DSN; disable via AVAI_TELEMETRY=0 or an empty SENTRY_DSN.
    DEFAULT_DSN = (
        "https://169b79dede851f0b9c7674fba38487d8"
        "@o4505128597127168.ingest.us.sentry.io/4511593453518848"
    )
    DSN_ENV = "SENTRY_DSN"
    TELEMETRY_ENV = "AVAI_TELEMETRY"

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ

    def dsn(self) -> str | None:
        """The DSN to report to, or None when the operator has opted out."""
        toggle = self._environ.get(self.TELEMETRY_ENV)
        if toggle is not None and toggle.strip().lower() in TELEMETRY_OFF_VALUES:
            return None
        return self._environ.get(self.DSN_ENV, self.DEFAULT_DSN) or None

    def init(self) -> bool:
        """Initialize Sentry unless the operator opted out. Returns whether it
        did. Safe to call once at process startup."""
        dsn = self.dsn()
        if not dsn:
            return False
        sentry_sdk.init(
            dsn=dsn,
            release=f"avai@{__version__}",
            send_default_pii=False,
            # event_level=WARNING promotes LOG.warning (the tolerated
            # monitor-loop degradations) to issues, on top of ERROR-and-above.
            integrations=[LoggingIntegration(event_level=logging.WARNING)],
        )
        return True
