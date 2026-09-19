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
import os

from . import __version__

# Bundled so reporting works for every install without setup. Override via
# SENTRY_DSN; disable via AVAI_TELEMETRY=0 or an empty SENTRY_DSN.
_DEFAULT_DSN = (
    "https://169b79dede851f0b9c7674fba38487d8"
    "@o4505128597127168.ingest.us.sentry.io/4511593453518848"
)

_DSN_ENV = "SENTRY_DSN"
_TELEMETRY_ENV = "AVAI_TELEMETRY"
# Values that turn the AVAI_TELEMETRY toggle off; unset means on.
_FALSY = frozenset({"", "0", "false", "no", "off"})


def _resolve_dsn() -> str | None:
    """The DSN to report to, or None when the operator has opted out."""
    toggle = os.environ.get(_TELEMETRY_ENV)
    if toggle is not None and toggle.strip().lower() in _FALSY:
        return None
    dsn = os.environ.get(_DSN_ENV, _DEFAULT_DSN)
    return dsn or None


def init_sentry() -> bool:
    """Initialize Sentry unless the operator opted out. Returns whether it did.

    Safe to call once at process startup; a no-op when reporting is disabled.
    """
    dsn = _resolve_dsn()
    if not dsn:
        return False

    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_sdk.init(
        dsn=dsn,
        release=f"avai@{__version__}",
        send_default_pii=False,
        # event_level=WARNING promotes LOG.warning (the tolerated monitor-loop
        # degradations) to issues, on top of the default ERROR-and-above.
        integrations=[LoggingIntegration(event_level=logging.WARNING)],
    )
    return True
