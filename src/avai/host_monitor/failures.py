"""The errors a monitor component can expect from the work it drives."""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError

# Tool and command errors (OSError, CommandFailedError), LLM call errors
# (CompletionError), parse errors on bad output, and database errors. A
# component that must keep running (a cycle, a stream, the control loop)
# records one of these and moves on; anything else is a bug and propagates.
HOST_FAILURES = (
    OSError,
    RuntimeError,
    ValueError,
    LookupError,
    TypeError,
    AttributeError,
    SQLAlchemyError,
)
