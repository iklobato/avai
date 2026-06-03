"""Data-coercion helpers used at the storage / serialization boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Any


class Coerce:
    """Coerce values into JSON-/enum-safe forms."""

    @staticmethod
    def jsonable(obj: Any) -> Any:
        """Recursively convert an object into something ``json.dumps`` can
        handle: bytes → hex, datetime → isoformat, dict keys → str."""
        if isinstance(obj, dict):
            return {str(k): Coerce.jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [Coerce.jsonable(v) for v in obj]
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    @staticmethod
    def enum(value: Any, enum_cls, default):
        """Best-effort coercion of *value* into *enum_cls*, falling back to
        *default* on an unknown/invalid value."""
        try:
            return enum_cls(value)
        except (ValueError, TypeError):
            return default
