from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

EnumT = TypeVar("EnumT", bound=Enum)


class Coerce:
    """Coerce values into JSON-/enum-safe forms."""

    def jsonable(self, raw: Any) -> Any:
        """Recursively convert an object into something ``json.dumps`` can
        handle: bytes → hex, datetime → isoformat, dict keys → str."""
        if isinstance(raw, dict):
            return {str(key): self.jsonable(item) for key, item in raw.items()}
        if isinstance(raw, (list, tuple)):
            return [self.jsonable(item) for item in raw]
        if isinstance(raw, bytes):
            return raw.hex()
        if isinstance(raw, datetime):
            return raw.isoformat()
        return raw

    def enum(self, raw: object, enum_cls: type[EnumT], default: EnumT) -> EnumT:
        """Best-effort coercion of *raw* into *enum_cls*, falling back to
        *default* on an unknown/invalid value."""
        try:
            return enum_cls(raw)
        except (ValueError, TypeError):
            return default
