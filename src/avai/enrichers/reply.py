"""Base for the JSON objects threat-intel sources get back."""

from __future__ import annotations

from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    ModelWrapValidatorHandler,
    PrivateAttr,
    model_validator,
)


class ApiReply(BaseModel):
    """An upstream JSON object. The fields a source reads are declared and
    checked; the object exactly as the API sent it is kept for the stored
    evidence details, so validating a reply never changes what is saved.
    Fields used only for display are typed ``object``: the API may send
    anything there and it is shown as given."""

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    _given: dict[str, Any] = PrivateAttr(default_factory=dict)

    @model_validator(mode="wrap")
    @classmethod
    def _keep_given(
        cls, raw: Any, handler: ModelWrapValidatorHandler[ApiReply]
    ) -> ApiReply:
        reply = handler(raw)
        reply._given = dict(raw) if isinstance(raw, dict) else {}
        return reply

    def given(self, fields: tuple[str, ...]) -> dict[str, Any]:
        """These fields as the API sent them (None when absent)."""
        return {field: self._given.get(field) for field in fields}

    def as_given(self) -> dict[str, Any]:
        return dict(self._given)
