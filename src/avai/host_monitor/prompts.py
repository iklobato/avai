"""Prompt-file loading (per-collector judge hints)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

from .enums import ThreatCategory, Verdict


@dataclass(frozen=True)
class Prompts:
    """All LLM-facing strings, loaded from an external TOML file.

    ``system`` is the fully-substituted system prompt (verdict /
    category lists already injected). ``user_template`` is a
    string.Template using ``$collector``, ``$hints``, ``$entries``.
    """

    system: str
    user_template: str
    collector_hints: dict[str, str] = field(default_factory=dict)
    narrator_system: str = ""
    narrator_user_template: str = ""

    @classmethod
    def load(cls, path: Path) -> "Prompts":
        with open(path, "rb") as f:
            data = tomllib.load(f)
        judge = data.get("judge") or {}
        raw_system = judge.get("system", "")
        system = Template(raw_system).safe_substitute(
            verdicts=" | ".join(str(v) for v in Verdict),
            categories=", ".join(str(c) for c in ThreatCategory),
        )
        narrator = data.get("narrator") or {}
        narrator_system = Template(narrator.get("system", "")).safe_substitute(
            categories=", ".join(str(c) for c in ThreatCategory),
        )
        return cls(
            system=system,
            user_template=judge.get("user_template", ""),
            collector_hints=dict(data.get("collector_hints") or {}),
            narrator_system=narrator_system,
            narrator_user_template=narrator.get("user_template", ""),
        )

    def hint_for(self, collector_name: str) -> str:
        return self.collector_hints.get(collector_name, "")
