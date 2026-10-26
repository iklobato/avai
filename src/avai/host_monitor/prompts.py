"""Prompt-file loading (per-collector judge hints)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any

from .enums import ThreatCategory, Verdict


class PromptSections:
    """The tables of a prompts TOML file. ``$verdicts`` and ``$categories``
    in a system prompt are filled with the enum values the schemas accept."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document

    def table(self, name: str) -> dict[str, str]:
        return dict(self._document.get(name) or {})

    def rendered(self, name: str) -> str:
        return Template(self.table(name).get("system", "")).safe_substitute(
            verdicts=" | ".join(str(verdict) for verdict in Verdict),
            categories=", ".join(str(category) for category in ThreatCategory),
        )


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
    coverage_system: str = ""
    coverage_user_template: str = ""
    verifier_system: str = ""
    verifier_user_template: str = ""
    investigator_system: str = ""
    investigator_user_template: str = ""

    @classmethod
    def load(cls, path: Path) -> Prompts:
        with open(path, "rb") as stream:
            sections = PromptSections(tomllib.load(stream))
        judge, narrator = sections.table("judge"), sections.table("narrator")
        coverage, verifier = sections.table("yara_coverage"), sections.table("verifier")
        investigator = sections.table("investigator")
        return cls(
            system=sections.rendered("judge"),
            user_template=judge.get("user_template", ""),
            collector_hints=sections.table("collector_hints"),
            narrator_system=sections.rendered("narrator"),
            narrator_user_template=narrator.get("user_template", ""),
            coverage_system=coverage.get("system", ""),
            coverage_user_template=coverage.get("user_template", ""),
            verifier_system=verifier.get("system", ""),
            verifier_user_template=verifier.get("user_template", ""),
            investigator_system=sections.rendered("investigator"),
            investigator_user_template=investigator.get("user_template", ""),
        )

    def hint_for(self, collector_name: str) -> str:
        return self.collector_hints.get(collector_name, "")
