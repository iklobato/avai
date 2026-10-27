"""Prompt-file loading (per-collector judge hints)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

from pydantic import BaseModel, ConfigDict

from .enums import ThreatCategory, Verdict


class PromptTable(BaseModel):
    """One ``[stage]`` table of the prompts file."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    system: str = ""
    user_template: str = ""

    def rendered_system(self) -> str:
        """``$verdicts`` and ``$categories`` filled with the enum values the
        schemas accept."""
        return Template(self.system).safe_substitute(
            verdicts=" | ".join(str(verdict) for verdict in Verdict),
            categories=", ".join(str(category) for category in ThreatCategory),
        )


class PromptFile(BaseModel):
    """The prompts TOML file, checked when it is read."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    judge: PromptTable = PromptTable()
    narrator: PromptTable = PromptTable()
    yara_coverage: PromptTable = PromptTable()
    verifier: PromptTable = PromptTable()
    investigator: PromptTable = PromptTable()
    collector_hints: dict[str, str] = {}


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
            document = PromptFile.model_validate(tomllib.load(stream))
        coverage, verifier = document.yara_coverage, document.verifier
        return cls(
            system=document.judge.rendered_system(),
            user_template=document.judge.user_template,
            collector_hints=dict(document.collector_hints),
            narrator_system=document.narrator.rendered_system(),
            narrator_user_template=document.narrator.user_template,
            coverage_system=coverage.system,
            coverage_user_template=coverage.user_template,
            verifier_system=verifier.system,
            verifier_user_template=verifier.user_template,
            investigator_system=document.investigator.rendered_system(),
            investigator_user_template=document.investigator.user_template,
        )

    def hint_for(self, collector_name: str) -> str:
        return self.collector_hints.get(collector_name, "")
