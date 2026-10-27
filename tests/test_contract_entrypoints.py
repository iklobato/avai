"""Pins the entry points that installers and the desktop bundle call by dotted path."""

from __future__ import annotations

import tomllib
from importlib import import_module
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
PACKAGING_LAUNCHER = PYPROJECT.parent / "packaging" / "avai_app.py"
CONSOLE_SCRIPT = "avai"


class DottedTarget:
    def __init__(self, reference: str) -> None:
        self._reference = reference

    def resolve(self) -> object:
        module_path, _, attribute_path = self._reference.partition(":")
        target: object = import_module(module_path)
        for attribute in attribute_path.split("."):
            target = getattr(target, attribute)
        return target


def test_avai_console_script_target_resolves_to_a_callable() -> None:
    scripts = tomllib.loads(PYPROJECT.read_text())["project"]["scripts"]

    target = DottedTarget(scripts[CONSOLE_SCRIPT]).resolve()

    assert callable(target)


def test_desktop_launcher_imports_a_callable_entry_point() -> None:
    import_line = next(
        line
        for line in PACKAGING_LAUNCHER.read_text().splitlines()
        if line.startswith("from avai.desktop import")
    )
    module_path, _, name = import_line.removeprefix("from ").partition(" import ")

    target = DottedTarget(f"{module_path}:{name.strip()}").resolve()

    assert callable(target)
