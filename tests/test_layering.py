"""Import-layering guard (docs/REFACTOR_PLAN.md, Phase 0).

Fails when a lower layer imports a higher one at runtime. Imports inside an
``if TYPE_CHECKING:`` block are annotations only and are skipped; imports
inside functions still run, so they count.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

_HM = "avai.host_monitor"
_COLLECTOR_MODULES = tuple(
    f"{_HM}.{name}"
    for name in (
        "collectors",
        "net_collectors",
        "exposure_collectors",
        "persistence_collectors",
    )
)
_LLM_STAGES = tuple(
    f"{_HM}.{name}"
    for name in ("llm", "judge", "narrator", "verifier", "investigator", "coverage")
)
_ORCHESTRATION = tuple(
    f"{_HM}.{name}"
    for name in (
        "runner",
        "streaming",
        "main",
        "control_loop",
        "finding_stages",
        "cycle_steps",
    )
)

# (importing module prefixes, forbidden target prefixes, allowed exceptions)
RULES: tuple[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    (
        (f"{_HM}.runtime",),
        (_HM,),
        (f"{_HM}.runtime", f"{_HM}.constants", f"{_HM}.enums"),
    ),
    (
        _COLLECTOR_MODULES,
        (f"{_HM}.hosts", f"{_HM}.sink", *_ORCHESTRATION, *_LLM_STAGES),
        (),
    ),
    (
        (f"{_HM}.sink",),
        (f"{_HM}.hosts", *_COLLECTOR_MODULES, *_ORCHESTRATION),
        (),
    ),
    (
        (_HM,),
        ("avai.dashboard", "avai.desktop", "avai.cli"),
        (),
    ),
    (
        ("avai.dashboard",),
        (
            f"{_HM}.hosts",
            *_COLLECTOR_MODULES,
            *_ORCHESTRATION,
            *_LLM_STAGES,
            "avai.desktop",
            "avai.cli",
        ),
        (),
    ),
    (
        ("avai.enrichers",),
        (_HM, "avai.dashboard"),
        (f"{_HM}.constants",),
    ),
    (
        ("avai.dashboard.queries", "avai.dashboard.control"),
        ("flask", "avai.dashboard.app", "avai.dashboard.routes"),
        (),
    ),
)


def _module_name(path: Path, root: Path) -> str:
    parts = path.relative_to(root).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _is_module(dotted: str, root: Path) -> bool:
    base = root.joinpath(*dotted.split("."))
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def _is_type_checking_block(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _runtime_imports(tree: ast.AST):
    stack = [tree]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if _is_type_checking_block(child):
                stack.extend(child.orelse)
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                yield child
            stack.append(child)


def _targets(node: ast.AST, module: str, is_package: bool, root: Path):
    if isinstance(node, ast.Import):
        yield from (alias.name for alias in node.names)
        return
    if node.level:
        package = module if is_package else module.rsplit(".", 1)[0]
        parts = package.split(".")
        parts = parts[: len(parts) - (node.level - 1)]
        base = ".".join([*parts, node.module] if node.module else parts)
    else:
        base = node.module or ""
    for alias in node.names:
        candidate = f"{base}.{alias.name}"
        yield candidate if _is_module(candidate, root) else base


def _matches(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def layering_violations(root: Path = SRC) -> list[str]:
    found = []
    for path in sorted(root.rglob("*.py")):
        if "migrations" in path.parts:
            continue
        module = _module_name(path, root)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _runtime_imports(tree):
            for target in _targets(node, module, path.name == "__init__.py", root):
                for importers, forbidden, allowed in RULES:
                    if (
                        _matches(module, importers)
                        and _matches(target, forbidden)
                        and not _matches(target, allowed)
                        and not _matches(target, importers)
                    ):
                        found.append(f"{module}:{node.lineno} imports {target}")
    return found


def test_src_respects_import_layers():
    assert layering_violations() == []


def test_checker_flags_a_lower_layer_importing_a_higher_one(tmp_path):
    runtime = tmp_path / "avai" / "host_monitor" / "runtime"
    runtime.mkdir(parents=True)
    for pkg in (tmp_path / "avai", runtime.parent, runtime):
        (pkg / "__init__.py").write_text("")
    (runtime.parent / "runner.py").write_text("")
    (runtime / "clock.py").write_text(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from ..runner import Runner\n"
        "from .. import runner\n"
    )

    assert layering_violations(tmp_path) == [
        "avai.host_monitor.runtime.clock:4 imports avai.host_monitor.runner"
    ]
