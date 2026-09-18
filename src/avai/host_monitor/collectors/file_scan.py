"""YARA signature scanning of a bounded set of high-signal files."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from itertools import islice
from typing import TYPE_CHECKING, Iterable, Optional

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout

import yara

try:
    import pwd  # POSIX only; used to resolve file owner for YARA externals
except ImportError:  # pragma: no cover - Windows has no pwd module
    pwd = None

from .. import constants, slices
from ..runtime import (
    Clock,
    Digest,
)
from .base import SnapshotCollector


def _crypto_hint(exc: "yara.Error") -> str:
    """Append an actionable hint when a ruleset fails to compile because
    this yara build lacks OpenSSL (the PyPI wheel does) — pe.imphash() /
    hash.* then read as 'invalid field name'. Empty for any other error."""
    msg = str(exc).lower()
    _hashish = ("md5", "sha1", "sha256", "checksum", "imphash")
    if "imphash" in msg or (
        "invalid field name" in msg and any(h in msg for h in _hashish)
    ):
        return (
            " — these rules need a crypto-enabled yara (pe.imphash / hash.*);"
            " the PyPI yara-python wheel is built without it. See"
            " avai/rules/NOTICE."
        )
    return ""


# External variables that LOKI / THOR (and thus the signature-base rules)
# expect. Defined at compile time with empty placeholders so rules that
# reference them compile; the real per-file values are supplied at match
# time (see FileScanCollector._match_externals). Without these, many
# signature-base rules fail to compile with "undefined identifier".
_YARA_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "md5": "",
    "owner": "",
}


def _file_type(path: Path) -> str:
    """Best-effort ``filetype`` external from leading magic bytes, using the
    labels signature-base rules compare against. Only the structural binary
    types are detected reliably (EXE/ELF/MACH-O/MDMP); LOKI's content-derived
    script labels (Python/PHP/VBS/…) are left empty rather than guessed."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return ""
    if head[:2] == b"MZ":
        return "EXE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return "MACH-O"
    if head[:4] == b"MDMP":
        return "MDMP"
    return ""


def _redact_one_match(identifier: str, offset: int, data: bytes) -> dict:
    """Render one matched byte run for the judge: printable runs as ``text``,
    anything else as ``hex``, truncated to ``YARA_MATCH_STRING_MAX_BYTES`` so
    a large or binary match can't bloat the prompt/DB or leak a full payload."""
    raw = bytes(data or b"")
    truncated = len(raw) > constants.YARA_MATCH_STRING_MAX_BYTES
    raw = raw[: constants.YARA_MATCH_STRING_MAX_BYTES]
    printable = sum(1 for b in raw if 0x20 <= b < 0x7F)
    out = {"id": identifier, "offset": int(offset), "truncated": truncated}
    if raw and printable / len(raw) >= 0.8:
        out["text"] = raw.decode("ascii", "replace")
    else:
        out["hex"] = raw.hex()
    return out


def _redact_match_strings(match) -> list[dict]:
    """A bounded, redacted view of the bytes a YARA match fired on.

    Tolerant of both yara-python string-match shapes: the >=4.3 object form
    (``StringMatch`` with ``.identifier`` + ``.instances`` carrying
    ``.offset`` / ``.matched_data``) and the legacy ``(offset, identifier,
    data)`` tuple. Capped at ``YARA_MAX_MATCH_STRINGS`` entries total — a
    broad rule on a big binary can otherwise report thousands of instances."""
    cap = constants.YARA_MAX_MATCH_STRINGS
    out: list[dict] = []
    for sm in getattr(match, "strings", None) or []:
        instances = getattr(sm, "instances", None)
        if instances is not None:  # modern object API
            identifier = getattr(sm, "identifier", "")
            for inst in instances:
                out.append(
                    _redact_one_match(
                        identifier,
                        getattr(inst, "offset", 0),
                        getattr(inst, "matched_data", b""),
                    )
                )
                if len(out) >= cap:
                    return out
        else:  # legacy tuple API: (offset, identifier, data)
            try:
                offset, identifier, data = sm
            except (TypeError, ValueError):
                continue
            out.append(_redact_one_match(identifier, offset, data))
            if len(out) >= cap:
                return out
    return out


def _rule_source(path: Path, rules_dir: Path) -> str:
    """Label a rule file by where it came from: top-level files are
    ``bundled``; a vendored pack file (``vendor/<name>/…``) is ``<name>``."""
    try:
        parts = path.relative_to(rules_dir).parts
    except ValueError:
        return "other"
    return "bundled" if len(parts) == 1 else parts[-2]


_RULE_SUFFIXES = (".yar", ".yara")


class YaraRulesetCompiler:
    """Compile every ``*.yar`` / ``*.yara`` under ``rules_dir`` into one
    :class:`yara.Rules`, plus a summary dict (counts, sources, skip
    reasons, per-category, one inventory entry per rule) for the
    dashboard's File Scan panel.

    Each file is validated independently first and uncompilable ones are
    skipped with a warning, so a single malformed rule in a fetched pack
    can't disable scanning entirely (signature-base's per-file layout makes
    this graceful: only the imphash/hash.* files skip on a crypto-less
    yara). Per-file namespaces keep rule identifiers from colliding across
    files. ``_YARA_EXTERNALS`` is supplied so rules referencing scanner
    externals (filename/filepath/extension/filetype/…) compile.
    """

    def __init__(self, rules_dir: Path) -> None:
        self._rules_dir = rules_dir

    def compile(self) -> tuple[Optional["yara.Rules"], dict]:
        """Return ``(rules, stats)``. ``rules`` is None when the directory
        is absent or holds no compilable rules; ``stats`` is always set."""
        stats = self._empty_stats()
        if not self._rules_dir.is_dir():
            return None, stats
        filepaths = self._load_files(stats)
        if not filepaths:
            return None, stats
        try:
            compiled = yara.compile(filepaths=filepaths, externals=_YARA_EXTERNALS)
        except yara.Error as exc:
            constants.LOG.warning("yara: combined compile failed: %s", exc)
            return None, stats
        stats["rules_loaded"] = sum(1 for _ in compiled)
        # One-line visibility into what the scanner actually loaded — the only
        # place rule counts surface, since there's no per-match log.
        constants.LOG.info(
            "yara: loaded %d rules from %d files (skipped %d) under %s",
            stats["rules_loaded"],
            stats["files_loaded"],
            stats["files_skipped"],
            self._rules_dir,
        )
        return compiled, stats

    def _empty_stats(self) -> dict:
        return {
            "rules_loaded": 0,
            "files_loaded": 0,
            "files_skipped": 0,
            "skip_reasons": {},
            "by_category": {},
            "sources": {},
            "rules_dir": str(self._rules_dir),
            "inventory": [],  # one entry per rule, for the dashboard's rule browser
        }

    def _load_files(self, stats: dict) -> dict[str, str]:
        """Validate each rule file on its own, record it in ``stats`` and
        return ``{namespace: path}`` for the ones that compile."""
        filepaths: dict[str, str] = {}
        for path in self._rule_files():
            file_rules = self._compile_one(path, stats["skip_reasons"])
            if file_rules is None:
                continue
            filepaths[_unique_namespace(path.stem, filepaths)] = str(path)
            self._record(path, file_rules, stats)
        stats["files_loaded"] = len(filepaths)
        stats["files_skipped"] = sum(stats["skip_reasons"].values())
        return filepaths

    def _rule_files(self) -> Iterable[Path]:
        for path in sorted(self._rules_dir.rglob("*")):
            if path.suffix.lower() in _RULE_SUFFIXES and path.is_file():
                yield path

    @staticmethod
    def _compile_one(path: Path, skip_reasons: dict) -> Optional["yara.Rules"]:
        try:
            return yara.compile(filepath=str(path), externals=_YARA_EXTERNALS)
        except yara.Error as exc:
            reason = "needs crypto-enabled yara" if _crypto_hint(exc) else "other"
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            constants.LOG.warning(
                "yara: skipping uncompilable rules %s: %s%s",
                path,
                exc,
                _crypto_hint(exc),
            )
            return None

    def _record(self, path: Path, file_rules: "yara.Rules", stats: dict) -> None:
        # The per-file compile is otherwise discarded; iterating it records
        # each rule's identity for the inventory at no extra compile cost.
        category = path.stem.split("_", 1)[0]
        source = _rule_source(path, self._rules_dir)
        by_category, sources = stats["by_category"], stats["sources"]
        by_category[category] = by_category.get(category, 0) + 1
        sources[source] = sources.get(source, 0) + 1
        stats["inventory"].extend(
            {
                "identifier": rule.identifier,
                "tags": " ".join(rule.tags),
                "author": str((rule.meta or {}).get("author") or ""),
                "source": source,
                "category": category,
            }
            for rule in file_rules
        )


def _unique_namespace(stem: str, taken: dict[str, str]) -> str:
    unique = stem
    suffix = 1
    while unique in taken:
        unique = f"{stem}_{suffix}"
        suffix += 1
    return unique


class FileScanCollector(SnapshotCollector):
    """Signature scanning: match YARA rules against a bounded set of
    high-signal files and emit one row per ``(file, matched rule)``.

    A rule hit is strong evidence the LLM judge weighs alongside any
    threat-intel on the file's hash (the matched file's sha256 is also
    enriched). avai stays observe-only — nothing is quarantined or killed.

    Targets are deliberately bounded (see ``constants.YARA_*``): a full
    disk walk is infeasible (~150k files under ``/Applications`` alone), so
    the scanner walks the same small, security-relevant corners other
    collectors already trust — privileged bin dirs and application
    executables — plus *recently modified* Downloads, where freshly
    delivered payloads land.
    """

    slice = slices.FILE_SCAN
    judge_fields = ("path", "sha256", "rule", "namespace", "tags_json")

    _SECONDS_PER_DAY = 86400

    def __init__(
        self,
        judge_hints: str = "",
        fs: "FilesystemLayout" = None,
        rules_dir: Optional[Path] = None,
        clock: Optional[Clock] = None,
    ):
        super().__init__(judge_hints=judge_hints)
        self._fs = fs
        self._rules_dir = Path(rules_dir) if rules_dir else constants.YARA_RULES_DIR
        self._clock = clock or Clock()
        self._rules = None  # compiled once, lazily
        self._compiled = False
        # Ruleset summary from the last compile — read by the Runner to
        # persist yara_status for the dashboard. None until first collect().
        self.compile_stats: Optional[dict] = None

    def _ruleset(self):
        if not self._compiled:
            compiler = YaraRulesetCompiler(self._rules_dir)
            self._rules, self.compile_stats = compiler.compile()
            self._compiled = True
        return self._rules

    def collect(self):
        rules = self._ruleset()
        if rules is None:
            return
        # The cap counts every scan attempt, matched or not.
        targets = islice(self._targets(), constants.YARA_MAX_FILES_PER_CYCLE)
        for path, source in targets:
            yield from self._scan_file(path, source, rules)

    def _targets(self):
        """Yield ``(path, scan_source)`` for each file to scan, deduped by
        path. Bounded by construction; ``collect`` applies the per-cycle
        cap. No ``fs`` ⇒ nothing to scan."""
        if self._fs is None:
            return
        sources = (
            # privileged bin dirs: recursive, but a small file set.
            ("bin_dirs", self._bin_dir_files()),
            # application executables (macOS bundles; [] elsewhere).
            ("app_bundle", self._fs.app_executables()),
            ("downloads", self._recent_downloads()),
        )
        seen: set[str] = set()
        for label, paths in sources:
            for path in paths:
                key = str(path)
                if key not in seen:
                    seen.add(key)
                    yield path, label

    def _bin_dir_files(self) -> Iterable[Path]:
        for base in self._fs.privileged_bin_dirs():
            yield from _walk(base)

    def _recent_downloads(self) -> Iterable[Path]:
        cutoff = self._recent_cutoff()
        for home in self._fs.home_dirs():
            for path in _walk(home / "Downloads"):
                if _modified_since(path, cutoff):
                    yield path

    def _recent_cutoff(self) -> float:
        now = datetime.fromisoformat(self._clock.now_iso()).timestamp()
        return now - constants.YARA_DOWNLOADS_RECENT_DAYS * self._SECONDS_PER_DAY

    def _scan_file(self, path: Path, source: str, rules):
        try:
            if not path.is_file():
                return
            st = path.stat()  # follow symlinks: size must reflect bytes read
        except (PermissionError, OSError):
            return
        if st.st_size > constants.YARA_MAX_FILE_BYTES:
            return
        try:
            matches = rules.match(
                str(path),
                externals=self._match_externals(path, st),
                timeout=constants.YARA_MATCH_TIMEOUT_S,
            )
        except yara.Error:
            # Unreadable, vanished mid-scan, or match timeout — skip this
            # file and keep scanning the rest.
            return
        if not matches:
            return
        sha = Digest.sha256_file(path)
        for m in matches:
            yield {
                "path": str(path),
                "sha256": sha,
                "rule": m.rule,
                "namespace": m.namespace,
                "tags_json": json.dumps(list(m.tags)),
                # Rule meta (author/reference/description) — retained on the
                # finding to satisfy the signature-base DRL attribution
                # obligation and to give the judge/dashboard rule context.
                "meta_json": json.dumps(m.meta, default=str),
                # Redacted sample of the bytes that matched — lets the judge
                # tell a substantive hit from a generic substring (false
                # positive). Bounded by the YARA_MATCH_STRING* caps.
                "strings_json": json.dumps(_redact_match_strings(m)),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "scan_source": source,
            }

    @staticmethod
    def _match_externals(path: Path, st) -> dict:
        """Per-file values for the scanner externals signature-base rules
        read. ``md5`` is intentionally empty — no rule compares it — so no
        per-file hashing is forced just to populate an unused variable."""
        owner = ""
        if pwd is not None:
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except (KeyError, OSError):
                owner = ""
        return {
            "filename": path.name,
            "filepath": str(path),
            "extension": path.suffix.lower(),
            "filetype": _file_type(path),
            "md5": "",
            "owner": owner,
        }


def _walk(base: Path) -> list[Path]:
    """Every entry under ``base``, or [] when it is missing or unreadable."""
    # is_dir() re-raises EACCES, so guard it together with the walk.
    try:
        if not base.is_dir():
            return []
        return list(base.rglob("*"))
    except OSError:
        return []


def _modified_since(path: Path, cutoff: float) -> bool:
    try:
        return path.stat().st_mtime >= cutoff
    except OSError:
        return False
