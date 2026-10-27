"""YARA signature scanning of a bounded set of high-signal files."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator, NamedTuple

import yara

from .. import constants
from ..enums import ScanSource, YaraSkipReason
from ..runtime import Clock, Digest
from ..slices import Slices
from .base import SnapshotCollector

if TYPE_CHECKING:
    from ..hosts.capabilities import ExecutableLayout


class CryptoHint:
    """Actionable hint for a ruleset that fails to compile because this yara
    build lacks OpenSSL (the PyPI wheel does): pe.imphash() / hash.* then read
    as 'invalid field name'. Empty for any other error."""

    HASH_TERMS = ("md5", "sha1", "sha256", "checksum", "imphash")
    TEXT = (
        ": these rules need a crypto-enabled yara (pe.imphash / hash.*);"
        " the PyPI yara-python wheel is built without it. See"
        " avai/rules/NOTICE."
    )

    def of(self, error: yara.Error) -> str:
        message = str(error).lower()
        if "imphash" in message or self._hash_field_missing(message):
            return self.TEXT
        return ""

    def _hash_field_missing(self, message: str) -> bool:
        return "invalid field name" in message and any(
            term in message for term in self.HASH_TERMS
        )


class FileMagic:
    """Best-effort ``filetype`` external from leading magic bytes, using the
    labels signature-base rules compare against. Only the structural binary
    types are detected (EXE/ELF/MACH-O/MDMP); LOKI's content-derived script
    labels are left empty rather than guessed."""

    HEADER_BYTES = 8
    SIGNATURES = (
        (b"MZ", "EXE"),
        (b"\x7fELF", "ELF"),
        (b"\xfe\xed\xfa\xce", "MACH-O"),
        (b"\xce\xfa\xed\xfe", "MACH-O"),
        (b"\xfe\xed\xfa\xcf", "MACH-O"),
        (b"\xcf\xfa\xed\xfe", "MACH-O"),
        (b"\xca\xfe\xba\xbe", "MACH-O"),
        (b"MDMP", "MDMP"),
    )

    def kind(self, path: Path) -> str:
        try:
            with open(path, "rb") as stream:
                head = stream.read(self.HEADER_BYTES)
        except OSError:
            return ""
        labels = (label for magic, label in self.SIGNATURES if head.startswith(magic))
        return next(labels, "")


class MatchedBytes(NamedTuple):
    identifier: str
    offset: int
    matched: bytes


class MatchRedactor:
    """A bounded, redacted view of the bytes a YARA match fired on.

    Reads both yara-python string-match shapes: the >=4.3 object form
    (``.identifier`` + ``.instances`` with ``.offset`` / ``.matched_data``)
    and the legacy ``(offset, identifier, data)`` tuple. Capped at
    ``YARA_MAX_MATCH_STRINGS`` entries: a broad rule on a big binary can
    otherwise report thousands of instances."""

    PRINTABLE_ASCII = range(0x20, 0x7F)
    # Share of printable bytes above which a match is shown as text, not hex.
    TEXT_MIN_PRINTABLE_RATIO = 0.8

    def strings(self, match: yara.Match) -> list[dict[str, Any]]:
        found = (
            piece
            for string_match in getattr(match, "strings", None) or []
            for piece in self._pieces(string_match)
        )
        cap = constants.YARA_MAX_MATCH_STRINGS
        return [self.redact(piece) for piece in islice(found, cap)]

    def redact(self, piece: MatchedBytes) -> dict[str, Any]:
        """Printable runs as ``text``, anything else as ``hex``, truncated to
        ``YARA_MATCH_STRING_MAX_BYTES`` so a big or binary match can't bloat
        the prompt/DB or leak a full payload."""
        cap = constants.YARA_MATCH_STRING_MAX_BYTES
        raw = bytes(piece.matched or b"")
        shown = raw[:cap]
        rendered: dict[str, Any] = {
            "id": piece.identifier,
            "offset": int(piece.offset),
            "truncated": len(raw) > cap,
        }
        if shown and self._printable_share(shown) >= self.TEXT_MIN_PRINTABLE_RATIO:
            rendered["text"] = shown.decode("ascii", "replace")
            return rendered
        rendered["hex"] = shown.hex()
        return rendered

    def _printable_share(self, shown: bytes) -> float:
        printable = sum(1 for byte in shown if byte in self.PRINTABLE_ASCII)
        return printable / len(shown)

    def _pieces(self, string_match: Any) -> Iterator[MatchedBytes]:
        instances = getattr(string_match, "instances", None)
        if instances is None:
            yield from self._legacy_pieces(string_match)
            return
        identifier = getattr(string_match, "identifier", "")
        yield from (
            MatchedBytes(
                identifier,
                getattr(instance, "offset", 0),
                getattr(instance, "matched_data", b""),
            )
            for instance in instances
        )

    def _legacy_pieces(self, string_match: Any) -> list[MatchedBytes]:
        try:
            offset, identifier, matched = string_match
        except (TypeError, ValueError):
            return []
        return [MatchedBytes(identifier, offset, matched)]


class YaraRulesDir:
    """Where the rules to compile live: AVAI_YARA_RULES_DIR, else the
    bundled pack."""

    def from_environ(self, environ: Mapping[str, str]) -> Path:
        override = environ.get(constants.YARA_RULES_ENV)
        return Path(override) if override else constants.BUNDLED_YARA_RULES_DIR


class YaraRulesetCompiler:
    """Compile every ``*.yar`` / ``*.yara`` under ``rules_dir`` into one
    :class:`yara.Rules`, plus a summary dict (counts, sources, skip
    reasons, per-category, one inventory entry per rule) for the
    dashboard's File Scan panel.

    Each file is validated on its own first and uncompilable ones are
    skipped with a warning, so one malformed rule in a fetched pack can't
    disable scanning. Per-file namespaces keep rule identifiers from
    colliding across files. The scanner externals LOKI / THOR rules read
    (filename/filepath/extension/filetype/...) are defined with empty
    placeholders so those rules compile; real values come at match time
    (see :meth:`ScannedFile.externals`).
    """

    RULE_SUFFIXES = (".yar", ".yara")
    EXTERNAL_NAMES = ("filename", "filepath", "extension", "filetype", "md5", "owner")

    def __init__(self, rules_dir: Path, logger: logging.Logger) -> None:
        self._rules_dir = rules_dir
        self._logger = logger

    def externals(self) -> dict[str, str]:
        return dict.fromkeys(self.EXTERNAL_NAMES, "")

    def compile(self) -> tuple[yara.Rules | None, dict[str, Any]]:
        """Return ``(rules, stats)``. ``rules`` is None when the directory
        is absent or holds no compilable rules; ``stats`` is always set."""
        stats = self._empty_stats()
        filepaths = self._load_files(stats) if self._rules_dir.is_dir() else {}
        if not filepaths:
            return None, stats
        try:
            compiled = yara.compile(filepaths=filepaths, externals=self.externals())
        except yara.Error as exc:
            self._logger.warning("yara: combined compile failed: %s", exc)
            return None, stats
        stats["rules_loaded"] = sum(1 for _ in compiled)
        self._log_loaded(stats)
        return compiled, stats

    def _log_loaded(self, stats: dict[str, Any]) -> None:
        # The only place rule counts surface, since there's no per-match log.
        self._logger.info(
            "yara: loaded %d rules from %d files (skipped %d) under %s",
            stats["rules_loaded"],
            stats["files_loaded"],
            stats["files_skipped"],
            self._rules_dir,
        )

    def _empty_stats(self) -> dict[str, Any]:
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

    def _load_files(self, stats: dict[str, Any]) -> dict[str, str]:
        """Validate each rule file on its own, record it in ``stats`` and
        return ``{namespace: path}`` for the ones that compile."""
        filepaths: dict[str, str] = {}
        for path in self._rule_files():
            file_rules = self._compile_one(path, stats["skip_reasons"])
            if file_rules is None:
                continue
            filepaths[self._namespace(path.stem, filepaths)] = str(path)
            self._record(path, file_rules, stats)
        stats["files_loaded"] = len(filepaths)
        stats["files_skipped"] = sum(stats["skip_reasons"].values())
        return filepaths

    def _rule_files(self) -> Iterable[Path]:
        for path in sorted(self._rules_dir.rglob("*")):
            if path.suffix.lower() in self.RULE_SUFFIXES and path.is_file():
                yield path

    def _compile_one(
        self, path: Path, skip_reasons: dict[str, int]
    ) -> yara.Rules | None:
        try:
            return yara.compile(filepath=str(path), externals=self.externals())
        except yara.Error as exc:
            hint = CryptoHint().of(exc)
            skipped = YaraSkipReason.NEEDS_CRYPTO if hint else YaraSkipReason.OTHER
            reason = skipped.value
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            self._logger.warning(
                "yara: skipping uncompilable rules %s: %s%s", path, exc, hint
            )
            return None

    def _record(
        self, path: Path, file_rules: yara.Rules, stats: dict[str, Any]
    ) -> None:
        # The per-file compile is otherwise discarded; iterating it records
        # each rule's identity for the inventory at no extra compile cost.
        category = path.stem.split("_", 1)[0]
        source = self._source(path)
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

    def _source(self, path: Path) -> str:
        """Top-level files are ``bundled``; a vendored pack file
        (``vendor/<name>/...``) is labelled ``<name>``."""
        try:
            parts = path.relative_to(self._rules_dir).parts
        except ValueError:
            return "other"
        return "bundled" if len(parts) == 1 else path.parent.name

    def _namespace(self, stem: str, taken: dict[str, str]) -> str:
        unique = stem
        suffix = 1
        while unique in taken:
            unique = f"{stem}_{suffix}"
            suffix += 1
        return unique


class ScanTargets:
    """The bounded set of files worth scanning, deduped by path: privileged
    bin dirs, application executables, and *recently modified* Downloads,
    where freshly delivered payloads land. A full disk walk is infeasible
    (~150k files under ``/Applications`` alone)."""

    SECONDS_PER_DAY = 86400

    def __init__(self, fs: ExecutableLayout, clock: Clock) -> None:
        self._fs = fs
        self._clock = clock

    def paths(self) -> Iterator[tuple[Path, ScanSource]]:
        """Yield ``(path, scan_source)``; the caller applies the cycle cap."""
        sources = (
            (ScanSource.BIN_DIRS, self._bin_dir_files()),
            (ScanSource.APP_BUNDLE, self._fs.app_executables()),
            (ScanSource.DOWNLOADS, self._recent_downloads()),
        )
        labelled = ((path, label) for label, paths in sources for path in paths)
        seen: set[str] = set()
        for path, label in labelled:
            if str(path) in seen:
                continue
            seen.add(str(path))
            yield path, label

    def _bin_dir_files(self) -> Iterable[Path]:
        for base in self._fs.privileged_bin_dirs():
            yield from self._walk(base)

    def _recent_downloads(self) -> Iterable[Path]:
        cutoff = self._recent_cutoff()
        homes = self._fs.home_dirs()
        walked = (path for home in homes for path in self._walk(home / "Downloads"))
        yield from (path for path in walked if self._modified_since(path, cutoff))

    def _recent_cutoff(self) -> float:
        now = datetime.fromisoformat(self._clock.now_iso()).timestamp()
        return now - constants.YARA_DOWNLOADS_RECENT_DAYS * self.SECONDS_PER_DAY

    def _walk(self, base: Path) -> list[Path]:
        """Every entry under ``base``, or [] when it is missing or unreadable."""
        # is_dir() re-raises EACCES, so guard it together with the walk.
        try:
            if not base.is_dir():
                return []
            return list(base.rglob("*"))
        except OSError:
            return []

    def _modified_since(self, path: Path, cutoff: float) -> bool:
        try:
            return path.stat().st_mtime >= cutoff
        except OSError:
            return False


@dataclass(frozen=True)
class ScannedFile:
    path: Path
    file_stat: os.stat_result
    source: ScanSource

    def externals(self) -> dict[str, str]:
        """Per-file values for the scanner externals signature-base rules
        read. ``md5`` stays empty: no rule compares it, so no per-file
        hashing is forced just to fill an unused variable."""
        return {
            "filename": self.path.name,
            "filepath": str(self.path),
            "extension": self.path.suffix.lower(),
            "filetype": FileMagic().kind(self.path),
            "md5": "",
            "owner": self._owner(),
        }

    def row(self, match: yara.Match, sha256: str) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "sha256": sha256,
            "rule": match.rule,
            "namespace": match.namespace,
            "tags_json": json.dumps(list(match.tags)),
            # Rule meta is kept for the signature-base DRL attribution duty.
            "meta_json": json.dumps(match.meta, default=str),
            # Redacted matched bytes let the judge tell a real hit from a
            # generic substring.
            "strings_json": json.dumps(MatchRedactor().strings(match)),
            "size": self.file_stat.st_size,
            "mtime": self.file_stat.st_mtime,
            "scan_source": self.source.value,
        }

    def _owner(self) -> str:
        # Path.owner() is unsupported on Windows and fails on unknown uids.
        try:
            return self.path.owner()
        except (KeyError, OSError, NotImplementedError):
            return ""


class FileScanCollector(SnapshotCollector):
    """Signature scanning: match YARA rules against the bounded
    :class:`ScanTargets` and emit one row per ``(file, matched rule)``.

    A rule hit is strong evidence the LLM judge weighs alongside any
    threat-intel on the file's hash (the matched file's sha256 is also
    enriched). avai stays observe-only: nothing is quarantined or killed.
    """

    slice = Slices.FILE_SCAN
    judge_fields = ("path", "sha256", "rule", "namespace", "tags_json")

    def __init__(
        self,
        targets: ScanTargets,
        compiler: YaraRulesetCompiler,
        judge_hints: str = "",
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._targets = targets
        self._compiler = compiler
        self._rules: yara.Rules | None = None
        self._compiled = False
        # Ruleset summary from the last compile, read by the Runner to
        # persist yara_status for the dashboard. None until first collect().
        self.compile_stats: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        fs: ExecutableLayout,
        compiler: YaraRulesetCompiler,
        judge_hints: str = "",
    ) -> FileScanCollector:
        return cls(ScanTargets(fs, Clock()), compiler, judge_hints)

    def collect(self) -> Iterator[dict[str, Any]]:
        rules = self._ruleset()
        if rules is None:
            return
        # The cap counts every scan attempt, matched or not.
        targets = islice(self._targets.paths(), constants.YARA_MAX_FILES_PER_CYCLE)
        for path, source in targets:
            yield from self._scan_file(path, source, rules)

    def _ruleset(self) -> yara.Rules | None:
        if not self._compiled:
            self._rules, self.compile_stats = self._compiler.compile()
            self._compiled = True
        return self._rules

    def _scan_file(
        self, path: Path, source: ScanSource, rules: yara.Rules
    ) -> Iterator[dict[str, Any]]:
        file_stat = self._scannable_stat(path)
        if file_stat is None:
            return
        scanned = ScannedFile(path, file_stat, source)
        matches = self._match(scanned, rules)
        if not matches:
            return
        sha256 = Digest().sha256_file(path)
        yield from (scanned.row(match, sha256) for match in matches)

    def _scannable_stat(self, path: Path) -> os.stat_result | None:
        try:
            if not path.is_file():
                return None
            file_stat = path.stat()  # follow symlinks: size must match bytes read
        except OSError:
            return None
        if file_stat.st_size > constants.YARA_MAX_FILE_BYTES:
            return None
        return file_stat

    def _match(self, scanned: ScannedFile, rules: yara.Rules) -> list[yara.Match]:
        # Unreadable, vanished mid-scan, or match timeout: skip this file.
        try:
            return rules.match(
                str(scanned.path),
                externals=scanned.externals(),
                timeout=constants.YARA_MATCH_TIMEOUT_S,
            )
        except yara.Error:
            return []
