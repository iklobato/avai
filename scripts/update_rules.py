#!/usr/bin/env python3
"""Fetch a pinned, opt-in YARA rule pack into src/avai/rules/vendor/<source>/.

The FileScanCollector compiles every ``*.yar`` / ``*.yara`` it finds under
the rules dir, so a fetched pack is picked up automatically. Packs are
NOT committed and NOT shipped in the wheel (see src/avai/rules/NOTICE);
they're opt-in per environment. Stdlib only; no third-party deps.

    python scripts/update_rules.py                       # signature-base (default)
    python scripts/update_rules.py --source yara-forge   # YARA-Forge core
    python scripts/update_rules.py --ref <sha-or-tag>    # override the pin

signature-base rules need a crypto-enabled yara for the imphash/hash.*
rules; the rest compile on the stock PyPI wheel (the collector skips the
uncompilable files individually). See src/avai/rules/NOTICE.
"""

from __future__ import annotations

import argparse
import io
import sys
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from enum import Enum
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Protocol, TextIO

RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "avai" / "rules"
VENDOR_DIR = RULES_DIR / "vendor"
RULE_SUFFIXES = (".yar", ".yara")
ATTRIBUTION_STEMS = ("license", "notice", "readme")  # lowercased stem match
ATTRIBUTION_SUFFIXES = ("", ".txt", ".md")
DEFAULT_SOURCE = "signature-base"


class UnsafeMemberError(ValueError):
    """An archive member name would escape the destination directory."""


class ArchiveKind(Enum):
    ZIP = "zip"
    TAR_GZ = "tar.gz"


class MemberFilter(Protocol):
    def keep(self, name: str) -> bool:
        """Whether this archive member belongs in the vendored pack."""
        ...


class SignatureBaseMembers:
    """Keep yara/*.yar|*.yara rules and the top-level LICENSE for attribution."""

    def keep(self, name: str) -> bool:
        member = Path(name)
        suffix = member.suffix.lower()
        if "/yara/" in name and suffix in RULE_SUFFIXES:
            return True
        stem = member.stem.lower()
        return stem in ATTRIBUTION_STEMS and suffix in ATTRIBUTION_SUFFIXES


class YaraForgeMembers:
    def keep(self, name: str) -> bool:
        member = Path(name)
        is_rule = member.suffix.lower() in RULE_SUFFIXES
        return is_rule or member.stem.lower() in ATTRIBUTION_STEMS


# Each source pins an exact upstream ref for reproducibility. Bump a pin
# deliberately (and re-check attribution) rather than tracking "latest".
@dataclass(frozen=True)
class RuleSource:
    name: str
    url: str  # may contain {ref}
    archive: ArchiveKind
    ref: str
    members: MemberFilter


class RuleSources:
    def by_name(self) -> dict[str, RuleSource]:
        sources = (self._signature_base(), self._yara_forge())
        return {source.name: source for source in sources}

    def _signature_base(self) -> RuleSource:
        """Florian Roth's signature-base: individual .yar files, DRL 1.1
        (permits MIT bundling with attribution). Fetched as a tarball at a
        pinned commit."""
        return RuleSource(
            name="signature-base",
            url="https://github.com/Neo23x0/signature-base/archive/{ref}.tar.gz",
            archive=ArchiveKind.TAR_GZ,
            ref="3b78d4102c12e6059ff71a6157909f1e4d3e3450",  # 2026-06-15
            members=SignatureBaseMembers(),
        )

    def _yara_forge(self) -> RuleSource:
        """YARA-Forge "core": one consolidated .yar, mixed-license (needs a
        sign-off before committing). Released as a date-stamped zip."""
        return RuleSource(
            name="yara-forge",
            url="https://github.com/YARAHQ/yara-forge/releases/download/{ref}/yara-forge-rules-core.zip",
            archive=ArchiveKind.ZIP,
            ref="20260614",
            members=YaraForgeMembers(),
        )


class FlatTarget:
    """Flattens a member to ``dest/<basename>``, refusing empty / traversal
    names (zip-slip / tar-slip)."""

    def __init__(self, dest: Path) -> None:
        self._dest = dest

    def write_all(self, members: Iterable[tuple[str, bytes]]) -> int:
        written = 0
        for name, content in members:
            self._write(name, content)
            written += 1
        return written

    def _write(self, member_name: str, content: bytes) -> None:
        base = Path(member_name).name
        if not base or base in (".", ".."):
            raise UnsafeMemberError(f"unsafe member name: {member_name!r}")
        (self._dest / base).write_bytes(content)


class Extractor(Protocol):
    def extract(self, blob: bytes) -> int:
        """Write the kept members of the archive; return how many."""
        ...


class ZipExtractor:
    def __init__(self, members: MemberFilter, target: FlatTarget) -> None:
        self._members = members
        self._target = target

    def extract(self, blob: bytes) -> int:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            return self._target.write_all(self._kept(archive))

    def _kept(self, archive: zipfile.ZipFile) -> Iterator[tuple[str, bytes]]:
        for name in archive.namelist():
            if name.endswith("/") or not self._members.keep(name):
                continue
            yield name, archive.read(name)


class TarGzExtractor:
    def __init__(self, members: MemberFilter, target: FlatTarget) -> None:
        self._members = members
        self._target = target

    def extract(self, blob: bytes) -> int:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            return self._target.write_all(self._kept(archive))

    def _kept(self, archive: tarfile.TarFile) -> Iterator[tuple[str, bytes]]:
        for member in archive.getmembers():
            content = self._content(archive, member)
            if content is None:
                continue
            yield member.name, content

    def _content(
        self, archive: tarfile.TarFile, member: tarfile.TarInfo
    ) -> bytes | None:
        if not member.isfile() or not self._members.keep(member.name):
            return None
        source = archive.extractfile(member)
        return None if source is None else source.read()


class RuleDownloader:
    TIMEOUT_S = 180
    USER_AGENT = "avai-update-rules"

    def __init__(self, out: TextIO) -> None:
        self._out = out

    def fetch(self, url: str) -> bytes:
        self._out.write(f"fetching {url}\n")
        request = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT})
        opened = urllib.request.urlopen(  # noqa: S310 (pinned host)
            request, timeout=self.TIMEOUT_S
        )
        with opened as response:
            return response.read()


class UpdateRulesCli:
    def __init__(self, out: TextIO, err: TextIO) -> None:
        self._out = out
        self._err = err

    @classmethod
    def main(cls) -> int:
        return cls(sys.stdout, sys.stderr).update(sys.argv[1:])

    def update(self, argv: list[str]) -> int:
        sources = RuleSources().by_name()
        args = self._parser(sorted(sources)).parse_args(argv)
        source = sources[args.source]
        dest = VENDOR_DIR / source.name
        dest.mkdir(parents=True, exist_ok=True)
        try:
            blob = RuleDownloader(self._out).fetch(
                source.url.format(ref=args.ref or source.ref)
            )
        except OSError as exc:
            self._err.write(f"download failed: {exc}\n")
            return 1
        count = self._extractor(source, FlatTarget(dest)).extract(blob)
        self._out.write(f"wrote {count} file(s) to {dest}\n")
        self._out.write(
            "Opt-in pack: not committed, not shipped. See src/avai/rules/NOTICE.\n"
        )
        return 0

    def _extractor(self, source: RuleSource, target: FlatTarget) -> Extractor:
        extractors = {ArchiveKind.ZIP: ZipExtractor, ArchiveKind.TAR_GZ: TarGzExtractor}
        return extractors[source.archive](source.members, target)

    def _parser(self, names: list[str]) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--source",
            choices=names,
            default=DEFAULT_SOURCE,
            help="which rule pack to fetch (default: signature-base)",
        )
        parser.add_argument("--ref", help="override the pinned commit/tag")
        return parser


if __name__ == "__main__":
    raise SystemExit(UpdateRulesCli.main())
