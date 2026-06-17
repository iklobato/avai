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
from pathlib import Path

_RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "avai" / "rules"
_VENDOR_DIR = _RULES_DIR / "vendor"
_RULE_SUFFIXES = (".yar", ".yara")
_ATTRIBUTION_STEMS = ("license", "notice", "readme")  # lowercased stem match


# Each source pins an exact upstream ref for reproducibility. Bump a pin
# deliberately (and re-check attribution) rather than tracking "latest".
class _Source:
    def __init__(self, name, url, archive, ref, member_filter):
        self.name = name
        self.url = url  # may contain {ref}
        self.archive = archive  # "zip" | "tar.gz"
        self.ref = ref
        self.member_filter = member_filter  # (member_name) -> bool


def _signature_base_member(name: str) -> bool:
    # Keep yara/*.yar|*.yara rules and the top-level LICENSE for attribution.
    p = Path(name)
    if "/yara/" in name and p.suffix.lower() in _RULE_SUFFIXES:
        return True
    return p.stem.lower() in _ATTRIBUTION_STEMS and p.suffix.lower() in (
        "",
        ".txt",
        ".md",
    )


def _yara_forge_member(name: str) -> bool:
    p = Path(name)
    return p.suffix.lower() in _RULE_SUFFIXES or p.stem.lower() in _ATTRIBUTION_STEMS


SOURCES = {
    # Florian Roth's signature-base — individual .yar files, DRL 1.1 (permits
    # MIT bundling with attribution). Fetched as a tarball at a pinned commit.
    "signature-base": _Source(
        name="signature-base",
        url="https://github.com/Neo23x0/signature-base/archive/{ref}.tar.gz",
        archive="tar.gz",
        ref="3b78d4102c12e6059ff71a6157909f1e4d3e3450",  # 2026-06-15
        member_filter=_signature_base_member,
    ),
    # YARA-Forge "core" — one consolidated .yar, mixed-license (needs a
    # sign-off before committing). Released as a date-stamped zip.
    "yara-forge": _Source(
        name="yara-forge",
        url="https://github.com/YARAHQ/yara-forge/releases/download/{ref}/yara-forge-rules-core.zip",
        archive="zip",
        ref="20260614",
        member_filter=_yara_forge_member,
    ),
}


def _download(url: str) -> bytes:
    print(f"fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "avai-update-rules"})
    with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (pinned host)
        return resp.read()


def _safe_target(dest: Path, member_name: str) -> Path:
    """Flatten a member to ``dest/<basename>``, refusing empty / traversal
    names (zip-slip / tar-slip)."""
    base = Path(member_name).name
    if not base or base in (".", ".."):
        raise ValueError(f"unsafe member name: {member_name!r}")
    return dest / base


def _extract_zip(blob: bytes, dest: Path, keep) -> int:
    written = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for name in zf.namelist():
            if name.endswith("/") or not keep(name):
                continue
            _safe_target(dest, name).write_bytes(zf.read(name))
            written += 1
    return written


def _extract_tar_gz(blob: bytes, dest: Path, keep) -> int:
    written = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not keep(member.name):
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            _safe_target(dest, member.name).write_bytes(src.read())
            written += 1
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=sorted(SOURCES),
        default="signature-base",
        help="which rule pack to fetch (default: signature-base)",
    )
    parser.add_argument("--ref", help="override the pinned commit/tag")
    args = parser.parse_args()

    source = SOURCES[args.source]
    ref = args.ref or source.ref
    dest = _VENDOR_DIR / source.name
    dest.mkdir(parents=True, exist_ok=True)

    try:
        blob = _download(source.url.format(ref=ref))
    except OSError as exc:
        print(f"download failed: {exc}", file=sys.stderr)
        return 1

    extractor = _extract_tar_gz if source.archive == "tar.gz" else _extract_zip
    count = extractor(blob, dest, source.member_filter)
    print(f"wrote {count} file(s) to {dest}")
    print("Opt-in pack: not committed, not shipped. See src/avai/rules/NOTICE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
