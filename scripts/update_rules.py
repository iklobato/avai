#!/usr/bin/env python3
"""Fetch a pinned YARA-Forge "core" rule pack into src/avai/rules/vendor/.

Pulls an exact, pinned upstream release (reproducible) and extracts its
``.yar`` / ``.yara`` files plus the upstream LICENSE/attribution into the
vendor directory, which the FileScanCollector then compiles alongside the
bundled baseline rules.

The pack is intentionally not committed to the repo by default — see
src/avai/rules/NOTICE for the licensing sign-off this requires. Stdlib
only; no third-party deps.

    python scripts/update_rules.py                  # fetch the pinned release
    python scripts/update_rules.py --version 20250901   # bump the pin
"""

from __future__ import annotations

import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

# Pinned YARA-Forge release (tags are date-stamped YYYYMMDD). Bump
# deliberately (and re-run the licensing review) rather than tracking
# "latest".
DEFAULT_VERSION = "20260614"
ASSET = "yara-forge-rules-core.zip"
_URL = "https://github.com/YARAHQ/yara-forge/releases/download/{version}/" + ASSET

_RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "avai" / "rules"
_VENDOR_DIR = _RULES_DIR / "vendor"

_RULE_SUFFIXES = (".yar", ".yara")
_KEEP_ALSO = ("license", "notice", "readme")  # attribution files, lowercased stem match


def _download(version: str) -> bytes:
    url = _URL.format(version=version)
    print(f"fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "avai-update-rules"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (pinned host)
        return resp.read()


def _extract(blob: bytes, dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for member in zf.namelist():
            name = Path(member).name
            if not name:
                continue
            stem = Path(name).stem.lower()
            is_rule = Path(name).suffix.lower() in _RULE_SUFFIXES
            is_attribution = any(k in stem for k in _KEEP_ALSO)
            if not (is_rule or is_attribution):
                continue
            # Flatten into dest; never honour absolute or parent paths (zip-slip).
            target = dest / name
            target.write_bytes(zf.read(member))
            written += 1
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", default=DEFAULT_VERSION, help="YARA-Forge release tag"
    )
    args = parser.parse_args()

    try:
        blob = _download(args.version)
    except OSError as exc:
        print(f"download failed: {exc}", file=sys.stderr)
        return 1
    count = _extract(blob, _VENDOR_DIR)
    print(f"wrote {count} file(s) to {_VENDOR_DIR}")
    print("Review licensing (src/avai/rules/NOTICE) before committing vendor/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
