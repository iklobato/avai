"""Hashing collaborator.

Groups the package's content-addressing primitives — file hashing, the
stable per-row content hash used for dedup, and OpenSSH-style public-key
fingerprints — behind one cohesive type. These are pure transforms with
no state or I/O seam, so they're exposed as static methods; the class
exists to give them one cohesive home rather than scattering free
functions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Iterable, Optional


class Digest:
    """Content-addressing helpers."""

    @staticmethod
    def sha256_file(path: Path, chunk: int = 65536) -> Optional[str]:
        """SHA-256 hex digest of a file's bytes, or ``None`` if unreadable."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(chunk), b""):
                    h.update(block)
        except OSError:
            return None
        return h.hexdigest()

    @staticmethod
    def of_row(row: dict, fields: Iterable[str]) -> Optional[str]:
        """Stable SHA-256 over the declared judgeable fields of a row.

        Order-independent across callers because the field list is fixed
        by the collector; ``None`` when no fields are declared.
        """
        keys = list(fields)
        if not keys:
            return None
        canonical = json.dumps(
            [row.get(k) for k in keys],
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def ssh_fingerprint(b64key: str) -> Optional[str]:
        """SHA256 fingerprint of an SSH public-key blob, OpenSSH-style
        (``SHA256:<base64 of sha256(raw key), unpadded>``)."""
        try:
            raw = base64.b64decode(b64key, validate=True)
        except (ValueError, binascii.Error):
            return None
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
