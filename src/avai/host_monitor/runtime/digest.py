from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

READ_CHUNK_BYTES = 65536


class Digest:
    """Content-addressing helpers."""

    def sha256_file(self, path: Path) -> str | None:
        """SHA-256 hex digest of a file's bytes, or ``None`` if unreadable."""
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as stream:
                self._feed(digest, stream)
        except OSError:
            return None
        return digest.hexdigest()

    def of_row(self, row: Mapping[str, Any], fields: Iterable[str]) -> str | None:
        """Stable SHA-256 over the declared judgeable fields of a row.

        Order-independent across callers because the field list is fixed
        by the collector; ``None`` when no fields are declared.
        """
        keys = list(fields)
        if not keys:
            return None
        canonical = json.dumps(
            [row.get(key) for key in keys],
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def ssh_fingerprint(self, b64key: str) -> str | None:
        """SHA256 fingerprint of an SSH public-key blob, OpenSSH-style
        (``SHA256:<base64 of sha256(raw key), unpadded>``)."""
        try:
            raw = base64.b64decode(b64key, validate=True)
        except (ValueError, binascii.Error):
            return None
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    def _feed(self, digest: Any, stream: Any) -> None:
        for block in iter(lambda: stream.read(READ_CHUNK_BYTES), b""):
            digest.update(block)
