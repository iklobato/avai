"""Jinja template filters: markdown, times, sizes, JSON, flags."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from flask import Flask

_MINUTE_S = 60
_HOUR_S = 3600
_DAY_S = 86400
_KIB = 1024
_COUNTRY_CODE_LEN = 2

try:
    import bleach as _bleach
    import markdown as _markdown

    _HAS_MARKDOWN = True
except ImportError:  # pragma: no cover - depends on optional extras
    _HAS_MARKDOWN = False


_MD_TAGS = [
    "p",
    "br",
    "strong",
    "em",
    "code",
    "pre",
    "blockquote",
    "hr",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
]


_LIST_ITEM_RE = re.compile(r"^\s*([-*+]\s+|\d+[.)]\s+)")


def _ensure_list_blank_lines(text: str) -> str:
    """Insert a blank line before a list that directly follows a non-list
    text line. The narrator (like most LLMs) writes ``**Timeline:**`` then a
    ``- item`` bullet on the very next line; python-markdown won't treat a
    list as interrupting a paragraph without a preceding blank line, so
    without this the bullets render as literal ``- `` text."""
    out: list[str] = []
    prev = ""
    for line in text.split("\n"):
        is_item = bool(_LIST_ITEM_RE.match(line))
        if (
            is_item
            and prev.strip()
            and not _LIST_ITEM_RE.match(prev)
            and not prev.lstrip().startswith("```")
        ):
            out.append("")
        out.append(line)
        prev = line
    return "\n".join(out)


def render_markdown(text: str) -> str:
    """LLM-written markdown → sanitised HTML. Falls back to HTML-escaped
    text (newlines preserved via CSS) when the optional libs are missing."""
    from markupsafe import Markup, escape

    if not text:
        return Markup("")
    if not _HAS_MARKDOWN:
        return Markup(f'<div class="whitespace-pre-line">{escape(text)}</div>')
    html = _markdown.markdown(
        _ensure_list_blank_lines(text),
        extensions=["fenced_code", "tables", "sane_lists"],
    )
    clean = _bleach.clean(html, tags=_MD_TAGS, attributes={}, strip=True)
    return Markup(clean)


def _relative_time(iso_string: str) -> str:
    """Short relative-time string like '5m ago' for an ISO timestamp."""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
    except (ValueError, TypeError):
        return str(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < _MINUTE_S:
        return f"{seconds}s ago"
    if seconds < _HOUR_S:
        return f"{seconds // _MINUTE_S}m ago"
    if seconds < _DAY_S:
        return f"{seconds // _HOUR_S}h ago"
    return f"{seconds // _DAY_S}d ago"


def _datetime_fmt(iso_string: str) -> str:
    """Human-readable absolute timestamp (UTC) like 'May 30, 2026 · 18:57:20
    UTC' from a stored ISO string. Returns the input unchanged if it isn't a
    parseable timestamp, and '' for empty input."""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
    except (ValueError, TypeError):
        return str(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%b %d, %Y · %H:%M:%S UTC")


def _pretty_json(value) -> str:
    """Re-serialize a JSON string with indentation. Pass non-JSON through."""
    if value in (None, "", b""):
        return ""
    try:
        return __import__("json").dumps(__import__("json").loads(value), indent=2)
    except Exception:
        return str(value)


def _human_bytes(n) -> str:
    """Human-readable data volume (e.g. 927 -> '927 B', 12345 -> '12.1 KB',
    5e6 -> '4.8 MB'). Returns '' for 0/None/unknown so the template can
    fall back to a packet count."""
    if not isinstance(n, (int, float)) or n <= 0:
        return ""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < _KIB or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= _KIB
    return ""


def _flag_emoji(cc) -> str:
    """Render a 2-letter ISO country code as its flag emoji (regional
    indicator symbols), e.g. 'US' -> 🇺🇸. Empty string for anything that
    isn't a clean 2-letter code."""
    if not isinstance(cc, str) or len(cc) != _COUNTRY_CODE_LEN or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc.upper())


def register_filters(app: Flask) -> None:
    app.add_template_filter(render_markdown, "markdown")
    app.add_template_filter(_relative_time, "relative_time")
    app.add_template_filter(_datetime_fmt, "datetime_fmt")
    app.add_template_filter(_human_bytes, "human_bytes")
    app.add_template_filter(_flag_emoji, "flag_emoji")
    app.add_template_filter(_pretty_json, "pretty_json")
