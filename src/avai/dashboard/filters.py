"""Jinja template filters: markdown, times, sizes, JSON, flags."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import bleach
import markdown
from flask import Flask
from markupsafe import Markup

from avai.host_monitor.runtime import Clock

MARKDOWN_TAGS = (
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
)


class MarkdownRenderer:
    """LLM-written markdown to sanitised HTML."""

    LIST_ITEM = re.compile(r"^\s*([-*+]\s+|\d+[.)]\s+)")
    EXTENSIONS = ("fenced_code", "tables", "sane_lists")

    def render(self, text: str) -> Markup:
        if not text:
            return Markup("")
        html = markdown.markdown(
            self._list_spacing(text), extensions=list(self.EXTENSIONS)
        )
        return Markup(
            bleach.clean(html, tags=list(MARKDOWN_TAGS), attributes={}, strip=True)
        )

    def _list_spacing(self, text: str) -> str:
        """Insert a blank line before a list that directly follows a text
        line. LLMs write ``**Timeline:**`` then a ``- item`` on the next line;
        python-markdown won't let a list interrupt a paragraph without a
        blank line, so the bullets would render as literal ``- `` text."""
        lines: list[str] = []
        previous = ""
        for line in text.split("\n"):
            if self._starts_list(line, previous):
                lines.append("")
            lines.append(line)
            previous = line
        return "\n".join(lines)

    def _starts_list(self, line: str, previous: str) -> bool:
        return bool(
            self.LIST_ITEM.match(line)
            and previous.strip()
            and not self.LIST_ITEM.match(previous)
            and not previous.lstrip().startswith("```")
        )


class TimeLabels:
    """Relative and absolute labels for stored ISO timestamps."""

    # (seconds per unit, suffix), coarsest last
    UNITS = ((1, "s"), (60, "m"), (3600, "h"), (86400, "d"))

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def relative(self, iso_string: str) -> str:
        """Short relative-time string like '5m ago'."""
        moment = self._parse(iso_string)
        if moment is None:
            return str(iso_string or "")
        seconds = int((self._clock.now() - moment).total_seconds())
        if seconds < 0:
            return "just now"
        fitting = [unit for unit in self.UNITS if seconds >= unit[0]] or [self.UNITS[0]]
        size, suffix = fitting[-1]
        return f"{seconds // size}{suffix} ago"

    def absolute(self, iso_string: str) -> str:
        """'May 30, 2026 · 18:57:20 UTC'; the input unchanged if it isn't a
        timestamp, and '' for empty input."""
        moment = self._parse(iso_string)
        if moment is None:
            return str(iso_string or "")
        return moment.astimezone(timezone.utc).strftime("%b %d, %Y · %H:%M:%S UTC")

    def _parse(self, iso_string: str) -> datetime | None:
        if not iso_string:
            return None
        try:
            moment = datetime.fromisoformat(iso_string)
        except (ValueError, TypeError):
            return None
        return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


class ValueLabels:
    """Sizes, JSON and country flags as the templates show them."""

    KIB = 1024
    BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")
    JSON_INDENT = 2
    COUNTRY_CODE_LEN = 2
    # REGIONAL INDICATOR SYMBOL LETTER A: flags are two such letters.
    REGIONAL_A = 0x1F1E6

    def human_bytes(self, size: Any) -> str:
        """927 -> '927 B', 12345 -> '12.1 KB', 5e6 -> '4.8 MB'; '' for
        0/None/unknown so the template can fall back to a packet count."""
        if not isinstance(size, (int, float)) or size <= 0:
            return ""
        scaled, unit = float(size), self.BYTE_UNITS[0]
        for unit in self.BYTE_UNITS:
            if scaled < self.KIB or unit == self.BYTE_UNITS[-1]:
                break
            scaled /= self.KIB
        return f"{int(scaled)} B" if unit == "B" else f"{scaled:.1f} {unit}"

    def pretty_json(self, value: Any) -> str:
        """Re-serialize a JSON string with indentation; pass non-JSON through."""
        if value in (None, "", b""):
            return ""
        try:
            return json.dumps(json.loads(value), indent=self.JSON_INDENT)
        except (ValueError, TypeError):
            return str(value)

    def flag_emoji(self, code: Any) -> str:
        """A 2-letter ISO country code as its flag emoji, e.g. 'US'; '' for
        anything that isn't a clean 2-letter code."""
        if (
            not isinstance(code, str)
            or len(code) != self.COUNTRY_CODE_LEN
            or not code.isalpha()
        ):
            return ""
        return "".join(
            chr(self.REGIONAL_A + ord(letter) - ord("A")) for letter in code.upper()
        )


class TemplateFilters:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def register(self, app: Flask) -> None:
        times, values = TimeLabels(self._clock), ValueLabels()
        app.add_template_filter(MarkdownRenderer().render, "markdown")
        app.add_template_filter(times.relative, "relative_time")
        app.add_template_filter(times.absolute, "datetime_fmt")
        app.add_template_filter(values.human_bytes, "human_bytes")
        app.add_template_filter(values.flag_emoji, "flag_emoji")
        app.add_template_filter(values.pretty_json, "pretty_json")
