"""Sanitizers for stripping concealed carriers used in indirect prompt injection."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width, bidirectional override, and invisible format characters
INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u00ad\u034f\u061c]"
)

# Hidden HTML comments frequently abused in GitHub issues / web pages
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Markdown reference-style invisible comments: [//]: # (hidden payload)
MD_HIDDEN_COMMENT_RE = re.compile(r"^\[//\]:\s*#\s*\(.*?\)\s*$", re.MULTILINE)


@dataclass
class SanitizeResult:
    cleaned: str
    removed_carriers: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.removed_carriers)


class TextSanitizer:
    """Strips invisible Unicode tricks, hidden HTML/Markdown comments, and normalizes text."""

    def __init__(
        self,
        strip_html_comments: bool = True,
        strip_invisible_unicode: bool = True,
        strip_markdown_comments: bool = True,
        normalize_nfkc: bool = True,
    ) -> None:
        self.strip_html_comments = strip_html_comments
        self.strip_invisible_unicode = strip_invisible_unicode
        self.strip_markdown_comments = strip_markdown_comments
        self.normalize_nfkc = normalize_nfkc

    def sanitize(self, text: str) -> SanitizeResult:
        if not text:
            return SanitizeResult(cleaned="")

        current = text
        removed: list[str] = []

        if self.strip_html_comments:
            updated = HTML_COMMENT_RE.sub("", current)
            if updated != current:
                removed.append("html_comment")
                current = updated

        if self.strip_markdown_comments:
            updated = MD_HIDDEN_COMMENT_RE.sub("", current)
            if updated != current:
                removed.append("markdown_hidden_comment")
                current = updated

        if self.strip_invisible_unicode:
            updated = INVISIBLE_UNICODE_RE.sub("", current)
            if updated != current:
                removed.append("invisible_unicode")
                current = updated

        if self.normalize_nfkc:
            current = unicodedata.normalize("NFKC", current)

        current = re.sub(r"\n{3,}", "\n\n", current).strip()
        return SanitizeResult(cleaned=current, removed_carriers=removed)
