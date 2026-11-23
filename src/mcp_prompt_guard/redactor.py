"""Secret redaction for preventing accidental credential exposure through MCP tool responses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]


DEFAULT_SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    SecretPattern("GITHUB_TOKEN", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    SecretPattern("API_KEY_SK", re.compile(r"\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    SecretPattern("AWS_ACCESS_KEY", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b")),
)


@dataclass
class RedactionResult:
    redacted: str
    redacted_types: list[str] = field(default_factory=list)


class SecretRedactor:
    """Masks leaked API keys, tokens, and private keys before tool output reaches the LLM context."""

    def __init__(self, patterns: tuple[SecretPattern, ...] = DEFAULT_SECRET_PATTERNS) -> None:
        self.patterns = patterns

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(redacted="")

        current = text
        hits: list[str] = []
        for sp in self.patterns:
            updated, count = sp.pattern.subn(f"[REDACTED:{sp.name}]", current)
            if count > 0:
                hits.append(sp.name)
                current = updated
        return RedactionResult(redacted=current, redacted_types=hits)
