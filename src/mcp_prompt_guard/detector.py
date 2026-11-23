"""Rule-based weighted detector for indirect prompt injection payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: int
    pattern: re.Pattern[str]
    description: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: int
    matched_text: str
    description: str


@dataclass
class DetectionResult:
    score: int
    threshold: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.score >= self.threshold


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PI001",
        category="instruction_override",
        severity=45,
        pattern=re.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)\b",
            re.IGNORECASE,
        ),
        description="Attempts to override system or developer instructions.",
    ),
    Rule(
        rule_id="PI002",
        category="role_hijack",
        severity=35,
        pattern=re.compile(
            r"\b(you\s+are\s+now|act\s+as\s+an?\s+unrestricted|new\s+system\s+prompt|developer\s+mode\s+enabled)\b",
            re.IGNORECASE,
        ),
        description="Attempts to hijack the assistant persona or system role.",
    ),
    Rule(
        rule_id="PI003",
        category="credential_exfiltration",
        severity=55,
        pattern=re.compile(
            r"\b(exfiltrate|steal|leak|send|upload|post)\b.{0,60}\b(api[_\s-]?key|token|secret|password|ssh|id_rsa|\.env|credentials?)\b",
            re.IGNORECASE,
        ),
        description="Attempts to instruct the agent to exfiltrate secrets or environment credentials.",
    ),
    Rule(
        rule_id="PI004",
        category="remote_code_execution",
        severity=55,
        pattern=re.compile(
            r"(curl|wget)\s+[^\n|]{1,120}\|\s*(sh|bash|zsh|python)|powershell(\.exe)?\s+-(e|enc|encodedcommand)\b",
            re.IGNORECASE,
        ),
        description="Contains obfuscated shell pipe or encoded PowerShell execution directives.",
    ),
    Rule(
        rule_id="PI005",
        category="tool_abuse",
        severity=40,
        pattern=re.compile(
            r"\b(silently\s+execute|without\s+(telling|informing|asking)\s+the\s+user|do\s+not\s+mention\s+this\s+to\s+the\s+user)\b",
            re.IGNORECASE,
        ),
        description="Attempts to coerce covert agent execution hidden from the user.",
    ),
    Rule(
        rule_id="PI006",
        category="delimiter_escape",
        severity=30,
        pattern=re.compile(
            r"(</?system>|<\|im_start\|>system|<\|endoftext\|>|\[INST\]|###\s*SYSTEM\s*INSTRUCTIONS?)",
            re.IGNORECASE,
        ),
        description="Contains special chat template delimiters used to spoof system turns.",
    ),
)


class InjectionDetector:
    """Weighted pattern scanner targeting indirect prompt injection in untrusted tool outputs."""

    def __init__(self, rules: tuple[Rule, ...] = DEFAULT_RULES, threshold: int = 40) -> None:
        self.rules = rules
        self.threshold = threshold

    def scan(self, text: str) -> DetectionResult:
        if not text:
            return DetectionResult(score=0, threshold=self.threshold)

        findings: list[Finding] = []
        total_score = 0
        for rule in self.rules:
            match = rule.pattern.search(text)
            if match:
                total_score += rule.severity
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        matched_text=match.group(0)[:120],
                        description=rule.description,
                    )
                )
        return DetectionResult(score=total_score, threshold=self.threshold, findings=findings)
