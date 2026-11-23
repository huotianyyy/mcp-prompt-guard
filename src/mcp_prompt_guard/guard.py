"""Core MCPPromptGuard middleware for inspecting, sanitizing, and wrapping MCP tool outputs."""

from __future__ import annotations

import copy
import inspect
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable

from .detector import DetectionResult, Finding, InjectionDetector
from .redactor import SecretRedactor
from .sanitizer import TextSanitizer


class GuardMode(str, Enum):
    BLOCK = "block"
    SANITIZE = "sanitize"
    AUDIT = "audit"


class PromptInjectionBlockedError(RuntimeError):
    """Raised when GuardMode.BLOCK rejects a high-risk tool output."""

    def __init__(self, decision: GuardDecision) -> None:
        self.decision = decision
        rule_ids = ", ".join(f.rule_id for f in decision.findings)
        super().__init__(
            f"MCP tool output blocked by mcp-prompt-guard (score={decision.score}, rules=[{rule_ids}])"
        )


@dataclass
class GuardDecision:
    allowed: bool
    output: str
    score: int
    findings: list[Finding] = field(default_factory=list)
    removed_carriers: list[str] = field(default_factory=list)
    redacted_secrets: list[str] = field(default_factory=list)


class MCPPromptGuard:
    """End-to-end defense pipeline for untrusted MCP tool outputs."""

    def __init__(
        self,
        mode: GuardMode = GuardMode.SANITIZE,
        threshold: int = 40,
        wrap_untrusted_boundary: bool = True,
        sanitizer: TextSanitizer | None = None,
        detector: InjectionDetector | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.mode = mode
        self.wrap_untrusted_boundary = wrap_untrusted_boundary
        self.sanitizer = sanitizer or TextSanitizer()
        self.detector = detector or InjectionDetector(threshold=threshold)
        self.redactor = redactor or SecretRedactor()

    def inspect_text(self, text: str, source: str = "mcp_tool") -> GuardDecision:
        san = self.sanitizer.sanitize(text)
        # Scan both original and sanitized forms to catch concealed comment payloads
        raw_scan: DetectionResult = self.detector.scan(text)
        clean_scan: DetectionResult = self.detector.scan(san.cleaned)

        merged_findings: dict[str, Finding] = {f.rule_id: f for f in raw_scan.findings}
        for f in clean_scan.findings:
            merged_findings.setdefault(f.rule_id, f)
        findings = list(merged_findings.values())
        score = sum(f.severity for f in findings)
        # Extra risk weight if concealed carriers were present alongside suspicious patterns
        if san.modified and findings:
            score += 15

        red = self.redactor.redact(san.cleaned)
        safe_text = red.redacted
        blocked = score >= self.detector.threshold

        if blocked and self.mode == GuardMode.BLOCK:
            decision = GuardDecision(
                allowed=False,
                output="",
                score=score,
                findings=findings,
                removed_carriers=san.removed_carriers,
                redacted_secrets=red.redacted_types,
            )
            raise PromptInjectionBlockedError(decision)

        if blocked and self.mode == GuardMode.SANITIZE:
            for f in findings:
                safe_text = safe_text.replace(f.matched_text, f"[NEUTRALIZED:{f.rule_id}]")

        if self.wrap_untrusted_boundary and self.mode != GuardMode.AUDIT:
            safe_text = (
                f'<untrusted_tool_output source="{source}">\n'
                f"{safe_text}\n"
                f"</untrusted_tool_output>"
            )

        return GuardDecision(
            allowed=not blocked or self.mode != GuardMode.BLOCK,
            output=safe_text if self.mode != GuardMode.AUDIT else text,
            score=score,
            findings=findings,
            removed_carriers=san.removed_carriers,
            redacted_secrets=red.redacted_types,
        )

    def guard_mcp_response(self, response: dict[str, Any], source: str = "mcp_tool") -> dict[str, Any]:
        """Guards an MCP JSON-RPC `tools/call` result dict containing a `content` array."""
        guarded = copy.deepcopy(response)
        content = guarded.get("content")
        if not isinstance(content, list):
            return guarded

        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                decision = self.inspect_text(item["text"], source=source)
                item["text"] = decision.output
        return guarded

    def protect_tool(self, source: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for guarding sync or async MCP tool handlers returning str or MCP response dicts."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_source = source or func.__name__

            def _apply(result: Any) -> Any:
                if isinstance(result, str):
                    return self.inspect_text(result, source=tool_source).output
                if isinstance(result, dict) and "content" in result:
                    return self.guard_mcp_response(result, source=tool_source)
                return result

            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    return _apply(await func(*args, **kwargs))

                return async_wrapper

            @wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return _apply(func(*args, **kwargs))

            return sync_wrapper

        return decorator
