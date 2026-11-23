"""mcp-prompt-guard: Defense middleware for MCP tool outputs and agent contexts."""

from .detector import DetectionResult, Finding, InjectionDetector
from .guard import GuardDecision, GuardMode, MCPPromptGuard, PromptInjectionBlockedError
from .redactor import SecretRedactor
from .sanitizer import TextSanitizer

__all__ = [
    "DetectionResult",
    "Finding",
    "GuardDecision",
    "GuardMode",
    "InjectionDetector",
    "MCPPromptGuard",
    "PromptInjectionBlockedError",
    "SecretRedactor",
    "TextSanitizer",
]

__version__ = "0.1.0"
