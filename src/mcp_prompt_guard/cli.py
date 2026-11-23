"""CLI entry point for inspecting untrusted text or MCP payloads via stdin or file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .guard import GuardMode, MCPPromptGuard, PromptInjectionBlockedError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-prompt-guard",
        description="Inspect and sanitize untrusted MCP tool outputs against indirect prompt injection.",
    )
    parser.add_argument("file", nargs="?", help="Input file path (reads stdin if omitted).")
    parser.add_argument("--mode", choices=[m.value for m in GuardMode], default="sanitize")
    parser.add_argument("--threshold", type=int, default=40)
    parser.add_argument("--no-wrap", action="store_true", help="Disable XML untrusted boundary tags.")
    parser.add_argument("--json", action="store_true", help="Output structured JSON decision.")
    args = parser.parse_args(argv)

    raw = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    guard = MCPPromptGuard(
        mode=GuardMode(args.mode),
        threshold=args.threshold,
        wrap_untrusted_boundary=not args.no_wrap,
    )

    try:
        decision = guard.inspect_text(raw, source=args.file or "stdin")
    except PromptInjectionBlockedError as exc:
        payload = {
            "allowed": False,
            "score": exc.decision.score,
            "findings": [f.rule_id for f in exc.decision.findings],
            "removed_carriers": exc.decision.removed_carriers,
        }
        print(json.dumps(payload, indent=2) if args.json else str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "allowed": decision.allowed,
                    "score": decision.score,
                    "findings": [f.rule_id for f in decision.findings],
                    "removed_carriers": decision.removed_carriers,
                    "redacted_secrets": decision.redacted_secrets,
                    "output": decision.output,
                },
                indent=2,
            )
        )
    else:
        print(decision.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
