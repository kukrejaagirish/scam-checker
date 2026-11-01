"""Command line interface: python -m scam_checker "message" (or pipe via stdin)."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional

from .detector import Result, analyze


def format_result(result: Result) -> str:
    lines = [f"Risk: {result.level} (score {result.score}/100)"]
    if result.matches:
        lines.append("")
        lines.append("Why:")
        for m in result.matches:
            lines.append(f"  - {m.name}: {m.reason}")
            lines.append(f"    matched: {', '.join(repr(e) for e in m.evidence)}")
    else:
        lines.append("")
        lines.append("Why: no known scam pattern matched.")
    lines.append("")
    lines.append("What to do:")
    for tip in result.advice:
        lines.append(f"  - {tip}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scam_checker",
        description="Check an SMS / WhatsApp message for common Indian scam patterns.",
    )
    parser.add_argument("message", nargs="*", help="the message text (reads stdin if omitted)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    text = " ".join(args.message) if args.message else sys.stdin.read()
    if not text.strip():
        parser.error("no message given - pass it as an argument or pipe it on stdin")

    result = analyze(text)
    if args.json:
        payload = asdict(result)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_result(result))
    # Exit code 0 for Low, 1 for Medium/High so scripts can use it.
    return 1 if result.is_suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
