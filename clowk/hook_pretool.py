#!/usr/bin/env python3
"""clowk PreToolUse / BeforeTool hook: deny the easy accidental credential reads.

Defence in depth. A plain deny, never a rewrite, so it relies only on documented behaviour.
Like the prompt hook, every host fails open -- so this must never crash.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import deny


def main(argv, stdin, stdout, stderr):
    try:
        payload = json.load(stdin)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    reason = deny.check(payload.get("tool_name", ""), payload.get("tool_input") or {})
    if not reason:
        return 0

    stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- fail open rather than break every tool call
        sys.exit(0)
