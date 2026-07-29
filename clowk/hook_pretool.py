#!/usr/bin/env python3
"""clowk PreToolUse / BeforeTool hook: deny the easy accidental credential reads.

Defence in depth. A plain deny, never a rewrite, so it relies only on documented behaviour.
Like the prompt hook, every host fails open -- so this must never crash.

The deny goes out through hosts.deny, because the shape is per host: claude-code reads decision
JSON on stdout, codex and gemini-cli read exit 2 + stderr. Emitting claude-code's JSON everywhere
meant exit 0 and output the host could not parse, which those two hosts read as an allow.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import deny, hosts


def main(argv, stdin, stdout, stderr):
    try:
        text = hosts.read_payload(stdin)
    except UnicodeDecodeError as e:
        # A call clowk could not read is not a call clowk checked. Never deny on our own
        # confusion, but do not look healthy either.
        stderr.write("clowk: cannot decode this payload as %s -- NOT checking this call\n" % e.encoding)
        return 0
    try:
        payload = json.loads(text)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    reason = deny.check(payload.get("tool_name", ""), payload.get("tool_input") or {})
    if not reason:
        return 0
    return hosts.deny(hosts.host_from(argv), reason, stdout, stderr)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- fail open rather than break every tool call
        sys.exit(0)
