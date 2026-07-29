#!/usr/bin/env python3
"""clowk UserPromptSubmit hook: detect pasted secrets -> store as $VAR -> block with a rewritten prompt.
Bypass: start the message with `unclowk` to send it raw (no scan)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clowk.detect import scan
from clowk import store

BYPASS = "unclowk"

def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)
    prompt = data.get("prompt", "")
    if prompt.lstrip().lower().startswith(BYPASS):   # explicit raw send
        sys.exit(0)

    findings = scan(prompt)
    if not findings:
        sys.exit(0)   # nothing detected -> pass through untouched

    source = data.get("cwd", "")
    rewritten, stored = prompt, []
    for f in findings:
        key = store.store(f.env, f.secret, source)
        rewritten = rewritten.replace(f.secret, f"${key}")
        stored.append(f"${key}")

    msg = (
        "clowk blocked a secret before it reached the model.\n"
        f"Stored locally as: {', '.join(stored)}\n\n"
        "Copy-paste this to continue (secret replaced):\n\n"
        f"    {rewritten}\n\n"
        f"To send the raw secret instead, start your message with:  {BYPASS} "
    )
    print(json.dumps({"decision": "block", "reason": msg}))
    sys.exit(0)

if __name__ == "__main__":
    main()
