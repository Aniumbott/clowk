#!/usr/bin/env python3
"""clowk PostToolUse hook: stop secrets in tool OUTPUT (file reads, command output) from reaching the model,
and record which commands use a stored secret (rotation ledger).
Redaction is post-execution: it hides the value from the model; the read/network call already happened.
ponytail: `updatedToolOutput` must be a STRING (per docs). Some Claude Code builds don't apply it yet
(inbound guard + Layer B sandbox masking are the guarantees); this runs correctly wherever it IS honored
(other CC versions, codex, opencode)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clowk.detect import scan
from clowk import store

OUTPUT_KEYS = ("tool_response", "tool_output", "output", "toolUseResult", "tool_result")
TEXT_FIELDS = ("stdout", "stderr", "output", "content")

def _get_output(data):
    for k in OUTPUT_KEYS:
        if k in data and data[k] not in (None, ""):
            return data[k]
    return None

def _redact(text):
    for key, val in store.values().items():          # known stored value -> $VAR
        if val and val in text:
            text = text.replace(val, f"${key}")
    for f in scan(text):                              # new/unstored secret -> [REDACTED]
        text = text.replace(f.secret, f"[REDACTED:{f.env}]")
    return text

def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)

    # usage tracking: note when a Bash command references a stored $VAR
    if data.get("tool_name") == "Bash":
        cmd = (data.get("tool_input") or {}).get("command", "")
        where = data.get("cwd", "")
        for key in store.values():
            if f"${key}" in cmd or f"${{{key}}}" in cmd:
                store.record_use(key, where)

    raw = _get_output(data)
    if isinstance(raw, dict):                          # Bash/Read: {stdout, stderr, ...}
        text = "\n".join(raw[f] for f in TEXT_FIELDS if isinstance(raw.get(f), str) and raw[f])
    elif isinstance(raw, str):
        text = raw
    else:
        sys.exit(0)

    redacted = _redact(text)
    if redacted != text:                               # updatedToolOutput is a single string
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PostToolUse", "updatedToolOutput": redacted}}))
    sys.exit(0)

if __name__ == "__main__":
    main()
