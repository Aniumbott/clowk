"""Per-host adapters for the pre-transmit prompt hook.

Verified 2026-07-29:
  claude-code  UserPromptSubmit  ~/.claude/settings.json      block: {"decision":"block"} (proven live)
  codex        UserPromptSubmit  ~/.codex/hooks.json          block: exit 2 + stderr reason
  gemini-cli   BeforeAgent       settings.json -> hooks       block: exit 2 + stderr reason

None of the three can rewrite the prompt, which is why block-and-repaste is the universal UX.
All three FAIL OPEN on hook error or timeout -- a crash here means the secret is transmitted.
That is why this module imports nothing but the stdlib and cannot raise.

gemini-cli's BeforeAgent payload shape is NOT verified by this project, so the prompt key is
discovered from PROMPT_KEYS rather than hardcoded. `clowk debug-payload` dumps what a host
actually sends, so a contributor can confirm or extend the list.
"""
import json
import sys

PROMPT_KEYS = ("prompt", "message", "user_message", "user_prompt", "text")

HOSTS = {
    "claude-code": {"event": "UserPromptSubmit", "block": "json"},
    "codex": {"event": "UserPromptSubmit", "block": "exit2"},
    "gemini-cli": {"event": "BeforeAgent", "block": "exit2"},
}


def read_event(payload):
    """Normalise a host payload to {"prompt", "cwd", "session_id"}. Never raises."""
    if not isinstance(payload, dict):
        payload = {}
    prompt = ""
    for key in PROMPT_KEYS:
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate:
            prompt = candidate
            break
    cwd = payload.get("cwd")
    session = payload.get("session_id")
    return {
        "prompt": prompt,
        "cwd": cwd if isinstance(cwd, str) else "",
        "session_id": session if isinstance(session, str) else "",
    }


def block(host, reason, stdout=None, stderr=None):
    """Emit the host's block output. Returns the exit code the caller must use."""
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    style = HOSTS.get(host, {}).get("block", "exit2")
    if style == "json":
        stdout.write(json.dumps({"decision": "block", "reason": reason}))
        return 0
    stderr.write(reason)
    return 2
