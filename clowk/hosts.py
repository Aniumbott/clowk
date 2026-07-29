"""Per-host adapters for both of clowk's hooks -- the pre-transmit prompt hook and the tool deny.

Prompt event, verified 2026-07-29:
  claude-code  UserPromptSubmit  ~/.claude/settings.json      block: {"decision":"block"} (proven live)
  codex        UserPromptSubmit  ~/.codex/hooks.json          block: exit 2 + stderr reason
  gemini-cli   BeforeAgent       settings.json -> hooks       block: exit 2 + stderr reason

Tool event: claude-code's PreToolUse deny shape is verified (hookSpecificOutput below). The deny
protocol on codex's PreToolUse and gemini-cli's BeforeTool is NOT verified by this project; both
get exit 2 + stderr, which is what their prompt event uses and the usual command-hook convention.
Exit 2 also blocks on claude-code, so it is the safe fallback for an unrecognised host too.

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

# "event"/"tool_event" mirror install.TARGETS: the hook is registered on those events, so the
# event a decision names has to be the one the host fired. A test pins the two together.
HOSTS = {
    "claude-code": {"event": "UserPromptSubmit", "tool_event": "PreToolUse", "block": "json"},
    "codex": {"event": "UserPromptSubmit", "tool_event": "PreToolUse", "block": "exit2"},
    "gemini-cli": {"event": "BeforeAgent", "tool_event": "BeforeTool", "block": "exit2"},
}


def host_from(argv):
    """The --host a registered hook command carries. Both hooks parse it the same way.

    Lives here rather than in either hook so the tool hook -- which runs on every Bash and Read
    call -- does not have to import the prompt hook and, with it, the whole compiled ruleset.
    """
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--host="):
            return arg.split("=", 1)[1]
    return "claude-code"


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
    """Emit the host's prompt-block output. Returns the exit code the caller must use."""
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    spec = HOSTS.get(host, {})
    if spec.get("block") == "json":
        stdout.write(json.dumps({"decision": "block", "reason": reason}))
        return 0
    stderr.write(reason)
    return 2


def deny(host, reason, stdout=None, stderr=None):
    """Emit the host's tool-call deny output. Returns the exit code the caller must use.

    Separate from block(): the prompt event's {"decision": "block"} is not what claude-code's
    PreToolUse reads, and emitting either shape on an exit-2 host is an allow with extra steps.
    """
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    spec = HOSTS.get(host, {})
    if spec.get("block") == "json":
        stdout.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": spec.get("tool_event", "PreToolUse"),
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))
        return 0
    stderr.write(reason)
    return 2
