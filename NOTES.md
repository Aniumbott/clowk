# Environment notes

Hard-won platform findings. Verified, dated, and worth keeping — rediscovering these costs hours.

## Hook registration (Claude Code)

**Hooks declared in a plugin manifest do not fire in build 2.1.202.** They load and are counted,
but never execute. Only hooks registered in `settings.json` / `settings.local.json` run. clowk
therefore ships no manifest hooks: `clowk install` does all registration — which also makes
double-registration impossible.

If you do try a manifest: it needs `"hooks": "./hooks/<name>.json"` and the file must **not** be
named `hooks.json`, which double-registers and reports "1 error during load". Even correct, it did
not execute here.

## What the prompt hook can and cannot do

- **It cannot rewrite the prompt.** Verified on Claude Code, Codex and Gemini CLI — none of the
  three can replace prompt text. It can only block or append context. Hence block-and-repaste.
- **A blocked prompt is not written to the transcript.** Verified empirically on Claude Code: a
  blocked prompt does not appear in `~/.claude/projects/*.jsonl` as a user message. Blocking keeps
  the value from both the model and the disk. Not checked on Codex or Gemini CLI.
- **Every host fails open.** A hook that errors or times out does not stop the turn. This is the
  most important fact for a security tool built on hooks. Codex has an open request for fail-closed
  on this specific event: openai/codex#33630.

## Host matrix (verified 2026-07-29)

| Host | Prompt event | Tool event | Settings file | Prompt block | Tool deny |
|---|---|---|---|---|---|
| Claude Code | `UserPromptSubmit` | `PreToolUse` | `~/.claude/settings.json` | `{"decision":"block"}` | `hookSpecificOutput.permissionDecision` |
| Codex | `UserPromptSubmit` | `PreToolUse` | `~/.codex/hooks.json` | exit 2 + stderr | exit 2 + stderr (assumed) |
| Gemini CLI | `BeforeAgent` | `BeforeTool` | `~/.gemini/settings.json` | exit 2 + stderr | exit 2 + stderr (assumed) |

The two block shapes are **not interchangeable**: Claude Code's `PreToolUse` reads
`hookSpecificOutput`, not the prompt event's `{"decision":"block"}`, and on an exit-2 host any JSON
on stdout with exit 0 is an allow. Both shapes come out of `clowk/hosts.py` (`block` and `deny`) so
one host's dialect cannot leak into another's.

Claude Code and Codex both deliver a `prompt` field on stdin JSON. **Gemini CLI's `BeforeAgent`
payload shape is not verified by this project** — `clowk/hosts.py` discovers the prompt key from a
candidate list, and `clowk debug-payload` dumps what a host actually sends so the list can be
extended. Codex additionally requires hash-based hook trust, so every clowk update re-prompts.

opencode uses a JS plugin API rather than command hooks and would need a shim. Grok CLI and
Antigravity are unverified and unsupported.

## Things that do not work here

- **`PostToolUse` `updatedToolOutput` is ignored in Claude Code 2.1.202.** The hook fires and emits
  the correct string; the platform does not apply it. clowk therefore does no output redaction.
- **`settings.json` `env` auto-reloads mid-session** (verified) — but clowk no longer uses it, since
  storing values there puts them in every session's Bash env and in a directory people commit.
- **Clearing a value does not unset it in a running session.** A restart is required.

## Still unverified

- Whether hooks fire for subagent (`Task`) tool calls. Affects the deny hook's coverage only.
- Gemini CLI's `BeforeAgent` payload field names.
- **How to deny a tool call on Codex (`PreToolUse`) and Gemini CLI (`BeforeTool`).** Only the
  prompt event's exit-2 block is verified there. clowk denies with exit 2 + the reason on stderr,
  the usual command-hook convention; Codex's `PreToolUse` is documented to accept a richer JSON
  protocol (`updatedInput.command`) that this project has not tested. If exit 2 turns out not to
  deny on those hosts, the call proceeds — but the reason is still on stderr, so it is visible.
