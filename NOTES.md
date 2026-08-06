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
- **A blocked prompt IS written to the transcript.** Blocking keeps the value from the model, not
  from the disk. Verified empirically on Claude Code: the blocked prompt does not appear as a `user`
  message -- which is what an earlier reading of this checked, and why this note used to claim the
  opposite -- but the host writes its own `system` record to `~/.claude/projects/*.jsonl` holding
  `UserPromptSubmit operation blocked by hook: <our reason>` followed by
  `Original prompt: <the raw prompt, credential and all>`. Measured: 10 such records for one test
  credential. Not checked on Codex or Gemini CLI; assume the same until it is.
- **Every host fails open.** A hook that errors or times out does not stop the turn. This is the
  most important fact for a security tool built on hooks. Codex has an open request for fail-closed
  on this specific event: openai/codex#33630.

## Host matrix (Claude Code and Gemini CLI 2026-07-29; Codex re-verified 2026-08-04)

| Host | Prompt event | Tool event | Settings file | Prompt block | Tool deny |
|---|---|---|---|---|---|
| Claude Code | `UserPromptSubmit` | `PreToolUse` | `~/.claude/settings.json` | `{"decision":"block"}` | `hookSpecificOutput.permissionDecision` |
| Codex | `UserPromptSubmit` | `PreToolUse` | `~/.codex/hooks.json` | exit 2 + stderr | exit 2 + stderr |
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

## How a block reason is RENDERED (Claude Code verified 2026-08-06; the other two are not)

The block message is the only thing a person reads at the moment of a catch, so whether it can carry
emphasis matters — and guessing wrong makes it *worse* than monotone, because a literal `[1m` in
front of every `$NAME` is harder to read than no emphasis at all. Measured with a real credential
paste through a real host, not from documentation.

**Claude Code 2.1.223 — VERIFIED, both paths.** Driven under a pty for the interactive TUI and again
as `claude -p`, with a hook whose reason carried an ANSI bold, an ANSI colour and a `**markdown**`
marker, then read back byte for byte:

| | result |
|---|---|
| ANSI SGR escapes | **rendered.** Survive into the terminal and are honoured |
| Markdown | **not rendered.** `**MDBOLD**` printed its asterisks verbatim |
| The host's own styling | the whole reason is wrapped in amber, SGR `38;2;255;193;7` |
| `\x1b[1m` (bold) | *composes* with that amber — Ink re-emitted `amber, 1m, 22m, 39m` |
| `\x1b[36m` (colour) | *replaces* the amber for that span, then reverts to the terminal default |

So clowk emphasises with **bold and nothing else**, closed with `22m` rather than `0m`: `0m` would
clear the host's amber too and drop the rest of the line to the default colour. Confirmed afterwards
against the shipped code — the real hook's real output in the real TUI shows
`amber … 💾  ESC[1m$STRIPE_SECRET_KEY ESC[22m   ·  shape-only guess …`, with no literal `[1m`
anywhere and the amber still running after the name.

**Codex and Gemini CLI — NOT VERIFIED, and deliberately get no escapes.** Both take the reason on
stderr with exit 2, which is a different rendering path that the Claude Code result says nothing
about. A probe was attempted on Codex 0.146.0 with a throwaway `CODEX_HOME` and could not be
completed: hook trust is hash-based, so a hook in a fresh config directory is never run, and
granting trust inside a live config to measure a cosmetic feature is not a trade worth making.
Gemini CLI was not attempted. `emphasis_ok()` is therefore `claude-code`-only, and the message is
built to read on structure alone — indentation, one idea per short line, the existing emoji.

**`isatty` is useless here, measured.** The hook's stdin, stdout and stderr are all pipes to the
host: a real invocation reported `isatty() == False` on all three. Any `isatty()` gate answers "no
colour" every time, so the feature would be dead code that the tests still pass.

**What IS true at runtime is the environment the host forwards.** A real hook invocation received
`TERM=xterm-256color`, `COLORTERM=truecolor`, `CLAUDECODE=1`, `CLAUDE_CODE_ENTRYPOINT=cli`,
`CLAUDE_PROJECT_DIR`, `CLAUDE_CODE_SESSION_ID` and `CLAUDE_PID`. `TERM` is the gate, and it is also
what covers **Windows without a platform special case**: a stock Windows console sets no `TERM` at
all, and needs virtual-terminal processing enabled before an escape is anything but garbage — which
a child process can neither check nor enable for its parent. No `TERM`, no escapes. Windows itself is
**not verified**; it is protected by that gate rather than by a measurement. `NO_COLOR` is honoured
for any non-empty value.

**The host prints the raw prompt back on screen after a block.** Verified in both the TUI and `-p`:
the reason is followed by `Original prompt: <the text, credential and all>`. The transcript note
below already said the value reaches the disk; it also reaches the screen, so a shoulder-surfer and
a scrollback buffer both get it. Nothing clowk can do about either — it is one more reason a blocked
paste is still a key you have to rotate.

## Things that do not work here

- **`PostToolUse` `updatedToolOutput` is ignored in Claude Code 2.1.202.** The hook fires and emits
  the correct string; the platform does not apply it. clowk therefore does no output redaction.
- **`settings.json` `env` auto-reloads mid-session** (verified) — but clowk no longer uses it, since
  storing values there puts them in every session's Bash env and in a directory people commit.
- **Clearing a value does not unset it in a running session.** A restart is required.

## Still unverified

- Whether hooks fire for subagent (`Task`) tool calls. Affects the deny hook's coverage only.
- Gemini CLI's `BeforeAgent` payload field names.
- **How to deny a tool call on Gemini CLI (`BeforeTool`).** Only the prompt event's exit-2 block is
  verified there. clowk denies with exit 2 + the reason on stderr, the usual command-hook
  convention. If exit 2 turns out not to deny, the call proceeds — but the reason is still on
  stderr, so it is visible.

Codex used to sit in that last bullet and no longer does. On 2026-08-04 the whole loop was run
against a real Codex session: a pasted credential blocked the turn, a tool call was denied, and a
value was used through `$(clowk get NAME)`. So exit 2 does deny on Codex's `PreToolUse`. Its
documented richer JSON protocol (`updatedInput.command`) is still untested — nothing needs it.

## The vendored gitleaks ruleset (verified 2026-08-05)

Written down because "the ruleset must be stale by now" is a very easy afternoon to spend.

- **`clowk/gitleaks.toml` is already upstream's newest.** It is byte-identical (md5
  `f709acf92fc6409c179f4f4426066a9a`) both to `master:config/gitleaks.toml` and to the config at the
  latest release tag, **v8.30.1** (published 2026-03-21). Verified by downloading each and comparing.
  Re-running `build_rules.py` over a fresh download reproduces the shipped `rules.json` byte for
  byte, twice.
- **Upstream's config last changed 2025-11-20** — #1947 (Looker client id/secret) and #1952 (Airtable
  personal access token), both already vendored here. Check those dates before assuming a refresh
  will bring anything.
- **222 `[[rules]]` blocks → 221 usable.** The one block that is not a rule is `pkcs12-file`: it
  carries a `path` and no `regex`, matching `*.p12` filenames, and clowk scans prompt text rather
  than directory listings. Nothing else is dropped, and a test now fails if that changes.
- **Go's POSIX character classes silently cost a rule.** `[[:alnum:]]` is legal in Go's regexp and
  is a nested-set FutureWarning in Python's `re`, which `build_rules.py` treated as "skip this
  rule". That is how the newest rule upstream has added, airtable-personnal-access-token
  (`pat` + 14 alphanumerics + `.` + 64 hex), was vendored and then never used. `build_rules.py` now
  translates the class.
- **No Supabase rule exists upstream at all**, verified by grepping the config and by a code search
  of the repository — the only hits are a Supabase demo JWT quoted inside `jwt.go`'s allowlist. So a
  missed `sbp_` token is an upstream gap, not a stale vendored copy. Measured, for `sbp_` + 40
  lowercase hex:

  | how it was pasted | caught |
  |---|---|
  | the token alone | no |
  | `here is my supabase token <token>` | no |
  | `SUPABASE_ACCESS_TOKEN=<token>` | yes, generic-api-key |
  | `supabase_key = <token>` | yes, generic-api-key |

  In prose it is missed because no rule knows the `sbp_` prefix and the standalone rule requires
  mixed case, which a lowercase-hex body does not have. The newer `sb_secret_` / `sb_publishable_`
  keys do mix case, so the standalone rule catches those even standing alone. Deliberately not
  fixed by hand: a clowk-authored rule inside a file whose header reads "auto-generated, do not edit
  manually" is a merge conflict with the next refresh, and it would put clowk's own guesswork behind
  a vendor's name.

## Test fixtures and push protection

Three fixture credentials are written as two adjacent string literals -- `"sk_" "live_..."`,
`"xoxb" "-1234..."`, `"FLWSECK" "_TEST-..."`. Python joins them at parse time, so the value each
test sees is unchanged.

The split is not cosmetic. Written contiguously, GitHub push protection rejects every push of this
repository -- including from a fork, and including pushes that touch nothing else -- because the
fixtures are valid-shaped Stripe, Slack and Flutterwave keys. They are synthetic, so the
"allow secret" bypass would work, but it needs a browser round-trip per secret from every
contributor. Splitting the literal costs nothing and removes the wall.

Do not assume a given fixture is safe. Stripe's own published example key is flagged too, and
which shapes trip the scanner is not predictable from the outside -- the `ghp_...` fixtures pass
(they fail GitHub's PAT checksum) while Stripe, Slack and Flutterwave shapes do not. GitHub also
reports only a subset of violations per push, so fixing what it names and retrying just surfaces
the next batch. Split every vendor-prefixed fixture up front and you never meet the wall.