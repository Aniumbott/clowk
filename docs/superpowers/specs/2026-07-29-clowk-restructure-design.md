# clowk — restructure design

Date: 2026-07-29. Supersedes the Layer A / Layer B framing in `DESIGN.md` and all of `HANDOFF.md`.
Companion diagram: `clowk-architecture.svg`.

## 1. What clowk is

A middle layer between your credentials and a coding agent. It captures credentials that pass
through an agent session and lends them back per-command, so the agent can *use* a value it
cannot *read*.

Not a vault. Vaults hold your standing personal secrets and have a different owner and lifecycle.
clowk handles the transient case: a key you pasted into a chat because the agent needed it now.
It complements a vault; it does not replace one.

## 2. Threat model (decided)

**Accident-proof, zero hassle.** No OS sandbox, no restart, no platform restriction.

In scope: values reaching the model or the transcript; `env`/`printenv` dumps; a value echoed
into a log, diff, or command output; a casual read of a credential file; a prompt-injected agent
sending a key to an attacker host.

Out of scope: an agent deliberately routing around the mechanism. Closing that requires OS
enforcement, which requires global strict sandbox + restart + macOS/Linux only — the cost that
made the previous Layer B unshippable.

The claim is "the agent uses your keys without seeing them", never "cannot possibly see them".

## 3. Architecture

| File | Responsibility | Status |
|---|---|---|
| `detect.py` + `rules.json` | scan text, 220 gitleaks rules, keyword + entropy gated, now tiered | keep, extend |
| `vault.py` | `~/.clowk/vault.json` (0600): value + metadata, one file | replaces `store.py` |
| `hook_prompt.py` | UserPromptSubmit: catch → store → block with rewrite | keep, retarget |
| `hook_pretool.py` | PreToolUse: deny credential paths, wrap every Bash through the runner | new |
| `runner.py` | `clowk run -- <cmd>`: inject per-command, stream, scrub, record | new |
| `cli.py` | `list / clear / rename / run / install / uninstall` | extend |
| `test_clowk.py` | assert-based self-check, no framework | new |

**Deleted:** `sandbox.py` (80 untested lines — but salvage `HOST_MAP` into `runner.py`),
`hook_output.py` (its job moves into the runner, where no platform cooperation is needed),
`store.py`, `HANDOFF.md`, the plugin manifest's `hooks` key, and `DESIGN.md`'s build-log and
competitive-landscape sections.

### Inbound

Paste → `UserPromptSubmit` → `detect.py`. No match: passes through. Match: turn is blocked (the
model receives nothing and nothing is written to the transcript — both verified), the value is
filed in the vault, and the user is shown their prompt rewritten with `$NAME` to repaste.

### Outbound

Agent writes a normal command referencing `$NAME`. `PreToolUse` inspects every Bash and Read:

- **Deny** anything touching `~/.clowk/`, `.env`, `*.pem`, `id_rsa`.
- **Wrap** every other Bash command into `clowk run -- …` via `updatedInput`. Nobody types it.

`runner.py` then spawns the command as a child, injecting only the names that command mentions,
and only when the target host matches that secret's known hosts. It streams both output streams
through a scrub pass and records the use.

The agent's own environment holds nothing. `echo $NAME` returns empty.

## 4. Component contracts

**`vault.py`** — `store(name, value, source) -> str` (collision-suffixes), `get(name)`,
`values()`, `list_secrets()`, `clear(name)`, `rename(old, new)`, `record_use(name, where)`.
Single JSON file at `~/.clowk/vault.json`, mode 0600, atomic replace. Path overridable by
`CLOWK_VAULT` for tests. Depends on: stdlib only.

**`runner.py`** — `main(argv)`, invoked as `clowk run -- <cmd...>`. Depends on `vault`.

- Injects `{name: value}` for names appearing as `$NAME` or `${NAME}` in the command, gated by
  the host check.
- Streams stdout and stderr, scrubbing each chunk. Carries a `len(longest_value)-1` byte overlap
  between chunks so a value split across a read boundary still matches.
- Needles per secret: the whole value, plus its first 12 and last 12 characters. Catches the
  common accident of a CLI printing a truncated key.
- Passes stdin through, preserves a TTY when the parent has one, and exits with the child's code.

**`hook_pretool.py`** — reads the PreToolUse payload, emits `updatedInput` to wrap, or a deny
decision. Depends on `vault` (names only, never values).

**Host check** — `HOST_MAP` salvaged from `sandbox.py` maps `STRIPE_SECRET_KEY → api.stripe.com`.
Hosts are parsed out of the command string. An unknown host prompts the user once and the answer
is remembered in the vault entry. A mismatch means the value is simply not injected, and the
reason is printed.

**Detection tiers** — `build_rules.py` tags a rule `high` when its regex carries a literal vendor
prefix (`ghp_`, `AKIA`, `sk_live_`), `low` otherwise. Both still block; blocking is the only thing
that prevents transmission, so a warn tier would just leak politely. The tier changes the message
wording and is recorded in the vault so false-positive junk is easy to purge. Recovery from a false
positive is one repaste prefixed `unclowk`.

**`clowk install`** — idempotently merges the hook block into `~/.claude/settings.json`, backing
the file up first. Required because plugin-manifest hooks do not fire in this build (2.1.202) but
settings-registered ones do. `uninstall` reverses it. This is the actual ship blocker today.

## 5. Honest limits

Stated in the diagram footer and to go in the README verbatim:

- A file you `@`-mention is read by the host, not by clowk. Unclosable from a hook.
- While a command runs, the value is in the child's env and argv, so a same-user `ps` or
  `/proc/<pid>/environ` can see it. OS reality; no fix without the sandbox.
- The deny is reliable for Read, which passes a structured `file_path`, but heuristic for Bash,
  where it matches a command string: `cat $HOME/.clo*/vault.json` or a two-line Python read walks
  past it. "Casual read" is the honest claim. Mode 0600 buys nothing against a process running as
  you — the deny hook is the real control.
- The host check reads the command string, so deliberate obfuscation beats it. It exists to stop
  injection-driven exfiltration, not a determined agent.
- Detection is regex. An unrecognised format goes straight through.
- Concurrent sessions both catching a secret can lose one entry to a read-modify-write race.
  `ponytail:` note the ceiling; add a lock only if it is ever observed.

## 6. Testing

One `test_clowk.py`, assert-based, no framework, run with `python3 test_clowk.py`:

1. detect + store + block: a fake `sk_live_` key produces a block decision and a vault entry.
2. runner scrub: a command that prints an injected value yields `$NAME` in the captured output,
   and the truncated first-12 form is also scrubbed.
3. runner passthrough: exit code and stdin survive the wrap.
4. host check: a secret is not injected for a host outside its list.
5. install idempotency: running it twice leaves one hook entry and a backup.

## 7. Build order

**Step 0 is a gate.** Empirically verify that `PreToolUse` `updatedInput` is honored in this
build. `updatedToolOutput` was documented and believed verified too, and turned out inert here —
that assumption is not being made twice.

If rewrite works, wrapping is silent. If it does not, `PreToolUse` denies with
`use clowk run -- instead`, which corrects the agent in one round trip. Either way the human does
nothing, but the answer decides how `hook_pretool.py` is written.

Then, in order:

1. `vault.py` + migrate any existing entries out of `settings.local.json`.
2. `runner.py` — streaming, scrub, host check, passthrough. The bulk of the work.
3. `hook_pretool.py` — deny paths, wrap all Bash.
4. `detect.py` tiers.
5. `clowk install` / `uninstall`.
6. Delete the dead files; collapse docs to `README.md` (what it does, honest limits) plus
   `NOTES.md` (the environment gotchas, which cost hours to find and are worth keeping).

The repo is not currently under git, so this spec is not committed. Worth doing before step 1.
