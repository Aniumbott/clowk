# clowk

Catches credentials you paste into an AI coding agent's chat **before they reach the model**,
files them locally, and records where each one came from.

Works with Claude Code, Codex, and Gemini CLI. Claude Code is the host it has been proven live on;
`NOTES.md` records what is verified per host and what is not.

## What it does

You paste an API key into the chat. A local hook scans the prompt before it is transmitted. If it
finds a credential, the turn is **blocked** — the model receives nothing, and on Claude Code the
blocked prompt is not written to the transcript either (verified there; not checked on the other
two hosts) — the value is filed in `~/.clowk/vault.json`, and you get your prompt back with the
credential replaced by `$STRIPE_SECRET_KEY`, put on your clipboard if a clipboard tool is
available. Repaste and carry on.

Each entry records the working directory of the session that pasted it, so `clowk uses` can tell
you where a credential came from — a starting point for what a rotation will touch. (The vault
reserves a `used by` list per credential, but nothing in this version fills it in automatically:
expect it to read `(nothing recorded yet)`.)

A second hook denies the easy accidental credential reads: `.env`, private keys, the vault itself,
and commands like `git credential fill` that print a live token in one line.

## What it is not

**clowk is not a security boundary.** It runs as the same OS user as the agent, so whatever clowk
can read, `cat` can read. It stops accidents — a pasted key reaching the model, a credential in a
command's output, a careless `cat` — and it does not stop an agent that is deliberately trying to
extract a value.

Specifically, it does **not** protect against:

- **Hook failure.** Every host fails open: if the hook crashes or times out, your prompt is
  transmitted. clowk raises the bar; it cannot guarantee interception.
- **Files you `@`-mention.** The host reads those, not clowk.
- **Grep**, which shows file contents to the model. The deny hook is registered on `Bash` and
  `Read` only, so anything else that reads a file goes around it.
- **Unrecognised formats.** Detection is regex over 220 gitleaks rules. A novel or custom
  credential shape goes straight through.

A real boundary needs a separate OS user, a container with clowk outside it, or a code-signed
binary holding an OS keychain ACL. None of those is what this tool is.

## Install

Requires `python3` (3.8+) on PATH. No pip installs — standard library only.

```bash
git clone https://github.com/<you>/clowk.git
cd clowk
python3 clowk/cli.py install              # Claude Code
python3 clowk/cli.py install codex        # Codex
python3 clowk/cli.py install gemini-cli   # Gemini CLI
```

Then restart the agent. `install` merges into your existing settings, backs the file up first, and
refuses to touch it if it is not valid JSON. `uninstall` removes only clowk's own entries.

The registered hook command holds this clone's absolute path, so if you move or rename the
directory, re-run `install` from the new location (and `uninstall` from the old one first).

On Codex, hooks require trust: run `/hooks` and approve clowk. Because trust is hash-based, every
clowk update will ask again.

## Use

There is no installed `clowk` binary — the CLI is `python3 <clone>/clowk/cli.py`. Alias it:

```bash
alias clowk='python3 ~/clowk/clowk/cli.py'
```

```
clowk list                 stored credentials — names and metadata, never values
clowk add NAME             type a credential at the terminal instead of pasting it in chat
clowk set NAME             replace a value after rotating it upstream
clowk clear NAME           forget one
clowk rename OLD NEW       rename one
clowk uses [NAME]          where a credential was caught, and its (unfilled) used-by list
clowk allow PATTERN        stop denying a path or command
clowk install [HOST]       register clowk's hooks; uninstall removes them
```

`add` and `set` never take the value as an argument — that would put it in your shell history.

To send a message without scanning it, start it with `unclowk`.

Inside Claude Code, `/clowk` runs the same commands, except `add` and `set`: those need a terminal
to type the value into, so run them in your own shell.

## Storage

`~/.clowk/vault.json`, mode 0600 on POSIX (on Windows it relies on user-profile ACLs). Set
`CLOWK_VAULT` to move it, and `CLOWK_DENY` to move the deny hook's config.

**Plaintext, deliberately.** Encryption cannot help here: clowk runs as the same user as the agent,
so any key would have to be reachable by that same user. This is the same posture as
`~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json` and an unencrypted `id_rsa`. Because the
file is plain JSON, reading it is also your export and backup path — there is nothing to lock you
out of your own credentials.

## False positives

124 of the 220 rules match on shape rather than a literal vendor prefix, so a legitimate prompt can
be blocked. (That count is deliberately conservative: a pinned format with no trailing separator,
like `AKIA…`, is counted as shape-only too.) Every block message tells you how to bypass
(`unclowk`), and shape-only matches are flagged in `clowk list` so they are easy to purge with
`clowk clear NAME`.

## Updating the ruleset

`clowk/rules.json` is generated from `clowk/gitleaks.toml` by `build_rules.py`. Re-run it to refresh.

## Attribution

Secret patterns derive from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT License).

## License

MIT — see `LICENSE`.
