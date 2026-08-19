# clowk — design

The durable decisions and why they are what they are. Diagram: `assets/architecture.svg`.
Platform findings, and what is verified against what is assumed: `NOTES.md`.

## The problem

People paste API keys into agent chats. The instant they hit enter the value is transmitted, and
there is no making the model forget. There is one real defence — intercept before transmit — and it
needs one primitive: a hook that runs locally before the turn is sent.

## Why block-and-repaste

No host can rewrite a submitted prompt — verified on Claude Code, Codex and Gemini CLI. A hook can
block or append context, nothing else. So a seamless in-place swap is impossible, and the flow is
block → repaste. Putting the rewrite on the clipboard is what makes it cheap.

## Why substitution, not a wrapper

`clowk run CMD` shipped briefly: it lent the value to one child process and scrubbed it back out of
that child's output. Wrong shape. It nested a shell around the agent's own command, so the host's
permission rules matched `clowk run` rather than what actually ran — a user with `deny: Bash(rm:*)`
would have had it silently bypassed for any credential-using command.

`psql "$(clowk get DATABASE_URL)"` keeps the command intact. The shell hands the value to the
command's arguments and it never reaches a transcript. Nothing wraps anything.

So `clowk get` is the only command that prints a credential, and the guard against every other use
of it lives in the tool hook rather than in `clowk get` itself: a process cannot tell whether it was
command-substituted. Measured, not assumed — in an agent harness the parent command line is the
harness's own shell preamble, identical for a bare call and a substituted one.

The SessionStart briefing went with the wrapper. A pointer inside the repasted prompt replaces it:
nothing is advertised when no credential is involved, and it cannot go stale.

## Why the vault is one plaintext file

Values used to live in `~/.claude/settings.local.json`, which put every credential into every
session's Bash env and into a directory people commit. `~/.clowk/vault.json` at 0600 on POSIX
(user-profile ACLs on Windows) fixes both.

Encryption was designed in and then removed. It cannot help: clowk runs as the same OS user as the
agent, so any key must be reachable by that user, and the agent reaches it too. Removing it also
removed a keychain integration, three platform code paths, and an export-recovery problem that
existed only because of the encryption. Plaintext at that mode is parity with `~/.aws/credentials`,
`~/.npmrc` and an unencrypted `id_rsa`.

## Why there is no output redaction, sandbox, or credential broker

All three were built or specified and then removed:

- **Output redaction** depended on `PostToolUse` `updatedToolOutput`, which Claude Code 2.1.202
  ignores.
- **Sandbox credential masking** required a global strict sandbox, a restart, and macOS/Linux only —
  to protect one network-only env var. Never live-tested, and the value it masked no longer enters
  the agent's env.
- **A credential broker with delivery tiers** was designed in full and dropped: its premise was
  that the value is not in a file the agent reads, but it is — clowk's own store, equally readable,
  because clowk runs as the same user.

Each of those was defending a value that should not have been handed over, or a store the agent can
read anyway. What survived is capture.

## Why capture is the seam

Vaults, brokers and injection tools are a crowded category — VaultAgent, 1Password AI Agent
Identity, Doppler, Infisical, the OSS Claude Secrets plugin. Their entry point is importing or
provisioning a credential, not intercepting the one you just pasted. That survey is from 2026-07-29
and is worth redoing before it gets repeated in public copy. Interception is the part that was
already working here, so it is the part that shipped.

## Why setup verifies instead of reporting success

Registering hooks is the easy half and every failure this project has had is silent: hosts fail open,
a hook whose script has moved says nothing, an unverified payload shape scans an empty string while
looking installed. So `clowk setup` ends by firing a canary credential through the command actually
registered in the settings file and checking the turn is blocked and the value reaches neither stream.

Read back rather than recomputed, deliberately. Recomputing proves install *could* write a working
command, which is a different claim from the one on disk working, and they diverge the moment a clone
moves or an interpreter is removed.

What the canary proves is bounded and the output says so: the registered command blocks a payload
clowk understands. It cannot prove the host sends one. gemini-cli is reported unverified for that
reason rather than given a tick it has not earned.

No arrow-key interface. That needs termios on POSIX and msvcrt on Windows, and curses is not in the
Windows standard library -- two paths, one of which this project cannot test, on the cosmetic layer.
Numbered prompts work over SSH and in every terminal, and setup must run headless anyway or it is
useless from a Dockerfile.

## Why update is a command and not `git pull`

Hooks and the launcher hold absolute paths and pick up new code immediately. The skill is COPIED into
each host's skills directory and `/clowk` is GENERATED into ~/.claude/commands, so both keep serving
old content until install runs again -- new code, old skill, nothing on screen saying so. That is the
half nobody remembers, so a command does both.

It does not upgrade a packaged install for you. pipx, uv and pip each need a different verb, guessing
wrong can leave a half-replaced package, and on Windows `pip install -U` against a running package can
fail on locked files. It prints the command for the manager it can see instead.

## Why uninstall asks about the vault instead of deciding

Uninstall used to leave ~/.clowk/vault.json behind in silence, which reads two opposite ways and both
are harmful: someone clearing a machine keeps a plaintext file of live credentials they believe is
gone, and someone who wanted to keep them has no idea whether they still exist.

So the vault is always mentioned, and the default without a terminal is to keep it -- keeping is
recoverable and deleting is not. Deletion needs the word DELETE typed rather than a keystroke. The
backup is the vault's own JSON rather than a report, so restoring is a file copy instead of re-typing
every credential by hand, and it says plainly that clowk's deny hook does not cover it: that hook
knows the vault's real path and nothing else.

## Why the package and the clone are both first-class

`pip install --user` is refused outright by Homebrew, Debian, Ubuntu and Fedora Pythons under PEP 668,
so packaging cannot be the only route. A clone needs no installer at all and is immune to that, which
makes it the fallback that always works -- and the consequence is that the launcher shim cannot be
deleted, only skipped when a console_scripts entry point already exists.

The skill therefore ships twice: clowk/data/SKILL.md inside the package, because a wheel has no
repository root, and skills/clowk/SKILL.md where the Claude Code plugin spec looks. A test pins them
byte-identical rather than generating one from the other, since a generated copy ships stale from any
build that skipped the step.

## Honest positioning

"Catches what you paste, and tells you where it came from." Not a boundary — clowk runs as the same
user as the agent. Never "first" or "only".

## Where the used-by ledger is recorded

`vault.record_use` is called from `clowk get`, which is the moment of use and the most precise place
to record one. The tool hook was the earlier candidate and is deliberately not the caller: it would
put a vault read and a conditional write on every tool invocation, to catch a `$NAME` sighting that
may never resolve to a use at all.
