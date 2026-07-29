# clowk — architecture

Date: 2026-07-29. **Supersedes** `2026-07-29-clowk-restructure-design.md`, all of `HANDOFF.md`, and
the Layer A / Layer B framing in `DESIGN.md`. Companion diagram: `clowk-architecture.svg`.

## 1. Principle

The agent never holds a usable credential. It holds a **reference**. A local broker holds real
values in memory and applies them at the moment of use, through whatever mechanism the target tool
already supports natively.

Everything that made the previous design complicated — scrubbing output, wrapping every command,
parsing hosts out of command strings, masking env vars behind an OS sandbox — was damage control
for handing the agent a real value and then playing defense. Don't hand it over.

## 2. Why this shape and not the previous one

The previous design gave the agent real values and defended them. That produced, in order:
output scrubbing → wrap every Bash command → base64 command handoff → double-wrap guards →
chunk-overlap streaming → byte-safety for binary output → host-string parsing. Each step was a
patch on the step before, and two of them contradicted each other (least-privilege injection needs
the secret named in the command; `npm run deploy` never names it).

Complexity that grows like that is the signal the root choice is wrong. This design deletes the
root choice.

## 3. Threat model

**Accident-proof, zero hassle.** No OS sandbox, no restart, no platform restriction.

In scope: values reaching the model or the transcript; `env`/`printenv`; a value echoed into a log,
diff, or command output; a casual read of a credential file or keychain; a prompt-injected agent
sending a key somewhere it does not belong.

Out of scope: an agent deliberately routing around the mechanism.

The claim is "the agent uses your keys without holding them", never "cannot possibly obtain one".

## 4. The broker

A per-user daemon. Real values live in its memory. On-disk vault is encrypted; the key lives in the
OS keychain (Keychain / libsecret / DPAPI). Listens on a unix socket at `~/.clowk/sock`, mode 0600
(localhost TCP plus a per-boot token on Windows). Auto-spawns on first connection; no lifecycle for
the user to manage.

**Its API is use-only. There is deliberately no `get_raw(name)` call.**

| Call | Purpose |
|---|---|
| `credential(protocol, host)` | answer a native credential-helper request |
| `forward(route, request)` | make an upstream call with the real value attached |
| `lend(names, argv, cwd)` | inject into one child process, T3 only |
| `names()` | list stored names and tiers — never values |

This is ssh-agent's discipline: clients present a reference, the agent performs the operation, the
key never leaves. Thirty years of production use behind the pattern.

## 5. Three delivery tiers

A tier is assigned per secret automatically at capture time, from the secret's type. `clowk list`
shows which tier each secret is on, so the protection level is never ambiguous.

### T1 — native credential hooks (best; no hacks, no value in env)

The ecosystem already standardised "don't store the secret, ask a program":

| Tool | Mechanism | Status |
|---|---|---|
| git | `credential.helper=clowk` | **verified working** — git invokes an arbitrary `git-credential-<name>` on PATH and consumes its `password=` output |
| aws | `credential_process` in `~/.aws/config` | official; contract to confirm at build |
| docker | `credsStore` | official; contract to confirm at build |
| kubectl | exec credential plugin | official; contract to confirm at build |

The value goes broker → tool directly. Never in env, never in argv, never in a file the agent reads.

### T2 — localhost reverse proxy (no TLS interception, no CA to trust)

The agent's env points a tool's **base URL** at the broker over plain localhost HTTP. The broker
makes the real HTTPS call outbound with the real key attached.

```
agent env:  OPENAI_API_KEY=clowk_ref_openai_a1b2      ← worthless
            OPENAI_BASE_URL=http://127.0.0.1:7799/openai
agent runs: npm run summarize                          ← ordinary command, nothing wrapped
broker:     recognises the ref, attaches the real key, calls api.openai.com
```

Covers OpenAI, Anthropic, GitHub API (`GH_HOST` / `GITHUB_API_URL`), and any SDK that takes a
configurable endpoint **and** a bearer-style credential. Env-var support per SDK is to be confirmed
at build.

**Not AWS.** SigV4 signs the canonical request, so a proxy cannot swap a header — it would have to
re-sign. AWS is T1 only, via `credential_process`. More generally, every T2 route needs its auth
scheme known (bearer / basic / custom header / query param), which is a curated table and ongoing
maintenance.

**A T2 reference is non-exfiltratable, not worthless.** It is useless off this machine and cannot be
aimed at another upstream. But it sits in plaintext env, so any same-user process — a malicious
postinstall script, a prompt-injected tool, another agent — can present it to `127.0.0.1:7799` and
spend the credential. T2 stops the key from walking; it does not stop local code from using it.

No `HTTPS_PROXY`. No man-in-the-middle. No local certificate authority. This is the decisive
simplification over the proxy sketch that preceded this document, which needed TLS termination to
rewrite an `Authorization` header and would have turned into a per-runtime trust-store fight
(`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, Java keystores, pinned clients). Redirecting the base
URL needs none of it.

**Host binding is structural.** A route only ever forwards to its own upstream, so a captured
reference cannot be pointed at an attacker. Not a heuristic that obfuscation defeats — impossible
by construction.

### T3 — scoped ephemeral injection (last resort, explicit, narrow)

For tools with neither a credential hook nor a configurable base URL — a Stripe SDK call inside
user code, Twilio, a bespoke internal API.

`clowk run -- <cmd>` puts the real value in **that one child's** env, streams the output through a
scrub pass, and logs the use. Not applied to every command: T3 secrets are few, and clowk is
therefore never in the path of `ls`, a test run, or a build.

If the agent forgets to use `clowk run`, the env holds a reference, the API returns 401, and the
error text says what to do. **Fails closed and self-corrects.** No hook rewriting is involved, so
this design does not depend on `PreToolUse` `updatedInput` — the unverified primitive that was the
previous plan's gate is no longer on the critical path.

## 6. Inbound capture — unchanged

The one part that was always right, and is verified live. `UserPromptSubmit` scans the prompt with
the 220-rule gitleaks set. On a hit the turn is blocked (the model receives nothing; nothing is
written to the transcript), the value goes to the broker, a tier is assigned, and the user gets
their prompt back rewritten with the reference name.

Two additions: `pbcopy`/`xclip` the rewritten prompt so repaste is one keystroke, and record the
detection tier so false-positive junk is easy to purge.

## 7. Defence in depth — PreToolUse deny

Not load-bearing (nothing above depends on it), and a plain `deny` rather than a rewrite, so it uses
only documented, reliable behaviour. Denies Bash and Read touching:

- `~/.clowk/`
- `.env`, `*.pem`, `id_rsa`
- **credential-extraction commands**: `git credential fill`, `security find-generic-password`,
  `git credential-osxkeychain get`, `secret-tool lookup`

That last group is not theoretical. While verifying T1 for this document, a `git credential fill`
printed a real `gho_` OAuth token to stdout from the system keychain. One line, no attack, no
clowk involvement — it is the single easiest accidental credential read on a developer machine, and
it works on any host configured with `gh` or osxkeychain.

## 8. What this deletes

`sandbox.py` · `hook_output.py` · `store.py` · wrap-every-Bash · base64 command handoff ·
double-wrap guard · global streaming scrub · chunk-overlap buffering · binary-output byte-safety ·
host-string parsing · the least-privilege-vs-indirect-reference contradiction · the dependency on
`updatedInput` · the dependency on `updatedToolOutput` · the dependency on sandbox credential
masking · `HANDOFF.md`.

Values also leave `~/.claude/settings.local.json`. That file now holds only references and base
URLs — all worthless — which means the verified env auto-reload mechanism is reused with nothing
sensitive in it.

## 8b. Human lifecycle — the CLI must own this

The inbound guard handles the accident. A person also needs the deliberate path, and none of it was
in the first draft of this document:

| Command | Why it is required |
|---|---|
| `clowk add NAME` | type a key at the terminal instead of pasting it into a chat — hidden input, never in shell history |
| `clowk set NAME` | replace a value after rotating it upstream |
| `clowk tier NAME <t1\|t2\|t3>` | auto-assignment will guess wrong; the human overrides |
| `clowk route NAME <host>` | correct or add a T2 upstream |
| `clowk export` | **recovery. Non-negotiable.** |

`export` exists because the vault is encrypted with a keychain-held key and the broker has no
raw-read API — so a broken daemon, a lost keychain entry, or a new machine would otherwise make a
user's own secrets unrecoverable. A vault that can hold data hostage is not shippable.

It is gated on an interactive TTY confirmation, which a non-interactive agent Bash call cannot
satisfy. That keeps it a human-only door without weakening the no-raw-read discipline for anything
the agent can reach.

## 9. Honest limits

- **T1 is accident-proof, not adversary-proof — and the exposure is wider than "the agent".** Any
  process running as you can call `git-credential-clowk get` and receive the real value: a malicious
  postinstall script, a prompt-injected tool, any local code. A parent-process check is spoofable and
  will be labelled a speed bump, not a control. T1's real property is that the value is not in env,
  argv, or a file the agent reads — that shrinks the accidental surface. It is not a boundary.
- **The long tail lands on the weakest tier.** Unknown secret types default to T3, so strong-tier
  coverage depends on a hand-maintained map of type → tier → upstream → auth scheme, which degrades
  quietly as the world adds APIs.
- **T3 puts a real value in one child's env and argv** for the duration of one command, so a
  same-user `ps` during that window sees it. No fix without the sandbox.
- **A file you `@`-mention** is read by the host, not by clowk. Unclosable from a hook.
- **Grep shows file contents to the model**, and it is unclear whether hooks fire for subagent tool
  calls. Both are host-side read paths outside clowk's reach. To be measured, then documented.
- **Detection is regex.** An unrecognised format goes straight through.
- **Tier coverage is not universal.** A client that pins to the real hostname or offers no endpoint
  configuration falls to T3, with T3's weaker guarantee. `clowk list` always states which tier a
  secret is on.

## 10. Multi-host

T1 and T2 need no host cooperation whatsoever — they are ordinary env vars and config files, so
codex, Gemini CLI, opencode and anything else get outbound protection for free. Only the inbound
paste guard is host-specific, and it is one small hook per host. This split is why the design is
portable where the previous one was Claude-Code-shaped.

## 11. To verify before building

Recorded explicitly, because asserting unverified platform behaviour is what broke the last two
iterations of this design:

1. `aws credential_process`, `docker credsStore`, `kubectl` exec-plugin contracts.
2. `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `AWS_ENDPOINT_URL` honoured by current SDK versions.
3. Whether hooks fire for subagent (`Task`) tool calls.
4. Whether Claude Code fails open or closed when a hook errors.
5. OS keychain read/write from a plain CLI on macOS and Linux without an interactive prompt per use.

## 12. Ship path — the reduction

**T1's premise does not hold.** Its pitch is "the value is not in a file the agent reads" — but it
is, it is in clowk's own store, and clowk runs as you. Encrypting that store buys nothing, because
the key must be reachable by the same user, so the agent reaches it too. `aws credential_process`
moves a value from `~/.aws/credentials` to `~/.clowk/vault.json`: a different path, identically
readable. For git it is worse than lateral — `gh auth login` already keeps the token in the OS
keychain rather than env, and a single `git credential fill` reads it straight back out.

Deleting encryption then removes the keychain integration (three platform code paths plus an
unresolved per-use-prompt question), the decrypt-per-invocation path, **and the entire `clowk export`
recovery problem — which existed only because of the encryption.** One removal, three things go.

Plaintext at 0600 is also ecosystem parity: `~/.aws/credentials`, `~/.npmrc`,
`~/.docker/config.json`, `.git-credentials`, an unencrypted `id_rsa`. Not a regression from the
world, and a clear improvement on `settings.local.json`, which sits in a directory people commit and
which every session's env loads wholesale.

### v1

1. **Inbound guard** — built and verified. The only part that prevents a leak at all: nothing else in
   any version of this design stops transmission to the provider.
2. **Store** — one plaintext file at 0600 in `~/.clowk/`.
3. **Lifecycle CLI** — `add / set / list / clear / rename / uses`.
4. **Rotation ledger** — first caught, source, every command that used it. This answers the original
   pain in `DESIGN.md` §1: rotating hurts because you cannot tell what depends on the key.
5. **PreToolUse deny** — `~/.clowk/`, `.env`, `*.pem`, `id_rsa`, `git credential fill`,
   `security find-generic-password`. Cheap, real accident prevention, explicitly not a boundary.

No daemon, proxy, credential helpers, tiers, encryption, or keychain. Mostly code that already
exists.

### What clowk is, stated honestly

**The thing that catches credentials at the paste boundary and tells you what depends on them.** Not
a security boundary — a capture-and-bookkeeping tool that closes the leak nobody else closes.
Capture is the seam `HANDOFF.md` §4 identified, and this document has now arrived back at it twice
from the opposite direction.

**Later, as hygiene and never as enforcement:** T1 native hooks, T2 localhost proxy (bearer APIs
only, needs a curated route and auth-scheme table), T3 `clowk run`. Each gets a value out of your
env, which is tidiness worth having — but none of them is a control, and none should be sold as one.

Form factor: a CLI installed via brew or pipx, plus a thin Claude Code plugin carrying the inbound
hook and `/clowk`. Only the plugin is host-specific.

## 12b. Multi-host support — verified, not assumed

The whole product depends on one primitive: a locally-executed hook that runs **before the prompt is
transmitted** and can block the turn. Everything else — store, ledger, CLI, detection — is ordinary
Python and ports for free.

| Host | Event | Config location | Blocks via | Rewrite prompt? | On hook error |
|---|---|---|---|---|---|
| Claude Code | `UserPromptSubmit` | `~/.claude/settings.json` | `decision: block` / exit 2 | **No** | fails open |
| Codex | `UserPromptSubmit` | `~/.codex/hooks.json` or `config.toml` | `decision: block` / exit 2 | **No** | fails open |
| Gemini CLI | `BeforeAgent` | `settings.json` → `hooks` | `decision: deny` / exit 2 | **No** (append only) | fails open |
| opencode | JS plugin API (`@opencode-ai/plugin`) | `~/.config/opencode` | plugin-defined | to verify | to verify |
| Grok CLI, Antigravity | unverified | — | — | — | — |

Claude Code and Codex both deliver a `prompt` field in a stdin JSON payload; Gemini CLI's event is
named differently and carries a different shape. All three are command hooks that block by exit code
2 or a JSON decision — so one Python core with a thin per-host adapter covers them.

**Three findings that change the design:**

1. **Every host fails open.** A crashed, slow, or timed-out hook means the secret is transmitted. This
   is the single most important fact for a published security tool and it is universal, not a
   per-host quirk. Consequences: the hook must stay defensive (stdlib only, the existing
   never-crash regex compile, no network, no imports that can fail), must stay fast enough to beat
   every host's timeout, and the README must state plainly that clowk raises the bar and cannot
   guarantee interception. Codex has an open issue requesting fail-closed for exactly this event
   (openai/codex#33630) — worth tracking, not worth waiting for.
2. **No host can rewrite the prompt.** Block-and-repaste is therefore universal rather than a Claude
   Code limitation, so the UX is identical everywhere and the clipboard convenience pays off on
   every host.
3. **Codex requires hook trust, hash-based.** Non-managed hooks must be reviewed and trusted before
   first run, and a changed hook re-triggers review — so **every clowk update prompts the user again**
   on Codex. That is an install-and-upgrade UX problem to document, not a bug to fix.

**Layout:** `clowk/core/` (detect, store, ledger — identical everywhere), `clowk/hosts/<host>.py`
(normalise the payload in, emit the host's block shape out), and `clowk install --host <name>` writing
the right config to the right place. A host whose primitive is unverified is listed as unsupported
rather than assumed to work.

The deny list ports as well: Claude Code and Codex both have `PreToolUse`, Gemini CLI has
`BeforeTool`. Codex's version can additionally rewrite `updatedInput.command`, which Claude Code's
build here ignores — noted only because it means capability differs per host and the docs must say so
per host.

### OS portability

The v1 reduction is what makes this work. The daemon, unix socket, proxy, credential helpers and the
`pty` wrapper were all platform-specific; a hook plus a JSON file plus a CLI has no platform-specific
code at all. Remaining specifics are small and must be handled honestly:

- **`chmod 0600` is effectively a no-op on Windows.** The claim must be "0600 on POSIX; on Windows the
  file relies on user-profile ACLs" — never a blanket 0600 promise.
- **Clipboard** needs `pbcopy` / `wl-copy` or `xclip` / `clip.exe`, and must degrade to just printing
  the rewritten prompt when none is present.
- Paths via `expanduser` throughout; no unix-only assumptions.

## 13. Public distribution

clowk is going out open source, so the environment is unknown. That is a design constraint, not a
packaging detail.

**The advertised guarantee is the weakest one true everywhere.** Anything stronger is conditional and
must be labelled as such. v1's claim — catches the paste, keeps the value out of session env and
committable directories, records what depends on it, no boundary — holds on any host, in any
container, on any platform. It needs no caveat about the reader's setup.

**Container hardening is documented advice, never an assumption.** For readers already running the
agent in a devcontainer, running clowk on the host with a use-only socket mounted in gives real
kernel-enforced separation. The documentation must state, prominently, that mounting
`/var/run/docker.sock` into that container voids it entirely — that is a common devcontainer
convenience, so the caveat is not academic.

**Install must not assume this machine's quirks.** Plugin-manifest hooks do not fire in build 2.1.202,
which is why `install` writes to `settings.json`. On builds where they *do* fire, doing both
double-registers: the block message appears twice and the value is stored twice. `install` must detect
or de-duplicate, and `uninstall` must fully reverse whatever it wrote.

**Never leave a stranger's `settings.json` broken.** Back it up, validate the JSON before replacing,
write atomically, and refuse with a clear message rather than guessing when the existing file will not
parse.

**The deny list must be configurable and explain itself.** Denying `.env` reads will block legitimate
work — reading a `.env.example`, debugging someone's config. A tool that silently breaks `cat` gets
uninstalled. Every denial states what was denied and how to allow it.

**False positives are now a stranger's problem.** The `unclowk` bypass belongs in every block message,
not just the documentation, and `clowk clear` has to be trivial. A wrongly-blocked prompt is the most
likely first impression.

**Plaintext at 0600 goes in the README, loudly, with the parity argument.** It is the first issue
someone will file. The answer is that encryption cannot help when the agent runs as the same user and
the key must be reachable — and that this is the same posture as `~/.aws/credentials`, `~/.npmrc` and
an unencrypted `id_rsa`.

**Build fresh rather than forking.** The OSS Claude Secrets plugin overlaps ~90% by feature list, but
the overlap is the storage half, which v1 has reduced to a single JSON file. Capture is the novel half
and it is already written. Forking would import the vault model this design spent its whole life
removing.

**Portability floor:** stdlib-only Python, a stated minimum version, the existing defensive regex
compile retained, and no unix-only path assumptions. Do not claim "first" or "only" anywhere.

### What a real boundary would require

Recorded so that "no boundary in v1" reads as a decision rather than an oversight. Three things could
actually stop a same-user read, and none is v1-cheap: a **separate OS user** for the agent (Claude
Code runs as you, so not available); a **container** with clowk on the host and a mounted socket
(genuinely enforced, but presumes containerised development); or a **macOS Keychain ACL bound to a
code-signed `clowk` binary** (OS-enforced against the same user, but macOS-only and needs a signing
certificate).

**Deferred, deliberately:** rotation and expiry (the broker log gives exact usage, which is the data
rotation needs), per-project scoping (routes give host binding, which was the security half of it),
and encryption-at-rest hardening beyond the keychain-held key.
