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

## 12. Ship path — leaner than the above

**v1 = T1 + inbound guard + the lifecycle CLI. No daemon.**

Credential helpers are short-lived processes, so they can decrypt the vault with a keychain-held key
per invocation. That removes the socket, the port, the proxy, the per-API auth adapters, and any
lifecycle for the user to manage — the largest source of complexity and of Windows second-code-paths
in this document.

Everything T1 does not cover stays an ordinary env var: no protection, but captured, listed,
tiered and rotatable, and labelled honestly as unprotected. That is a narrower pitch than "the agent
never holds a credential", and it is one that can be defended line by line.

**v2 = T2 proxy**, once the route/auth-scheme table is work worth doing, plus the daemon it needs.
**v2.1 = T3.**

Form factor: a CLI plus helper binaries on PATH, installed via brew or pipx, with a thin Claude Code
plugin carrying only the inbound hook and `/clowk`. Host-agnostic by default; the plugin is the only
Claude-Code-specific piece.

**Deferred, deliberately:** rotation and expiry (the broker log gives exact usage, which is the data
rotation needs), per-project scoping (routes give host binding, which was the security half of it),
and encryption-at-rest hardening beyond the keychain-held key.
