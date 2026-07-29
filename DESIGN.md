# clowk — design notes

A Claude Code plugin that catches credentials pasted into the chat **before they reach the model**,
stores them locally as environment variables, and hands the agent a `$VAR` reference so it keeps
working — without ever seeing the raw value.

Status: design locked, spike proven. Working name `clowk` (respell of "cloak"; also the bypass keyword `!clowk`).

---

## 1. Problem

People paste API keys, tokens, and connection strings into AI agent chats. The instant they hit
enter, the secret is already sent to the provider. The agent flags "rotate this" — but people forget,
and rotating is painful because many services depend on one credential.

Goal: **stop the leak at the source**, and make secrets reusable by reference so nothing breaks.

## 2. Core insight (the thing everything hinges on)

Once a secret is in the prompt, it is already transmitted. There is no "make the model forget."
The only real defense is to **intercept before transmit**, which on Claude Code means one primitive:
the `UserPromptSubmit` hook, which runs locally before the turn is sent.

## 3. Verified constraints (all confirmed, not assumed)

| Question | Answer | How verified |
|---|---|---|
| Can `UserPromptSubmit` rewrite/replace the prompt text? | **No.** Docs: "Cannot change or replace the prompt text itself." | Official hooks docs, cross-checked 3x |
| What *can* it do? | Block the turn (`decision: block` / exit 2), or inject `additionalContext` (appended, not replacing) | Official docs |
| Can we make `$VAR` resolve in Bash calls, cross-platform, no restart? | **Yes** — write to `settings.local.json` `env`; it auto-reloads mid-session | Tested live in a real session (wrote var, next Bash call resolved it) |
| Can `PreToolUse` modify a tool command / `PostToolUse` redact output? | **Yes, verified.** PreToolUse `hookSpecificOutput.updatedInput` (dict). PostToolUse `hookSpecificOutput.updatedToolOutput` (**single string**, v2.1.121+, all built-in tools incl. Read). | Official docs + issue #32105 |
| Does a blocked prompt leak to the on-disk transcript? | **No — verified.** A blocked prompt is NOT written to `~/.claude/projects/*.jsonl` as a user message. Block = never reaches model AND never persists to disk. | empirical test, this session |

**Consequence:** seamless in-place swap is impossible. The UX is **block → repaste**.

## 4. The loop (final)

1. You paste a secret, hit enter.
2. `clowk` hook scans locally. No secret → passes through silently.
3. Secret found → **turn is blocked** (model receives nothing), secret stored as `$ENV_VAR`,
   hook shows the rewritten prompt with the secret swapped for `$ENV_VAR`.
4. You copy-paste the rewritten prompt → normal turn, agent uses `$ENV_VAR`.
5. Bypass: start the message with `!clowk` → skip the scan, send raw.

No tokens are wasted on a blocked turn — the scan is 100% local; only the rewritten prompt is ever sent.

## 5. Decisions

- **Detection engine:** vendor an existing maintained ruleset (gitleaks TOML, ~200 rules; detect-secrets
  as the engine LLM Guard uses). Do **not** hand-write patterns. Two tiers:
  - Known prefix match (`ghp_`, `AKIA`, `sk-`, `xoxb-`…) → high confidence → **block**.
  - Entropy-only guess → **warn**, don't block (avoids false positives on hashes/UUIDs/SHAs).
- **Env-var naming:** auto-suggest from the secret type (`ghp_` → `GITHUB_TOKEN`), fall back to
  surrounding text (`DATABASE_URL=`), fall back to `SECRET_1`. User can rename (see loophole #8).
- **Storage (central, one place, NOT per-session):** two user-level files, shared by every session/project:
  - Values → **`~/.claude/settings.local.json`** `env` block (the only file Claude Code reads to resolve
    `$VAR` in Bash; not our choice). Never project-level (see loophole #3).
  - Ledger → **`~/.clowk/ledger.json`** (metadata: name, first caught, projects/commands used).
  Plaintext at rest (acceptable for the threat model; disk encryption is v2). Trade-off: global means
  every session's Bash env gets every stored secret — fine for the threat model; per-project scoping is v2.
  (The `/tmp/...` path in the spike is throwaway test isolation only, not the design.)
- **Dependency:** check for gitleaks at SessionStart; if missing, tell user to `brew install gitleaks`
  (or equivalent) and halt activation.
- **Bypass:** `clowk:` prefix (plain word). NOT `!clowk` — `!`/`@`/`/`/`#` are all reserved by Claude
  Code at prompt start (`!`=shell mode, `@`=file mention, `/`=slash cmd, `#`=add-to-memory), so a symbol
  prefix never reaches the hook. Verified live.
- **Block message formatting:** hooks can't set color/markdown; a block `reason` renders as plain (yellow)
  text. So the message is plain-text optimized for readability + easy copy, not styled.

## 6. Novelty (researched)

The four-part combo — intercept pasted secret + block + auto-store as env var + rewrite to a *usable*
`$VAR` — is **not shipped anywhere**. Closest neighbors:
- **nopeek** (Claude Code): protects *existing* `.env` secrets from leaking *outward* via PreToolUse
  redaction — opposite direction, doesn't touch the inbound paste.
- **LLM Guard**: redacts secrets in LLM I/O, but produces opaque `[REDACTED]` the agent can't use, and
  is an app-side library.
- **1Password/Doppler/Vault**: "reference not value" injection — prior art for the env mechanic only.

Differentiator: guarding the *inbound paste* (the gap everyone leaves) + a *usable* substitution.
Honest caveat: the primitive is public and nopeek is close, so a fast-follower barrier is low. The
defensible part is the UX, not the mechanism.

## 7. Loopholes & blockers (be honest about these)

1. **Output-path leak (biggest gap).** clowk guards the *inbound paste* only. If the agent reads a file
   or command output containing a secret, the model still sees it. Closing this needs a `PostToolUse`
   redactor (what nopeek does). Decision needed: v1 or v2?
2. **RESOLVED — no transcript leak.** Verified empirically: a blocked prompt is NOT written to the
   on-disk transcript as a user message. Block keeps the secret from both the model and disk. No scrub
   step needed.
3. **Project-level settings = git leak footgun.** If secrets were ever written to a project
   `.claude/settings.local.json`, they could be committed. Mitigation: **always** write to user-level
   `~/.claude/settings.local.json`, never inside a repo. Non-negotiable.
4. **Clearing doesn't unset live.** Proven: removing a var from settings does NOT unset it in the running
   session until restart. So "clear/rotate" has a caveat to surface in the UX.
5. **Secrets accumulate forever** in settings.local.json. Needs a lifecycle: list / clear / expire, plus
   the rotation-tracking ledger (which also serves the original "scoped rotation" goal).
6. **Undetected formats leak silently.** A novel/custom secret we don't match goes straight through.
   Entropy tier + honest "raises the bar, not a guarantee" framing.
7. **False positives block legit prompts.** Blocking on a bad match is annoying. Mitigation: block only
   on high-confidence prefix matches; warn on entropy guesses.
8. **Renaming the env var is awkward in a hook.** Hooks can't show an interactive prompt. So "change the
   suggested name" happens either by the user editing `$NAME` in the repasted prompt, or via a follow-up
   `/clowk rename` command. UX constraint, not a blocker.
9. **RESOLVED.** PreToolUse `updatedInput` and PostToolUse `updatedToolOutput` verified real (see §3).
   Output guard for #1 is viable; PostToolUse also fires for Read (prior art: l-mb/claude-code-redaction-hooks).
   Note: `updatedToolOutput` is a single string (not stdout/stderr/exit_code subfields) — handle structure ourselves.
   Redaction is post-execution: stops the model seeing the secret, but the file/network access already happened.

## 7b. "Agent can use but not read" — the hard security layer (verified from official docs)

The naive "write-only file the agent can't read" is **impossible**: Claude Code's Bash runs as the same
OS user as the human, so any file you can read, `cat` can read; and `echo $VAR` prints any plain env var.
No permission trick separates human from agent.

BUT Claude Code has a real mechanism that delivers the actual property: **sandbox credential masking**
(`sandbox.credentials.envVars`, `"mode": "mask"`, v2.1.199+). Verified from
https://code.claude.com/docs/en/sandboxing.md:
- Sandboxed commands see a per-session **sentinel**, not the real secret (`echo $VAR` → garbage).
- The proxy injects the **real value only at the network boundary**, for hosts in `injectHosts`
  (each must be within `network.allowedDomains`).
- Config: `sandbox.enabled: true` + `network.tlsTerminate: {}` + `credentials.envVars: [{name, mode:"mask", injectHosts}]`.
- Honored only from user/managed/CLI settings — a repo's `.claude/settings.json` can't set mask entries. Good.

**Constraints (must state honestly, cannot sell as absolute):**
1. Network-only, to allow-listed hosts. Non-network use (local decrypt, CLI that prints it) not covered.
2. Sandbox is macOS/Linux/WSL2 only — **NOT native Windows** (dents cross-platform; Windows = run under WSL2).
3. Requires strict sandbox: `allowUnsandboxedCommands: false`, else the escape hatch runs a command
   unsandboxed where the real value is visible. Tools that must be `excludedCommands` (gh/gcloud/terraform
   on macOS TLS) also see the real value.
4. Must also `denyRead` / `credentials.files` deny the store file, else a sandboxed `cat` reads the raw value.
5. `tlsTerminate` is experimental; documented domain-fronting caveat.

**Product consequence — clowk is two layers:**
- **Layer 1 (all platforms):** catch → block → store → `$VAR`. Raises the bar; not a hard guarantee (`echo` still works).
- **Layer 2 (sandbox-capable):** clowk auto-generates the mask config + strict mode + denyRead. Now the agent
  genuinely cannot read network secrets. This makes clowk a *configurator for an OS-level control*, the real
  differentiator. Honest tagline: "pasted secrets become usable-but-unreadable for API calls, OS-enforced" —
  with the network/sandbox caveats, never "the agent can never see a secret."

## 8. Improvements to consider (my additions)

- **Add the PostToolUse output-guard** so clowk covers both directions (in *and* out). This closes
  loophole #1 and, combined with the inbound guard, is the actual "complete" product — and a stronger
  differentiator than either half alone.
- **Rotation ledger**: log {secret name, when caught, project, commands that used it}. Directly serves
  the original pain — scoped rotation instead of blind panic. Powers a `/clowk` list/clear command.
- **`/clowk` slash command**: list stored secrets, clear one, rename, show usage.

## 9. Scope (decided 2026-07-28)

**v1 (full):**
- Inbound: UserPromptSubmit block hook + gitleaks ruleset + user-level settings storage + `!clowk` bypass
- Outbound: PostToolUse redactor so secrets in file reads / command output don't reach the model
- Rotation ledger: {secret name, first caught, projects, commands that used it} + `/clowk` list/clear/rename
- SessionStart gitleaks dependency check
**v2 (deferred):** entropy warn-tier, disk encryption, editable-naming polish.

**Pre-build verification still owed (both now v1-critical):**
- Transcript-leak (loophole #2): does a blocked prompt get written to `~/.claude` on disk?
- PreToolUse `updatedInput` / PostToolUse `updatedToolOutput` schemas (loophole #9) — needed for the
  outbound guard.

## 10. Open questions for Aniket

1. Storage location: confirm **user-level** `~/.claude/settings.local.json` (recommended) — never project.
2. Output-path guard (loophole #1): v1 or v2?
3. Rotation ledger + `/clowk` command: in scope, or later?
4. How much do we care about the transcript-leak vector (#2)? (Affects whether we add a scrub step.)

## BUILD STATUS — Option A (Layer 1) COMPLETE (2026-07-28)

Built + unit-tested at `~/clowk/`. Plugin manifest validates (`claude plugin validate` → passed).
- `clowk/detect.py` — 220 gitleaks rules (vendored `gitleaks.toml` → `rules.json` via `build_rules.py`),
  keyword-gated + entropy-filtered, defensive compile (never crashes on any Python 3).
- `clowk/store.py` — central storage (`~/.claude/settings.local.json` env) + rotation ledger (`~/.clowk/ledger.json`),
  atomic writes, collision suffixing.
- `clowk/hook_prompt.py` — UserPromptSubmit: detect → store → block with rewritten prompt. `unclowk` bypass.
- `clowk/hook_output.py` — PostToolUse (Bash|Read): known value → `$VAR`, new secret → `[REDACTED]`, usage tracking.
- `clowk/cli.py` + `commands/clowk.md` — `/clowk list|clear|rename`.
- `hooks/hooks.json`, `.claude-plugin/plugin.json`, `README.md`.

**Tested (isolated files):** multi-secret detect+block, settings+ledger writes, bypass, clean passthrough,
output redaction (known + new), usage tracking, CLI list/clear/rename.

## LIVE INSTALL FINDINGS (2026-07-28) — hard-won, environment-specific

Installed via a local marketplace (`.claude-plugin/marketplace.json`, source `.`) → `/plugin install clowk@clowk-dev`.

1. **INBOUND GUARD WORKS END-TO-END, VERIFIED LIVE.** Pasted a fresh `sk_live_...` → blocked before the
   model saw it → stored as `$STRIPE_SECRET_KEY` → resolves in Bash → ledger logged it. This is the core product.
2. **Plugin-manifest hooks DON'T FIRE in this Claude Code build.** `hooks/hooks.json` is NOT auto-discovered;
   the manifest must declare `"hooks": "./hooks/<file>.json"` AND the file must NOT be named `hooks.json`
   (that name double-registers → "1 error during load"). Even with the correct manifest, the hooks loaded
   (counted) but never executed. **Only settings-registered hooks fire here.** → clowk is wired via
   `~/.claude/settings.local.json` pointing at the installed scripts. For distribution: ship an install step
   that writes the hook block to settings (per host).
3. **PostToolUse `updatedToolOutput` is NOT honored in this build.** The output hook fires and emits the
   correct redacted string, but Claude Code doesn't apply it (confirmed even with no competing hook). The
   outbound code is correct and works where the platform honors it (other CC versions / codex / opencode).
   Here, outbound protection = **Layer B sandbox masking** (§7b), which is the stronger guarantee anyway.
4. **Multi-host plan** (user goal): codex, gemini/antigravity CLI, grok, opencode. Mirror ponytail's layout —
   Python core stays identical; ship per-host hook manifests (`claude-*.json`, `codex-*.json`, `opencode.json`,
   `gemini-extension.json`). Registration mechanism differs per host; detection/store/ledger are shared.

## LAYER B — BUILT (2026-07-28)

`clowk/sandbox.py` + `clowk mask|unmask` CLI. `clowk mask <NAME> [hosts]` writes the sandbox credential-mask
config to `~/.claude/settings.json`: `sandbox.enabled`, `network.tlsTerminate`, `allowedDomains` += hosts,
`credentials.envVars` += `{name, mode:"mask", injectHosts}`, `credentials.files` deny on the value store,
and `allowUnsandboxedCommands:false` (strict, closes the escape hatch). Host defaults per secret type in
`HOST_MAP`. Config generation verified correct against the docs. This CC build is **2.1.202** (mask +
tlsTerminate supported, unlike `updatedToolOutput`).

**Not yet tested live:** enabling strict sandbox is a global workflow change (all Bash sandboxed) + needs a
restart. The verifiable assurance: after `clowk mask GITHUB_TOKEN` + restart, `echo $GITHUB_TOKEN` in a
sandboxed shell shows a SENTINEL, not the real value. Caveats: network-only to listed hosts; tlsTerminate is
experimental; some tools need allowedDomains/allowWrite; native Windows unsupported.

**Next:** live-test Layer B (opt-in, disruptive); then per-host packaging for other agent tools.

## COMPETITIVE LANDSCAPE + DESIGN RECONSIDERATION (2026-07-29)

⚠️ **The vision is being rethought.** Reframing clowk as a full "secrets manager for AI coding agents"
walked into a crowded, incumbent-heavy category. Researched competitors:
- **VaultAgent** (vaultagent.io) — near-identical tagline; vault + broker + multi-host + scoped `run`.
- **Claude Secrets / MCP Secrets** (OSS) — ~90% feature overlap; closest analogue.
- **Doppler / Infisical agent-vault / LLM Secrets** — agent secret injection, multi-host.
- **1Password AI Agent Identity** — enterprise: agents as first-class identities, OAuth token exchange
  (RFC 8693), DPoP-bound short-lived tokens, code-signed local broker, Device Trust MCP.
- Arcade.dev / Composio — adjacent only (agent→SaaS tool-call auth, not coding-agent shell workflows).

**Only unfilled seam:** proactive **detection that auto-captures** into the vault (others import/provision)
+ **local-first, zero-config** dev UX + **per-session group-scoped** access. The original narrow idea
(catch-at-paste + block + rewrite) was *more* differentiated than the broad reframe.

**Open design questions (see HANDOFF.md §5):** narrow tool vs full platform; build vs fork Claude Secrets;
env-var/sandbox vs a broker (`clowk run --group X -- cmd` / MCP tool); central-vault group ACL model;
multi-host packaging; positioning ("detects and captures, not just stores"). **Do not claim first/only.**

See `HANDOFF.md` for the full session state, live-machine state, and resume instructions.

## Spike

Proven at `scratchpad/stow_spike.py` (to be renamed): detect → block → store → rewritten prompt, plus
clean-passthrough and `!clowk` bypass. Env auto-reload proven separately in a live session.
