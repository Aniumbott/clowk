# clowk — session handoff (2026-07-29)

Pick up here in a new session. Full design detail is in `DESIGN.md`; this is the fast bootstrap.

---

## 0. One-liner + where things live

**clowk** = a secrets manager for AI coding agents. Detects secrets, stores them in a local vault, and lets
the agent *use* them without ever *reading* the raw values.

- **Source of truth:** `~/clowk/`  (this folder)
- **Installed copy:** `~/.claude/plugins/cache/clowk-dev/clowk/0.1.0/`
- **Value store:** `~/.claude/settings.local.json` (env block) — real secret values live here
- **Ledger:** `~/.clowk/ledger.json` — metadata (name, first_caught, sources, uses)
- Working name `clowk`; bypass prefix `unclowk`; management command `/clowk`.

## 1. What's built and VERIFIED WORKING

- **Layer A — inbound guard (WORKS LIVE, end-to-end verified).** Paste a secret → `UserPromptSubmit` hook
  detects it (gitleaks ruleset) → **blocks** the turn (model never sees it, not even in transcript) →
  stores as `$VAR` in `settings.local.json` env → shows a rewritten prompt to re-paste → `$VAR` resolves in
  Bash → ledger logs it. Proven with a fresh `sk_live_` key through the real plugin.
- **Detection:** 220 gitleaks rules, vendored → `clowk/rules.json` (regenerate with `build_rules.py` from
  `clowk/gitleaks.toml`). Keyword-gated + entropy-filtered. Dependency-free (stdlib only, any python3).
- **`/clowk` CLI** (`clowk/cli.py`): `list | clear | rename | mask | unmask`.
- **Layer B — sandbox masking (BUILT, config-verified, NOT live-tested).** `clowk/sandbox.py` +
  `clowk mask <NAME> [hosts]` writes the sandbox credential-mask config to `~/.claude/settings.json`:
  sandbox on, `tlsTerminate`, `allowedDomains`, `credentials.envVars` mask entry, `credentials.files` deny
  on the store, strict mode. After restart, `echo $VAR` shows a sentinel; real value injected only at the
  network boundary for allow-listed hosts. **Not yet applied/tested** (enabling strict sandbox is a global
  workflow change + needs restart). This CC build is **2.1.202** → mask + tlsTerminate ARE supported here.

## 2. HARD-WON ENVIRONMENT GOTCHAS (do not re-discover — cost hours)

1. **Plugin-manifest hooks DO NOT FIRE in this Claude Code build (2.1.202).** They load (counted) but never
   execute. **Only hooks registered in `settings.json` / `settings.local.json` fire.** → clowk is currently
   wired via `~/.claude/settings.local.json` (UserPromptSubmit + PostToolUse) pointing at the *installed*
   script paths. For distribution: ship an install step that writes the hook block to settings, per host.
   - If you DO use a plugin manifest: it needs `"hooks": "./hooks/<name>.json"` AND the file must NOT be
     named `hooks.json` (that double-registers → "1 error during load"). Even then it didn't execute here.
2. **`UserPromptSubmit` can only block or inject context — it CANNOT rewrite the prompt text.** Hence the
   block-and-repaste UX (no silent in-place swap possible).
3. **`PostToolUse` `updatedToolOutput` is NOT applied by this build.** The output hook fires and emits the
   correct redacted string, but Claude Code ignores it (confirmed even with no competing hook). Outbound
   redaction is dormant here; the code is correct and works where the platform honors it (other CC versions,
   codex, opencode). Real outbound protection = Layer B sandbox masking.
4. `settings.json` `env` auto-reloads mid-session (proven). A **blocked** prompt is NOT written to the
   on-disk transcript (verified) — so blocking keeps the secret from both the model and disk.

## 3. CURRENT LIVE STATE OF THIS MACHINE (clean up or keep)

- `~/.claude/settings.local.json`: contains clowk's UserPromptSubmit + PostToolUse hook registration AND
  test env values `GITHUB_TOKEN`, `STRIPE_SECRET_KEY` (both FAKE test values — safe to clear).
- `~/.clowk/ledger.json`: has test entries for those two.
- `~/.claude/settings.json`: user's clawd telemetry `PostToolUse` hook was removed then **restored** — it
  needs a `/reload-plugins` to re-register. A backup is at `/private/tmp/claude-501/-Users-aniketrana/settings.json.bak` (and `~/clowk/.settings.json.bak`).
- Debug scaffolding has been stripped from source and installed hooks.
- To fully reset test state: clear the two fake secrets (`/clowk clear GITHUB_TOKEN`, `/clowk clear STRIPE_SECRET_KEY`) and remove clowk's hooks from `settings.local.json` if desired.

## 4. COMPETITIVE REALITY (why a rethink is warranted)

As a broad "secrets manager for AI coding agents," the category is **crowded** (researched 2026-07-29):
- **VaultAgent** (vaultagent.io) — near-identical tagline; vault + broker + multi-host + scoped `run`.
- **Claude Secrets / MCP Secrets** (OSS, glama.ai) — ~90% of the feature list; the closest analogue.
- **Doppler / Infisical agent-vault / LLM Secrets** — agent secret injection, multi-host.
- **1Password AI Agent Identity** — enterprise-grade: agents as first-class identities, OAuth token
  exchange (RFC 8693), DPoP-bound short-lived tokens, code-signed local broker, Device Trust MCP. Heavyweight.
- Arcade.dev / Composio — adjacent only (agent→SaaS tool-call auth, not coding-agent shell workflows).

**The one seam nobody fills:** proactive **detection that AUTO-CAPTURES** secrets into the vault (others
import/provision), plus a simple **local-first, zero-config** dev experience and **per-session group-scoped**
access. Everyone else is import-based, cloud/enterprise, or provisioning-heavy.

**Insight:** the ORIGINAL narrow idea (catch-at-paste-boundary + block + rewrite) was *more* differentiated
than the broad "full secrets manager" reframe, which walked into VaultAgent/1Password territory.

## 5. THE RETHINK — open questions for the next session

The user wants to reconsider the whole design. Decisions on the table:
- **Scope:** narrow lightweight dev tool (detect-and-capture wedge) vs full vault/broker/identity platform
  (crowded, incumbent-heavy). Leaning narrow.
- **Build vs fork:** build fresh vs fork/extend the OSS **Claude Secrets** plugin (already ~90% there).
- **Core mechanism:** env-var + sandbox (current) vs a **broker** (`clowk run --group X -- <cmd>` / MCP tool)
  so the value never enters the agent's env at all. Broker is more secure + host-agnostic.
- **Access model:** central vault + logical **groups/projects** + **per-session ACL** (user's latest vision).
  Note: keep it a central vault, NOT project-level files (a project `.claude/` can leak to git).
- **Multi-host:** Claude Code, Codex, Grok, Gemini/Antigravity CLI, opencode — shared Python core, per-host
  hook/registration manifests (ponytail's layout is the model).
- **Positioning:** don't claim "first/only"; lead with "the one that *detects and captures*, not just stores"
  + local-first + zero-config.

## 6. How to resume / test quickly

- Reinstall/refresh: edit `~/clowk`, then `/plugin marketplace add ~/clowk` + `/plugin install clowk@clowk-dev`
  (or `cp` changed files into the installed dir). Remember: **hooks must be settings-registered to fire.**
- Test inbound: paste a fake secret (e.g. `ghp_` + 36 chars, or `sk_live_` + 24) → expect a block + rewrite.
- Test detection logic offline: `python3 ~/clowk/scratch_test_detect.py` pattern (recreate if needed) or
  pipe a JSON `{"prompt": "..."}` into `clowk/hook_prompt.py` with `CLOWK_SETTINGS`/`CLOWK_LEDGER` overrides.
- Layer B test (opt-in, disruptive): `/clowk mask GITHUB_TOKEN` → restart → `echo $GITHUB_TOKEN` should show
  a sentinel. Revert with `/clowk unmask GITHUB_TOKEN` + restart.

## 7. Memory

A project memory exists at the user's auto-memory (`clowk-project.md`) with the state + gotchas; update it as
the design evolves.
