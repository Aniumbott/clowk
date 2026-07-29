# clowk

> **Status (2026-07-29):** Layer A (inbound catch/block/store) works live; Layer B (sandbox masking) is
> built but untested. The product vision is **under reconsideration** — see `HANDOFF.md` and `DESIGN.md`
> before continuing. Positioning is shifting toward "a local-first secrets manager for AI coding agents
> that *detects and captures* secrets," which is a crowded category (VaultAgent, 1Password AI Identity,
> the OSS Claude Secrets plugin, Doppler/Infisical) — the differentiator is detect-and-auto-capture.

Catches secrets you paste into the Claude Code chat **before they reach the model**, stores them
locally as environment variables, and hands the agent a `$VAR` reference so it keeps working — without
ever seeing (or logging) the raw value. Also redacts secret values that show up in tool output.

## How it works

- **Inbound (UserPromptSubmit):** scans your prompt with the gitleaks ruleset. If it finds a secret, it
  **blocks the turn** (nothing is sent to the model or written to the transcript), stores the value in
  `~/.claude/settings.local.json` under `env`, and shows you the prompt rewritten with `$VAR`. Copy-paste
  it to continue — `$VAR` resolves in every Bash call.
- **Outbound (PostToolUse on Bash/Read):** if a stored secret's value appears in command output or a file
  read, it's swapped back to `$VAR`; any *new* secret is replaced with `[REDACTED:...]` before the model
  sees it.
- **Bypass:** start a message with `unclowk` to send it raw, no scan.
- **Manage:** `/clowk list`, `/clowk clear NAME`, `/clowk rename OLD NEW`. A rotation ledger
  (`~/.clowk/ledger.json`) tracks where each secret was caught and which commands used it.

## Requirements

- `python3` on PATH (stdlib only — no pip installs).

## Install (local)

```
/plugin marketplace add /Users/aniketrana/clowk    # or your clone path
/plugin install clowk
```

## Honest limitations (v1 / Layer A)

- This keeps secrets from the **model** and the **transcript**. It does **not** stop the agent from
  running `echo $VAR` — a plain env var is resolvable. A future **Layer B** wires Claude Code's sandbox
  credential masking so the agent can *use* network secrets without being able to *read* them; that layer
  is macOS/Linux/WSL2-only and network-only.
- Detection is regex-based (gitleaks rules): unknown/custom secret formats can slip through. It raises the
  bar; it is not a guarantee.
- Output redaction is post-execution — it hides the value from the model, but the file read / network call
  already happened.

## Updating the ruleset

`clowk/rules.json` is generated from `clowk/gitleaks.toml` by `build_rules.py`. Re-run it to refresh.

## Attribution

Secret patterns are derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT License).
