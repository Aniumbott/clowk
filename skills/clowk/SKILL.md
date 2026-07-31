---
name: clowk
description: Use when a prompt contains a $NAME placeholder clowk substituted for a credential, or when a command needs an API key, token, password or database URL clowk is holding. Explains how to use one without reading its value.
---

# Using a credential clowk is holding

You have a name. You do not get the value.

## The hard rule

**Never read, print, log, echo, or store the plain value.** Not to check it, not to debug, not once.
Anything you print is written to the transcript on disk, which defeats the interception that just
happened.

## The only correct form

```bash
psql "$(clowk get DATABASE_URL)"
curl -H "Authorization: Bearer $(clowk get STRIPE_KEY)" https://api.stripe.com/v1/charges
```

Inside `$( )`, quoted, at the point of use. The shell hands the value straight to the command.

## Forbidden — each of these puts the value in the transcript

- `clowk get X` on its own
- `echo "$(clowk get X)"` — substitution is fine, `echo` prints it anyway
- `V=$(clowk get X)` — whatever reads `V` next prints it
- `clowk get X > file` or `clowk get X | anything`
- pasting a value into source, config, or a message

clowk's hook blocks these. If you are blocked, rephrase to `$( )` — do not look for a way around.

## Stop if you think any of this

| Thought | Reality |
|---|---|
| "I'll print it once to verify it" | You cannot verify a credential by looking. Run the command, read the exit code. |
| "A variable isn't printing it" | The next command that touches it prints it. |
| "I need it to debug this auth failure" | A wrong key and a right key look identical. Use the API's error body. |
| "I'll write it to .env for the app" | That is a plaintext credential one commit from being public. |

## Practicalities

- `clowk list` — names and metadata, never values. Use it when unsure which credential a task needs.
- `$NAME` is empty in your environment. Expected. Use `$(clowk get NAME)`.
- "not in the vault" means the name is close but wrong: a second, different value under a taken name
  is stored suffixed, so `DATABASE_URL` and `DATABASE_URL_2` can be different databases.
  `clowk uses NAME` shows which project each came from.
- If a credential is genuinely stale, the user rotates it and runs `clowk set NAME` themselves — that
  reads from a terminal and cannot be driven from here.

**Never ask the user to paste a credential you could reach with `$(clowk get NAME)`.** That
retransmits it and writes it to disk, undoing the whole point.
