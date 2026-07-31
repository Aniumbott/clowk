---
name: clowk
description: Use when a prompt contains a $NAME placeholder that clowk substituted for a credential, or when a command needs an API key, token, password, or database URL that clowk is holding. Explains how to use a captured credential without ever reading its value.
---

# Using a credential clowk is holding

clowk intercepted a credential before it reached you. You have a name; you do not have the value,
and you are not going to get it.

## The hard rule

**You never read, print, log, echo, copy, or store the plain value of a credential clowk captured.**

Not into a message. Not into a file. Not into a variable you then display. Not "just to check it
looks right". Not "just this once to debug". The value exists so a command can use it — nothing in
your job requires you to see it, and everything you write is recorded permanently.

This is not a preference. A value you print is written to the session transcript on disk, where it
outlives the conversation and defeats the interception that just happened.

## How to use one

Substitute it at the point of use:

```bash
psql "$(clowk get DATABASE_URL)"
curl -H "Authorization: Bearer $(clowk get STRIPE_SECRET_KEY)" https://api.stripe.com/v1/charges
pg_dump "$(clowk get DATABASE_URL)" > backup.sql
```

The shell runs `clowk get`, captures the value, and hands it straight to your command as an
argument. The value passes through the shell and never appears in what you or the user read.

Always inside `$( )`. Always quoted. That is the only form.

## What is forbidden, and why each one leaks

| Never write | What happens |
|---|---|
| `clowk get DATABASE_URL` | prints the value into the transcript |
| `echo "$(clowk get X)"` | substitution is fine, `echo` prints it anyway |
| `V=$(clowk get X); echo $V` | same leak, one step later |
| `clowk get X > /tmp/k` | plaintext on disk, and you will read it back |
| `clowk get X | anything` | the pipeline's output is the transcript |
| pasting a value into source, a config file, or a message | permanent, and usually committed |

clowk's own hook **blocks** most of these before they run. If you are blocked, that is the rule
working — rephrase to the `$( )` form rather than looking for a way around it.

## Red flags — if you catch yourself thinking any of these, stop

| Thought | Reality |
|---|---|
| "I'll print it once to verify it's correct" | You cannot verify a credential by looking at it. Run the command and read the exit code. |
| "I need to see it to construct the connection string" | You do not. Substitute the whole string: `psql "$(clowk get DATABASE_URL)"`. |
| "I'll store it in a variable, that's not printing it" | The next command that touches that variable prints it. |
| "The user asked me to show it" | Tell them where it lives: `~/.clowk/vault.json`. They can read their own file; you must not put it in the transcript. |
| "I'll write it to .env so the app can read it" | That is a plaintext credential in the project, one commit from being public. Use `$( )` at the point of use. |
| "It's only a staging/test credential" | You cannot tell which it is by looking, and staging credentials reach real data. |
| "I need it to debug why auth is failing" | Debug with the exit code and the API's error body. A wrong key and a right key look identical. |

## Finding out what exists

```bash
clowk list          # names, when captured, where from — never values
clowk uses NAME     # what has consumed it, so a rotation's blast radius is knowable
```

`clowk list` is safe and prints no values. Use it when a prompt references a `$NAME` you have not
seen, or when you are unsure which credential a task needs.

## When something does not work

**`$NAME` is empty.** Expected — captured values are deliberately not in your environment. Use
`$(clowk get NAME)`.

**"not in the vault".** The name is close but wrong. A second, different value arriving under a
name already taken is stored suffixed, so `DATABASE_URL` and `DATABASE_URL_2` can both exist and
mean different databases. Run `clowk list` and pick deliberately — `clowk uses NAME` shows which
project each came from.

**A command fails with an auth error.** Do not print the credential to investigate. Check you used
the right name, then report the API's own error to the user. If the credential is genuinely stale,
they rotate it upstream and run `clowk set NAME` themselves — that command reads from a terminal
prompt and cannot be driven from here.

## Never ask for a value you could get this way

If a task needs a credential clowk is already holding, use `$(clowk get NAME)`. Asking the user to
paste it again transmits it to the model and writes it to disk — undoing the entire interception,
and it is the single worst thing you can do with this tool installed.
