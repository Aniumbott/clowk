---
description: Manage clowk-captured credentials (list, uses, clear, rename, allow, setup, update)
argument-hint: [list | uses [NAME] | clear NAME | rename OLD NEW | allow PATTERN | update --check]
allowed-tools: Bash
---
Result of the clowk management CLI:

!`python3 "${CLAUDE_PLUGIN_ROOT}/clowk/cli.py" $ARGUMENTS`

Present the result above to the user clearly. With no arguments the CLI prints its usage summary
and exits 1 — point the user at `/clowk list` to see what is stored.

Notes for the assistant:

- `clowk add` and `clowk set` deliberately prompt for the value on a terminal and cannot be driven
  from here. Tell the user to run them in their own shell.
- `clowk setup` and `clowk uninstall` are interactive too, and `uninstall` can delete the user's
  whole vault. Never run either from here — print the command for the user instead.
- `clowk get` prints a real credential and is blocked by clowk's own tool hook outside `$( )`.
  Never call it to inspect a value.
- `clowk update --check` is read-only and safe to run.
