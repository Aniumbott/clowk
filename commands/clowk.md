---
description: Manage clowk-captured credentials (list, clear, rename, uses, allow)
argument-hint: [list | clear NAME | rename OLD NEW | uses [NAME] | allow PATTERN]
allowed-tools: Bash
---
Result of the clowk management CLI:

!`python3 "${CLAUDE_PLUGIN_ROOT}/clowk/cli.py" $ARGUMENTS`

Present the result above to the user clearly. With no arguments the CLI prints its usage summary
and exits 1 — point the user at `/clowk list` to see what is stored.

Note for the assistant: `clowk add` and `clowk set` deliberately prompt for the value on a
terminal and cannot be driven from here — tell the user to run them in their own shell.
