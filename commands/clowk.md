---
description: Manage clowk-stored secrets (list, clear, rename)
argument-hint: [list | clear NAME | rename OLD NEW]
allowed-tools: Bash
---
Result of the clowk management CLI:

!`python3 "${CLAUDE_PLUGIN_ROOT}/clowk/cli.py" $ARGUMENTS`

Present the result above to the user clearly. If no arguments were given, the list is shown — also remind them they can run `/clowk clear NAME` to remove a secret or `/clowk rename OLD NEW` to rename one.
