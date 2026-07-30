#!/usr/bin/env python3
"""clowk SessionStart hook: tell the agent that clowk exists, and how to use a credential.

Without this the agent has no idea a vault exists. It sees `$DATABASE_URL` in a prompt, treats it
as an ordinary shell variable, finds it empty, and either gives up or -- worse -- asks the human to
paste the real value again, undoing the capture that just happened.

Names only, never values. The point of the briefing is that the agent can USE a credential without
ever being told what it is.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import vault

BRIEFING = """clowk is holding %d credential(s) for this machine: %s

These are NOT in your environment. `echo $NAME` prints nothing, and that is deliberate -- the
values were captured before they reached you and are stored outside your reach.

To use one, run the command through clowk and quote it as a single argument:

    %s run -- 'psql $DATABASE_URL -c "select 1"'

clowk puts the value into that one command's environment, and scrubs it back out of the output. The
single quotes matter: unquoted, your own shell expands $NAME to nothing before clowk sees it.

Never ask the user to paste a raw credential you could get this way, and never try to read
~/.clowk/vault.json -- that read is denied, and the value would land in the transcript."""


def briefing(names, cli):
    if not names:
        return ""
    return BRIEFING % (len(names), ", ".join("$" + n for n in names), cli)


def main(argv, stdout=None, stderr=None):
    stdout = stdout if stdout is not None else sys.stdout
    try:
        names = vault.names()
    except Exception:  # noqa: BLE001 -- a session must start even if the vault is unreadable
        return 0
    if not names:
        return 0        # nothing captured yet: say nothing rather than advertise an empty vault

    cli = '"%s" "%s"' % (sys.executable or "python3",
                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      "clowk", "cli.py"))
    stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": briefing(names, cli),
        }
    }))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- never block a session from starting
        sys.exit(0)
