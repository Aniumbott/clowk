"""The Claude Code plugin: install and remove it through the `claude` CLI, for `setup` and `uninstall`.

The plugin carries the mod (hooks/register.js) that rewrites a credential in place instead of
blocking. It only does anything with this package installed, because it runs `clowk rewrite`; and
this package works without it, on the block-and-repaste flow. So `setup` adds it when Claude Code is
new enough, and reports a skip rather than failing when it can't.

`uninstall` has to remove it too. The mod fails closed: left behind without `clowk`, it would hold
back every message.

Everything goes through the user's own `claude`, never by editing its files: plugin state is
Claude Code's, its format is not ours to depend on, and `claude plugin` is the supported surface.
CLOWK_CLAUDE names the executable, which is how the test suite keeps every run away from the real one.
"""
import json
import os
import re
import subprocess

MARKETPLACE = "Aniumbott/clowk"
PLUGIN = "clowk@clowk"
MIN_VERSION = (2, 1, 287)        # the first Claude Code with mods
TIMEOUT = 120.0                  # adding the marketplace clones it from GitHub


def _claude():
    return os.environ.get("CLOWK_CLAUDE", "claude")


def _run(args):
    """(exit code, stdout + stderr) of `claude <args>`, or None if it could not run at all."""
    try:
        proc = subprocess.run([_claude()] + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def version():
    """Claude Code's version as a tuple, or None when there is no `claude` to ask."""
    ran = _run(["--version"])
    if ran is None or ran[0] != 0:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", ran[1])
    return tuple(int(n) for n in match.groups()) if match else None


def installed():
    ran = _run(["plugin", "list", "--json"])
    if ran is None or ran[0] != 0:
        return False
    try:
        return any(p.get("id") == PLUGIN for p in json.loads(ran[1]))
    except (ValueError, AttributeError, TypeError):
        return False


def install():
    """(ok, detail). ok is None for a skip: no `claude`, or one too old for mods."""
    found = version()
    if found is None:
        return None, "skipped: no `claude` on PATH to install it with"
    if found < MIN_VERSION:
        return None, ("skipped: Claude Code %s has no mods (needs %s+); the hooks still block"
                      % (".".join(map(str, found)), ".".join(map(str, MIN_VERSION))))
    if installed():
        return True, "already installed -- prompts are rewritten, not blocked"
    added = _run(["plugin", "marketplace", "add", MARKETPLACE])
    # Already added reads as a failure from some builds; the install below is the real test.
    if added is None:
        return False, "could not run `claude plugin marketplace add`"
    done = _run(["plugin", "install", PLUGIN, "--scope", "user"])
    if done is None or done[0] != 0 or not installed():
        tail = (done[1].strip().splitlines() or [""])[-1] if done else ""
        return False, "install failed%s -- the hooks still block" % (": " + tail if tail else "")
    return True, "installed -- prompts are rewritten, not blocked"


def uninstall():
    """True if the plugin was there and is now gone."""
    if not installed():
        return False
    ran = _run(["plugin", "uninstall", PLUGIN, "--scope", "user"])
    return ran is not None and ran[0] == 0 and not installed()
