"""Deny the easy accidental credential reads.

Defence in depth only: nothing else in clowk depends on this, and it is deliberately NOT a
boundary. It matches file paths (reliable -- the host passes a structured path) and command
strings (heuristic -- `cat $HOME/.clo*/vault.json` walks past it).

`git credential fill` is on the list because it prints a live token from the OS keychain in one
line, with no attack involved. It did exactly that during this project's design review.

Configurable on purpose: denying .env outright would block reading a .env.example or debugging
someone's config, and a tool that silently breaks `cat` gets uninstalled.
"""
import json
import os

from clowk import vault

DEFAULT_PATHS = (".env", "id_rsa", "id_ed25519", "id_ecdsa", ".git-credentials", ".netrc")
DEFAULT_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
# Suffixes that mean "this variant is publishable", exempting a name that would otherwise match
# a pattern through the `pattern + "."` branch below. `.pub` belongs here for the same reason
# `.example` does: `id_rsa.pub` is a public key, and the alternative -- `clowk allow 'id_rsa'`,
# which the deny message printed -- stopped denying the private key too.
ALLOW_SUFFIXES = (".example", ".sample", ".template", ".dist", ".md", ".pub")
DEFAULT_COMMANDS = (
    "git credential fill",
    "git credential-osxkeychain get",
    "git credential-store get",
    "security find-generic-password",
    "secret-tool lookup",
)
HINT = "If this is legitimate, run:  clowk allow %r   (or edit %s)"


def config_path():
    return os.environ.get("CLOWK_DENY", os.path.join(os.path.dirname(vault.path()), "deny.json"))


def _config():
    try:
        with open(config_path()) as f:
            data = json.load(f)
    except (IOError, OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _strings(value):
    """Every config list is hand-editable, so treat anything but a list of strings as absent."""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str)]


def _rules():
    cfg = _config()
    allow = _strings(cfg.get("allow"))
    paths = [p for p in DEFAULT_PATHS if p not in allow]
    paths += _strings(cfg.get("deny_paths"))
    commands = [c for c in DEFAULT_COMMANDS if c not in allow]
    commands += _strings(cfg.get("deny_commands"))
    return paths, commands, allow


def _path_reason(target, paths, allow):
    base = os.path.basename(target)
    # The store's own directory first: an allow suffix exempts a *variant of a pattern*, and it
    # must not exempt a file inside ~/.clowk. `clowk allow` promises that directory stays
    # protected either way, so `~/.clowk/vault.json.md` cannot be a way around it.
    protected = os.path.dirname(vault.path())
    if protected and os.path.abspath(target).startswith(os.path.abspath(protected) + os.sep):
        return "clowk denied a read of its own store (%s)." % target
    if os.path.abspath(target) == os.path.abspath(vault.path()):
        return "clowk denied a read of its own store (%s)." % target
    if any(base.endswith(suffix) for suffix in ALLOW_SUFFIXES):
        return None
    for pattern in paths:
        if base == pattern or base.startswith(pattern + "."):
            return "clowk denied a read of %s -- it usually holds credentials. %s" % (
                target, HINT % (pattern, config_path()))
    for suffix in DEFAULT_SUFFIXES:
        if base.endswith(suffix) and suffix not in allow:
            return "clowk denied a read of %s -- %s files usually hold keys. %s" % (
                target, suffix, HINT % (suffix, config_path()))
    return None


def check(tool_name, tool_input):
    """Return a reason string to deny the call, or None to allow it. Never raises."""
    if not isinstance(tool_input, dict):
        return None
    paths, commands, allow = _rules()

    target = tool_input.get("file_path") or tool_input.get("path")
    if isinstance(target, str) and target:
        reason = _path_reason(target, paths, allow)
        if reason:
            return reason

    command = tool_input.get("command")
    if isinstance(command, str) and command:
        lowered = " ".join(command.lower().split())
        for phrase in commands:
            if phrase.lower() in lowered:
                return "clowk denied `%s` -- it prints a live credential. %s" % (
                    phrase, HINT % (phrase, config_path()))
        for token in command.split():
            stripped = token.strip("'\"")
            if stripped.startswith(("/", "~", ".")) or os.sep in stripped:
                reason = _path_reason(os.path.expanduser(stripped), paths, allow)
                if reason:
                    return reason
    return None
