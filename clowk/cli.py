#!/usr/bin/env python3
"""clowk management CLI. Backs the /clowk slash command.

Usage:
  clowk list                    stored credentials -- names and metadata, never values
  clowk add NAME                type a credential at the terminal instead of pasting it in chat
  clowk set NAME                replace a value after rotating it upstream
  clowk clear NAME              forget a credential
  clowk rename OLD NEW          rename one
  clowk uses [NAME]             where each credential came from and what has used it
  clowk allow PATTERN           stop denying a path or command
  clowk debug-payload           dump what a host sends this hook, to add a new host

There is no `export`: the vault is a plaintext JSON file, so reading it IS the export.
"""
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import deny, vault


def _read_value(prompt):
    """From CLOWK_VALUE if set (for tests and scripts), else a hidden terminal prompt.
    Never from argv -- that would put the credential in shell history."""
    if "CLOWK_VALUE" in os.environ:
        return os.environ["CLOWK_VALUE"]
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


def cmd_list(out):
    items = vault.list_secrets()
    if not items:
        out.write("No credentials stored.\n")
        return 0
    out.write("%d stored (values are never printed):\n\n" % len(items))
    for name in sorted(items):
        meta = items[name]
        flag = ""
        if meta.get("confidence") == "low":
            flag = "   [shape-only match -- clear it if it was a false positive]"
        out.write("  $%s%s\n" % (name, flag))
        out.write("      caught: %s" % (meta.get("first_caught") or "?"))
        if meta.get("rule"):
            out.write("   rule: %s" % meta["rule"])
        out.write("\n")
        if meta.get("sources"):
            out.write("      from:   %s\n" % ", ".join(meta["sources"]))
        out.write("      used by: %s\n" % (", ".join(meta["uses"]) if meta.get("uses") else "(nothing recorded yet)"))
    out.write("\nStored at %s (0600 on POSIX; user-profile ACLs on Windows).\n" % vault.path())
    return 0


def cmd_add(name, out, err, replace=False):
    existing = vault.get(name) is not None
    if replace and not existing:
        err.write("No credential named %s. Use `clowk add %s` to create it.\n" % (name, name))
        return 1
    if existing and not replace:
        err.write("%s already exists. Use `clowk set %s` to replace its value.\n" % (name, name))
        return 1
    value = _read_value("Value for %s (not echoed): " % name)
    if not value:
        err.write("No value given; nothing stored.\n")
        return 1
    if replace:
        vault.clear(name)
    key = vault.store(name, value, confidence="manual", source="(added by hand)")
    out.write("Stored as $%s.\n" % key)
    return 0


def cmd_clear(name, out, err):
    if vault.clear(name):
        out.write("Cleared %s.\n" % name)
        out.write("Note: a running agent session may keep an old value until it restarts.\n")
        return 0
    err.write("No credential named %s.\n" % name)
    return 1


def cmd_rename(old, new, out, err):
    if vault.rename(old, new):
        out.write("Renamed %s -> %s.\n" % (old, new))
        return 0
    err.write("Cannot rename %s to %s: unknown name, or %s already exists.\n" % (old, new, new))
    return 1


def cmd_uses(name, out, err):
    items = vault.list_secrets()
    if name:
        if name not in items:
            err.write("No credential named %s.\n" % name)
            return 1
        items = {name: items[name]}
    if not items:
        out.write("No credentials stored.\n")
        return 0
    for key in sorted(items):
        meta = items[key]
        out.write("$%s\n" % key)
        out.write("  caught from: %s\n" % (", ".join(meta["sources"]) if meta.get("sources") else "(unknown)"))
        out.write("  used by:     %s\n" % (", ".join(meta["uses"]) if meta.get("uses") else "(nothing recorded yet)"))
    return 0


def _without(cfg, key, pattern):
    """Drop pattern from a user-added deny list, leaving anything else in it untouched."""
    value = cfg.get(key)
    if isinstance(value, list):
        cfg[key] = [item for item in value if item != pattern]


def cmd_allow(pattern, out, err):
    path = deny.config_path()
    try:
        with open(path) as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
    except (IOError, OSError, ValueError):
        cfg = {}
    allow = [a for a in cfg.get("allow", []) if isinstance(a, str)]
    if pattern not in allow:
        allow.append(pattern)
    cfg["allow"] = allow
    # "allow" only filters clowk's built-in rules, so a hand-added rule has to be removed
    # instead -- otherwise this command would report success and keep denying.
    _without(cfg, "deny_paths", pattern)
    _without(cfg, "deny_commands", pattern)
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, mode=0o700)
        except OSError:
            pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)
    out.write("Allowed %r. clowk will no longer deny it.\n" % pattern)
    out.write("The vault's own directory stays protected either way.\n")
    return 0


def cmd_debug_payload(out):
    out.write("Paste or pipe a host's hook payload on stdin, then Ctrl-D:\n")
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        out.write("Not valid JSON.\n")
        return 1
    if not isinstance(payload, dict):
        out.write("Not a JSON object.\n")
        return 1
    out.write("\nTop-level keys: %s\n" % sorted(payload.keys()))
    out.write("String fields (candidates for the prompt key):\n")
    for key, value in sorted(payload.items()):
        if isinstance(value, str):
            out.write("  %-16s len=%d\n" % (key, len(value)))
    out.write("\nAdd the right key to clowk/hosts.py PROMPT_KEYS if it is missing.\n")
    return 0


def main(argv, out=None, err=None):
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    if not argv or argv[0] in ("-h", "--help", "help"):
        out.write(__doc__ + "\n")
        return 1 if not argv else 0
    cmd, args = argv[0], argv[1:]
    if cmd == "list" and not args:
        return cmd_list(out)
    if cmd == "add" and len(args) == 1:
        return cmd_add(args[0], out, err)
    if cmd == "set" and len(args) == 1:
        return cmd_add(args[0], out, err, replace=True)
    if cmd in ("add", "set") and len(args) > 1:
        err.write("Refusing: never pass the value as an argument -- it would land in your shell history.\n"
                  "Run `clowk %s %s` and type it at the prompt.\n" % (cmd, args[0]))
        return 1
    if cmd == "clear" and len(args) == 1:
        return cmd_clear(args[0], out, err)
    if cmd == "rename" and len(args) == 2:
        return cmd_rename(args[0], args[1], out, err)
    if cmd == "uses" and len(args) <= 1:
        return cmd_uses(args[0] if args else "", out, err)
    if cmd == "allow" and len(args) == 1:
        return cmd_allow(args[0], out, err)
    if cmd == "debug-payload" and not args:
        return cmd_debug_payload(out)
    err.write("Unknown command, or wrong number of arguments. Run `clowk help`.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
