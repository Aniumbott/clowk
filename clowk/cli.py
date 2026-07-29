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
  clowk install [HOST]          register clowk's hooks (default host: claude-code)
  clowk uninstall [HOST]        remove them

There is no `export`: the vault is a plaintext JSON file, so reading it IS the export.
"""
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import deny, install as install_mod, vault


def _use_utf8(*streams):
    """Make the CLI's own output UTF-8 rather than the console codec. Never raises.

    `list` and `uses` print the session cwd a credential was caught in, so one accented character
    in a project path is enough. On a strict non-UTF-8 stdout -- an installed latin-1 locale, or any
    redirected stdout on Windows, which is what the `/clowk` slash command gets -- that write raised
    UnicodeEncodeError in the middle of the loop: exit 1, a raw traceback, and every credential
    sorting after the offending one silently missing from the listing.

    Called only from __main__, and guarded: tests inject StringIO and a test runner may have
    replaced sys.stdout with a capture object of its own. Neither is ours to reconfigure.
    """
    for stream in streams:
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


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
        if not vault.replace(name, value):
            err.write("No credential named %s.\n" % name)
            return 1
        out.write("Replaced the value of $%s; when and where it was caught is kept.\n" % name)
        return 0
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
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
    except UnicodeDecodeError:
        # A file we cannot decode is not "no config": falling through to {} would overwrite the
        # user's whole hand-written deny list while printing success.
        err.write("%s is not UTF-8. clowk will not modify it -- re-save it as UTF-8, "
                  "then retry.\n" % path)
        return 1
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
    # ensure_ascii stays on here (unlike install.py): deny.py reads this file back with the
    # locale codec, so keeping it pure ASCII is what makes a non-ASCII pattern survive the trip.
    with open(tmp, "w", encoding="utf-8") as f:
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


def cmd_install(host, out, err):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        result = install_mod.install(host, root)
    except KeyError:
        err.write("Unknown host %r. Known: %s\n" % (host, ", ".join(sorted(install_mod.TARGETS))))
        return 1
    except (ValueError, IOError, OSError) as exc:
        err.write("%s\n" % exc)
        return 1
    if result["added"]:
        out.write("Registered %d clowk hook(s) in %s.\n" % (result["added"], result["settings"]))
    else:
        out.write("clowk is already registered in %s; nothing to do.\n" % result["settings"])
    if result["backup"]:
        out.write("Backed up your previous settings to %s.\n" % result["backup"])
    out.write("Restart %s so it picks the hooks up.\n" % host)
    if host == "codex":
        out.write("Codex requires hook trust: run /hooks and approve clowk. Every clowk\n"
                  "update changes the script hash and will ask you again.\n")
    return 0


def cmd_uninstall(host, out, err):
    try:
        result = install_mod.uninstall(host)
    except KeyError:
        err.write("Unknown host %r. Known: %s\n" % (host, ", ".join(sorted(install_mod.TARGETS))))
        return 1
    except (ValueError, IOError, OSError) as exc:
        err.write("%s\n" % exc)
        return 1
    out.write("Removed %d clowk hook(s) from %s.\n" % (result["removed"], result["settings"]))
    return 0


def main(argv, out=None, err=None):
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    try:
        return _dispatch(argv, out, err)
    except vault.VaultUnreadable as exc:
        # One catch for every vault-touching command. Reporting an empty vault instead would
        # both lie and invite the next write to overwrite the file.
        err.write("%s\n" % exc)
        return 1


def _dispatch(argv, out, err):
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
    if cmd == "install" and len(args) <= 1:
        return cmd_install(args[0] if args else "claude-code", out, err)
    if cmd == "uninstall" and len(args) <= 1:
        return cmd_uninstall(args[0] if args else "claude-code", out, err)
    if cmd == "debug-payload" and not args:
        return cmd_debug_payload(out)
    err.write("Unknown command, or wrong number of arguments. Run `clowk help`.\n")
    return 1


if __name__ == "__main__":
    _use_utf8(sys.stdout, sys.stderr)
    sys.exit(main(sys.argv[1:]))
