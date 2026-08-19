#!/usr/bin/env python3
"""clowk management CLI. Backs the /clowk slash command.

Usage:
  clowk list                    stored credentials -- names and metadata, never values
  clowk add NAME                type a credential at the terminal instead of pasting it in chat
  clowk set NAME                replace a value after rotating it upstream
  clowk clear NAME              forget a credential
  clowk rename OLD NEW          rename one
  clowk get NAME                print one value, for use ONLY inside $( ) -- see skills/clowk
  clowk uses [NAME]             where each credential was caught, and what has used it
  clowk allow PATTERN           stop denying one of clowk's rules -- a filename, a suffix or a
  clowk deny PATTERN            undo an allow, putting the rule back
                                command phrase, exactly as the deny message prints it
  clowk debug-payload           dump what a host sends this hook, to add a new host
  clowk setup                   guided first-time setup: pick hosts, install, then verify
                                --hosts a,b  --yes  --dry-run  for unattended use
  clowk update                  fetch new code, then refresh the skill and command that
                                do not move on their own. --check to look without changing
  clowk install [HOST]          register clowk's hooks (default host: claude-code)
  clowk uninstall [HOST]        remove them, then decide about the vault -- it is NOT
                                deleted unless you say so. --backup FILE writes the vault
                                as JSON at mode 0600, --purge deletes it, --keep-vault keeps
  clowk --version               the installed version

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


def _repeats(meta):
    """True if this credential has been caught more than once, so a count says something new.

    A value caught once needs no extra line: `first_caught` already answers when, and `last_caught`
    is the same instant. A vault written before the count existed reports 0 and so prints nothing
    either -- it must not claim a number it does not have.
    """
    catches = meta.get("catches")
    return isinstance(catches, int) and catches > 1


def _caught_summary(meta):
    """When this credential was caught, and how often, in one line for `clowk uses`."""
    first = meta.get("first_caught") or "(unknown)"
    if not _repeats(meta):
        return first
    return "%d times, first %s, last %s" % (
        meta["catches"], first, meta.get("last_caught") or "?")


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
        if _repeats(meta):
            out.write("      repeat: %d times in all, last %s\n"
                      % (meta["catches"], meta.get("last_caught") or "?"))
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
        out.write("  caught:      %s\n" % _caught_summary(meta))
        out.write("  caught from: %s\n" % (", ".join(meta["sources"]) if meta.get("sources") else "(unknown)"))
        out.write("  used by:     %s\n" % (", ".join(meta["uses"]) if meta.get("uses") else "(nothing recorded yet)"))
    return 0


def _without(cfg, key, pattern):
    """Drop pattern from a user-added deny list, leaving anything else in it untouched."""
    value = cfg.get(key)
    if isinstance(value, list):
        cfg[key] = [item for item in value if item != pattern]


def _is_a_rule(cfg, pattern):
    """True if an allow entry for `pattern` actually changes what clowk denies.

    deny.py compares its allow list, string for string, against its built-in rule patterns, and
    cmd_allow additionally drops a matching hand-added rule. Those are the only arguments this
    command can act on -- an absolute path, a glob or a longer command line is inert, and saying
    "clowk will no longer deny it" about one is a plain untruth.
    """
    for names in (deny.DEFAULT_PATHS, deny.DEFAULT_SUFFIXES, deny.DEFAULT_COMMANDS):
        if pattern in names:
            return True
    for key in ("deny_paths", "deny_commands"):
        value = cfg.get(key)
        if isinstance(value, list) and pattern in value:
            return True
    return False


def cmd_deny(pattern, out, err):
    """Undo an allow. `clowk allow` had no inverse, so relaxing a rule was a one-way door and the
    only way back was hand-editing the deny config -- for a security tool, the wrong asymmetry."""
    path = deny.config_path()
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
    except (IOError, OSError, ValueError):
        cfg = {}
    allow = [a for a in cfg.get("allow", []) if isinstance(a, str)]
    if pattern not in allow:
        err.write("%r is not on the allow list. `clowk list`-style rules in effect are the "
                  "defaults; nothing to undo.\n" % pattern)
        return 1
    cfg["allow"] = [a for a in allow if a != pattern]
    _write_deny_config(path, cfg)
    out.write("Denying %r again.\n" % pattern)
    return 0


def _write_deny_config(path, cfg):
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent)
        except OSError:
            pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


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
    if not _is_a_rule(cfg, pattern):
        # Check the claim before making it. deny.check already computes the pattern the user needs
        # and prints it in its hint, so hand them its own answer rather than a second guess at it.
        reason = (deny.check("Read", {"file_path": pattern})
                  or deny.check("Bash", {"command": pattern}))
        if reason:
            err.write("Nothing to allow: %r is not one of clowk's deny rule patterns. What clowk "
                      "denies here is:\n  %s\n" % (pattern, reason))
            return 1
        out.write("clowk does not deny %r, so there is nothing to allow.\n" % pattern)
        out.write("The vault's own directory stays protected either way.\n")
        return 0
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


def cmd_get(name, out, err):
    """Print one value, with no trailing newline, for command substitution.

    This is the only command that prints a credential, and it exists so a command can use one
    without anybody reading it: `psql "$(clowk get DATABASE_URL)"`. The value passes through the
    shell into the command's arguments and never reaches a transcript.

    Used bare -- `clowk get NAME` on its own -- it prints straight into the transcript, which is
    exactly what clowk exists to prevent. That cannot be detected from in here: a process cannot
    tell it was command-substituted, because the shell's own command line is not visible to it in
    an agent harness. So the guard lives in the PreToolUse hook, which sees the whole command before
    it runs. See deny.check().
    """
    value = vault.get(name)
    if value is None:
        err.write("No credential named %s. Run `clowk list` to see the stored names.\n" % name)
        return 1
    out.write(value)          # no newline: $( ) strips one, and a stray one breaks a header
    try:
        vault.record_use(name, os.getcwd())
    except Exception:  # noqa: BLE001 -- bookkeeping must never fail the command that needed the value
        pass
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
    # Every host, not just Claude Code: `clowk get` is how a credential is used everywhere, and
    # until this existed the word `clowk` was not a command on any of them.
    packaged = install_mod.packaged_command()
    if packaged:
        out.write("`clowk` already resolves to %s, so no launcher was written.\n" % packaged)
        launcher = None
    else:
        launcher = install_mod.install_launcher(root)
    if launcher:
        out.write("Wrote %s, so `clowk` runs as a command.\n" % launcher)
        if not install_mod.launcher_on_path(launcher):
            folder = os.path.dirname(launcher)
            out.write("  %s is NOT on your PATH, so that command cannot be found yet. Add it:\n"
                      "    export PATH=\"%s:$PATH\"\n" % (folder, folder))
    elif not packaged:
        out.write("Left %s alone -- it exists and clowk did not write it.\n"
                  % install_mod.launcher_path())
    # Only Claude Code has ~/.claude/commands; the others use different mechanisms.
    if host == "claude-code":
        command = install_mod.install_command(root)
        if command:
            out.write("Wrote %s, so `/clowk` works without installing the plugin.\n" % command)
        else:
            out.write("Left %s alone -- it exists and clowk did not write it.\n"
                      % install_mod.command_path())
    # The skill goes wherever the host reads one, which is Claude Code AND Codex -- identical
    # layout. Gated on the path existing rather than on the host name, so adding a host is a
    # table entry rather than another branch here.
    if install_mod.skill_path(host) is not None:
        skill = install_mod.install_skill(root, host)
        if skill:
            out.write("Wrote %s -- the assistant reads this to learn how to use a credential "
                      "without reading it.\n" % skill)
    else:
        out.write("No skill installed: %s has no known skills directory, so the assistant will "
                  "not be told what a $NAME is.\n" % host)
    out.write("Restart %s so it picks the hooks up.\n" % host)
    if host == "codex":
        out.write("Codex requires hook trust: run /hooks and approve clowk. Every clowk\n"
                  "update changes the script hash and will ask you again.\n")
    return 0


VAULT_FLAGS = ("--purge", "--keep-vault", "--backup")


def install_mod_vault_flags():
    return VAULT_FLAGS


def _vault_notice(out, err, argv, stdin):
    """Deal with the vault after the hooks are gone. Returns an exit code.

    The vault is the only copy of what it holds, and until now uninstall left it behind in silence.
    That reads two opposite ways and both are bad: someone wanting a clean machine keeps a plaintext
    file of live credentials, and someone assuming uninstall took it with them believes they have
    cleaned up when they have not. So it is always mentioned, deletion always needs a typed word, and
    a backup is always on offer first.
    """
    purge = "--purge" in argv
    keep = "--keep-vault" in argv
    backup_to = None
    if "--backup" in argv:
        index = list(argv).index("--backup")
        if index + 1 < len(argv) and not argv[index + 1].startswith("-"):
            backup_to = argv[index + 1]
        else:
            backup_to = os.path.join("~", "clowk-vault-backup.json")

    total = vault.count()
    if total == 0:
        out.write("\nYour vault holds nothing, so there was nothing to keep or remove.\n")
        return 0

    out.write("\n%s\n" % ("-" * 66))
    out.write("Your vault still holds %d credential%s, in plaintext:\n    %s\n"
              % (total, "" if total == 1 else "s", vault.path()))
    out.write("Removing clowk does not remove that file, and nothing else on your machine\n"
              "reads it. It is the only copy of every value in it.\n")

    if backup_to:
        try:
            written = vault.write_export(backup_to)
        except (IOError, OSError) as exc:
            err.write("Could not write the backup (%s), so the vault was left alone.\n" % exc)
            return 1
        out.write("\nBacked up to %s (mode 0600).\n" % written)
        out.write("That file is the vault's own JSON with every value in the clear, so restoring is\n"
                  "copying it back over %s. clowk's deny hook does NOT protect it -- move it\n"
                  "somewhere safe or delete it when you are done.\n" % vault.path())

    if purge:
        if vault.purge():
            out.write("\nDeleted %s. %d credential%s gone.\n"
                      % (vault.path(), total, "" if total == 1 else "s"))
        return 0
    if keep:
        out.write("\nKept, as asked.\n")
        return 0

    interactive = False
    try:
        interactive = bool((stdin or sys.stdin).isatty())
    except Exception:  # noqa: BLE001 -- a StringIO has no isatty
        interactive = False
    if not interactive:
        out.write("\nKept it, because there is no terminal here to ask. To decide explicitly:\n"
                  "    clowk uninstall --backup FILE     copy the vault, values and all, to a JSON file\n"
                  "    clowk uninstall --purge           delete the vault\n"
                  "    clowk uninstall --keep-vault      keep it without being asked again\n")
        return 0

    stream = stdin or sys.stdin
    while True:
        out.write("\n  b) back it up to a JSON file first\n"
                  "  d) delete it now\n"
                  "  k) keep it  (default)\n\nWhich? ")
        out.flush()
        answer = (stream.readline() or "").strip().lower()
        if answer in ("", "k", "keep"):
            out.write("Kept %s.\n" % vault.path())
            return 0
        if answer in ("b", "backup"):
            target = os.path.join("~", "clowk-vault-backup.json")
            out.write("Write it to [%s]: " % target)
            out.flush()
            typed = (stream.readline() or "").strip()
            try:
                written = vault.write_export(typed or target)
            except (IOError, OSError) as exc:
                err.write("Could not write that (%s). Nothing was deleted.\n" % exc)
                continue
            out.write("Backed up to %s (mode 0600). It is the vault's own JSON, so restoring is\n"
                      "copying it back over %s. Every value is in the clear in there, and clowk's\n"
                      "deny hook does not protect it.\n" % (written, vault.path()))
            continue
        if answer in ("d", "delete"):
            # A typed word, not y/n. This is irreversible and the vault is the only copy.
            out.write("\nThis cannot be undone. Type DELETE to remove %d credential%s: "
                      % (total, "" if total == 1 else "s"))
            out.flush()
            if (stream.readline() or "").strip() != "DELETE":
                out.write("Not deleted.\n")
                continue
            if vault.purge():
                out.write("Deleted %s.\n" % vault.path())
            return 0
        out.write("Not one of b, d or k.\n")


def cmd_uninstall(host, out, err, argv=(), stdin=None):
    try:
        result = install_mod.uninstall(host)
    except KeyError:
        err.write("Unknown host %r. Known: %s\n" % (host, ", ".join(sorted(install_mod.TARGETS))))
        return 1
    except (ValueError, IOError, OSError) as exc:
        err.write("%s\n" % exc)
        return 1
    out.write("Removed %d clowk hook(s) from %s.\n" % (result["removed"], result["settings"]))
    if install_mod.uninstall_command():
        out.write("Removed %s.\n" % install_mod.command_path())
    if install_mod.uninstall_skill(host):
        out.write("Removed %s.\n" % install_mod.skill_path(host))
    if install_mod.uninstall_launcher():
        out.write("Removed %s.\n" % install_mod.launcher_path())
    return _vault_notice(out, err, tuple(argv), stdin)


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
    if argv and argv[0] in ("-V", "--version", "version"):
        from clowk import __version__
        out.write("clowk %s\n" % __version__)
        return 0
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
    if cmd == "deny" and len(args) == 1:
        return cmd_deny(args[0], out, err)
    if cmd == "allow" and len(args) == 1:
        return cmd_allow(args[0], out, err)
    if cmd == "update":
        from clowk import update as update_mod
        return update_mod.run(args, out, err)
    if cmd == "setup":
        from clowk import setup as setup_mod
        return setup_mod.run(args, out, err)
    if cmd == "install" and len(args) <= 1:
        return cmd_install(args[0] if args else "claude-code", out, err)
    if cmd == "uninstall":
        flags = [a for a in args if a.startswith("-")]
        positional = [a for a in args if not a.startswith("-")]
        # --backup may take a path, which is positional-looking but belongs to the flag.
        if "--backup" in args:
            index = args.index("--backup")
            if index + 1 < len(args) and not args[index + 1].startswith("-"):
                taken = args[index + 1]
                if taken in positional:
                    positional.remove(taken)
        if len(positional) > 1:
            err.write("Usage: clowk uninstall [HOST] [--backup FILE] [--purge] [--keep-vault]\n")
            return 1
        unknown = [f for f in flags if f not in install_mod_vault_flags()]
        if unknown:
            err.write("Unknown option(s): %s\n"
                      "Usage: clowk uninstall [HOST] [--backup FILE] [--purge] [--keep-vault]\n"
                      % ", ".join(unknown))
            return 1
        return cmd_uninstall(positional[0] if positional else "claude-code", out, err, args)
    if cmd == "get" and len(args) == 1:
        return cmd_get(args[0], out, err)
    if cmd == "debug-payload" and not args:
        return cmd_debug_payload(out)
    err.write("Unknown command, or wrong number of arguments. Run `clowk help`.\n")
    return 1


def entry():
    """The console_scripts target. `main` takes argv explicitly so the tests can drive it."""
    _use_utf8(sys.stdout, sys.stderr)
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    entry()
