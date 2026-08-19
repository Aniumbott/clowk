"""`clowk setup` -- the one command a fresh install has to run.

Prompt-driven rather than a full-screen interface, deliberately. A raw-key TUI needs termios on
POSIX and msvcrt on Windows, and curses is not in the Windows standard library at all -- two code
paths, one of which this project cannot test. A launcher went unexecuted on Windows for weeks here
already; repeating that bet on the cosmetic layer buys nothing. Numbered prompts work over SSH, in
every terminal, and are driven in tests by piping stdin.

It also has to run headless (`--hosts`, `--yes`, `--dry-run`) or it cannot be used from dotfiles, a
Dockerfile or CI -- and that is how the tests drive it too.

The last step is the one that matters. Registering hooks is easy and every failure this project has
had is silent: hosts fail open, a hook whose script has moved reports nothing, and an unverified
payload shape means scanning an empty string while looking installed. So setup finishes by firing a
canary through the hook command that is *actually registered in the settings file* and checking that
the turn is blocked and the value reaches neither stream. A host that cannot be proven is reported
as unproven rather than given a tick.

What the canary proves and what it does not: it proves the command registered in the settings file
runs, blocks, and leaks nothing, given a payload clowk understands. It cannot prove the host actually
sends such a payload -- that is per-host knowledge, and VERIFIED_PROMPT_EVENT below is the list this
project has earned. gemini-cli is not on it.
"""
import json
import os
import subprocess
import sys

from clowk import __version__, install as install_mod

# Assembled from parts on purpose. A literal Stripe-shaped key in a tracked file is blocked by
# GitHub push protection -- the same class of tool as clowk, refusing clowk's own test fixture.
CANARY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
CANARY_TIMEOUT = 20.0

HOST_ORDER = ("claude-code", "codex", "gemini-cli")

# Which hosts this project has actually verified end to end, and which are inference. Mirrors
# NOTES.md; setup must never print a tick this list does not support.
VERIFIED_PROMPT_EVENT = ("claude-code", "codex")


def host_present(host):
    """True if this host's configuration directory exists, i.e. it is plausibly installed."""
    settings = install_mod.settings_path(host)
    return os.path.isdir(os.path.dirname(settings))


def detected_hosts():
    return [h for h in HOST_ORDER if host_present(h)]


def registered_command(host, script="hook_prompt.py"):
    """The hook command string the host will really run, read back out of its settings. None if absent.

    Read rather than recomputed: recomputing proves that install *could* write a working command,
    not that the one on disk is working. Those differ after a clone moves or an interpreter goes away.
    """
    try:
        # _load returns (data, existed). Unpacking matters: walking the tuple silently found nothing
        # and reported every host as unverified while the hooks were registered correctly.
        data, _existed = install_mod._load(install_mod.settings_path(host))
    except Exception:                                   # noqa: BLE001 -- unreadable settings is a no
        return None
    found = []

    def walk(node):
        if isinstance(node, dict):
            command = node.get("command")
            if isinstance(command, str) and install_mod.MARKER in command and script in command:
                found.append(command)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(data)
    return found[0] if found else None


def verify(host):
    """Fire a canary through the registered prompt hook. Returns (ok, detail)."""
    command = registered_command(host)
    if command is None:
        return False, "no clowk prompt hook found in %s" % install_mod.settings_path(host)
    payload = json.dumps({"prompt": "here is my key " + CANARY,
                          "cwd": os.getcwd(), "session_id": "clowk-setup-canary"})
    env = dict(os.environ)
    # Never let the canary reach the real vault or the real session ledger.
    env["CLOWK_VAULT"] = os.path.join(os.path.expanduser("~"), ".clowk", "setup-canary.json")
    env["CLOWK_SESSIONS"] = os.path.join(os.path.expanduser("~"), ".clowk", "setup-canary-sessions.json")
    try:
        proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr = proc.communicate(payload.encode("utf-8"), timeout=CANARY_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.communicate()
        except Exception:                               # noqa: BLE001
            pass
        return False, "the hook did not answer in %.0fs -- a timeout means the host transmits" % CANARY_TIMEOUT
    except (OSError, ValueError) as exc:
        return False, "the registered command could not run (%s)" % exc
    finally:
        for key in ("CLOWK_VAULT", "CLOWK_SESSIONS"):
            path = env[key]
            try:
                os.remove(path)
            except OSError:
                pass

    out_text = stdout.decode("utf-8", "replace")
    err_text = stderr.decode("utf-8", "replace")
    if CANARY in out_text or CANARY in err_text:
        return False, "the hook echoed the credential back -- that is a leak, not a guard"
    blocked = proc.returncode == 2
    if not blocked:
        try:
            blocked = json.loads(out_text).get("decision") == "block"
        except ValueError:
            blocked = False
    if not blocked:
        return False, "the hook ran but did not block (exit %s)" % proc.returncode
    return True, "canary blocked, value in neither stream"


def _parse(argv):
    opts = {"hosts": None, "yes": False, "dry_run": False}
    rest = list(argv)
    while rest:
        arg = rest.pop(0)
        if arg in ("-y", "--yes"):
            opts["yes"] = True
        elif arg == "--dry-run":
            opts["dry_run"] = True
        elif arg == "--hosts":
            if not rest:
                raise ValueError("--hosts needs a comma-separated list")
            opts["hosts"] = [h.strip() for h in rest.pop(0).split(",") if h.strip()]
        elif arg.startswith("--hosts="):
            opts["hosts"] = [h.strip() for h in arg.split("=", 1)[1].split(",") if h.strip()]
        else:
            raise ValueError("unknown option %r" % arg)
    return opts


def _interactive(stream):
    """True only when there is a human to prompt. A pipe or a CI runner must never be asked."""
    try:
        return bool(stream.isatty())
    except Exception:                                   # noqa: BLE001 -- a StringIO has no isatty
        return False


def _choose(found, out, err, stdin):
    """Ask which of the detected hosts to set up. Returns a list, possibly empty."""
    out.write("Found these agent CLIs on this machine:\n\n")
    for i, host in enumerate(found, 1):
        out.write("  %d) %-12s %s\n" % (i, host, install_mod.settings_path(host)))
    out.write("\n  a) all of them\n  q) quit\n\n")
    out.write("Which? (numbers separated by spaces, or a) ")
    out.flush()
    answer = (stdin.readline() or "").strip().lower()
    if not answer or answer in ("q", "quit"):
        return []
    if answer in ("a", "all"):
        return list(found)
    picked = []
    for token in answer.replace(",", " ").split():
        try:
            index = int(token)
        except ValueError:
            err.write("Not a number: %s\n" % token)
            return []
        if not 1 <= index <= len(found):
            err.write("No option %d.\n" % index)
            return []
        if found[index - 1] not in picked:
            picked.append(found[index - 1])
    return picked


def run(argv, out, err, stdin=None):
    stdin = stdin if stdin is not None else sys.stdin
    try:
        opts = _parse(argv)
    except ValueError as exc:
        err.write("%s\nUsage: clowk setup [--hosts a,b] [--yes] [--dry-run]\n" % exc)
        return 1

    out.write("clowk %s setup\n\n" % __version__)
    found = detected_hosts()
    if opts["hosts"] is not None:
        unknown = [h for h in opts["hosts"] if h not in install_mod.TARGETS]
        if unknown:
            err.write("Unknown host(s): %s. Known: %s\n"
                      % (", ".join(unknown), ", ".join(sorted(install_mod.TARGETS))))
            return 1
        chosen = opts["hosts"]
    elif not found:
        err.write("No agent CLI configuration directories found. Looked for:\n")
        for host in HOST_ORDER:
            err.write("  %-12s %s\n" % (host, os.path.dirname(install_mod.settings_path(host))))
        err.write("Install one, or name it anyway: clowk setup --hosts claude-code\n")
        return 1
    elif opts["yes"]:
        chosen = list(found)
    elif not _interactive(stdin):
        # Without this, a non-interactive caller (CI, a Dockerfile, a pipe) blocks forever on a
        # prompt nobody can answer. Refusing with the two flags that fix it is the only useful
        # behaviour, and it is how the tests reach this branch.
        err.write("Not a terminal, so there is nobody to ask. Name the hosts or accept the "
                  "detected ones:\n  clowk setup --hosts %s\n  clowk setup --yes\n"
                  % ",".join(found))
        return 1
    else:
        chosen = _choose(found, out, err, stdin)
        if not chosen:
            out.write("Nothing to do.\n")
            return 0

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out.write("\nWill set up: %s\n" % ", ".join(chosen))
    for host in chosen:
        out.write("  %-12s hooks into %s\n" % (host, install_mod.settings_path(host)))
    out.write("  %-12s %s\n" % ("skill", install_mod.skill_path()))
    out.write("  %-12s %s\n" % ("/clowk", install_mod.command_path()))
    if opts["dry_run"]:
        out.write("\n--dry-run: nothing was written.\n")
        return 0

    results = []
    for host in chosen:
        out.write("\n--- %s ---\n" % host)
        try:
            from clowk import cli
            code = cli.cmd_install(host, out, err)
        except Exception as exc:                        # noqa: BLE001 -- one bad host must not stop the rest
            err.write("install failed: %s\n" % exc)
            results.append((host, False, "install failed: %s" % exc))
            continue
        if code != 0:
            results.append((host, False, "install reported a failure"))
            continue
        ok, detail = verify(host)
        results.append((host, ok, detail))

    out.write("\n%s\n" % ("-" * 58))
    out.write("Result\n\n")
    worst = 0
    for host, ok, detail in results:
        mark = "verified" if ok else "NOT VERIFIED"
        out.write("  %-12s %-13s %s\n" % (host, mark, detail))
        if not ok:
            worst = 1
        if ok and host not in VERIFIED_PROMPT_EVENT:
            out.write("  %-12s %s\n"
                      % ("", "note: this proves the registered command blocks a payload clowk"))
            out.write("  %-12s %s\n"
                      % ("", "understands. It does NOT prove this host sends one -- its payload"))
            out.write("  %-12s %s\n"
                      % ("", "shape is unverified, so it may scan an empty string. See NOTES.md."))
    out.write("\nRestart each agent so it reads the new hooks.\n")
    if "codex" in [h for h, _, _ in results]:
        out.write("Codex also needs hook trust: run /hooks and approve clowk.\n")
    out.write("Before ever removing clowk with pip or pipx, run `clowk uninstall` first --\n"
              "otherwise the hooks stay registered, point at a script that is gone, and every\n"
              "host fails open silently from then on.\n")
    return worst
