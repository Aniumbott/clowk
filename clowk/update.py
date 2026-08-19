"""`clowk update` -- fetch new code, then refresh the copies that do not move on their own.

The second half is the reason this exists. Hooks and the launcher hold absolute paths, so they pick
up new code the moment it lands. The skill is COPIED into each host's skills directory and /clowk is
GENERATED into ~/.claude/commands, so both keep serving the old content until install runs again --
new code, old skill, and nothing on screen saying so. That is the documented half-updated state, and
a command that cannot leave you in it is worth having.

What this deliberately does NOT do is upgrade a packaged install for you. Whether clowk arrived via
pipx, uv or pip changes the correct command, guessing wrong can leave a half-replaced package, and on
Windows `pip install -U` against a running package can fail on locked files. So for package installs
it prints the command for the manager it can see and then refreshes what it can. A clone it can
handle end to end, because `git pull` is unambiguous.

Network: a clone's `git pull`, and the printed upgrade command if you run it. Neither hook ever
touches the network, which is the claim that actually matters.
"""
import os
import subprocess
import sys

from clowk import __version__, install as install_mod, setup as setup_mod

GIT_TIMEOUT = 120.0


def root_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def install_mode(root=None):
    """"clone" if this is a git checkout, else "package"."""
    root = root if root is not None else root_dir()
    return "clone" if os.path.isdir(os.path.join(root, ".git")) else "package"


def package_manager():
    """Best guess at what owns a packaged install, from the interpreter's own location."""
    prefix = sys.prefix.replace("\\", "/")
    if "/pipx/venvs/" in prefix:
        return "pipx"
    if "/uv/tools/" in prefix:
        return "uv"
    return "pip"


def upgrade_command(manager=None):
    manager = manager or package_manager()
    if manager == "pipx":
        return "pipx upgrade clowk"
    if manager == "uv":
        return "uv tool upgrade clowk"
    return "%s -m pip install --upgrade clowk" % os.path.basename(sys.executable)


def registered_hosts():
    """Hosts with a clowk prompt hook actually present in their settings."""
    return [h for h in setup_mod.HOST_ORDER if setup_mod.registered_command(h) is not None]


def _git(args, root):
    try:
        proc = subprocess.Popen(["git"] + args, cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        text, _ = proc.communicate(timeout=GIT_TIMEOUT)
        return proc.returncode, text.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.communicate()
        except Exception:                               # noqa: BLE001
            pass
        return 1, "git %s did not finish in %.0fs" % (" ".join(args), GIT_TIMEOUT)
    except (OSError, ValueError) as exc:
        return 1, "could not run git (%s)" % exc


def run(argv, out, err):
    if argv and argv[0] not in ("--check",):
        err.write("Usage: clowk update [--check]\n")
        return 1
    check_only = bool(argv)

    root = root_dir()
    mode = install_mode(root)
    hosts = registered_hosts()
    out.write("clowk %s, installed as a %s\n" % (__version__, mode))
    if not hosts:
        out.write("\nNo host has a clowk hook registered. Run `clowk setup` instead.\n")
        return 1
    out.write("Registered on: %s\n\n" % ", ".join(hosts))

    if mode == "package":
        out.write("Upgrade the package first, then run this again:\n\n    %s\n\n"
                  % upgrade_command())
        if check_only:
            return 0
    else:
        # --untracked-files=no on purpose. Untracked files do not stop `git pull --ff-only`, and
        # refusing on them would refuse for anyone holding a stray note or a build artefact -- which
        # is to say, almost everyone. Only modified TRACKED files can make the pull fail.
        code, dirty = _git(["status", "--porcelain", "--untracked-files=no"], root)
        if code != 0:
            err.write("%s\n" % dirty)
            return 1
        if check_only:
            # --check must never change anything and never refuse; it reports and returns.
            out.write("Tracked changes: %s\n" % (dirty or "none"))
            code, fetched = _git(["fetch", "--dry-run"], root)
            out.write("git fetch --dry-run: %s\n" % (fetched or "nothing to fetch"))
            return 0
        if dirty:
            err.write("The clone has modified tracked files, so `git pull` is not safe to run for "
                      "you:\n%s\n\nCommit, stash or discard them, then retry.\n" % dirty)
            return 1
        out.write("--- git pull ---\n")
        code, status = _git(["pull", "--ff-only"], root)
        out.write("%s\n" % status)
        if code != 0:
            err.write("git pull failed, so nothing was refreshed.\n")
            return 1

    # The half nobody remembers: re-copy the skill and re-generate the command, per host.
    from clowk import cli
    worst = 0
    for host in hosts:
        out.write("\n--- refreshing %s ---\n" % host)
        if cli.cmd_install(host, out, err) != 0:
            worst = 1

    out.write("\nRestart each agent so it reads the refreshed hooks.\n")
    if "codex" in hosts:
        out.write("Codex trust is hash-based, so run /hooks and approve clowk again.\n")
    return worst
