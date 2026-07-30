"""`clowk run -- '<command>'` -- lend a captured credential to one command, and only that command.

The value never enters the agent's own environment. It is placed in the environment of a single
child process, and scrubbed back out of that child's output before anything returns. So
`echo $DATABASE_URL` in an ordinary tool call still prints nothing, and `clowk run -- 'echo
$DATABASE_URL'` prints `$DATABASE_URL` rather than the value.

Quote the command as ONE argument:

    clowk run -- 'psql $DATABASE_URL -c "select 1"'

For a command whose reference is inside a script rather than on the command line -- `npm run
deploy`, `make migrate` -- there is nothing for clowk to spot, so lend everything explicitly:

    clowk run --all -- 'npm run deploy'

Single quotes matter. Written unquoted, the agent's own shell expands `$DATABASE_URL` before clowk
ever sees it -- to the empty string, because that is the whole point of the value not being in the
environment. Unquoted, the command silently runs against nothing.

Capture-then-scrub rather than streaming: the Bash tool on every supported host is
non-interactive, so there is no TTY to preserve and nothing to stream to. Output is bounded by
MAX_OUTPUT so a runaway command cannot exhaust memory.
"""
import os
import re
import subprocess
import sys

from clowk import vault

# Enough for any plausible command output; past this the tail is dropped with a notice rather than
# buffered without limit. A command producing more than this is not one a credential is needed for.
MAX_OUTPUT = 4 * 1024 * 1024

# A partial print is still a leak: a CLI that truncates a key to its first 12 characters would
# otherwise sail through an exact-match scrub.
EDGE = 12


def referenced(command, names):
    """The vault names this command mentions, however it spells them.

    Not just `$NAME`: a command reaches an environment variable in several ways that never write a
    dollar sign -- `os.environ["STRIPE_KEY"]`, `process.env.DATABASE_URL`, `%NAME%` on Windows. An
    earlier version matched `$NAME` alone and lent nothing to any of them, so the command ran
    against an empty value and failed in a way that looked like clowk working.

    A bare name still has to appear as a whole word, so DB does not match DB_EXTRA or "dbname".
    Commands that name the variable nowhere at all -- `npm run deploy`, where the reference lives
    inside the script -- are the case this cannot see; use --all for those.
    """
    found = []
    for name in names:
        pattern = r"\$\{%s\}|\$%s(?![A-Za-z0-9_])|%%%s%%|(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % (
            re.escape(name), re.escape(name), re.escape(name), re.escape(name))
        if re.search(pattern, command):
            found.append(name)
    return found


_DOLLAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _dollar_names(command):
    """Names the command spells with a dollar sign, in order, deduplicated."""
    seen, out = set(), []
    for braced, bare in _DOLLAR.findall(command):
        name = braced or bare
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def scrub(text, values):
    """Replace every captured value -- and any substantial fragment of one -- with its $NAME."""
    for name, value in values:
        if not value:
            continue
        text = text.replace(value, "$" + name)
        if len(value) > EDGE * 2:
            # A truncated print, e.g. "using key sk_live_4eC39Hq..." from a CLI's own logging.
            text = text.replace(value[:EDGE], "$" + name).replace(value[-EDGE:], "$" + name)
    return text


def main(argv, stdout=None, stderr=None):
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    # --all lends every stored credential, for commands whose reference lives inside a script
    # rather than on the command line: `npm run deploy`, `make migrate`, `docker compose up`.
    # Explicit rather than the default, because it also marks every credential as used and would
    # otherwise turn the ledger -- the thing that makes a rotation's blast radius knowable -- into
    # noise. The output scrub is what keeps it safe either way.
    lend_all = "--all" in argv
    argv = [a for a in argv if a != "--all"]
    if "--" in argv:
        command = " ".join(argv[argv.index("--") + 1:])
    else:
        command = " ".join(argv)
    if not command.strip():
        stderr.write("clowk run: nothing to run.\n"
                     "Usage: clowk run -- '<command>'   (quote it, so your shell does not expand "
                     "$NAME to nothing first)\n")
        return 2

    names = vault.names()
    wanted = names if lend_all else referenced(command, names)
    env = os.environ.copy()
    lent = []
    for name in wanted:
        value = vault.get(name)
        if value is not None:
            env[name] = value
            lent.append((name, value))

    # A $NAME the vault does not hold and the environment does not define is almost always a near
    # miss -- the agent wrote $DATABASE_URL while the vault holds DATABASE_URL_2, which suffixed
    # because a second, different value arrived under the same name. Silence there produces an
    # empty expansion and a failure that looks like the credential being wrong.
    unknown = [n for n in _dollar_names(command)
               if n not in names and n not in os.environ]
    if unknown:
        stderr.write("clowk run: %s %s not in the vault and not in the environment. "
                     "Run `clowk list` to see the stored names.\n"
                     % (", ".join("$" + n for n in unknown),
                        "is" if len(unknown) == 1 else "are"))
    if not wanted:
        stderr.write("clowk run: this command names no stored credential, so nothing was lent. "
                     "Quote the command as one argument, or pass --all if the reference is "
                     "inside a script rather than on the command line.\n")

    try:
        proc = subprocess.Popen(command, shell=True, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        code = proc.returncode
    except OSError as exc:
        stderr.write("clowk run: could not start the command (%s)\n" % exc)
        return 127

    truncated = len(out) > MAX_OUTPUT or len(err) > MAX_OUTPUT
    out, err = out[:MAX_OUTPUT], err[:MAX_OUTPUT]
    # Decode permissively: a command that emits invalid UTF-8 must not turn into a traceback, and
    # U+FFFD cannot hide a credential because every captured value is compared as text.
    stdout.write(scrub(out.decode("utf-8", "replace"), lent))
    stderr.write(scrub(err.decode("utf-8", "replace"), lent))
    if truncated:
        stderr.write("\nclowk run: output truncated at %d bytes.\n" % MAX_OUTPUT)

    # The used-by ledger, finally populated by something. This is the only place clowk can observe
    # a credential actually being used, which is what makes a rotation's blast radius knowable.
    for name, _value in lent:
        try:
            vault.record_use(name, os.getcwd())
        except Exception:  # noqa: BLE001 -- bookkeeping must never fail the command that ran
            pass
    return code
