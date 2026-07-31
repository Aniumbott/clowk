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
import re

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


# `clowk get NAME` prints a credential. That is deliberate -- it exists so a command can use one
# via `psql "$(clowk get DATABASE_URL)"`, where the value passes through the shell into the
# command's arguments and never reaches a transcript. Used any other way it prints straight into the
# transcript, which is the exact leak clowk exists to prevent.
#
# The guard has to live here rather than in `clowk get` itself: a process cannot tell whether it was
# command-substituted, because in an agent harness the invoking shell's command line is not visible
# to it -- measured, not assumed. This hook is the only layer that sees the whole command before it
# runs, so this is the only place the rule can be enforced.
_GET = re.compile(r"clowk(?:/cli\.py)?['\"]?\s+get\b|cli\.py['\"]?\s+get\b")
# A substitution whose output is immediately printed leaks just as surely as a bare call.
_PRINTERS = ("echo", "printf", "print", "cat", "tee", "head", "tail", "less", "more",
             "xxd", "hexdump", "base64", "od", "strings", "write", "logger")


def _is_invocation(command, match):
    """True if the match at `start` is a command being run, not prose mentioning it.

    Writing *about* `clowk get` -- in a comment, a docstring, a commit message, a heredoc of
    documentation -- is not running it, and denying it made the guard fire on its own explanation
    twice while being written. A shell only treats a word as a command at the start of input or
    after a separator, so that is the test.

    A backtick counts as a separator because it IS one in shell (legacy command substitution), and
    because it is how prose quotes a command in Markdown -- both readings mean "do not deny".
    """
    # The script-path form is its own evidence: nobody writes "python3 clowk/cli.py get X" as
    # prose. Checked on the matched TEXT, not the position -- the regex matches from "clowk/" in
    # "clowk/cli.py", so a position check looked at the wrong characters and let it through.
    if "cli.py" in match.group(0):
        return True

    prefix = command[:match.start()].rstrip()
    if not prefix:
        return True                       # start of the command
    tail = prefix[-1]
    if tail in ";|&(){\n":
        return True
    if prefix.endswith("$("):
        return True
    if tail in "\"'" and prefix[:-1].rstrip().endswith("$("):
        return True

    # A backtick reads as prose here, not as legacy command substitution. Both readings exist --
    # `cmd` really is substitution in shell -- but in an agent's Bash command a backtick is
    # overwhelmingly a Markdown code span quoting a name, and denying those made the guard fire on
    # its own documentation. The cost is that legacy `clowk get X` substitution is unguarded; the
    # skill teaches only the $( ) form, and $( ) is what every check above is built around.
    return False                          # preceded by a word or a backtick: prose


def get_misuse(command):
    """A reason to deny a `clowk get` that would print a credential, or None if it is used safely."""
    match = None
    for candidate in _GET.finditer(command):
        if _is_invocation(command, candidate):
            match = candidate
            break
    if not match:
        return None
    hint = ("Use it only inside a command substitution, so the value goes to the command and not to "
            "the transcript:\n    psql \"$(clowk get DATABASE_URL)\"\nSee the clowk skill.")

    # Every substitution in the command, as (open_index, body).
    substitutions = []
    i = 0
    while True:
        start = command.find("$(", i)
        if start < 0:
            break
        depth, j = 1, start + 2
        while j < len(command) and depth:
            if command[j] == "(":
                depth += 1
            elif command[j] == ")":
                depth -= 1
            j += 1
        substitutions.append((start, command[start + 2:j - 1]))
        i = start + 2

    inside = [s for s in substitutions if _GET.search(s[1])]
    if not inside:
        return ("clowk denied a bare `clowk get`: it would print a credential into the transcript. "
                + hint)

    # Inside a substitution, but is the surrounding command one that prints it straight back?
    for start, _body in inside:
        prefix = command[:start]
        # The head of the pipeline segment the substitution sits in -- not the word immediately
        # before it. `printf "%s" "$(clowk get X)"` puts a format string in that position, so
        # looking only at the nearest word let printf through while catching echo.
        segment = re.split(r"\|\||&&|[|;\n]", prefix)[-1].strip()
        words = [w.strip("'\"") for w in segment.split() if w.strip("'\"")]
        if words and os.path.basename(words[0]).lower() in _PRINTERS:
            return ("clowk denied this: `%s` prints its argument, so substituting a credential into "
                    "it puts the value in the transcript. " % os.path.basename(words[0])) + hint
        # Capturing into a shell variable. There is no use for this that substituting at the point
        # of use does not serve, and the next command touching that variable prints the value -- by
        # which time the substitution is out of sight and nothing here can see the leak coming.
        if re.search(r"(?:^|[\s;&|])[A-Za-z_][A-Za-z0-9_]*=$", prefix):
            return ("clowk denied capturing a credential into a shell variable: whatever reads that "
                    "variable next puts the value in the transcript. " + hint)
    return None


def check(tool_name, tool_input):
    """Return a reason string to deny the call, or None to allow it. Never raises."""
    if not isinstance(tool_input, dict):
        return None
    paths, commands, allow = _rules()

    command_text = tool_input.get("command")
    if isinstance(command_text, str) and command_text:
        misuse = get_misuse(command_text)
        if misuse:
            return misuse

    target = tool_input.get("file_path") or tool_input.get("path")
    if isinstance(target, str) and target:
        reason = _path_reason(target, paths, allow)
        if reason:
            return reason

    command = tool_input.get("command")
    if isinstance(command, str) and command:
        # At the head of a pipeline segment, not anywhere in the text. Matching anywhere denied any
        # command that merely mentioned the phrase -- a README edit, a commit message, a grep -- and
        # that is what blocked the commit describing this very fix.
        for segment in re.split(r"\|\||&&|[|;\n]", command):
            head = " ".join(_strip_edges(w) for w in segment.split())
            for phrase in commands:
                if head.lower().startswith(phrase.lower()):
                    return "clowk denied `%s` -- it prints a live credential. %s" % (
                        phrase, HINT % (phrase, config_path()))
        # os.altsep as well as os.sep: on Windows os.sep is "\\" and "/" is os.altsep, and cmd,
        # PowerShell and Git Bash all take forward slashes -- so `type C:/repo/.env`, the ordinary
        # way a model writes that path, skipped the check entirely. None on POSIX, so no change.
        # Only when the segment is actually running a reader. A path named in a commit message, a
        # comment, an echo of documentation or a grep pattern is a mention, not a read -- and
        # denying those made this hook block five of its own author's commands, including the commit
        # that introduced this fix. The Read tool's structured file_path is checked above and is
        # unaffected: that is the reliable half, and it stays strict.
        separators = tuple(s for s in (os.sep, os.altsep) if s)
        for segment in re.split(r"\|\||&&|[|;\n]", command):
            words = [w for w in segment.split() if w]
            if not words:
                continue
            head = os.path.basename(_strip_edges(words[0])).lower()
            if head not in _READERS:
                continue
            for token in words[1:]:
                stripped = _strip_edges(token)
                if stripped.startswith(("/", "~", ".")) or any(s in stripped for s in separators):
                    reason = _path_reason(os.path.expanduser(stripped), paths, allow)
                    if reason:
                        return reason
    return None


# Shell and prose punctuation that can sit against a path but is not part of it. A trailing
# sentence period is the one that matters: a command mentioning ".env.example." in a comment or a
# heredoc yielded the token ".env.example." , whose basename does not end in ".example", so the
# allow-suffix check missed and the command was denied. Found when this hook blocked a command
# whose only sin was writing about .env.example in a sentence.
# Commands that read a file's contents. A path in a Bash command counts as a read only when one of
# these is the head of its pipeline segment; anything else naming a path is talking about it, not
# opening it. The Read tool's structured file_path is checked separately and stays strict.
_READERS = frozenset((
    "cat", "bat", "less", "more", "head", "tail", "nl", "od", "xxd", "hexdump", "strings",
    "base64", "cp", "mv", "install", "rsync", "scp", "tee", "sed", "awk", "grep", "rg", "ag",
    "python", "python2", "python3", "ruby", "perl", "node", "php", "source", ".", "open",
    "dd", "gzip", "gunzip", "zip", "unzip", "tar", "shasum", "md5sum", "sha256sum", "wc",
    "jq", "yq", "envsubst", "dotenv", "type", "vi", "vim", "nano", "emacs", "code",
))

_EDGES = "'\"`,;:!?()[]{}<>|&"


def _strip_edges(token):
    """A token as written in a command, minus quoting and sentence punctuation around it."""
    token = token.strip(_EDGES)
    # Trailing dots only: a leading dot is meaningful (".env"), a trailing one never is.
    return token.rstrip(".")
