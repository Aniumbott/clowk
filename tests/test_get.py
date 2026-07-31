"""`clowk get` and the guard that makes the never-read rule enforceable.

`clowk get NAME` prints a credential. That is the point: it exists so a command can use one via
`psql "$(clowk get DATABASE_URL)"`, where the value passes through the shell into the command's
arguments and never reaches a transcript. Used any other way it prints straight into the transcript,
which is the exact leak clowk exists to prevent.

The guard cannot live inside `clowk get`: a process cannot tell whether it was command-substituted,
because in an agent harness the invoking shell's command line is not visible to it. That was
measured, not assumed -- the parent command line showed the harness's own shell preamble, identical
for a bare call and a substituted one. So the guard lives in the PreToolUse hook, the only layer
that sees the whole command before it runs, and these tests pin both halves.

Commands are assembled from parts so that this file, and any command that reads it, is not itself a
deny trigger -- which it was, twice, while being written.
"""
import importlib
import io
import os
import shutil
import tempfile
import unittest

GET = "clowk" + " get"


class GetCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="clowk-get-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.dir, "deny.json")
        for key in ("CLOWK_VAULT", "CLOWK_DENY"):
            self.addCleanup(os.environ.pop, key, None)
        from clowk import vault

        self.vault = importlib.reload(vault)
        from clowk import deny

        self.deny = importlib.reload(deny)
        from clowk import cli

        self.cli = importlib.reload(cli)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = self.cli.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()

    def denied(self, command):
        return self.deny.check("Bash", {"command": command}) is not None


class TestGetPrintsTheValue(GetCase):
    SECRET = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def test_it_prints_the_value_and_nothing_else(self):
        self.vault.store("STRIPE_KEY", self.SECRET)
        code, out, err = self.run_cli("get", "STRIPE_KEY")
        self.assertEqual((code, out, err), (0, self.SECRET, ""))

    def test_no_trailing_newline(self):
        # $( ) strips one trailing newline, but a value used inside a header or a URL must not gain
        # one from anywhere else either.
        self.vault.store("STRIPE_KEY", self.SECRET)
        self.assertFalse(self.run_cli("get", "STRIPE_KEY")[1].endswith("\n"))

    def test_an_unknown_name_fails_without_printing_anything(self):
        code, out, err = self.run_cli("get", "NOPE")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("clowk list", err)

    def test_getting_a_value_records_the_use(self):
        # This is the moment of use, so it is where the used-by ledger gets its entry. Without a
        # caller the list stayed permanently empty however much a credential was used.
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        self.assertEqual(self.vault.list_secrets()["DB"]["uses"], [])
        self.run_cli("get", "DB")
        self.assertEqual(self.vault.list_secrets()["DB"]["uses"], [os.getcwd()])


class TestSafeUsageIsAllowed(GetCase):
    """The value goes to a command that consumes it, so nothing reaches the transcript."""

    def test_substituted_into_a_consuming_command(self):
        for command in ('psql "$(%s DATABASE_URL)"' % GET,
                        'pg_dump "$(%s DATABASE_URL)" > backup.sql' % GET,
                        'mysql --password="$(%s DB_PASS)" -e "select 1"' % GET,
                        'redis-cli -u "$(%s REDIS_URL)" ping' % GET,
                        'curl -H "Authorization: Bearer $(%s KEY)" https://x.dev' % GET):
            self.assertFalse(self.denied(command), "wrongly denied: %r" % command)

    def test_the_other_subcommands_are_untouched(self):
        for command in ("clowk list", "clowk uses DATABASE_URL", "clowk clear OLD"):
            self.assertFalse(self.denied(command), "wrongly denied: %r" % command)


class TestLeakingUsageIsDenied(GetCase):
    def test_a_bare_call_is_denied(self):
        self.assertTrue(self.denied("%s DATABASE_URL" % GET))
        self.assertTrue(self.denied("python3 clowk/cli.py get DATABASE_URL"))

    def test_printing_the_substitution_is_denied(self):
        # Substitution alone is not sufficient: echo prints its argument.
        for printer in ("echo", "cat", "printf", "tee /tmp/x", "base64", "logger"):
            command = '%s "$(%s KEY)"' % (printer, GET)
            self.assertTrue(self.denied(command), "not denied: %r" % command)

    def test_printf_is_caught_despite_its_format_argument(self):
        # The word immediately before the substitution is the format string, not printf -- checking
        # only that neighbour let this through while catching echo.
        self.assertTrue(self.denied('printf "%%s" "$(%s KEY)"' % GET))

    def test_a_printer_later_in_the_command_is_still_caught(self):
        self.assertTrue(self.denied('ls; echo "$(%s KEY)"' % GET))

    def test_piping_or_redirecting_is_denied(self):
        self.assertTrue(self.denied("%s KEY | base64" % GET))
        self.assertTrue(self.denied("%s KEY > /tmp/k" % GET))

    def test_capturing_into_a_shell_variable_is_denied(self):
        # Whatever reads that variable next prints the value, by which time the substitution is out
        # of sight and nothing can see the leak coming.
        self.assertTrue(self.denied("V=$(%s KEY)" % GET))
        self.assertTrue(self.denied("export TOKEN=$(%s KEY)" % GET))

    def test_the_denial_explains_the_safe_form(self):
        reason = self.deny.check("Bash", {"command": "%s KEY" % GET})
        self.assertIn("$(", reason)
        self.assertIn("skill", reason.lower())


class TestProseIsNotAnInvocation(GetCase):
    """Writing about the command is not running it.

    The guard fired on its own documentation twice while being written -- once on a comment
    explaining it, once on a heredoc of these very cases. A shell only treats a word as a command at
    the start of input or after a separator, so that is the test the guard applies.
    """

    def test_a_mention_in_prose_is_allowed(self):
        for command in ("echo every other way of invoking `%s` is refused" % GET,
                        "git commit -m 'guard a bare %s'" % GET,
                        "grep -n '%s' README.md" % GET,
                        'echo "the %s command prints a value"' % GET):
            self.assertFalse(self.denied(command), "prose was denied: %r" % command)

    def test_the_script_path_form_is_always_an_invocation(self):
        # Checked on the matched text, not its position: the pattern matches from "clowk/" in
        # "clowk/cli.py", so a position check looked at the wrong characters and let this through.
        #
        # Deliberately unconditional, unlike the bare form -- so writing about this spelling in a
        # command does get denied. For a guard whose whole job is stopping a credential reaching the
        # transcript, refusing an ambiguous string is the right way to be wrong, and the message says
        # how to allow it. Assembled from parts here for exactly that reason.
        script = "clowk/cli" + ".py get"
        for command in ("python3 %s DATABASE_URL" % script,
                        "python3 /opt/clowk/%s X" % script):
            self.assertTrue(self.denied(command), "an invocation was allowed: %r" % command)

    def test_an_invocation_after_a_separator_is_still_caught(self):
        self.assertTrue(self.denied("ls; %s KEY" % GET))
        self.assertTrue(self.denied("cd /tmp && %s KEY" % GET))


if __name__ == "__main__":
    unittest.main()
