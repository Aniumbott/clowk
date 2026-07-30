"""`clowk run` -- lend a credential to one command without putting it in the agent's environment.

Closes the gap that made v1 protect a credential and break the workflow: the block message hands
back `$DATABASE_URL`, which resolved to nothing, so the value was safe and useless at the same
time.

Two properties carry the whole design, and both are asserted here: the command CAN use the value,
and the value does NOT come back in the output.
"""
import importlib
import io
import os
import shutil
import sys
import tempfile
import unittest


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="clowk-runner-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        self.addCleanup(os.environ.pop, "CLOWK_VAULT", None)
        from clowk import vault

        self.vault = importlib.reload(vault)
        from clowk import runner

        self.runner = importlib.reload(runner)

    def run_it(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = self.runner.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()


class TestLending(RunnerCase):
    SECRET = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def test_a_referenced_credential_reaches_the_command(self):
        self.vault.store("STRIPE_KEY", self.SECRET)
        # The command prints a fingerprint of the value rather than the value, so a pass here
        # cannot be produced by the scrub silently blanking everything.
        code, out, err = self.run_it("--", 'python3 -c "import os;print(len(os.environ[\'STRIPE_KEY\']))"')
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), str(len(self.SECRET)))

    def test_the_value_never_comes_back_in_stdout(self):
        self.vault.store("STRIPE_KEY", self.SECRET)
        code, out, err = self.run_it("--", "echo $STRIPE_KEY")
        self.assertNotIn(self.SECRET, out)
        self.assertIn("$STRIPE_KEY", out)

    def test_the_value_never_comes_back_in_stderr_either(self):
        self.vault.store("STRIPE_KEY", self.SECRET)
        code, out, err = self.run_it("--", "echo $STRIPE_KEY 1>&2")
        self.assertNotIn(self.SECRET, err)

    def test_a_truncated_print_is_scrubbed_too(self):
        # A CLI that logs "using key sk_live_4eC39Hq..." would defeat an exact-match scrub.
        self.vault.store("STRIPE_KEY", self.SECRET)
        code, out, err = self.run_it("--", "echo using ${STRIPE_KEY:0:12} now")
        self.assertNotIn(self.SECRET[:12], out)

    def test_only_the_named_credential_is_lent(self):
        # The command prints the env key names and references the wanted one from a comment, so
        # naming the unwanted one is not required to check that it is absent -- which matters now
        # that a bare word counts as a reference.
        self.vault.store("WANTED", "Ab3xQ9zLmN4pR7tV2wY8")
        self.vault.store("UNWANTED", "Zz9yQ1xLmN4pR7tV2wY8")
        code, out, err = self.run_it(
            "--", 'python3 -c "import os;print(\' \'.join(sorted(os.environ)))" # $WANTED')
        keys = out.split()
        self.assertIn("WANTED", keys)
        self.assertNotIn("UNWANTED", keys)

    def test_all_lends_everything_for_a_reference_inside_a_script(self):
        # `npm run deploy` names nothing clowk can see, which is what --all exists for.
        self.vault.store("WANTED", "Ab3xQ9zLmN4pR7tV2wY8")
        self.vault.store("UNWANTED", "Zz9yQ1xLmN4pR7tV2wY8")
        code, out, err = self.run_it(
            "--all", "--", 'python3 -c "import os;print(\' \'.join(sorted(os.environ)))"')
        keys = out.split()
        self.assertIn("WANTED", keys)
        self.assertIn("UNWANTED", keys)

    def test_the_exit_code_is_the_commands_own(self):
        self.assertEqual(self.run_it("--", "exit 7")[0], 7)

    def test_every_spelling_of_a_reference_is_recognised(self):
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        show = 'python3 -c "import os;print(len(os.environ.get(chr(68)+chr(66), \'\')))"'
        for spelling in ("# $DB", "# ${DB}", "# %DB%", "# DB"):
            code, out, err = self.run_it("--", show + " " + spelling)
            self.assertEqual(out.strip(), "20", "%r was not recognised as a reference" % spelling)

    def test_a_command_naming_nothing_is_lent_nothing(self):
        # chr() assembles the name so the command does not mention it, now that a bare word counts.
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        code, out, err = self.run_it(
            "--", 'python3 -c "import os;print(len(os.environ.get(chr(68)+chr(66), \'\')))"')
        self.assertEqual(out.strip(), "0")

    def test_a_similarly_named_variable_is_not_confused_for_it(self):
        # $DB_EXTRA must not count as a reference to DB, or a longer name would drag a shorter one
        # into every command that mentions it.
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        code, out, err = self.run_it(
            "--", 'python3 -c "import os;print(len(os.environ.get(chr(68)+chr(66), \'\')))" # $DB_EXTRA')
        self.assertEqual(out.strip(), "0")


class TestBookkeeping(RunnerCase):
    def test_using_a_credential_records_it_in_the_ledger(self):
        # The used-by list had no shipped caller at all until now, so `clowk uses` always read
        # "(nothing recorded yet)" however much a credential was used.
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        self.assertEqual(self.vault.list_secrets()["DB"]["uses"], [])
        self.run_it("--", "echo $DB")
        self.assertEqual(self.vault.list_secrets()["DB"]["uses"], [os.getcwd()])

    def test_a_command_that_uses_nothing_records_nothing(self):
        self.vault.store("DB", "Ab3xQ9zLmN4pR7tV2wY8")
        self.run_it("--", "echo hello")
        self.assertEqual(self.vault.list_secrets()["DB"]["uses"], [])


class TestGuidance(RunnerCase):
    def test_an_empty_command_explains_the_quoting(self):
        code, out, err = self.run_it("--")
        self.assertEqual(code, 2)
        self.assertIn("quote it", err.lower())

    def test_a_near_miss_name_is_pointed_out(self):
        # $DATABASE_URL when the vault holds DATABASE_URL_2 -- the exact shape produced when a
        # second, different value arrives under a name already taken. Silence gives an empty
        # expansion and a failure that reads as the credential being wrong.
        self.vault.store("DATABASE_URL_2", "Ab3xQ9zLmN4pR7tV2wY8")
        code, out, err = self.run_it("--", "echo $DATABASE_URL")
        self.assertIn("$DATABASE_URL", err)
        self.assertIn("not in the vault", err)

    def test_an_ordinary_environment_variable_is_not_flagged(self):
        # A variable the environment already defines is not a near miss, and warning about it would
        # turn the warning into noise. PATH rather than HOME: HOME does not exist on Windows, where
        # it is USERPROFILE, so the warning fired correctly and it was the test that was wrong.
        self.assertIn("PATH", os.environ, "this test needs PATH to exist")
        code, out, err = self.run_it("--", "echo $PATH")
        self.assertNotIn("not in the vault", err)

    def test_naming_nothing_says_nothing_was_lent(self):
        code, out, err = self.run_it("--", "echo plain")
        self.assertIn("names no stored credential", err)


if __name__ == "__main__":
    unittest.main()
