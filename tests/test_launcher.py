"""`clowk install` writes an executable named clowk, so the documented examples can actually run.

Everything clowk tells a person or an agent to type starts with the word `clowk` -- the skill's one
correct form, the pointer appended to every block message, every line of the README's Commands
table. install registered two hooks, wrote a slash command and copied a skill, and left that word
meaning nothing: following the README end to end produced `command not found`.

The README's answer was a shell alias, and an alias is an interactive-shell feature. It is therefore
absent from exactly the non-interactive Bash an agent runs, which is the one caller that matters --
`clowk get` exists for the agent, not for the human.

Absent would be survivable if it failed loudly. It does not: a failed `$(clowk get X)` expands to
the empty string and the outer command runs anyway, so `psql "$(clowk get DATABASE_URL)"` opens the
default database and `curl -H "Authorization: Bearer $(clowk get X)"` sends an empty bearer. Both
report a downstream error that reads as a wrong credential rather than a missing clowk.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from clowk import install

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LauncherCase(unittest.TestCase):
    def setUp(self):
        # CLOWK_BIN for the reason CLOWK_COMMANDS and CLOWK_SKILL exist: on Windows
        # expanduser("~") reads USERPROFILE and never HOME, so reassigning HOME redirects nothing
        # and the test writes into the real user profile.
        self.home = tempfile.mkdtemp(prefix="clowk-bin-")
        self.addCleanup(shutil.rmtree, self.home, True)
        name = "clowk.cmd" if os.name == "nt" else "clowk"
        self.target = os.path.join(self.home, ".local", "bin", name)
        os.environ["CLOWK_BIN"] = self.target
        self.addCleanup(os.environ.pop, "CLOWK_BIN", None)

    def read(self):
        with open(install.launcher_path(), encoding="utf-8") as f:
            return f.read()


class TestTheLauncherIsWritten(LauncherCase):
    def test_install_creates_it_at_the_configured_path(self):
        self.assertEqual(install.install_launcher(ROOT), self.target)
        self.assertTrue(os.path.exists(self.target))

    def test_it_names_an_absolute_interpreter_and_an_absolute_script(self):
        """No part of it may depend on anything being on PATH -- that is what it exists to fix."""
        install.install_launcher(ROOT)
        body = self.read()
        self.assertIn(os.path.join(ROOT, "clowk", "cli.py"), body)
        self.assertIn(sys.executable, body)

    def test_it_leaves_no_temp_file_behind(self):
        install.install_launcher(ROOT)
        self.assertFalse(os.path.exists(self.target + ".tmp"))

    @unittest.skipIf(os.name == "nt", "Windows keys execution off the .cmd extension, not a mode")
    def test_it_is_executable(self):
        install.install_launcher(ROOT)
        self.assertTrue(os.access(self.target, os.X_OK))


class TestTheLauncherActuallyRuns(LauncherCase):
    """The point of the whole file. A shim that exists but cannot run fixes nothing."""

    @unittest.skipIf(os.name == "nt", "a .cmd shim needs a shell to invoke; covered by content")
    def test_running_it_reaches_the_cli(self):
        install.install_launcher(ROOT)
        env = dict(os.environ, CLOWK_VAULT=os.path.join(self.home, "vault.json"))
        proc = subprocess.run([self.target, "list"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("No credentials stored", proc.stdout)

    @unittest.skipIf(os.name == "nt", "a .cmd shim needs a shell to invoke; covered by content")
    def test_it_forwards_arguments_and_the_exit_code(self):
        """`clowk get NOPE` must exit 1, or a caller cannot tell a miss from a value."""
        install.install_launcher(ROOT)
        env = dict(os.environ, CLOWK_VAULT=os.path.join(self.home, "vault.json"))
        proc = subprocess.run([self.target, "get", "NOPE"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("No credential named NOPE", proc.stderr)


class TestItNeverClobbersSomeoneElsesClowk(LauncherCase):
    def test_a_foreign_file_is_left_alone(self):
        os.makedirs(os.path.dirname(self.target))
        with open(self.target, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho someone else's clowk\n")
        self.assertIsNone(install.install_launcher(ROOT))
        self.assertIn("someone else's clowk", self.read())

    def test_uninstall_leaves_a_foreign_file_alone(self):
        os.makedirs(os.path.dirname(self.target))
        with open(self.target, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho someone else's clowk\n")
        self.assertFalse(install.uninstall_launcher())
        self.assertTrue(os.path.exists(self.target))

    def test_uninstall_removes_the_one_clowk_wrote(self):
        install.install_launcher(ROOT)
        self.assertTrue(install.uninstall_launcher())
        self.assertFalse(os.path.exists(self.target))

    def test_uninstall_with_nothing_there_is_false(self):
        self.assertFalse(install.uninstall_launcher())


class TestTheUserIsToldWhenItIsUnreachable(LauncherCase):
    """Writing an executable the user cannot reach is the same bug in a new place."""

    def test_a_directory_on_path_reports_reachable(self):
        parent = os.path.dirname(self.target)
        os.makedirs(parent)
        with mock_path(parent):
            self.assertTrue(install.launcher_on_path(self.target))

    def test_a_directory_off_path_reports_unreachable(self):
        with mock_path(os.path.join(self.home, "somewhere-else")):
            self.assertFalse(install.launcher_on_path(self.target))


class mock_path(object):
    """PATH set to exactly one directory, restored afterwards."""

    def __init__(self, entry):
        self.entry = entry

    def __enter__(self):
        self.saved = os.environ.get("PATH", "")
        os.environ["PATH"] = self.entry
        return self

    def __exit__(self, *exc):
        os.environ["PATH"] = self.saved
        return False


if __name__ == "__main__":
    unittest.main()
