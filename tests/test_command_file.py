"""`clowk install` writes a user-level /clowk command, so the plugin is optional.

A plugin command is always namespaced <plugin>:<command>, so the plugin's copy is reachable only
as `/clowk:clowk`. A file in ~/.claude/commands is not namespaced, so it gives a plain `/clowk`.

It has to be GENERATED, not copied: commands/clowk.md resolves ${CLAUDE_PLUGIN_ROOT}, which is set
only for plugin commands, so copying that file produced `python3 "/clowk/cli.py"` -- a path that
does not exist -- and an unknown-command error.
"""
import os
import shutil
import tempfile
import unittest

from clowk import install

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CommandFileCase(unittest.TestCase):
    def setUp(self):
        # CLOWK_COMMANDS, not a reassigned HOME: on Windows expanduser("~") reads USERPROFILE, so
        # setting HOME redirected nothing and these tests wrote into the real user profile.
        self.home = tempfile.mkdtemp(prefix="clowk-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.target = os.path.join(self.home, ".claude", "commands", "clowk.md")
        os.environ["CLOWK_COMMANDS"] = self.target
        self.addCleanup(os.environ.pop, "CLOWK_COMMANDS", None)

    def read(self):
        with open(install.command_path(), encoding="utf-8") as f:
            return f.read()


class TestWriting(CommandFileCase):
    def test_it_lands_in_the_unnamespaced_commands_directory(self):
        path = install.install_command(ROOT)
        self.assertEqual(path, self.target)
        self.assertTrue(os.path.exists(path))

    def test_frontmatter_is_the_very_first_line(self):
        # The marker used to sit above the frontmatter, which stops it being frontmatter at all.
        install.install_command(ROOT)
        self.assertTrue(self.read().startswith("---\n"))

    def test_it_carries_no_plugin_root_variable(self):
        install.install_command(ROOT)
        self.assertNotIn("CLAUDE_PLUGIN_ROOT", self.read())

    def test_the_interpreter_and_cli_path_both_exist_on_disk(self):
        install.install_command(ROOT)
        body = self.read()
        lines = [ln for ln in body.splitlines() if ln.startswith("!`")]
        self.assertEqual(len(lines), 1, "expected exactly one command line, got %r" % lines)
        interpreter = lines[0].split('"')[0].lstrip("!`").strip()
        cli = lines[0].split('"')[1]
        self.assertTrue(os.path.exists(interpreter), "interpreter missing: %r" % interpreter)
        self.assertTrue(os.path.exists(cli), "cli.py missing: %r" % cli)

    def test_writing_twice_is_idempotent(self):
        install.install_command(ROOT)
        first = self.read()
        install.install_command(ROOT)
        self.assertEqual(self.read(), first)

    def test_no_temp_file_is_left_behind(self):
        install.install_command(ROOT)
        self.assertFalse(os.path.exists(install.command_path() + ".tmp"))


class TestNotClobbering(CommandFileCase):
    def write_foreign(self):
        path = install.command_path()
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8") as f:
            f.write("---\ndescription: my own clowk command\n---\ndo not touch\n")
        return path

    def test_a_hand_written_command_is_refused_not_overwritten(self):
        path = self.write_foreign()
        self.assertIsNone(install.install_command(ROOT))
        self.assertIn("do not touch", self.read())

    def test_uninstall_leaves_a_hand_written_command_alone(self):
        self.write_foreign()
        self.assertFalse(install.uninstall_command())
        self.assertTrue(os.path.exists(install.command_path()))


class TestRemoving(CommandFileCase):
    def test_uninstall_removes_what_install_wrote(self):
        install.install_command(ROOT)
        self.assertTrue(install.uninstall_command())
        self.assertFalse(os.path.exists(install.command_path()))

    def test_uninstall_with_nothing_installed_is_false(self):
        self.assertFalse(install.uninstall_command())


if __name__ == "__main__":
    unittest.main()
