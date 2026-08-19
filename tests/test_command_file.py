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
        self.skill_target = os.path.join(self.home, ".claude", "skills", "clowk", "SKILL.md")
        os.environ["CLOWK_COMMANDS"] = self.target
        os.environ["CLOWK_SKILL"] = self.skill_target
        for key in ("CLOWK_COMMANDS", "CLOWK_SKILL"):
            self.addCleanup(os.environ.pop, key, None)

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


class TestSkill(CommandFileCase):
    """The skill is what carries the never-read rule, so install has to actually place it."""

    def test_it_is_copied_to_the_user_skills_directory(self):
        path = install.install_skill(ROOT)
        self.assertEqual(path, self.skill_target)
        self.assertTrue(os.path.exists(path))

    def test_it_states_the_hard_rule_and_the_safe_form(self):
        install.install_skill(ROOT)
        with open(self.skill_target, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("never read", body.lower())
        self.assertIn("$(clowk get", body)
        self.assertTrue(body.startswith("---"), "frontmatter must be first for discovery")
        self.assertIn("name: clowk", body)

    def test_it_names_no_real_credential(self):
        # The examples are placeholders; a skill shipped with a live value would be its own leak.
        install.install_skill(ROOT)
        from clowk.detect import scan
        with open(self.skill_target, encoding="utf-8") as f:
            findings = [f_.rule_id for f_ in scan(f.read())]
        self.assertEqual(findings, [], "the skill text itself trips detection: %s" % findings)

    def test_copying_twice_is_idempotent(self):
        install.install_skill(ROOT)
        first = open(self.skill_target, encoding="utf-8").read()
        install.install_skill(ROOT)
        self.assertEqual(open(self.skill_target, encoding="utf-8").read(), first)

    def test_uninstall_removes_it(self):
        install.install_skill(ROOT)
        self.assertTrue(install.uninstall_skill())
        self.assertFalse(os.path.exists(self.skill_target))

    def test_uninstall_leaves_an_unrelated_file_alone(self):
        os.makedirs(os.path.dirname(self.skill_target))
        with open(self.skill_target, "w", encoding="utf-8") as f:
            f.write("---\nname: something-else\n---\nnot clowk's\n")
        self.assertFalse(install.uninstall_skill())
        self.assertTrue(os.path.exists(self.skill_target))


class TestSkillSurvivesPackaging(CommandFileCase):
    """A wheel has no repo root, and the skill was resolved relative to one.

    `cli.py` computes root as the parent of the clowk package. In a clone that is the repository, so
    root/skills/clowk/SKILL.md resolves. Installed with pip, root is site-packages -- that path does
    not exist, install_skill returned None, and cmd_install printed nothing about it. The result
    would be a pip release that registers both hooks and silently ships no skill, and without the
    skill an agent reads $DATABASE_URL as an ordinary empty variable and asks for the real value
    again. That is the defect 0.1.0 exists to have fixed, reintroduced by the packaging.
    """

    def test_the_skill_installs_when_root_is_not_a_repository(self):
        # tempfile stands in for site-packages: a directory with no skills/ tree beneath it.
        fake_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, fake_root, True)
        path = install.install_skill(fake_root)
        self.assertEqual(path, self.skill_target,
                         "install_skill found no source outside a repo, so a pip install would "
                         "register hooks and quietly deliver no skill")
        self.assertTrue(os.path.isfile(path))

    def test_the_packaged_copy_matches_the_one_the_plugin_spec_needs(self):
        # Two copies of one file on purpose: the wheel needs it inside the package, and the Claude
        # Code plugin spec looks for skills/clowk/SKILL.md at the plugin root. Neither can move, so
        # this pins them together instead -- the same trick the diagram's counts use.
        packaged = install.PACKAGED_SKILL
        plugin = os.path.join(ROOT, install.SKILL_SOURCE)
        self.assertTrue(os.path.isfile(packaged), "%s is missing from the package" % packaged)
        with open(packaged, "rb") as a, open(plugin, "rb") as b:
            self.assertEqual(a.read(), b.read(),
                             "the packaged skill and the plugin copy have drifted")


if __name__ == "__main__":
    unittest.main()
