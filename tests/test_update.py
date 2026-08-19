"""`clowk update` exists for the half of an update that does not happen on its own.

Hooks and the launcher hold absolute paths and pick up new code immediately. The skill is copied and
/clowk is generated, so both keep serving old content until install runs again -- new code, old
skill, nothing on screen saying so.

Two of these tests exist because the first implementation was wrong. It refused to pull when the
clone had UNTRACKED files, which do not affect `git pull --ff-only` at all, so it would have refused
for anyone holding a stray note. And `--check`, which is supposed to look without touching anything,
refused outright on the same condition.
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import update


class UpdateCase(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        self.err = io.StringIO()


class TestInstallModeDetection(UpdateCase):
    def test_a_git_checkout_is_a_clone(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, ".git"))
        self.assertEqual(update.install_mode(root), "clone")

    def test_anything_else_is_a_package(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        self.assertEqual(update.install_mode(root), "package")

    def test_this_repository_is_detected_as_a_clone(self):
        self.assertEqual(update.install_mode(), "clone")


class TestTheUpgradeCommandMatchesTheManager(UpdateCase):
    """Guessing wrong can half-replace a package, so the command is named per manager."""

    def test_each_manager_gets_its_own_verb(self):
        self.assertEqual(update.upgrade_command("pipx"), "pipx upgrade clowk")
        self.assertEqual(update.upgrade_command("uv"), "uv tool upgrade clowk")
        self.assertIn("pip install --upgrade clowk", update.upgrade_command("pip"))

    def test_the_pip_form_names_a_real_interpreter(self):
        # `pip install -U` bare can be a different environment's pip than the one running clowk.
        self.assertIn(os.path.basename(sys.executable), update.upgrade_command("pip"))

    def test_detection_returns_one_of_the_three(self):
        self.assertIn(update.package_manager(), ("pipx", "uv", "pip"))


class TestCheckIsReadOnly(UpdateCase):
    def test_check_does_not_refuse_on_a_dirty_tree(self):
        # The whole point of --check is to report. Refusing made it useless in any working clone.
        code = update.run(["--check"], self.out, self.err)
        self.assertEqual(code, 0, self.err.getvalue())
        self.assertIn("Tracked changes", self.out.getvalue())

    def test_check_reports_the_mode_and_the_hosts(self):
        update.run(["--check"], self.out, self.err)
        body = self.out.getvalue()
        self.assertIn("installed as a", body)
        self.assertIn("Registered on", body)

    def test_an_unknown_flag_is_refused_with_usage(self):
        code = update.run(["--force"], self.out, self.err)
        self.assertEqual(code, 1)
        self.assertIn("clowk update", self.err.getvalue())


class TestUntrackedFilesDoNotBlockAPull(UpdateCase):
    """`git status --porcelain` lists untracked files; `git pull --ff-only` does not care about them.

    Blocking on them refused the update for anyone with a stray note in their clone.
    """

    def make_repo(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        for args in (["init", "-q"], ["config", "user.email", "t@example.com"],
                     ["config", "user.name", "t"]):
            subprocess.check_call(["git"] + args, cwd=root,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(os.path.join(root, "tracked.txt"), "w") as f:
            f.write("one\n")
        subprocess.check_call(["git", "add", "-A"], cwd=root,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["git", "commit", "-qm", "first"], cwd=root,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return root

    def dirty(self, root):
        code, text = update._git(["status", "--porcelain", "--untracked-files=no"], root)
        self.assertEqual(code, 0, text)
        return text

    def test_an_untracked_file_leaves_the_tree_clean_for_our_purposes(self):
        root = self.make_repo()
        with open(os.path.join(root, "stray-note.md"), "w") as f:
            f.write("not committed\n")
        self.assertEqual(self.dirty(root), "",
                         "an untracked file was treated as a blocking change")

    def test_a_modified_tracked_file_does_make_it_dirty(self):
        root = self.make_repo()
        with open(os.path.join(root, "tracked.txt"), "w") as f:
            f.write("two\n")
        self.assertIn("tracked.txt", self.dirty(root))


class TestRefusingWhenNothingIsRegistered(UpdateCase):
    def test_it_points_at_setup_rather_than_pulling(self):
        real = update.registered_hosts
        update.registered_hosts = lambda: []
        try:
            code = update.run([], self.out, self.err)
        finally:
            update.registered_hosts = real
        self.assertEqual(code, 1)
        self.assertIn("clowk setup", self.out.getvalue())


if __name__ == "__main__":
    unittest.main()
