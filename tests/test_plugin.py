"""Installing and removing the Claude Code plugin through `claude plugin`.

Driven against a fake `claude` -- a script that answers from a state file and logs every call --
because the real one would change the developer's own Claude Code setup. CLOWK_CLAUDE points at it.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import plugin

FAKE = r'''#!%(python)s
import json, sys
state_path, log_path = %(state)r, %(log)r
state = json.load(open(state_path))
args = sys.argv[1:]
open(log_path, "a").write(json.dumps(args) + "\n")
if args == ["--version"]:
    print(state["version"] + " (Claude Code)")
elif args[:2] == ["plugin", "list"]:
    print(json.dumps([{"id": "clowk@clowk"}] if state["installed"] else [{"id": "other@x"}]))
elif args[:3] == ["plugin", "marketplace", "add"]:
    print("added")
elif args[:2] == ["plugin", "install"]:
    if state.get("install_fails"):
        print("Error: could not reach github.com"); sys.exit(1)
    state["installed"] = True; json.dump(state, open(state_path, "w"))
elif args[:2] == ["plugin", "uninstall"]:
    state["installed"] = False; json.dump(state, open(state_path, "w"))
'''


class FakeClaude(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = os.path.join(self.dir, "state.json")
        self.log = os.path.join(self.dir, "calls.log")
        self.bin = os.path.join(self.dir, "claude")
        with open(self.bin, "w") as f:
            f.write(FAKE % {"python": sys.executable, "state": self.state, "log": self.log})
        os.chmod(self.bin, 0o755)
        self.addCleanup(os.environ.__setitem__, "CLOWK_CLAUDE", os.environ.get("CLOWK_CLAUDE", ""))
        os.environ["CLOWK_CLAUDE"] = self.bin
        self.set(version="2.1.295", installed=False)

    def set(self, **state):
        with open(self.state, "w") as f:
            json.dump(state, f)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        return [json.loads(line) for line in open(self.log)]


@unittest.skipIf(os.name == "nt", "the fake claude is a POSIX script")
class TestInstall(FakeClaude):
    def test_it_adds_the_marketplace_then_installs_for_the_user(self):
        ok, detail = plugin.install()
        self.assertTrue(ok, detail)
        self.assertIn(["plugin", "marketplace", "add", "Aniumbott/clowk"], self.calls())
        self.assertIn(["plugin", "install", "clowk@clowk", "--scope", "user"], self.calls())

    def test_an_installed_plugin_is_left_alone(self):
        self.set(version="2.1.295", installed=True)
        ok, detail = plugin.install()
        self.assertTrue(ok)
        self.assertIn("already", detail)
        self.assertFalse(any(c[:2] == ["plugin", "install"] for c in self.calls()))

    def test_a_claude_code_without_mods_is_skipped_not_failed(self):
        self.set(version="2.1.284", installed=False)
        ok, detail = plugin.install()
        self.assertIsNone(ok)
        self.assertIn("2.1.287", detail)
        self.assertFalse(any(c[:1] == ["plugin"] for c in self.calls()))

    def test_no_claude_at_all_is_a_skip(self):
        os.environ["CLOWK_CLAUDE"] = os.path.join(self.dir, "nope")
        ok, detail = plugin.install()
        self.assertIsNone(ok)

    def test_a_failed_install_says_why_and_that_the_hooks_still_block(self):
        self.set(version="2.1.295", installed=False, install_fails=True)
        ok, detail = plugin.install()
        self.assertFalse(ok)
        self.assertIn("github.com", detail)
        self.assertIn("hooks still block", detail)


@unittest.skipIf(os.name == "nt", "the fake claude is a POSIX script")
class TestUninstall(FakeClaude):
    def test_it_removes_an_installed_plugin(self):
        self.set(version="2.1.295", installed=True)
        self.assertTrue(plugin.uninstall())
        self.assertIn(["plugin", "uninstall", "clowk@clowk", "--scope", "user"], self.calls())

    def test_nothing_installed_is_nothing_to_do(self):
        self.assertFalse(plugin.uninstall())
        self.assertFalse(any(c[:2] == ["plugin", "uninstall"] for c in self.calls()))


@unittest.skipIf(os.name == "nt", "the fake claude is a POSIX script")
class TestOneSkillNotTwo(FakeClaude):
    """The plugin ships skills/clowk, so a copy in ~/.claude/skills lists the skill twice."""

    def setUp(self):
        super().setUp()
        self.home = tempfile.mkdtemp(prefix="clowk-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        for key in ("HOME", "USERPROFILE", "CLOWK_VAULT", "CLOWK_DENY", "CLOWK_SKILL", "CLOWK_COMMANDS"):
            self.addCleanup(self._restore, key, os.environ.get(key))
            os.environ.pop(key, None)
        os.environ["HOME"] = self.home
        os.environ["USERPROFILE"] = self.home
        os.environ["CLOWK_VAULT"] = os.path.join(self.home, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.home, "deny.json")
        self.skill = os.path.join(self.home, ".claude", "skills", "clowk", "SKILL.md")

    @staticmethod
    def _restore(key, value):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    def install(self, *argv):
        from clowk import cli
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["install"] + list(argv), out, err)
        self.assertEqual(code, 0, err.getvalue())
        return out.getvalue()

    def test_without_the_plugin_the_skill_is_copied(self):
        self.install("claude-code")
        self.assertTrue(os.path.exists(self.skill))

    def test_with_the_plugin_no_copy_is_written(self):
        self.set(version="2.1.295", installed=True)
        self.install("claude-code")
        self.assertFalse(os.path.exists(self.skill))

    def test_a_copy_left_by_an_older_install_is_removed(self):
        # An existing user: `clowk install` before the plugin, then the plugin. `clowk update`
        # re-runs install, which is when the stale copy goes.
        self.install("claude-code")
        self.set(version="2.1.295", installed=True)
        printed = self.install("claude-code")
        self.assertFalse(os.path.exists(self.skill))
        self.assertIn("plugin", printed)

    def test_codex_still_gets_its_copy(self):
        self.set(version="2.1.295", installed=True)
        self.install("codex")
        self.assertTrue(os.path.exists(os.path.join(self.home, ".codex", "skills", "clowk", "SKILL.md")))

    def test_setup_that_adds_the_plugin_leaves_one_skill(self):
        from clowk import setup
        out, err = io.StringIO(), io.StringIO()
        setup.run(["--hosts", "claude-code", "--yes"], out, err, io.StringIO())
        self.assertTrue(plugin.installed(), out.getvalue() + err.getvalue())
        self.assertFalse(os.path.exists(self.skill))


class TestTheSuiteNeverTouchesTheRealClaude(unittest.TestCase):
    def test_the_default_is_overridden_for_every_test(self):
        # tests/__init__.py sets it before any module runs; without it, setup and uninstall tests
        # would install or remove the developer's real plugin.
        self.assertNotEqual(os.environ.get("CLOWK_CLAUDE", "claude"), "claude")
