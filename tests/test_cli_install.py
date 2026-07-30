"""`clowk install`, `clowk uninstall` and `clowk debug-payload` through the CLI.

tests/test_install.py drives install.install()/uninstall() directly, always with an explicit
settings path. That leaves the CLI adapter and the per-host path table unexercised -- and those
are exactly the two facts that decide whether a user is protected: which host was asked for, and
which file the hooks landed in. A dropped host argument sent Codex's hooks to
~/.claude/settings.json while printing "Registered 2 clowk hook(s)", and the suite stayed green.

test_integration.py says cmd_install cannot be driven because it has no path override. It does not
need one: install.settings_path() expands `~` at call time, so pointing the home directory at a
temp dir is enough. HOME and USERPROFILE are both set -- ntpath.expanduser never looks at HOME, so
a HOME-only sandbox would rewrite a Windows contributor's real profile.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from clowk import cli, install
from tests.test_install import hook_count

# Literals on purpose: deriving these from install.TARGETS would assert the table against itself,
# and a typo in a host's filename is precisely what this file exists to catch.
EXPECTED = {
    "claude-code": (os.path.join(".claude", "settings.json"), "UserPromptSubmit", "PreToolUse"),
    "codex": (os.path.join(".codex", "hooks.json"), "UserPromptSubmit", "PreToolUse"),
    "gemini-cli": (os.path.join(".gemini", "settings.json"), "BeforeAgent", "BeforeTool"),
}
ALL_HOSTS = tuple(sorted(EXPECTED))


class CliInstallCase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="clowk-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        for key in ("HOME", "USERPROFILE", "CLOWK_VAULT", "CLOWK_DENY"):
            self.addCleanup(self._restore, key, os.environ.get(key))
        os.environ["HOME"] = self.home
        os.environ["USERPROFILE"] = self.home
        # Nothing here should touch a vault, but if anything does it must not be the real one.
        os.environ["CLOWK_VAULT"] = os.path.join(self.home, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.home, "deny.json")

    @staticmethod
    def _restore(key, value):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()

    def settings_for(self, host):
        return os.path.join(self.home, EXPECTED[host][0])

    def read_settings(self, host):
        with open(self.settings_for(host), encoding="utf-8") as f:
            return json.load(f)

    def home_files(self):
        found = []
        for root, _dirs, files in os.walk(self.home):
            for name in files:
                found.append(os.path.relpath(os.path.join(root, name), self.home))
        return sorted(found)


class TestInstallThroughTheCli(CliInstallCase):
    def test_each_host_gets_its_hooks_in_its_own_file_on_its_own_events(self):
        for host in ALL_HOSTS:
            path, prompt_event, tool_event = EXPECTED[host]
            code, out, err = self.run_cli("install", host)
            self.assertEqual((host, code, err), (host, 0, ""))
            self.assertIn("Registered %d clowk hook(s)" % hook_count(host), out)
            self.assertIn(self.settings_for(host), out)
            self.assertTrue(os.path.exists(self.settings_for(host)),
                            "%s: no hooks written to %s" % (host, path))
            hooks = self.read_settings(host)["hooks"]
            expected = [prompt_event, tool_event]
            session = install.TARGETS[host].get("session_event")
            if session:
                expected.append(session)   # the briefing, where the host has a session event
            self.assertEqual(sorted(hooks), sorted(expected))
            blob = json.dumps(hooks)
            self.assertIn("--host " + host, blob)
            self.assertIn("hook_prompt.py", blob)
            self.assertIn("hook_pretool.py", blob)

    def test_install_with_no_host_touches_only_claude_codes_files(self):
        """Defaulting to claude-code must not write into ~/.codex or ~/.gemini.

        It writes two files, not one: the hook registration, and the unnamespaced /clowk command
        (the plugin's copy is only reachable as /clowk:clowk). The assertion that matters is that
        no OTHER host's settings appear, so it is spelled that way rather than as an exact list --
        the previous exact-list form failed the moment a legitimate second file was added.
        """
        code, out, err = self.run_cli("install")
        self.assertEqual((code, err), (0, ""))
        written = self.home_files()
        self.assertIn(EXPECTED["claude-code"][0], written)
        # normalise separators: home_files() yields OS-native paths, and Windows uses backslashes
        normalised = [w.replace(os.sep, "/") for w in written]
        self.assertIn(".claude/commands/clowk.md", normalised)
        for host in ("codex", "gemini-cli"):
            self.assertNotIn(EXPECTED[host][0], written,
                             "installing for claude-code wrote %s's settings" % host)
        self.assertIn("--host claude-code", json.dumps(self.read_settings("claude-code")))

    def test_the_prompt_hook_lands_on_the_command_this_clone_can_actually_run(self):
        # Read the command out of the parsed settings rather than substring-matching the serialised
        # blob: on Windows json.dumps escapes every backslash, so a raw path is never found in it
        # and the test failed for a reason that had nothing to do with what it was checking.
        self.run_cli("install")
        settings = self.read_settings("claude-code")
        commands = [
            entry["command"]
            for group in settings["hooks"]["UserPromptSubmit"]
            for entry in group.get("hooks", [])
        ]
        root = os.path.dirname(os.path.dirname(os.path.abspath(cli.__file__)))
        script = os.path.join(root, "clowk", "hook_prompt.py")
        self.assertTrue(os.path.exists(script))
        matching = [c for c in commands if script in c]
        self.assertTrue(matching, "no registered command references %s: %r" % (script, commands))

        # The interpreter has to be one that exists. "python3" is absent on stock Windows -- it is
        # python, the py launcher, or a Store alias stub -- so registering that name produced a hook
        # that could never run while install reported success.
        interpreter = matching[0].split('" "')[0].lstrip('"')
        self.assertTrue(os.path.exists(interpreter),
                        "registered interpreter does not exist: %r" % interpreter)

    def test_only_codex_is_told_about_hook_trust(self):
        self.assertIn("hook trust", self.run_cli("install", "codex")[1])
        for host in ("claude-code", "gemini-cli"):
            self.assertNotIn("hook trust", self.run_cli("install", host)[1])

    def test_every_host_is_told_to_restart_itself_and_not_another_host(self):
        for host in ALL_HOSTS:
            out = self.run_cli("install", host)[1]
            self.assertIn("Restart %s" % host, out)

    def test_installing_twice_adds_nothing_the_second_time(self):
        self.run_cli("install")
        code, out, err = self.run_cli("install")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("already registered", out)
        self.assertNotIn("Registered", out)

    def test_a_pre_existing_settings_file_is_backed_up_and_the_backup_is_named(self):
        path = self.settings_for("claude-code")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"theme": "dark"}, f)
        code, out, err = self.run_cli("install")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Backed up your previous settings to ", out)
        backup = out.split("Backed up your previous settings to ")[1].split("\n")[0].rstrip(".")
        with open(backup, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"theme": "dark"})
        self.assertEqual(self.read_settings("claude-code")["theme"], "dark")

    def test_an_unknown_host_exits_one_and_writes_nothing(self):
        code, out, err = self.run_cli("install", "emacs")
        self.assertEqual(code, 1)
        self.assertIn("Unknown host", err)
        for known in ALL_HOSTS:
            self.assertIn(known, err)
        self.assertEqual((out, self.home_files()), ("", []))

    def test_an_unparseable_settings_file_is_refused_not_overwritten(self):
        path = self.settings_for("claude-code")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        code, out, err = self.run_cli("install")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("not valid JSON", err)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{not json")


class TestUninstallThroughTheCli(CliInstallCase):
    def test_uninstall_removes_what_install_registered_for_that_host(self):
        for host in ALL_HOSTS:
            self.assertEqual(self.run_cli("install", host)[0], 0)
            code, out, err = self.run_cli("uninstall", host)
            self.assertEqual((host, code, err), (host, 0, ""))
            self.assertIn("Removed %d clowk hook(s)" % hook_count(host), out)
            self.assertIn(self.settings_for(host), out)
            self.assertNotIn("clowk", json.dumps(self.read_settings(host)))

    def test_uninstall_with_no_host_defaults_to_claude_code(self):
        self.run_cli("install")
        code, out, err = self.run_cli("uninstall")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Removed %d" % hook_count("claude-code"), out)
        self.assertIn(self.settings_for("claude-code"), out)

    def test_uninstalling_one_host_leaves_another_hosts_hooks_alone(self):
        self.run_cli("install", "codex")
        self.run_cli("install", "gemini-cli")
        self.assertIn("Removed 2", self.run_cli("uninstall", "codex")[1])
        self.assertIn("--host gemini-cli", json.dumps(self.read_settings("gemini-cli")))

    def test_uninstall_where_nothing_was_installed_removes_nothing(self):
        code, out, err = self.run_cli("uninstall")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Removed 0 clowk hook(s)", out)

    def test_an_unknown_host_exits_one(self):
        code, out, err = self.run_cli("uninstall", "emacs")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Unknown host", err)


class TestDebugPayloadThroughTheCli(CliInstallCase):
    """The command that exists so a user can report an unknown host's payload shape."""

    def run_with_stdin(self, text):
        real = sys.stdin
        sys.stdin = io.StringIO(text)
        try:
            return self.run_cli("debug-payload")
        finally:
            sys.stdin = real

    def test_it_reports_the_keys_and_the_length_of_each_string_field(self):
        code, out, err = self.run_with_stdin(json.dumps(
            {"prompt": "hello there", "cwd": "/proj", "nested": {"a": 1}}))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("'cwd'", out)
        self.assertIn("'prompt'", out)
        self.assertIn("len=11", out)  # "hello there"
        self.assertIn("PROMPT_KEYS", out)

    def test_it_never_echoes_the_payload_itself(self):
        # The payload is a prompt, so it can hold the credential the user is debugging.
        code, out, err = self.run_with_stdin(json.dumps({"prompt": "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"}))
        self.assertEqual(code, 0)
        self.assertNotIn("sk_" "live_4eC39HqLyjWDarjtT1zdp7dc", out + err)

    def test_input_that_is_not_json_exits_one(self):
        code, out, err = self.run_with_stdin("not json at all")
        self.assertEqual(code, 1)
        self.assertIn("Not valid JSON", out)

    def test_json_that_is_not_an_object_exits_one(self):
        code, out, err = self.run_with_stdin("[1, 2, 3]")
        self.assertEqual(code, 1)
        self.assertIn("Not a JSON object", out)


if __name__ == "__main__":
    unittest.main()
