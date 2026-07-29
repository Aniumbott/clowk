import importlib
import json
import os
import tempfile
import unittest


class InstallCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.settings = os.path.join(self.dir, "settings.json")
        self.root = "/opt/clowk"
        from clowk import install

        self.install = importlib.reload(install)

    def write(self, data):
        with open(self.settings, "w") as f:
            json.dump(data, f)

    def read(self):
        with open(self.settings) as f:
            return json.load(f)

    def read_json(self, path):
        with open(path) as f:
            return json.load(f)

    def read_text(self, path):
        with open(path) as f:
            return f.read()


class TestInstall(InstallCase):
    def test_creates_settings_when_absent(self):
        result = self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(result["added"], 2)
        hooks = self.read()["hooks"]
        self.assertIn("UserPromptSubmit", hooks)
        self.assertIn("PreToolUse", hooks)

    def test_preserves_unrelated_settings_and_existing_hooks(self):
        self.write({
            "theme": "dark",
            "hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "echo mine"}]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo theirs"}]}],
            },
        })
        self.install.install("claude-code", self.root, self.settings)
        data = self.read()
        self.assertEqual(data["theme"], "dark")
        commands = json.dumps(data["hooks"])
        self.assertIn("echo mine", commands)
        self.assertIn("echo theirs", commands)
        self.assertIn("hook_prompt.py", commands)

    def test_is_idempotent(self):
        self.install.install("claude-code", self.root, self.settings)
        second = self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(second["added"], 0)
        entries = [
            entry
            for group in self.read()["hooks"]["UserPromptSubmit"]
            for entry in group.get("hooks", [])
            if self.install.is_clowk_entry(entry)
        ]
        self.assertEqual(len(entries), 1)

    def test_writes_a_backup_when_a_file_existed(self):
        self.write({"theme": "dark"})
        result = self.install.install("claude-code", self.root, self.settings)
        self.assertTrue(os.path.exists(result["backup"]))
        self.assertEqual(self.read_json(result["backup"])["theme"], "dark")

    def test_refuses_to_touch_an_unparseable_file(self):
        with open(self.settings, "w") as f:
            f.write("{not json")
        with self.assertRaises(ValueError):
            self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(self.read_text(self.settings), "{not json")

    def test_refuses_an_event_whose_value_is_not_a_list(self):
        self.write({"hooks": {"UserPromptSubmit": {"hooks": [{"command": "echo mine"}]}}})
        with self.assertRaises(ValueError):
            self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(self.read()["hooks"]["UserPromptSubmit"]["hooks"][0]["command"], "echo mine")

    def test_codex_uses_its_own_event_names(self):
        self.install.install("codex", self.root, self.settings)
        self.assertIn("UserPromptSubmit", self.read()["hooks"])

    def test_gemini_uses_beforeagent_and_beforetool(self):
        self.install.install("gemini-cli", self.root, self.settings)
        hooks = self.read()["hooks"]
        self.assertIn("BeforeAgent", hooks)
        self.assertIn("BeforeTool", hooks)

    def test_the_host_is_passed_to_the_hook_command(self):
        self.install.install("codex", self.root, self.settings)
        self.assertIn("--host codex", json.dumps(self.read()["hooks"]))

    def test_unknown_host_raises(self):
        with self.assertRaises(KeyError):
            self.install.install("nope", self.root, self.settings)


class TestUninstall(InstallCase):
    def test_removes_only_clowk_entries(self):
        self.write({"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "echo mine"}]}]}})
        self.install.install("claude-code", self.root, self.settings)
        result = self.install.uninstall("claude-code", self.settings)
        self.assertEqual(result["removed"], 2)
        commands = json.dumps(self.read()["hooks"])
        self.assertIn("echo mine", commands)
        self.assertNotIn("hook_prompt.py", commands)

    def test_prunes_emptied_groups_and_events(self):
        self.install.install("claude-code", self.root, self.settings)
        self.install.uninstall("claude-code", self.settings)
        self.assertEqual(self.read().get("hooks", {}), {})

    def test_uninstall_when_nothing_installed_is_zero(self):
        self.write({"theme": "dark"})
        self.assertEqual(self.install.uninstall("claude-code", self.settings)["removed"], 0)


if __name__ == "__main__":
    unittest.main()
