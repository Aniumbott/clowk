import importlib
import json
import os
import stat
import tempfile
import unittest

from tests import default_encoding


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

    def test_refuses_a_group_whose_hooks_value_is_not_a_list(self):
        # `hooks -> EVENT -> [{matcher, hooks: [...]}]` nests an array inside an object under a
        # key also called "hooks", so writing `"hooks": {...}` for `"hooks": [{...}]` is an
        # ordinary hand-edit slip. It used to reach .append on a dict or iterate an int, and
        # cmd_install catches neither AttributeError nor TypeError: the user got a traceback.
        for bad in ({"type": "command", "command": "x"}, 5, "python3 mine.py", None, True):
            self.write({"hooks": {"UserPromptSubmit": [{"hooks": bad}]}})
            with self.assertRaises(ValueError):
                self.install.install("claude-code", self.root, self.settings)
            self.assertEqual(self.read()["hooks"]["UserPromptSubmit"][0]["hooks"], bad)

    def test_a_group_with_no_hooks_key_at_all_is_still_fine(self):
        # A matcher-only group is legal and common; "absent" must not be confused with "wrong".
        self.write({"hooks": {"PreToolUse": [{"matcher": "Write"}]}})
        self.assertEqual(self.install.install("claude-code", self.root, self.settings)["added"], 2)
        self.assertIn({"matcher": "Write"}, self.read()["hooks"]["PreToolUse"])

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


class TestFileMode(InstallCase):
    """_save replaces the file, so the mode has to be carried across deliberately.

    settings.json can hold an `env` block that auto-reloads into every session's Bash
    environment, so it is a credential-carrying surface. A tool that exists for credential
    hygiene must not widen a mode the user narrowed on purpose -- nor narrow one they left open.
    Only the backup got this right, because _backup goes through shutil.copy2.
    """

    def setUp(self):
        InstallCase.setUp(self)
        if os.name == "nt":
            self.skipTest("POSIX modes only; on Windows this relies on user-profile ACLs")
        previous = os.umask(0o022)  # pinned: the bug is invisible under a strict umask
        self.addCleanup(os.umask, previous)

    def mode(self, path=None):
        return stat.S_IMODE(os.stat(path or self.settings).st_mode)

    def test_a_narrowed_mode_survives_install_and_uninstall(self):
        self.write({"theme": "dark", "env": {"ANTHROPIC_API_KEY": "sk-" "ant-not-real"}})
        os.chmod(self.settings, 0o600)
        self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(self.mode(), 0o600)
        self.install.uninstall("claude-code", self.settings)
        self.assertEqual(self.mode(), 0o600)

    def test_a_wider_mode_is_not_tightened_either(self):
        self.write({"theme": "dark"})
        os.chmod(self.settings, 0o640)
        self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(self.mode(), 0o640)

    def test_a_file_install_creates_from_scratch_starts_closed(self):
        self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(self.mode(), 0o600)

    def test_the_temp_file_is_never_created_wider_than_owner_only(self):
        # If the process dies mid-write, whatever mode the temp file was created with is what a
        # full copy of the settings keeps on disk. Create closed, widen only at the end.
        self.write({"env": {"ANTHROPIC_API_KEY": "sk-" "ant-not-real"}})
        os.chmod(self.settings, 0o644)
        tmp = self.settings + ".tmp"
        seen = []

        class SpyJson(object):
            loads = staticmethod(json.loads)
            dump = staticmethod(json.dump)

            @staticmethod
            def dumps(data, **kwargs):
                # Sampled here because _save serialises to a string after creating the temp file at
                # 0600 and before writing a byte to it -- exactly the window this test is about.
                # (It serialises rather than streaming so it can match the file's line endings; the
                # invariant is unchanged, only the point at which it is observable.)
                seen.append(stat.S_IMODE(os.stat(tmp).st_mode))
                return json.dumps(data, **kwargs)

        self.install.json = SpyJson
        self.addCleanup(setattr, self.install, "json", json)
        self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(seen, [0o600])
        self.assertFalse(os.path.exists(tmp))


class TestEncoding(InstallCase):
    """settings.json is UTF-8. Hosts write it with JS JSON.stringify, which emits raw UTF-8.

    Reading it with the locale codec instead either mangles a valid file -- a cp1252 read plus an
    escaped write leaves permanent mojibake in the user's live settings, with only clowk's backup
    still holding the original -- or refuses it outright, since a byte undefined in cp1252 raises
    a UnicodeDecodeError that cmd_install reports as if the JSON were the user's fault.
    """

    def write_bytes(self, raw):
        with open(self.settings, "wb") as f:
            f.write(raw)

    def read_bytes(self):
        with open(self.settings, "rb") as f:
            return f.read()

    def test_non_ascii_settings_survive_install_unchanged(self):
        text = "café — déjà vu"
        self.write_bytes(json.dumps({"note": text}, ensure_ascii=False).encode("utf-8"))
        with default_encoding("cp1252"):
            self.install.install("claude-code", self.root, self.settings)
        self.assertIn(text.encode("utf-8"), self.read_bytes())

    def test_a_byte_undefined_in_the_locale_codec_does_not_block_install(self):
        name = "Łukasz"  # U+0141 is C5 81 in UTF-8; 0x81 is undefined in cp1252
        self.write_bytes(json.dumps({"user": name}, ensure_ascii=False).encode("utf-8"))
        with default_encoding("cp1252"):
            result = self.install.install("claude-code", self.root, self.settings)
        self.assertEqual(result["added"], 2)
        self.assertIn(name.encode("utf-8"), self.read_bytes())

    def test_uninstall_puts_a_non_ascii_file_back_byte_for_byte(self):
        raw = json.dumps({"note": "café", "hooks": {}}, ensure_ascii=False, indent=2)
        self.write_bytes(raw.encode("utf-8"))
        with default_encoding("cp1252"):
            self.install.install("claude-code", self.root, self.settings)
            self.install.uninstall("claude-code", self.settings)
        self.assertEqual(self.read_bytes(), raw.encode("utf-8"))

    def test_a_settings_file_that_is_not_utf8_is_refused_with_a_clear_message(self):
        self.write_bytes(json.dumps({"note": "café"}, ensure_ascii=False).encode("cp1252"))
        with self.assertRaises(ValueError) as caught:
            self.install.install("claude-code", self.root, self.settings)
        self.assertIn("UTF-8", str(caught.exception))
        self.assertIn(self.settings, str(caught.exception))
        self.assertEqual(self.read_bytes(),
                         json.dumps({"note": "café"}, ensure_ascii=False).encode("cp1252"))


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

    def test_keeps_a_malformed_sibling_group_while_removing_our_own(self):
        # The group clowk cannot read has to be carried over, not skipped: `continue` alone would
        # drop it from kept_groups, and the removal below writes that deletion to disk.
        malformed = {"matcher": "MY-IMPORTANT-HOOK", "hooks": 5}
        ours = {"type": "command",
                "command": self.install._command(self.root, "hook_prompt.py", "claude-code")}
        self.write({"hooks": {"UserPromptSubmit": [dict(malformed), {"hooks": [ours]}]}})
        result = self.install.uninstall("claude-code", self.settings)
        self.assertEqual(result["removed"], 1)
        self.assertEqual(self.read()["hooks"]["UserPromptSubmit"], [malformed])

    def test_uninstall_when_nothing_installed_is_zero(self):
        self.write({"theme": "dark"})
        self.assertEqual(self.install.uninstall("claude-code", self.settings)["removed"], 0)


if __name__ == "__main__":
    unittest.main()
