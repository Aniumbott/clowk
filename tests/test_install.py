import importlib
import json
import os
import stat
import tempfile
import unittest

from tests import default_encoding


def hook_count(host):
    """How many hooks a host gets: prompt + tool, plus a session briefing where the host has a
    session event.

    Derived from TARGETS rather than written as a literal. These assertions used to say 2, and
    adding the SessionStart briefing turned eight of them red at once while asserting nothing
    useful -- the count is an implementation detail, "all of this host's events" is the intent.
    """
    from clowk import install

    return 2 + (1 if install.TARGETS[host].get("session_event") else 0)


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
        self.assertEqual(result["added"], hook_count("claude-code"))
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
        self.assertEqual(self.install.install("claude-code", self.root, self.settings)["added"], hook_count("claude-code"))
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
        self.assertEqual(result["added"], hook_count("claude-code"))
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
        self.assertEqual(result["removed"], hook_count("claude-code"))
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

class TestLegacyAndDuplicateRegistrations(InstallCase):
    """Registrations from an older clowk, and from a different interpreter.

    Both were found in a real settings.json: UserPromptSubmit and PreToolUse each registered twice,
    and a SessionStart entry pointing at a script clowk no longer ships -- failing silently on every
    session start with no way to remove it short of hand-editing.
    """

    LEGACY = '"py" "/opt/clowk/clowk/hook_session.py" --host claude-code'

    def test_a_second_install_from_another_interpreter_does_not_duplicate(self):
        self.install.install("claude-code", self.root, self.settings)
        data = self.read()
        for groups in data["hooks"].values():
            for group in groups:
                for entry in group.get("hooks", []):
                    entry["command"] = entry["command"].replace(
                        __import__("sys").executable, "/other/venv/bin/python3")
        self.write(data)

        self.assertEqual(self.install.install("claude-code", self.root, self.settings)["added"], 0)
        for event, groups in self.read()["hooks"].items():
            ours = [e for g in groups for e in g.get("hooks", [])
                    if self.install.is_clowk_entry(e)]
            self.assertEqual(len(ours), 1, "%s ended up with %d entries" % (event, len(ours)))

    def test_a_stale_interpreter_is_repaired_rather_than_left_unrunnable(self):
        # A hook whose interpreter has moved can never run. Replacing the command is the repair;
        # skipping it as "already registered" would leave it broken forever.
        self.install.install("claude-code", self.root, self.settings)
        data = self.read()
        groups = data["hooks"]["UserPromptSubmit"]
        groups[0]["hooks"][0]["command"] = '"/gone/python3" "%s" --host claude-code' % os.path.join(
            self.root, "clowk", "hook_prompt.py")
        self.write(data)
        self.install.install("claude-code", self.root, self.settings)
        command = self.read()["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
        self.assertNotIn("/gone/python3", command)

    def test_uninstall_removes_an_entry_on_an_event_this_version_never_registers(self):
        self.write({"hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": self.LEGACY},
            {"type": "command", "command": "echo someone-elses-session-hook"}]}]}})
        self.install.install("claude-code", self.root, self.settings)
        self.install.uninstall("claude-code", self.settings)
        blob = json.dumps(self.read())
        self.assertNotIn("hook_session.py", blob, "a legacy clowk entry survived uninstall")
        self.assertIn("someone-elses-session-hook", blob, "someone else's hook was removed")

    def test_a_removed_script_is_still_recognised_as_ours(self):
        # Dropping hook_session.py from the recognised list is what stranded it: uninstall could not
        # see it as clowk's, so it stayed registered forever.
        self.assertTrue(self.install.is_clowk_entry({"command": self.LEGACY}))



if __name__ == "__main__":
    unittest.main()
