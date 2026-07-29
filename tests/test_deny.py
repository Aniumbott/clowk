import importlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock


class DenyCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.dir, "deny.json")
        from clowk import vault

        importlib.reload(vault)
        from clowk import deny

        self.deny = importlib.reload(deny)

    def tearDown(self):
        os.environ.pop("CLOWK_VAULT", None)
        os.environ.pop("CLOWK_DENY", None)


class TestPaths(DenyCase):
    def test_reading_a_dotenv_is_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/proj/.env"}))

    def test_dotenv_example_is_allowed(self):
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.example"}))
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.sample"}))
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.template"}))

    def test_private_keys_are_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/home/me/.ssh/id_rsa"}))
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/certs/server.pem"}))

    def test_ssh_public_keys_are_allowed(self):
        # `id_rsa` matches `id_rsa.pub` through the `pattern + "."` branch that exists for
        # `.env.local`-style variants. A .pub is publishable by definition -- and the escape the
        # deny message offered (`clowk allow 'id_rsa'`) also stopped denying the private key.
        for name in ("id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub"):
            path = "/home/me/.ssh/" + name
            self.assertIsNone(self.deny.check("Read", {"file_path": path}), name)
            self.assertIsNone(self.deny.check("Bash", {"command": "ssh-keygen -lf " + path}), name)

    def test_private_key_copies_and_backups_stay_denied(self):
        # The same prefix branch is what catches these, so allowing .pub must not disarm it.
        for name in ("id_rsa.bak", "id_rsa.old", "id_ed25519.backup", ".env.local"):
            self.assertIsNotNone(self.deny.check("Read", {"file_path": "/home/me/" + name}), name)

    def test_the_vault_itself_is_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": self.deny.vault.path()}))

    def test_the_vault_directory_stays_protected_whatever_a_file_is_called(self):
        # The allow-suffix exemption used to run before the store check, so a `vault.json.md` or
        # an `x.example` inside ~/.clowk was readable -- and now that .pub is exempt too, that
        # ordering would have widened the hole rather than left it where it was.
        for name in ("vault.json.md", "vault.json.pub", "x.example"):
            path = os.path.join(self.dir, name)
            self.assertIsNotNone(self.deny.check("Read", {"file_path": path}), name)

    def test_an_ordinary_source_file_is_allowed(self):
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/src/main.py"}))


class TestCommands(DenyCase):
    def test_git_credential_fill_is_denied(self):
        reason = self.deny.check("Bash", {"command": "git credential fill"})
        self.assertIsNotNone(reason)

    def test_keychain_lookup_is_denied(self):
        self.assertIsNotNone(self.deny.check("Bash", {"command": "security find-generic-password -s x -w"}))
        self.assertIsNotNone(self.deny.check("Bash", {"command": "secret-tool lookup service x"}))

    def test_cat_of_the_vault_is_denied(self):
        self.assertIsNotNone(self.deny.check("Bash", {"command": "cat " + self.deny.vault.path()}))

    def test_an_ordinary_command_is_allowed(self):
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))

    def test_reason_explains_how_to_allow_it(self):
        reason = self.deny.check("Bash", {"command": "git credential fill"})
        self.assertIn("clowk allow", reason)


class TestPlatformSeparators(DenyCase):
    """os.sep is "\\" on Windows and os.altsep is "/". Both spell a path there."""

    def windows_separators(self):
        return mock.patch.object(os, "sep", "\\"), mock.patch.object(os, "altsep", "/")

    def test_forward_slash_paths_are_checked_when_the_platform_separator_is_backslash(self):
        # cmd, PowerShell and Git Bash all accept forward slashes, so `type C:/repo/.env` is the
        # ordinary way a model writes a Windows path -- not obfuscation. It matched neither
        # startswith(("/", "~", ".")) nor `os.sep in stripped`, so the token was never handed to
        # the path matcher, which resolves it correctly once it gets it.
        sep, altsep = self.windows_separators()
        with sep, altsep:
            for command in ("type C:/repo/.env", "more C:/certs/server.pem",
                            "cat C:/Users/me/.ssh/id_rsa", "type repo/.env"):
                self.assertIsNotNone(self.deny.check("Bash", {"command": command}), command)

    def test_an_ordinary_windows_command_is_still_allowed(self):
        sep, altsep = self.windows_separators()
        with sep, altsep:
            for command in ("git status", "dir /s", "type C:/repo/main.py"):
                self.assertIsNone(self.deny.check("Bash", {"command": command}), command)

    def test_posix_behaviour_is_unchanged(self):
        # os.altsep is None on POSIX, so the added clause is a falsy no-op there.
        self.assertIsNone(os.altsep)
        self.assertIsNotNone(self.deny.check("Bash", {"command": "cat /repo/.env"}))
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))


class TestUserConfig(DenyCase):
    def test_user_can_remove_a_default_rule(self):
        with open(self.deny.config_path(), "w") as f:
            json.dump({"allow": ["git credential fill"]}, f)
        self.assertIsNone(self.deny.check("Bash", {"command": "git credential fill"}))

    def test_user_can_add_a_command_rule(self):
        with open(self.deny.config_path(), "w") as f:
            json.dump({"deny_commands": ["vault kv get"]}, f)
        self.assertIsNotNone(self.deny.check("Bash", {"command": "vault kv get secret/x"}))

    def test_corrupt_config_falls_back_to_defaults(self):
        with open(self.deny.config_path(), "w") as f:
            f.write("{not json")
        self.assertIsNotNone(self.deny.check("Bash", {"command": "git credential fill"}))

    def test_a_wrongly_typed_config_value_is_ignored_not_iterated(self):
        # deny.json is hand-edited, so a bare string or number where a list belongs is likely.
        # It must not raise (the host fails open) and must not become one rule per character.
        with open(self.deny.config_path(), "w") as f:
            json.dump({"allow": 5, "deny_commands": "ls"}, f)
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))
        self.assertIsNotNone(self.deny.check("Bash", {"command": "git credential fill"}))


class TestHook(DenyCase):
    def run_hook(self, payload, host="claude-code"):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        code = hook.main(["--host", host], io.StringIO(json.dumps(payload)), out, err)
        return code, out.getvalue(), err.getvalue()

    def test_allowed_call_is_silent(self):
        code, out, err = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_denied_call_emits_a_deny_decision(self):
        code, out, err = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "git credential fill"}})
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("clowk allow", decision["permissionDecisionReason"])

    def test_exit_two_hosts_deny_on_stderr(self):
        # This hook is registered on Codex and Gemini CLI too, and there a deny is exit 2 with the
        # reason on stderr. Claude Code's decision JSON plus exit 0 reads as an allow on both.
        for host in ("codex", "gemini-cli"):
            code, out, err = self.run_hook(
                {"tool_name": "Bash", "tool_input": {"command": "git credential fill"}}, host)
            self.assertEqual((host, code, out), (host, 2, ""))
            self.assertIn("clowk allow", err)

    def test_a_hook_registered_without_a_host_flag_still_denies(self):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        payload = {"tool_name": "Bash", "tool_input": {"command": "git credential fill"}}
        code = hook.main([], io.StringIO(json.dumps(payload)), out, err)
        self.assertEqual(code, 0)
        decision = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")

    def test_a_non_utf8_locale_does_not_disable_the_hook(self):
        # Hosts send UTF-8 JSON (Node's JSON.stringify does not escape non-ASCII), but sys.stdin
        # decodes with the locale codec. On a cp1252 box one accented character anywhere in the
        # payload -- `cwd` rides along on every tool call, and this hook never even reads it --
        # raised UnicodeDecodeError, which subclasses ValueError and so was indistinguishable
        # from malformed JSON: exit 0, no deny, every tool call of the session allowed.
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        payload = {"tool_name": "Read", "tool_input": {"file_path": self.deny.vault.path()},
                   "cwd": "C:\\Users\\\u0141ukasz\\proj"}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="cp1252")
        out, err = io.StringIO(), io.StringIO()
        code = hook.main(["--host", "claude-code"], stdin, out, err)
        self.assertEqual(code, 0)
        decision = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")

    def test_unparseable_input_is_silent(self):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(hook.main(["--host", "claude-code"], io.StringIO("{nope"), out, err), 0)


if __name__ == "__main__":
    unittest.main()
