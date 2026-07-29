import importlib
import io
import json
import os
import tempfile
import unittest


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

    def test_the_vault_itself_is_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": self.deny.vault.path()}))

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

    def test_unparseable_input_is_silent(self):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(hook.main(["--host", "claude-code"], io.StringIO("{nope"), out, err), 0)


if __name__ == "__main__":
    unittest.main()
