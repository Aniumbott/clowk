import importlib
import io
import json
import os
import tempfile
import unittest


class HookCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        from clowk import vault

        self.vault = importlib.reload(vault)
        from clowk import hook_prompt

        self.hook = importlib.reload(hook_prompt)
        self.hook.clip.CANDIDATES = [["clowk-nonexistent-clipboard-binary"]]

    def tearDown(self):
        os.environ.pop("CLOWK_VAULT", None)

    def run_hook(self, payload, host="claude-code"):
        out, err = io.StringIO(), io.StringIO()
        code = self.hook.main(["--host", host], io.StringIO(json.dumps(payload)), out, err)
        return code, out.getvalue(), err.getvalue()


class TestPassthrough(HookCase):
    def test_clean_prompt_produces_no_output_and_exit_zero(self):
        code, out, err = self.run_hook({"prompt": "refactor src/main.py", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertEqual(self.vault.names(), [])

    def test_unparseable_stdin_exits_zero_silently(self):
        out, err = io.StringIO(), io.StringIO()
        code = self.hook.main(["--host", "claude-code"], io.StringIO("{not json"), out, err)
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), "")

    def test_bypass_prefix_skips_the_scan(self):
        code, out, err = self.run_hook({"prompt": "unclowk sk_" "live_4eC39HqLyjWDarjtT1zdp7dc", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(self.vault.names(), [])


class TestCapture(HookCase):
    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def test_secret_is_stored_and_the_turn_is_blocked(self):
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/proj"})
        self.assertEqual(code, 0)
        decision = json.loads(out)
        self.assertEqual(decision["decision"], "block")
        self.assertTrue(self.vault.names())
        name = self.vault.names()[0]
        self.assertEqual(self.vault.get(name), self.KEY)

    def test_block_reason_contains_the_rewrite_and_not_the_secret(self):
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/proj"})
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.KEY, reason)
        name = self.vault.names()[0]
        self.assertIn("use $" + name + " now", reason)

    def test_block_reason_always_mentions_the_bypass(self):
        code, out, err = self.run_hook({"prompt": "use " + self.KEY, "cwd": "/proj"})
        self.assertIn("unclowk", json.loads(out)["reason"])

    def test_source_is_recorded_from_cwd(self):
        self.run_hook({"prompt": "use " + self.KEY, "cwd": "/proj"})
        name = self.vault.names()[0]
        self.assertEqual(self.vault.list_secrets()[name]["sources"], ["/proj"])

    def test_two_distinct_secrets_are_both_replaced(self):
        second = "ghp" "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        code, out, err = self.run_hook({"prompt": self.KEY + " and " + second, "cwd": "/p"})
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.KEY, reason)
        self.assertNotIn(second, reason)
        self.assertEqual(len(self.vault.names()), 2)

    def test_a_nested_match_never_leaves_a_fragment_of_the_value(self):
        # Two vendored rules nest: flutterwave-encryption-key's regex is a prefix of
        # flutterwave-secret-key's, so this one paste produces two findings whose values
        # overlap. Replacing the shorter one first would leave the tail of the real key in
        # the rewrite -- and the rewrite is what goes on the clipboard to be repasted.
        key = "FLWSECK" "_TEST-0123456789abcdef0123456789abcdef-X"
        code, out, err = self.run_hook({"prompt": "key " + key + " ok", "cwd": "/p"})
        reason = json.loads(out)["reason"]
        self.assertNotIn(key, reason)
        self.assertNotIn("cdef0123456789abcdef", reason)
        self.assertEqual(self.vault.names(), ["FLUTTERWAVE_SECRET_KEY"])
        self.assertIn("key $FLUTTERWAVE_SECRET_KEY ok", reason)

    def test_codex_host_blocks_via_exit_two_and_stderr(self):
        code, out, err = self.run_hook({"prompt": "use " + self.KEY, "cwd": "/p"}, host="codex")
        self.assertEqual(code, 2)
        self.assertNotIn(self.KEY, err)
        self.assertIn("unclowk", err)


if __name__ == "__main__":
    unittest.main()
