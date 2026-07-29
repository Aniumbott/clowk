import io
import json
import unittest

from clowk import hosts


class TestReadEvent(unittest.TestCase):
    def test_claude_code_and_codex_prompt_field(self):
        event = hosts.read_event({"prompt": "hello", "cwd": "/p", "session_id": "s1"})
        self.assertEqual(event["prompt"], "hello")
        self.assertEqual(event["cwd"], "/p")
        self.assertEqual(event["session_id"], "s1")

    def test_falls_back_across_candidate_keys(self):
        self.assertEqual(hosts.read_event({"message": "hi"})["prompt"], "hi")
        self.assertEqual(hosts.read_event({"user_message": "hi"})["prompt"], "hi")

    def test_missing_prompt_yields_empty_string(self):
        self.assertEqual(hosts.read_event({"cwd": "/p"})["prompt"], "")

    def test_non_string_prompt_is_ignored(self):
        self.assertEqual(hosts.read_event({"prompt": {"nested": 1}})["prompt"], "")


class TestBlock(unittest.TestCase):
    def _capture(self, host):
        out, err = io.StringIO(), io.StringIO()
        code = hosts.block(host, "because reasons", stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_claude_code_emits_json_decision_and_exits_zero(self):
        code, out, err = self._capture("claude-code")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"decision": "block", "reason": "because reasons"})

    def test_codex_writes_stderr_and_exits_two(self):
        code, out, err = self._capture("codex")
        self.assertEqual(code, 2)
        self.assertIn("because reasons", err)

    def test_gemini_cli_writes_stderr_and_exits_two(self):
        code, out, err = self._capture("gemini-cli")
        self.assertEqual(code, 2)
        self.assertIn("because reasons", err)

    def test_unknown_host_falls_back_to_exit_two(self):
        code, out, err = self._capture("something-new")
        self.assertEqual(code, 2)
        self.assertIn("because reasons", err)


if __name__ == "__main__":
    unittest.main()
