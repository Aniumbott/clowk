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


class TestReadPayload(unittest.TestCase):
    def test_bytes_are_decoded_as_utf8_whatever_the_stream_codec_says(self):
        stdin = io.TextIOWrapper(io.BytesIO("hej Łukasz".encode("utf-8")), encoding="cp1252")
        self.assertEqual(hosts.read_payload(stdin), "hej Łukasz")

    def test_undecodable_bytes_are_replaced_rather_than_raising(self):
        stdin = io.TextIOWrapper(io.BytesIO(b'{"a": "\xff"}'), encoding="utf-8")
        self.assertEqual(hosts.read_payload(stdin), '{"a": "�"}')

    def test_a_text_stream_with_no_buffer_is_read_directly(self):
        self.assertEqual(hosts.read_payload(io.StringIO("plain")), "plain")


class TestDeny(unittest.TestCase):
    """The tool-call deny. A separate emitter: PreToolUse has its own decision shape."""

    def _capture(self, host):
        out, err = io.StringIO(), io.StringIO()
        code = hosts.deny(host, "because reasons", stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_claude_code_emits_a_permission_decision_and_exits_zero(self):
        code, out, err = self._capture("claude-code")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "because reasons",
        }})
        self.assertEqual(err, "")

    def test_codex_writes_stderr_and_exits_two(self):
        code, out, err = self._capture("codex")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("because reasons", err)

    def test_gemini_cli_writes_stderr_and_exits_two(self):
        code, out, err = self._capture("gemini-cli")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("because reasons", err)

    def test_unknown_host_falls_back_to_exit_two(self):
        # Exit 2 also blocks on Claude Code, so the fallback is the safe one for a new host.
        code, out, err = self._capture("something-new")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("because reasons", err)

    def test_the_named_event_matches_the_event_the_hook_is_registered_on(self):
        from clowk import install

        for host, target in install.TARGETS.items():
            self.assertEqual(hosts.HOSTS[host]["tool_event"], target["tool_event"])
            self.assertEqual(hosts.HOSTS[host]["event"], target["prompt_event"])


class TestHostFrom(unittest.TestCase):
    def test_reads_both_flag_spellings(self):
        self.assertEqual(hosts.host_from(["--host", "codex"]), "codex")
        self.assertEqual(hosts.host_from(["--host=gemini-cli"]), "gemini-cli")

    def test_defaults_to_claude_code(self):
        self.assertEqual(hosts.host_from([]), "claude-code")
        self.assertEqual(hosts.host_from(["--host"]), "claude-code")


if __name__ == "__main__":
    unittest.main()
