"""`clowk rewrite`: the Python half of the Claude Code mod.

The mod's `prompt.submit` hook runs this with the prompt on stdin and passes the rewritten text on
to the model in place of what was typed -- no block, no clipboard, no repaste. So the contract is
narrow and every breach of it is a leak or a lockout:

- stdout is one JSON object, and the raw value is nowhere in it (stdout is what the mod reads);
- every value detected is filed and replaced, exactly as the prompt hook would;
- a failure is a NON-ZERO exit, never a pass-through: the mod fails closed on it, so a zero exit
  with the original text in it would send the credential.
"""
import io
import json
import os

from tests.test_hook_prompt import HookCase


class RewriteCase(HookCase):
    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def setUp(self):
        HookCase.setUp(self)
        os.environ["CLOWK_SESSIONS"] = os.path.join(self.dir, "sessions.json")
        self.addCleanup(os.environ.pop, "CLOWK_SESSIONS", None)
        self.copied = []
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: self.copied.append(text) or True

    def rewrite(self, payload, raw=None):
        out, err = io.StringIO(), io.StringIO()
        stdin = io.StringIO(raw if raw is not None else json.dumps(payload))
        code = self.hook.main_rewrite(stdin, out, err)
        return code, out.getvalue(), err.getvalue()

    def ok(self, prompt, session="s1"):
        code, out, err = self.rewrite({"prompt": prompt, "cwd": "/p", "session_id": session})
        self.assertEqual(code, 0, err)
        return out, json.loads(out)


class TestARewrite(RewriteCase):
    def test_a_clean_prompt_comes_back_unchanged(self):
        out, result = self.ok("just refactor the parser")
        self.assertEqual(result, {"text": "just refactor the parser", "names": [], "pointer": None})

    def test_the_value_is_replaced_by_its_name(self):
        out, result = self.ok("charge it with " + self.KEY + " please")
        self.assertEqual(result["text"], "charge it with $STRIPE_SECRET_KEY please")
        self.assertEqual(result["names"], ["STRIPE_SECRET_KEY"])

    def test_the_raw_value_is_nowhere_in_stdout(self):
        out, result = self.ok("charge it with " + self.KEY)
        self.assertNotIn(self.KEY, out)
        self.assertNotIn(self.KEY[8:], out, "a fragment of the value survived")

    def test_the_value_is_filed_so_the_name_resolves(self):
        self.ok("charge it with " + self.KEY)
        self.assertEqual(self.vault.get("STRIPE_SECRET_KEY"), self.KEY)

    def test_the_clipboard_is_never_touched(self):
        # Nothing is repasted on this path; overwriting the clipboard would just destroy whatever
        # the user had on it.
        self.ok("charge it with " + self.KEY)
        self.assertEqual(self.copied, [])

    def test_the_text_never_carries_the_pointer(self):
        # The pointer is for the model only; the mod puts it in context. In the text it would show
        # up in the user's own message in the transcript.
        out, result = self.ok("charge it with " + self.KEY)
        self.assertNotIn("[assistant:", result["text"])

    def test_the_pointer_is_offered_once_per_session(self):
        first = self.ok("one " + self.KEY, session="sess")[1]
        second = self.ok("two " + self.KEY, session="sess")[1]
        self.assertEqual(first["pointer"], self.hook.SKILL_POINTER)
        self.assertIsNone(second["pointer"])

    def test_the_bypass_prefix_passes_the_text_through_unfiled(self):
        out, result = self.ok("unclowk this is a test fixture " + self.KEY)
        self.assertEqual(result["names"], [])
        self.assertIsNone(self.vault.get("STRIPE_SECRET_KEY"))

    def test_two_values_get_two_names(self):
        second = "ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        out, result = self.ok("both " + self.KEY + " and " + second)
        self.assertEqual(result["names"], ["GITHUB_TOKEN", "STRIPE_SECRET_KEY"])
        self.assertNotIn(second, out)


class TestARewriteFailsLoudly(RewriteCase):
    """The mod drops the prompt on a non-zero exit. A zero exit must therefore mean "this text is
    safe to send"; anything that could not be checked has to come back non-zero."""

    def test_unparseable_stdin_is_an_error_not_a_pass(self):
        code, out, err = self.rewrite(None, raw="not json")
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")

    def test_a_payload_with_no_prompt_is_an_error(self):
        code, out, err = self.rewrite({"cwd": "/p"})
        self.assertNotEqual(code, 0)

    def test_an_internal_error_after_detection_is_an_error_and_prints_nothing(self):
        self.addCleanup(setattr, self.hook, "redact", self.hook.redact)

        def boom(*a, **k):
            raise RuntimeError("simulated")
        self.hook.redact = boom
        code, out, err = self.rewrite({"prompt": "charge " + self.KEY, "cwd": "/p"})
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "", "a half-made rewrite reached stdout")
        self.assertNotIn(self.KEY, err)


class TestTheCliRoutesRewrite(RewriteCase):
    def test_clowk_rewrite_reads_stdin_and_prints_json(self):
        from clowk import cli
        self.addCleanup(setattr, cli.sys, "stdin", cli.sys.stdin)
        cli.sys.stdin = io.StringIO(json.dumps({"prompt": "use " + self.KEY, "cwd": "/p"}))
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["rewrite"], out, err)
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["text"], "use $STRIPE_SECRET_KEY")

    def test_rewrite_takes_no_arguments(self):
        # An argument here could only be the prompt, which belongs on stdin and not in `ps`.
        from clowk import cli
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(cli.main(["rewrite", "use " + self.KEY], out, err), 1)
