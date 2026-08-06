import importlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from tests import plain

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HookCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)  # it holds a real vault, in plaintext
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        from clowk import vault

        self.vault = importlib.reload(vault)
        from clowk import hook_prompt

        self.hook = importlib.reload(hook_prompt)
        # clowk.clip is one module object shared by the whole run -- reload rebinds the same one --
        # so this stub has to be put back, or test_clip's real-platform case silently spawns
        # nothing. The stub itself is load-bearing: without it the capture cases would write the
        # rewritten prompts to the developer's actual clipboard.
        self.addCleanup(setattr, self.hook.clip, "CANDIDATES", self.hook.clip.CANDIDATES)
        self.hook.clip.CANDIDATES = [["clowk-nonexistent-clipboard-binary"]]

    def tearDown(self):
        os.environ.pop("CLOWK_VAULT", None)

    def run_hook(self, payload, host="claude-code"):
        out, err = io.StringIO(), io.StringIO()
        code = self.hook.main(["--host", host], io.StringIO(json.dumps(payload)), out, err)
        return code, out.getvalue(), err.getvalue()


class TestHookCaseCleansUpAfterItself(unittest.TestCase):
    """HookCase stubs the process-wide clip.CANDIDATES and never put it back.

    clowk.clip is one module object shared by every test (importlib.reload rebinds the same one),
    so the stub outlived the case that set it. test_clip.py's
    `test_returns_a_bool_on_the_real_platform` is the only test in the suite that spawns a real
    clipboard tool, and it is exactly the one the leak voids -- silently, because asserting a bool
    still passes against a nonexistent binary. Alphabetical discovery hides that today; any
    reordering (-k, a parallel split, naming two modules on the command line) voids it.
    """

    def run_probe(self, probe):
        result = unittest.TestResult()
        probe.run(result)
        self.assertEqual(result.errors + result.failures, [])

    def test_the_stub_clipboard_does_not_outlive_the_case(self):
        from clowk import clip

        self.addCleanup(setattr, clip, "CANDIDATES", clip.CANDIDATES)
        sentinel = [["clowk-sentinel-not-a-real-tool"]]
        clip.CANDIDATES = sentinel

        class Probe(HookCase):
            def runTest(self):
                self.run_hook({"prompt": "nothing to see here", "cwd": "/p"})

        self.run_probe(Probe())
        self.assertIs(clip.CANDIDATES, sentinel, "HookCase leaked its stub clipboard")

    def test_the_temporary_vault_does_not_outlive_the_case(self):
        seen = {}

        class Probe(HookCase):
            def runTest(self):
                seen["dir"] = self.dir
                self.run_hook({"prompt": "use sk_" "live_4eC39HqLyjWDarjtT1zdp7dc", "cwd": "/p"})

        self.run_probe(Probe())
        self.assertFalse(os.path.exists(seen["dir"]),
                         "left a plaintext vault at rest in %s" % seen["dir"])


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


class TestARealVendorKeyIsNotOfferedForDeletion(HookCase):
    """The reported bug, read the way the user read it.

    A live AWS pair was blocked and the message said

        $AWS_ACCESS_KEY_ID   ·  shape-only guess, `clowk clear AWS_ACCESS_KEY_ID` if wrong

    which advises deleting the only local copy of a working credential. `AKIA` is one of the most
    vendor-specific shapes in the whole ruleset; it read "low" purely because classify only
    recognised a literal prefix that ends in `_` or `-`. Asserted through the real block message
    rather than on the tier, because the wording is the defect.
    """

    # AWS's own documented example key. Split like the other vendor-shaped fixtures so GitHub push
    # protection does not reject every push of this repository -- see NOTES.md.
    AKIA = "AKIA" + "IOSFODNN7EXAMPLE"

    def test_the_message_names_the_key_without_offering_to_clear_it(self):
        code, out, err = self.run_hook({"prompt": "rotate " + self.AKIA + " for me", "cwd": "/p"})
        reason = plain(json.loads(out)["reason"])
        self.assertIn("$AWS_ACCESS_KEY_ID", reason)
        self.assertNotIn("shape-only guess", reason)
        self.assertNotIn("clowk clear", reason)

    def test_a_genuinely_shapeless_value_still_gets_the_hint(self):
        # The other half: the hint has to keep appearing where it is true, or this "fix" is just
        # the removal of a useful warning.
        generic = "DL" + "fdfnU8pAERrHbccVspNtcq37DhhIyh"
        code, out, err = self.run_hook({"prompt": "my api key is " + generic, "cwd": "/p"})
        self.assertIn("shape-only guess", plain(json.loads(out)["reason"]))


class TestBypassIsAnchoredToTheStart(HookCase):
    """`unclowk` is the one deliberate fail-open switch, so where it counts has to be pinned.

    Every existing test put the token at position 0, so widening the check to
    `BYPASS in prompt.lower()` passed the whole suite -- and under that widening merely naming
    the tool ("explain unclowk then rotate <key>") transmits the credential silently.
    """

    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def test_the_token_anywhere_but_the_start_does_not_bypass(self):
        code, out, err = self.run_hook(
            {"prompt": "explain unclowk then rotate " + self.KEY, "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "", "a mid-prompt mention of unclowk bypassed the scan")
        self.assertEqual(json.loads(out)["decision"], "block")
        self.assertEqual(self.vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(self.vault.get("STRIPE_SECRET_KEY"), self.KEY)

    def test_leading_whitespace_and_upper_case_still_bypass(self):
        # Deliberate, not accidental: people paste with an indent, and people shout.
        code, out, err = self.run_hook({"prompt": "  UNCLOWK " + self.KEY, "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(self.vault.names(), [])


class TestFilingFailureStillBlocks(HookCase):
    """Blocking is the only thing that prevents transmission, so it cannot be gated on a write.

    vault.store ran before hosts.block, and vault._save's open/os.replace are unguarded, so an
    unwritable or full ~/.clowk, a root-owned directory, a Windows AV holding vault.json open, or
    one hand-edited vault entry turned a *successful* detection into a completely silent
    pass-through: exit 0, nothing on either stream, credential transmitted.
    """

    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def break_store(self, exc=None):
        original = self.hook.vault.store
        self.addCleanup(setattr, self.hook.vault, "store", original)

        def raiser(*a, **kw):
            raise exc or OSError(28, "No space left on device")

        self.hook.vault.store = raiser

    def test_block_is_still_emitted_when_the_vault_cannot_be_written(self):
        self.break_store()
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "", "a failed vault write cancelled the block")
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.KEY, reason)
        self.assertIn("use $STRIPE_SECRET_KEY now", reason)
        self.assertIn("not saved", reason)
        self.assertIn("unclowk", reason)

    def test_a_read_only_vault_directory_still_blocks(self):
        if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            self.skipTest("POSIX mode bits do not bind here")
        os.chmod(self.dir, 0o500)
        self.addCleanup(os.chmod, self.dir, 0o700)
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "", "an unwritable ~/.clowk cancelled the block")
        self.assertNotIn(self.KEY, json.loads(out)["reason"])

    def test_a_vault_entry_of_the_wrong_shape_still_blocks(self):
        # _load only checks that `secrets` is a dict, not each entry -- and the README points at
        # this file as the export path, so a flattened hand-edit is a plausible state.
        with open(self.vault.path(), "w") as f:
            f.write('{"version": 1, "secrets": {"STRIPE_SECRET_KEY": "sk_" "live_old"}}')
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "", "a malformed vault entry cancelled the block")
        self.assertNotIn(self.KEY, json.loads(out)["reason"])

    def test_a_second_secret_still_blocks_when_only_the_first_could_be_filed(self):
        token = "ghp" "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        original = self.hook.vault.store
        self.addCleanup(setattr, self.hook.vault, "store", original)
        calls = []

        def once(*a, **kw):
            calls.append(a)
            if len(calls) > 1:
                raise OSError(13, "Permission denied")
            return original(*a, **kw)

        self.hook.vault.store = once
        code, out, err = self.run_hook({"prompt": self.KEY + " and " + token, "cwd": "/p"})
        self.assertNotEqual(out, "")
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.KEY, reason)
        self.assertNotIn(token, reason)

    def test_two_unfilable_values_of_one_kind_do_not_collapse_into_one_placeholder(self):
        self.break_store()
        second = "ghp" "_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
        first = "ghp" "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        code, out, err = self.run_hook({"prompt": "old " + first + " new " + second, "cwd": "/p"})
        reason = json.loads(out)["reason"]
        self.assertNotIn(first, reason)
        self.assertNotIn(second, reason)
        self.assertIn("$GITHUB_TOKEN_2", reason)  # two values are not one name

    def test_an_error_anywhere_after_detection_still_blocks_without_the_secret(self):
        original = self.hook.clip.copy
        self.addCleanup(setattr, self.hook.clip, "copy", original)

        def raiser(text):
            raise RuntimeError("clipboard exploded")

        self.hook.clip.copy = raiser
        code, out, err = self.run_hook({"prompt": "use " + self.KEY + " now", "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "", "an error after detection cancelled the block")
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.KEY, reason)
        self.assertIn("unclowk", reason)


class TestLogPasteDoesNotAvalanche(HookCase):
    """A pasted app log trips the shape-only rules hundreds of times in one prompt.

    Filing every hit minted one named vault entry per hit, and vault.store reloads and rewrites
    the whole file on every call, so the cost was O(hits x vault size) -- and recovery was one
    `clowk clear` per entry. The reason also grew to hundreds of KB, which is what the host shows
    the user. Redaction and the block itself are NOT capped; only filing is.
    """

    @classmethod
    def setUpClass(cls):
        rnd = random.Random(7)
        hexes = lambda n: "".join(rnd.choice("0123456789abcdef") for _ in range(n))
        cls.log = "\n".join(
            "2026-07-29T10:%02d:%02d INFO request_id=%s auth_token_hint=%s status=200"
            % (i % 60, i % 60, hexes(32), hexes(16)) for i in range(1800))
        from clowk.detect import scan

        cls.secrets = [f.secret for f in scan(cls.log)]

    def setUp(self):
        HookCase.setUp(self)
        self.assertGreater(len(self.secrets), 100, "fixture no longer trips the shape-only rules")

    def block_reason(self, copied=False):
        if copied:
            self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
            self.hook.clip.copy = lambda text: True
        code, out, err = self.run_hook({"prompt": self.log, "cwd": "/p"})
        self.assertEqual(code, 0)
        self.assertNotEqual(out, "")
        return json.loads(out)["reason"]

    def test_one_paste_files_at_most_the_cap(self):
        self.block_reason()
        self.assertLessEqual(len(self.vault.names()), self.hook.MAX_FILED)

    def test_every_match_is_still_redacted_even_past_the_cap(self):
        reason = self.block_reason()
        for secret in self.secrets:
            self.assertNotIn(secret, reason)

    def test_the_reason_says_what_it_did_not_file_and_how_to_resend(self):
        reason = self.block_reason()
        self.assertIn("not saved", reason)
        self.assertIn("unclowk", reason)

    def test_the_reason_stays_small_when_the_rewrite_is_on_the_clipboard(self):
        self.assertLess(len(self.block_reason(copied=True)), 20000)

    def test_the_rewrite_is_echoed_in_full_when_there_is_no_clipboard(self):
        # The echo is the user's only copy when no clipboard tool exists (every headless box),
        # so it must never be truncated there -- the alternative is retyping or `unclowk`.
        reason = self.block_reason()
        self.assertIn("$GENERIC_API_KEY status=200", reason)
        self.assertGreater(len(reason), len(self.log) - len("".join(self.secrets)))


class TestARotationIsNamedWhenItHappens(HookCase):
    """After a rotation, $NAME kept resolving to the revoked key and nothing said so.

    Reproduced: paste a Stripe key, it files as $STRIPE_SECRET_KEY. Rotate upstream, paste the new
    one, and vault.store suffixes it to $STRIPE_SECRET_KEY_2 because the name is taken by a
    different value. The user's code and habits still say $STRIPE_SECRET_KEY, which silently still
    holds the dead value, so the next command gets a revoked credential and the failure arrives
    looking like an API error rather than a clowk problem.

    The storage model is right and stays: nothing is overwritten, the old value survives, and
    `clowk set NAME` already exists to move a name onto a new value while keeping its ledger. The
    only defect was that build_message annotated the shape-only guess and nothing else, so the one
    moment when the user could act on this passed in silence.
    """

    OLD = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"
    NEW = "sk_" "live_9zQ71KpMxRvBnHt3Ld6sw2fa"

    def block(self, secret):
        code, out, err = self.run_hook({"prompt": "charge with " + secret, "cwd": "/p"})
        self.assertEqual(code, 0)
        return json.loads(out)["reason"]

    def rotate(self):
        self.block(self.OLD)
        return self.block(self.NEW)

    def test_the_suffixed_name_and_the_stale_one_are_both_named(self):
        reason = self.rotate()
        self.assertIn("$STRIPE_SECRET_KEY_2", plain(reason))
        self.assertIn("$STRIPE_SECRET_KEY already holds", plain(reason))

    def test_the_remedy_is_spelled_out_as_a_command_that_exists(self):
        self.assertIn("clowk set STRIPE_SECRET_KEY", self.rotate())

    def test_the_new_value_is_not_silently_promoted_to_the_plain_name(self):
        # The same class of bug in the other direction: promoting would change what an existing
        # $NAME means for anyone who already scripted against it.
        self.rotate()
        self.assertEqual(self.vault.get("STRIPE_SECRET_KEY"), self.OLD)
        self.assertEqual(self.vault.get("STRIPE_SECRET_KEY_2"), self.NEW)

    def test_neither_value_appears_in_the_message(self):
        reason = self.rotate()
        self.assertNotIn(self.OLD, reason)
        self.assertNotIn(self.NEW, reason)

    def test_a_first_capture_says_nothing_about_rotation(self):
        reason = self.block(self.OLD)
        self.assertNotIn("clowk set", reason)
        self.assertNotIn("rotat", reason.lower())

    def test_the_same_key_pasted_twice_is_not_a_rotation(self):
        self.block(self.OLD)
        reason = self.block(self.OLD)
        self.assertNotIn("clowk set", reason)
        self.assertEqual(self.vault.names(), ["STRIPE_SECRET_KEY"])

    def test_a_different_kind_of_credential_under_the_same_name_is_not_called_a_rotation(self):
        # Written straight into the vault, because reaching this through two real rules that share
        # an env name is incidental to what is being tested: the guard is rule id, not name.
        self.vault.store("STRIPE_SECRET_KEY", "sk_" "live_someothervendorsvalue00",
                         rule="generic-api-key")
        reason = self.block(self.NEW)
        self.assertIn("$STRIPE_SECRET_KEY_2", reason)
        self.assertNotIn("clowk set", reason)


class TestRedactionIsOnePass(HookCase):
    """capture() redacted with one str.replace over the whole prompt per finding.

    That is O(findings x prompt length), and on credential-dense text findings grow WITH length,
    so the real curve is quadratic. Measured on lines of the form
    `2026-08-05 INFO api_key=<32 hex> request served`:

        1000 lines /  70 KB / 1000 findings -> 0.13s   (scan 0.03s)
        2000 lines / 141 KB / 2000 findings -> 0.45s   (scan 0.05s)
        4000 lines / 281 KB / 4000 findings -> 1.62s   (scan 0.11s)
        8000 lines / 563 KB / 8000 findings -> 6.32s   (scan 0.21s)

    3.6x per doubling with scan() flat at 2.0x, so the whole quadratic term was the redaction
    loop. Extrapolating t = k*n^2 puts ~1.7 MB of credential-dense text past Claude Code's 60s
    hook timeout -- and past the timeout every host fails open, so the entire paste is transmitted
    with the credentials in it. That is the worst outcome this tool has, so the cost of redaction
    is pinned here rather than described.
    """

    LINES = 8000
    BUDGET = 2.0          # 40x the one-pass measurement, 30x under the host timeout

    @classmethod
    def setUpClass(cls):
        rnd = random.Random(11)
        hexes = lambda n: "".join(rnd.choice("0123456789abcdef") for _ in range(n))
        cls.log = "\n".join("2026-08-05 INFO api_key=%s request served" % hexes(32)
                            for _ in range(cls.LINES))
        from clowk.detect import scan

        cls.findings = scan(cls.log)

    def setUp(self):
        HookCase.setUp(self)
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: True   # measure redaction, not a clipboard spawn
        self.assertGreater(len(self.findings), self.LINES - 1, "fixture stopped being dense")

    def test_a_credential_dense_paste_is_redacted_far_inside_the_host_hook_timeout(self):
        start = time.time()
        self.hook.capture({"prompt": self.log, "cwd": "/p", "session_id": "s"}, self.findings)
        elapsed = time.time() - start
        self.assertLess(elapsed, self.BUDGET, "%.2fs to redact %d findings out of %d KB"
                        % (elapsed, len(self.findings), len(self.log) // 1000))


class TestTheOnePassPatternHoldsUnderDegenerateInput(HookCase):
    """The trie is a regex, and `re` parses nested groups recursively.

    Compressing non-branching runs means one long value costs one level, but values that are
    successive prefixes of each other each cost one -- and re.compile raises RecursionError
    somewhere past 400 of those. A RecursionError here does not fail open (main's except still
    blocks) but it does cost the user the rewrite and the vault entry, so the trie stops nesting
    at MAX_DEPTH and flattens the rest.
    """

    # Each of these branches from the previous one character later, so an uncapped trie nests once
    # per value. 600 is past what re.compile survives, so the cap is load-bearing here rather than
    # decorative. The boundary is the default 1000-frame recursion limit rather than anything
    # version-specific: 400 compiles and 500 does not, identically on 3.9, 3.11 and 3.14.
    CHAIN = ["A" * (20 + i) + "b1" for i in range(600)]

    def test_a_long_branch_chain_still_compiles_and_still_prefers_the_longest(self):
        pattern = self.hook._one_pass(self.CHAIN)
        longest = max(self.CHAIN, key=len)
        self.assertEqual(pattern.search("x " + longest + " y").group(0), longest)
        for value in (self.CHAIN[0], self.CHAIN[299], longest):
            self.assertEqual(pattern.search("v=" + value + "!").group(0), value)

    def test_without_the_cap_that_same_chain_does_not_compile_at_all(self):
        self.addCleanup(setattr, self.hook, "MAX_DEPTH", self.hook.MAX_DEPTH)
        self.hook.MAX_DEPTH = 10 ** 9
        self.assertRaises(RecursionError, self.hook._one_pass, self.CHAIN)

    def test_one_very_long_value_costs_no_nesting_at_all(self):
        # A connection string has no fixed length, and an uncompressed trie would nest once per
        # character -- so this is the case compression exists for, not a micro-optimisation.
        value = "postgresql://svc:" + "Q" * 900 + "@db.internal:5432/orders"
        pattern = self.hook._one_pass([value])
        self.assertEqual(pattern.search("psql " + value).group(0), value)

    def test_regex_metacharacters_in_a_value_are_matched_literally(self):
        value = "a.b*c[d]e+f?g|h(i)j{k}l\\m^n$o"
        pattern = self.hook._one_pass([value])
        self.assertEqual(pattern.search("x " + value + " y").group(0), value)
        self.assertIsNone(pattern.search("aXbXcXdXeXfXgXhXiXjXkXlXmXnXo"))

    def test_no_value_and_an_empty_value_both_produce_no_pattern(self):
        # An empty alternative matches at every position, so it would replace the whole prompt
        # with $NAMEs. Nothing produces one today; this is the guard that keeps that true.
        self.assertIsNone(self.hook._one_pass([]))
        self.assertIsNone(self.hook._one_pass([""]))


class TestEveryOccurrenceIsReplaced(HookCase):
    """scan() dedupes by value, so one finding can stand for several occurrences in the prompt.

    `str.replace` replaced all of them. Any span-based rewrite using finding.start/finding.end
    replaces only the occurrence scan() happened to report and leaves the second copy in the
    rewrite -- which is what goes on the clipboard and gets repasted. A new leak, from the fix.
    """

    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"

    def paste_and_reason(self, prompt):
        captured = {}
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: captured.setdefault("text", text) or True
        code, out, err = self.run_hook({"prompt": prompt, "cwd": "/p", "session_id": "s"})
        self.assertEqual(code, 0)
        return captured.get("text", ""), json.loads(out)["reason"]

    def test_the_same_credential_pasted_twice_leaves_no_copy_behind(self):
        paste, reason = self.paste_and_reason(
            "old value " + self.KEY + " and again later " + self.KEY + " done")
        for where, text in (("clipboard", paste), ("reason", reason)):
            self.assertNotIn(self.KEY, text, "the second copy survived in the %s" % where)
        # Counted on the paste alone: the reason additionally lists the name it filed.
        self.assertEqual(paste.count("$STRIPE_SECRET_KEY"), 2,
                         "both occurrences should become the same $NAME")
        self.assertEqual(self.vault.names(), ["STRIPE_SECRET_KEY"])  # one value, one name

    def test_a_credential_repeated_on_many_lines_is_replaced_on_every_line(self):
        paste, _ = self.paste_and_reason("\n".join("line %d: %s" % (i, self.KEY) for i in range(50)))
        self.assertNotIn(self.KEY, paste)
        self.assertEqual(paste.count("$STRIPE_SECRET_KEY"), 50)


class TestOverlappingFindingsStillCollapseToOneName(HookCase):
    """Longest-first is load-bearing, and a connection string is the case that proves it.

    An Azure storage string yields overlapping findings: clowk's own rule claims the whole string,
    while a vendored rule claims the base64 key inside it. Replacing the shorter one first files
    two names and leaves `AccountName=prodstore;EndpointSuffix=core.windows.net` in the prompt --
    the account name and the endpoint host, named to the model as plainly as the key would have
    been.
    """

    KEY = ("Zk9tQjNyTHc4dVhhSDJwVjZuRDRzWTdjRWc1aktmUW1UeUJ4"
           "TjFvUmw0dldoQzhkR3oyU3BLNGVBaVU5bXJYdA==")
    CONN = ("DefaultEndpointsProtocol=https;AccountName=prodstore;"
            + "Account" "Key=" + KEY + ";EndpointSuffix=core.windows.net")

    def test_one_name_is_filed_and_neither_the_account_nor_the_host_survives(self):
        code, out, err = self.run_hook({"prompt": "connect with " + self.CONN, "cwd": "/p"})
        reason = json.loads(out)["reason"]
        self.assertEqual(self.vault.names(), ["AZURE_STORAGE_CONNECTION_STRING"])
        self.assertNotIn(self.KEY, reason)
        self.assertNotIn("prodstore", reason)
        self.assertNotIn("core.windows.net", reason)
        self.assertIn("connect with $AZURE_STORAGE_CONNECTION_STRING", reason)


class TestStraddlingFindingsLeaveNoWholeValue(HookCase):
    """Two findings can overlap with NEITHER containing the other, and one scan must pick one.

    A leftmost scan commits to whichever starts first and never revisits the other's start, so
    bytes of the loser can survive -- which the `str.replace` loop also did, from the other end,
    because replacing the longer one first destroys the shorter one's start just as thoroughly.
    Measured over the 126 straddling texts the shipped ruleset produces: a whole value survived 0
    of 126 under both, and the longest surviving fragment was worse under one pass on 12, better
    on 9, identical on 105.

    What must hold unconditionally is the part that is a guarantee rather than a coin flip: no
    COMPLETE detected value is ever left in the rewrite. An unmatched value's every occurrence
    begins inside a committed match -- otherwise the scan would have matched it there -- so its
    first byte is always replaced.
    """

    # clowk's URI rule matches from `postgresql://` to the end; its key=value rule matches from
    # `DATABASE_URL=` to the last pair. They overlap and neither contains the other.
    PASSWORD = "Ab3xQ9zLmN4pR7tV"
    SQL_PASSWORD = "Tr0ub4dor&3xKq7Zm"
    PROMPT = ("DATABASE_URL=postgresql://svc:" + PASSWORD + "@db.internal/orders;"
              + "Pass" "word=" + SQL_PASSWORD + ";")

    def test_the_fixture_really_does_straddle(self):
        # The premise, not the assertion: if the ruleset stops straddling here the test below
        # silently stops testing anything.
        from clowk.detect import scan

        spans = sorted((self.PROMPT.find(f.secret),
                        self.PROMPT.find(f.secret) + len(f.secret)) for f in scan(self.PROMPT))
        self.assertGreater(len(spans), 1, "only one finding, so nothing can straddle")
        (a_lo, a_hi), (b_lo, b_hi) = spans[0], spans[-1]
        self.assertLess(b_lo, a_hi, "the findings do not overlap")
        self.assertGreater(b_hi, a_hi, "one finding still contains the other")

    def test_no_whole_value_survives_the_rewrite(self):
        from clowk.detect import scan

        code, out, err = self.run_hook({"prompt": self.PROMPT, "cwd": "/p"})
        reason = json.loads(out)["reason"]
        for finding in scan(self.PROMPT):
            self.assertNotIn(finding.secret, reason,
                             "a whole detected value survived: %r" % finding.rule_id)
        for password in (self.PASSWORD, self.SQL_PASSWORD):
            self.assertNotIn(password, reason)


class TestFilingStillGoesLongestFirst(HookCase):
    """MAX_FILED decides which 20 of a noisy paste's hits reach the vault, so the order matters.

    Substitution no longer needs one -- a single pass handles every value at once -- so the sort
    survives only for filing, and it has to: in text order a longer credential pasted BELOW enough
    log lines falls outside the cap and is never written to the vault at all, leaving `clowk get`
    nothing to find once the terminal has scrolled. Redaction is unaffected either way; every
    value leaves the prompt whether or not it was filed.

    Length is a weak proxy for "a real key rather than log noise" and is only being preserved
    here, not defended: a 32-character `sk_live_...` ties with a 32-hex log id and loses on
    stability. Confidence tier would discriminate properly, but changing what the cap prefers is
    not this fix.
    """

    # 57 characters against the noise's 32, and last in the text, so only the sort can save it.
    TOKEN = "xoxb" "-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

    def test_a_longer_credential_below_the_cap_worth_of_log_noise_is_still_filed(self):
        rnd = random.Random(5)
        noise = "\n".join(
            "2026-08-05 INFO api_key=%s served"
            % "".join(rnd.choice("0123456789abcdef") for _ in range(32))
            for _ in range(self.hook.MAX_FILED + 10))
        code, out, err = self.run_hook({"prompt": noise + "\nslack bot token " + self.TOKEN,
                                        "cwd": "/p"})
        self.assertNotIn(self.TOKEN, json.loads(out)["reason"])
        self.assertIn("SLACK_BOT_TOKEN", self.vault.names(),
                      "the longest value was crowded out of the vault by shorter log noise")
        self.assertEqual(self.vault.get("SLACK_BOT_TOKEN"), self.TOKEN)
        self.assertLessEqual(len(self.vault.names()), self.hook.MAX_FILED)


class TestTheEchoedRewriteIsElided(HookCase):
    """The reason echoed the whole rewritten prompt, which floods the terminal on a long one.

    There was already a cap, and it went too far the other way: above ECHO_LIMIT the echo was
    replaced ENTIRELY by a character count, so the user was told to paste something they could not
    see any of. Head and tail are what let them confirm it is the right message before pasting it.

    The one branch that must never be elided is a failed clipboard copy. clip.copy is best effort
    and returns False when no clipboard tool exists -- every headless box -- and there the printed
    text is the user's only copy of the rewrite. Eliding it would leave retyping or `unclowk`.
    """

    KEY = "ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    OPENING = "here is the deploy token"
    CLOSING = "and that is the end of the message"

    def prompt(self, filler_lines=200):
        middle = "\n".join("step %d: rebuild the image and push it to the registry" % i
                           for i in range(filler_lines))
        return "%s %s\n%s\n%s" % (self.OPENING, self.KEY, middle, self.CLOSING)

    def reason(self, copied, filler_lines=200):
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: copied
        code, out, err = self.run_hook({"prompt": self.prompt(filler_lines), "cwd": "/p"})
        self.assertEqual(code, 0)
        return json.loads(out)["reason"]

    def test_a_long_rewrite_shows_its_opening_and_its_closing(self):
        reason = self.reason(copied=True)
        self.assertIn(self.OPENING + " $GITHUB_TOKEN", reason, "the head of the message was cut")
        self.assertIn(self.CLOSING, reason, "the tail of the message was cut")

    def test_the_middle_is_dropped_rather_than_the_whole_thing(self):
        reason = self.reason(copied=True)
        self.assertNotIn("step 100:", reason, "nothing was elided")
        self.assertLess(len(reason), 2000, "%d characters is still a flood" % len(reason))

    def test_the_elision_says_where_the_whole_message_is(self):
        self.assertIn("clipboard", self.reason(copied=True))

    def test_a_failed_clipboard_copy_is_never_elided(self):
        # The printed text is the only copy in that case, so every line has to be there.
        reason = self.reason(copied=False)
        self.assertIn(self.OPENING + " $GITHUB_TOKEN", reason)
        self.assertIn(self.CLOSING, reason)
        for i in (0, 100, 199):
            self.assertIn("step %d:" % i, reason, "line %d was elided with no clipboard" % i)

    def test_a_short_rewrite_is_still_echoed_whole(self):
        reason = self.reason(copied=True, filler_lines=2)
        for i in (0, 1):
            self.assertIn("step %d:" % i, reason)
        self.assertNotIn("elided", reason)

    def test_the_raw_value_is_absent_from_both_branches(self):
        for copied in (True, False):
            self.assertNotIn(self.KEY, self.reason(copied=copied))

    def test_one_enormous_single_line_is_still_cut(self):
        # A minified bundle or a base64 blob has no newline to cut at, so the boundary preference
        # has nothing to work with and the hard cut has to stand rather than fall through to whole.
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: True
        one_line = "start " + self.KEY + " " + "x" * 9000 + " finish"
        code, out, err = self.run_hook({"prompt": one_line, "cwd": "/p"})
        reason = json.loads(out)["reason"]
        self.assertIn("start $GITHUB_TOKEN", reason)
        self.assertIn("finish", reason)
        self.assertLess(len(reason), 2000, "a single long line was not cut")
        self.assertGreater(len(reason), 800, "the head and tail were dropped too")

    def test_an_elision_always_hides_enough_to_be_worth_a_marker(self):
        self.assertGreater(self.hook.ECHO_LIMIT, self.hook.ECHO_HEAD + self.hook.ECHO_TAIL,
                           "at this limit an elision can claim to hide almost nothing")


class TestEmphasisIsGatedOnSomethingTrueAtRuntime(HookCase):
    """The block message was one undifferentiated block: nothing marked the $NAME you need.

    Whether a host renders an escape was UNVERIFIED before this, and getting it wrong makes the
    message worse than monotone -- a literal `[1m` in front of every name. Measured on the real
    Claude Code 2.1.223 interactive TUI on 2026-08-06 (see NOTES.md): escapes survive and are
    honoured, markdown is not rendered. codex and gemini-cli take the reason on stderr instead and
    are still unverified, so they get no escapes at all.

    The gate must not be isatty. The hook's streams are pipes to the host -- measured, all three
    report False -- so an isatty gate answers "no colour" always and the feature is dead code that
    tests still pass. What is actually true at runtime is that the host forwards the terminal's own
    TERM and COLORTERM into the hook's environment.
    """

    KEY = "ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    ESC = "\x1b"

    def env(self, **over):
        base = {"TERM": "xterm-256color"}
        base.update(over)
        return base

    def test_the_verified_host_gets_emphasis(self):
        self.assertTrue(self.hook.emphasis_ok("claude-code", self.env()))

    def test_the_gate_is_not_isatty_which_is_always_false_here(self):
        # The trap, asserted rather than described: emphasis is on while nothing is a terminal.
        out = io.StringIO()
        self.assertFalse(out.isatty())
        self.assertFalse(sys.stdout.isatty() and False)
        self.assertTrue(self.hook.emphasis_ok("claude-code", self.env()),
                        "the gate went looking for a tty it can never have")

    def test_an_unverified_host_gets_none(self):
        for host in ("codex", "gemini-cli", "some-future-host"):
            self.assertFalse(self.hook.emphasis_ok(host, self.env()),
                             "%s would be sent escapes nobody has checked it renders" % host)

    def test_no_color_is_honoured(self):
        self.assertFalse(self.hook.emphasis_ok("claude-code", self.env(NO_COLOR="1")))
        self.assertTrue(self.hook.emphasis_ok("claude-code", self.env(NO_COLOR="")))

    def test_an_absent_or_dumb_term_gets_none(self):
        # This is what protects Windows, where a stock console sets no TERM at all and needs
        # virtual-terminal processing enabled before an escape is anything but garbage.
        self.assertFalse(self.hook.emphasis_ok("claude-code", {}))
        for term in ("", "dumb", "DUMB", "Dumb"):
            self.assertFalse(self.hook.emphasis_ok("claude-code", self.env(TERM=term)),
                             "TERM=%r was sent escapes" % term)

    def test_a_terminal_that_only_looks_dumb_still_gets_emphasis(self):
        # dumb-emacs-ansi is a real TERM that does render escapes, so the check is an exact match
        # on the folded name rather than a prefix.
        self.assertTrue(self.hook.emphasis_ok("claude-code", self.env(TERM="dumb-emacs-ansi")))

    def reason(self, host="claude-code", emphasis=True):
        self.addCleanup(setattr, self.hook, "emphasis_ok", self.hook.emphasis_ok)
        self.hook.emphasis_ok = lambda h, env=None: emphasis and h == "claude-code"
        code, out, err = self.run_hook({"prompt": "deploy with " + self.KEY, "cwd": "/p"},
                                       host=host)
        return json.loads(out)["reason"] if host == "claude-code" else err

    def test_the_name_is_emphasised_where_it_is_announced(self):
        reason = self.reason()
        self.assertIn("\x1b[1m$GITHUB_TOKEN\x1b[22m", reason)

    def test_bold_is_closed_with_22_not_with_a_full_reset(self):
        # Measured: the host wraps the whole reason in its own amber, and 0m would clear that too,
        # dropping the rest of the line to the terminal default. 22m ends bold and nothing else.
        reason = self.reason()
        self.assertNotIn("\x1b[0m", reason)

    def test_the_echoed_paste_carries_no_escapes_even_when_the_rest_does(self):
        # The echo is a preview of the clipboard payload, so it has to look like the payload.
        reason = self.reason()
        body = reason.split("📋")[1]
        self.assertNotIn(self.ESC, body, "the preview of the paste was styled")

    def test_an_unverified_host_gets_a_message_with_no_escapes_at_all(self):
        err = self.reason(host="codex")
        self.assertNotIn(self.ESC, err)
        self.assertIn("$GITHUB_TOKEN", err)      # still says the thing, just plainly
        self.assertIn("unclowk", err)

    def test_with_emphasis_off_the_message_is_byte_identical_to_the_old_plain_one(self):
        styled = self.reason(emphasis=True)
        self.setUp()                              # a fresh vault, so the name does not suffix
        plain = self.reason(emphasis=False)
        self.assertNotIn(self.ESC, plain)
        self.assertEqual(styled.replace("\x1b[1m", "").replace("\x1b[22m", ""), plain,
                         "emphasis changed more than the escapes")


class TestTheClipboardPayloadIsNeverStyled(HookCase):
    """The clipboard payload is the text the user repastes INTO the chat.

    An escape clowk PUT there would corrupt their prompt, could break the $NAME reference the whole
    flow depends on, and would be transmitted to the model. The display string and the clipboard
    string are built separately for exactly that reason, and these keep them separate.

    Note the exact claim. clowk adds none; it does not promise the payload is escape-free, because
    the user's own pasted text may contain escapes and clowk substitutes values without editing
    anything else. The last two tests below pin that distinction rather than leaving it implied.
    """

    KEY = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"
    SECOND = "ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

    def paste(self, prompt, host="claude-code"):
        captured = {}
        self.addCleanup(setattr, self.hook.clip, "copy", self.hook.clip.copy)
        self.hook.clip.copy = lambda text: captured.setdefault("text", text) or True
        self.addCleanup(setattr, self.hook, "emphasis_ok", self.hook.emphasis_ok)
        self.hook.emphasis_ok = lambda h, env=None: True   # forced on, on every host
        self.run_hook({"prompt": prompt, "cwd": "/p", "session_id": "s"}, host=host)
        return captured.get("text", "")

    def test_no_escape_character_reaches_the_clipboard(self):
        for host in ("claude-code", "codex", "gemini-cli"):
            payload = self.paste("deploy with " + self.KEY, host=host)
            self.assertNotEqual(payload, "")
            for ch in ("\x1b", "\x9b", "\x0f", "\x07"):
                self.assertNotIn(ch, payload, "a control character reached the clipboard on %s"
                                 % host)

    def test_the_name_in_the_payload_is_a_bare_reference(self):
        # Not merely escape-free: the $NAME has to be exactly what the shell and the agent will
        # read, with nothing wrapped around it.
        payload = self.paste("rotate this: " + self.KEY)
        self.assertIn("rotate this: $STRIPE_SECRET_KEY", payload)

    def test_a_multi_name_payload_is_plain_throughout(self):
        payload = self.paste("both " + self.KEY + " and " + self.SECOND)
        self.assertNotIn("\x1b", payload)
        self.assertIn("$STRIPE_SECRET_KEY", payload)
        self.assertIn("$GITHUB_TOKEN", payload)

    def test_the_payload_is_all_printable_plus_newlines(self):
        payload = self.paste("deploy with " + self.KEY + "\nthen restart")
        bad = [c for c in payload if ord(c) < 32 and c != "\n"]
        self.assertEqual(bad, [], "non-newline control characters in the payload: %r" % bad)

    def test_clowk_adds_no_escape_to_a_prompt_that_already_had_one(self):
        """The precise invariant, which is narrower than "the payload has no escapes".

        A person pasting a coloured build log has escapes in their own text, and clowk deliberately
        does not touch them: it substitutes the values it found and changes nothing else, so
        stripping them would silently mangle the message the user chose to send. What must hold is
        that clowk ADDS none of its own -- and that a pre-existing one cannot break the $NAME
        reference the whole flow depends on, which is the thing the rule is protecting.
        """
        prompt = "build log:\n\x1b[31mERROR\x1b[0m failed\ndeploy with " + self.KEY + "\ndone"
        payload = self.paste(prompt)
        self.assertEqual(payload.count("\x1b"), prompt.count("\x1b"),
                         "clowk added or removed an escape of its own")
        self.assertIn("deploy with $STRIPE_SECRET_KEY\ndone", payload)
        self.assertNotIn(self.KEY, payload)

    def test_an_escape_near_the_credential_does_not_corrupt_the_reference(self):
        payload = self.paste("\x1b[31mfailed\x1b[0m — deploy with " + self.KEY + " now")
        self.assertIn("deploy with $STRIPE_SECRET_KEY now", payload)
        self.assertNotIn(self.KEY, payload)
        self.assertEqual(payload.count("\x1b"), 2)

    def test_an_escape_glued_to_the_credential_still_redacts_it(self):
        """A KNOWN limitation of detection, pinned here for its one guarantee: no leak.

        With no separator, `ESC[1m` + the value reads as one token to the standalone rule -- `[`
        is not in its lookbehind, so the match starts at the `1` and swallows the `1m`. The value
        is still fully redacted, which is the property that matters, but it is filed under $SECRET
        rather than $STRIPE_SECRET_KEY and the stored value carries the `1m`, so it would not work
        as a credential. Fixing that means changing the token rule's boundaries, which is a
        detection change needing the labelled-corpus run this repo does for those, and is not part
        of the redaction work. Recorded rather than quietly tolerated.
        """
        payload = self.paste("\x1b[1m" + self.KEY + "\x1b[0m now")
        self.assertNotIn(self.KEY, payload, "the credential leaked, which is not tolerable")
        self.assertIn("$SECRET", payload)


class TestStdinIsDecodedAsUtf8(HookCase):
    """Hosts send UTF-8 JSON. Reading it through the locale codec is a silent pass-through.

    UnicodeDecodeError subclasses ValueError, so a locale that cannot decode the payload was
    indistinguishable from malformed JSON: exit 0, nothing on either stream, credential
    transmitted. Windows' default ANSI codepages cannot decode most non-ASCII UTF-8, and Claude
    Code puts `cwd` in every payload -- so one accented character in a profile path disabled the
    hook for every prompt. These run the real entrypoint, because the bug lives in the stream
    sys.stdin hands us and no in-process StringIO can see it.
    """

    TOKEN = "ghp" "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    # ď encodes as C4 8F, and 0x8F is undefined in cp1252; cp932 rejects the pair too.
    PROMPT = "nasaď " + TOKEN + " na server"
    REWRITE = "nasaď $GITHUB_TOKEN na server"

    def run_script(self, encoding):
        payload = json.dumps({"prompt": self.PROMPT, "cwd": "/p"}, ensure_ascii=False)
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = encoding
        env.pop("PYTHONUTF8", None)
        env["PATH"] = self.dir  # no clipboard tool on PATH: never touch the developer's clipboard
        proc = subprocess.Popen(
            [sys.executable, os.path.join(REPO_ROOT, "clowk", "hook_prompt.py"),
             "--host", "claude-code"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        try:
            out, err = proc.communicate(payload.encode("utf-8"), timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("the hook hung under %s -- every host reads that as a pass-through" % encoding)
        return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def assert_blocked_and_filed(self, encoding):
        code, out, err = self.run_script(encoding)
        self.assertEqual(code, 0, "stderr: " + err)
        self.assertNotEqual(out, "", "no block under %s: the credential was transmitted" % encoding)
        reason = json.loads(out)["reason"]
        self.assertNotIn(self.TOKEN, reason)
        self.assertEqual(self.vault.names(), ["GITHUB_TOKEN"])
        self.assertEqual(self.vault.get("GITHUB_TOKEN"), self.TOKEN)
        return reason

    def test_a_utf8_locale_blocks_and_files_the_token(self):
        self.assertIn(self.REWRITE, self.assert_blocked_and_filed("utf-8"))

    def test_a_cp1252_locale_still_blocks_and_the_rewrite_is_not_mojibake(self):
        self.assertIn(self.REWRITE, self.assert_blocked_and_filed("cp1252"))

    def test_a_cp932_locale_still_blocks_and_the_rewrite_is_not_mojibake(self):
        self.assertIn(self.REWRITE, self.assert_blocked_and_filed("cp932"))

    def test_a_stream_that_cannot_be_decoded_says_so_instead_of_looking_clean(self):
        class Undecodable(object):
            def read(self):
                raise UnicodeDecodeError("charmap", b"\x8f", 0, 1, "undefined")

        out, err = io.StringIO(), io.StringIO()
        code = self.hook.main(["--host", "claude-code"], Undecodable(), out, err)
        self.assertEqual(code, 0)          # a payload we cannot read is not ours to block on
        self.assertEqual(out.getvalue(), "")
        self.assertIn("NOT scanning", err.getvalue())


class TestPointerOncePerSession(HookCase):
    """The skill pointer goes out on a session's first block, not on every one.

    A session that blocks five credentials does not need the explanation five times: the agent read
    it the first time and the skill stays loaded. The pointer is ~46 tokens, so repeating it is pure
    waste once it has landed.
    """

    A = "ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    B = "xoxb" "-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

    def setUp(self):
        HookCase.setUp(self)
        os.environ["CLOWK_SESSIONS"] = os.path.join(self.dir, "sessions.json")
        self.addCleanup(os.environ.pop, "CLOWK_SESSIONS", None)

    def paste(self, secret, session):
        """The text the user repastes -- i.e. the only thing a blocked turn sends to the model.

        Asserted on the clipboard, not the block reason. A blocked turn transmits nothing, so the
        reason is read by the human and never reaches the agent: the pointer sat there for a while
        being decorative, and the agent received a bare $NAME with no idea what it meant.
        """
        captured = {}
        original = self.hook.clip.copy
        self.hook.clip.copy = lambda text: captured.setdefault("text", text) or True
        try:
            self.run_hook({"prompt": "use " + secret, "cwd": "/p", "session_id": session})
        finally:
            self.hook.clip.copy = original
        return captured.get("text", "")

    def reason(self, secret, session):
        code, out, err = self.run_hook(
            {"prompt": "use " + secret, "cwd": "/p", "session_id": session})
        return json.loads(out)["reason"]

    def test_the_first_block_of_a_session_carries_it_in_the_repasted_text(self):
        self.assertIn("[assistant:", self.paste(self.A, "s1"))

    def test_a_later_block_in_the_same_session_does_not(self):
        self.paste(self.A, "s1")
        self.assertNotIn("[assistant:", self.paste(self.B, "s1"))

    def test_a_different_session_gets_it_again(self):
        self.paste(self.A, "s1")
        self.assertIn("[assistant:", self.paste(self.B, "s2"))

    def test_the_rest_of_the_message_is_unaffected(self):
        # Only the pointer is dropped -- the rewrite and the bypass line still have to be there,
        # because the human reads those every time.
        # Two channels with different audiences. The repasted text is what the model receives, so it
        # carries the rewrite and (once) the pointer, and nothing else. The block reason is what the
        # human reads, so it always carries the bypass line -- putting that in the paste would make
        # the user's own message tell the agent how to skip the guard.
        self.paste(self.A, "s1")
        second_paste = self.paste(self.B, "s1")
        self.assertIn("$SLACK_BOT_TOKEN", second_paste)
        self.assertNotIn("unclowk", second_paste)
        self.assertIn("unclowk", self.reason(self.B, "s1"))

    def test_a_payload_with_no_session_id_repeats_the_pointer(self):
        # Omitting it costs the agent the one thing that stops it printing a credential, so an
        # untrackable session errs towards repeating rather than towards silence.
        for _ in range(2):
            self.assertIn("[assistant:", self.paste(self.A, ""))

    def test_an_unwritable_state_file_still_blocks_and_still_points(self):
        os.environ["CLOWK_SESSIONS"] = os.path.join(self.dir, "nope", "x", "sessions.json")
        self.assertIn("[assistant:", self.paste(self.A, "s1"))

    def test_a_corrupt_state_file_is_treated_as_unseen(self):
        with open(os.environ["CLOWK_SESSIONS"], "w", encoding="utf-8") as f:
            f.write("{not a list")
        self.assertIn("[assistant:", self.paste(self.A, "s1"))

    def test_the_state_file_does_not_grow_without_bound(self):
        for n in range(self.hook.MAX_SESSIONS + 20):
            self.hook.pointer_needed("session-%d" % n)
        with open(os.environ["CLOWK_SESSIONS"], encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)), self.hook.MAX_SESSIONS)

    def test_the_most_recent_sessions_are_the_ones_kept(self):
        for n in range(self.hook.MAX_SESSIONS + 5):
            self.hook.pointer_needed("session-%d" % n)
        newest = "session-%d" % (self.hook.MAX_SESSIONS + 4)
        self.assertFalse(self.hook.pointer_needed(newest), "the newest session was evicted")


if __name__ == "__main__":
    unittest.main()
