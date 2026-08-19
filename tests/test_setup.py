"""`clowk setup` is the front door, so its refusals matter as much as its successes.

Two of these exist because the code got them wrong first. `setup --dry-run` with no host flags hung
forever waiting on a prompt with no terminal to answer it, which is what a Dockerfile or a CI runner
would have hit. And `registered_command` walked the tuple `install._load` returns instead of the dict
inside it, so it found no hooks and reported every host as unverified while all three were registered
correctly -- a green install described as broken, which is the one direction of error this tool cannot
afford to make routine.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import install, setup


class SetupCase(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        self.err = io.StringIO()

    def run_setup(self, argv, stdin=None):
        return setup.run(argv, self.out, self.err, stdin if stdin is not None else io.StringIO())


class TestItNeverBlocksWithoutATerminal(SetupCase):
    def test_no_flags_and_no_tty_refuses_instead_of_prompting(self):
        code = self.run_setup([])
        self.assertEqual(code, 1)
        self.assertIn("Not a terminal", self.err.getvalue())
        # the message has to carry the fix, or the caller is stuck
        self.assertIn("--yes", self.err.getvalue())
        self.assertIn("--hosts", self.err.getvalue())

    def test_a_stringio_is_not_treated_as_interactive(self):
        self.assertFalse(setup._interactive(io.StringIO()))


class TestDryRunWritesNothing(SetupCase):
    def test_it_prints_a_plan_and_returns_zero(self):
        code = self.run_setup(["--hosts", "claude-code", "--dry-run"])
        self.assertEqual(code, 0)
        body = self.out.getvalue()
        self.assertIn("--dry-run", body)
        self.assertIn("claude-code", body)

    def test_it_names_every_path_it_would_touch(self):
        self.run_setup(["--hosts", "claude-code", "--dry-run"])
        body = self.out.getvalue()
        self.assertIn(install.settings_path("claude-code"), body)
        self.assertIn(install.skill_path(), body)
        self.assertIn(install.command_path(), body)


class TestArgumentHandling(SetupCase):
    def test_unknown_host_is_refused_by_name(self):
        code = self.run_setup(["--hosts", "emacs"])
        self.assertEqual(code, 1)
        self.assertIn("emacs", self.err.getvalue())

    def test_unknown_option_is_refused_with_usage(self):
        code = self.run_setup(["--turbo"])
        self.assertEqual(code, 1)
        self.assertIn("--turbo", self.err.getvalue())
        self.assertIn("clowk setup", self.err.getvalue())

    def test_both_hosts_spellings_parse(self):
        self.assertEqual(setup._parse(["--hosts", "a,b"])["hosts"], ["a", "b"])
        self.assertEqual(setup._parse(["--hosts=a, b"])["hosts"], ["a", "b"])
        self.assertTrue(setup._parse(["-y"])["yes"])
        self.assertTrue(setup._parse(["--dry-run"])["dry_run"])


class TestReadingBackTheRegisteredHook(SetupCase):
    """Read the command out of the settings file, do not recompute it.

    Recomputing proves install *could* write a working command; it says nothing about the one on
    disk, and those differ the moment a clone moves or an interpreter is removed.
    """

    def setUp(self):
        SetupCase.setUp(self)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.settings = os.path.join(self.dir, "settings.json")
        self._real = install.TARGETS["claude-code"]["settings"]
        install.TARGETS["claude-code"]["settings"] = self.settings

    def tearDown(self):
        install.TARGETS["claude-code"]["settings"] = self._real

    def write(self, blob):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump(blob, f)

    def test_it_finds_a_nested_clowk_prompt_hook(self):
        self.write({"hooks": {"UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": '"/usr/bin/python3" "/x/clowk/hook_prompt.py" --host claude-code'}]}]}})
        found = setup.registered_command("claude-code")
        self.assertIsNotNone(found, "the tuple from _load was walked instead of the dict inside it")
        self.assertIn("hook_prompt.py", found)

    def test_it_ignores_somebody_elses_hooks(self):
        self.write({"hooks": {"UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": 'node /somewhere/other-tool.js'}]}]}})
        self.assertIsNone(setup.registered_command("claude-code"))

    def test_a_missing_settings_file_is_not_an_exception(self):
        self.assertIsNone(setup.registered_command("claude-code"))

    def test_verify_fails_loudly_when_nothing_is_registered(self):
        ok, detail = setup.verify("claude-code")
        self.assertFalse(ok)
        self.assertIn("no clowk prompt hook", detail)


class TestTheCanaryIsNotAWeakTest(SetupCase):
    def test_the_canary_is_something_the_ruleset_actually_catches(self):
        # A canary the detector ignores would make every verification pass for the wrong reason.
        from clowk.detect import scan
        self.assertTrue(scan("here is my key " + setup.CANARY),
                        "the canary is not detected, so verification proves nothing")

    def test_no_literal_credential_is_written_into_the_source(self):
        # GitHub push protection blocks a literal Stripe-shaped key in a tracked file, so the canary
        # is assembled from parts. This keeps it that way.
        body = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "clowk", "setup.py"), encoding="utf-8").read()
        self.assertNotIn(setup.CANARY, body,
                         "the canary appears whole in setup.py and will be blocked on push")


class TestHostDetection(SetupCase):
    def test_detection_only_reports_known_hosts(self):
        for host in setup.detected_hosts():
            self.assertIn(host, install.TARGETS)

    def test_every_ordered_host_is_a_real_target(self):
        self.assertEqual(sorted(setup.HOST_ORDER), sorted(install.TARGETS))

    def test_the_verified_list_is_a_subset_of_the_hosts(self):
        for host in setup.VERIFIED_PROMPT_EVENT:
            self.assertIn(host, install.TARGETS)


class TestChoosing(SetupCase):
    def test_numbers_select(self):
        picked = setup._choose(["claude-code", "codex"], self.out, self.err, io.StringIO("2\n"))
        self.assertEqual(picked, ["codex"])

    def test_a_selects_all(self):
        picked = setup._choose(["claude-code", "codex"], self.out, self.err, io.StringIO("a\n"))
        self.assertEqual(picked, ["claude-code", "codex"])

    def test_quitting_picks_nothing(self):
        self.assertEqual(setup._choose(["codex"], self.out, self.err, io.StringIO("q\n")), [])

    def test_an_out_of_range_number_picks_nothing_rather_than_guessing(self):
        self.assertEqual(setup._choose(["codex"], self.out, self.err, io.StringIO("7\n")), [])


if __name__ == "__main__":
    unittest.main()
