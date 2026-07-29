import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest

from clowk.detect import scan, secret_group

DETECT_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "detect.py")

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "rules.json")

# Synthetic values in the shapes the vendored rules recognise. None of these is live.
SONAR_PROMPT = "sonar.login=squ" "_ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90 fix the login step"
SONAR_TOKEN = "squ" "_ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90"

TEAMS_URL = ("https://acme.webhook.office.com/webhookb2/"
             "11111111-2222-3333-4444-555555555555@66666666-7777-8888-9999-aaaaaaaaaaaa"
             "/IncomingWebhook/0123456789abcdef0123456789abcdef/bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
TEAMS_PROMPT = "post the build status to " + TEAMS_URL + " please"

JWT_B64 = ("ZXlK" "aGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0"
           "l3aWJtRnRaU0k2SWtwdmFHNGdSRzlsSWl3aWFXRjBJam94TlRFMk1qTTVNREl5ZlE")
JWT_B64_PROMPT = "please decode this for me " + JWT_B64


def _load_rules():
    with open(RULES) as f:
        return json.load(f)


class TestSecretSpan(unittest.TestCase):
    """The reported secret must COVER the credential.

    hook_prompt rewrites the prompt with `prompt.replace(finding.secret, "$NAME")` and puts the
    result on the clipboard for the user to repaste, so a finding whose secret is a keyword or a
    fixed marker instead of the value leaves the live credential in the rewrite -- and files junk
    in the vault under the credential's name.
    """

    def _assert_covered(self, prompt, credential):
        findings = scan(prompt)
        self.assertTrue(findings, "nothing detected at all")
        covering = [f for f in findings if credential in f.secret]
        self.assertTrue(
            covering,
            "no finding covers the credential; secrets were %r" % ([f.secret for f in findings],),
        )

    def test_sonar_token_is_covered_not_the_login_keyword(self):
        self._assert_covered(SONAR_PROMPT, SONAR_TOKEN)

    def test_sonar_token_is_captured_exactly_via_its_declared_secret_group(self):
        # gitleaks.toml declares `secretGroup = 2` for this rule; honouring it turns the safe
        # whole-match over-capture into the exact token, so $SONAR_API_TOKEN expands correctly.
        self.assertIn(SONAR_TOKEN, [f.secret for f in scan(SONAR_PROMPT)])

    def test_teams_webhook_key_is_covered_not_a_uuid_chunk(self):
        self._assert_covered(TEAMS_PROMPT, "0123456789abcdef0123456789abcdef")

    def test_base64_jwt_is_covered_not_the_fixed_header_marker(self):
        self._assert_covered(JWT_B64_PROMPT, JWT_B64)

    def test_stripe_key_is_still_captured_exactly(self):
        # control: the fix must not widen a rule that already captured the value exactly
        findings = scan("deploy with sk_" "live_4eC39HqLyjWDarjtT1zdp7dc tonight")
        self.assertIn("sk_" "live_4eC39HqLyjWDarjtT1zdp7dc", [f.secret for f in findings])

    def test_generic_api_key_value_excludes_the_keyword_and_quotes(self):
        # control: the generic keyword=value template must keep its exact group-1 value
        findings = scan('api_key = "aB3xQ9zLmN4pR7tV2wY8"')
        self.assertIn("aB3xQ9zLmN4pR7tV2wY8", [f.secret for f in findings])


class TestSecretGroupMetadata(unittest.TestCase):
    def test_every_rule_declares_a_secret_group(self):
        for r in _load_rules():
            self.assertIsInstance(r.get("group"), int, "%s has no group" % r["id"])

    def test_every_declared_group_is_a_valid_group_index(self):
        for r in _load_rules():
            pat = re.compile(r["regex"])
            self.assertLessEqual(r["group"], pat.groups, r["id"])
            self.assertGreaterEqual(r["group"], 0, r["id"])

    def test_a_declared_secret_group_wins_over_the_derived_one(self):
        rules = {r["id"]: r for r in _load_rules()}
        sonar = rules["sonar-api-token"]
        self.assertEqual(sonar["secret_group"], 2)   # as declared in gitleaks.toml
        self.assertEqual(sonar["group"], 2)

    def test_group_metadata_matches_what_the_resolver_derives(self):
        # rules.json is generated; a hand-edit that drops the key must not silently change tiers
        for r in _load_rules():
            if r.get("secret_group") is None:
                self.assertEqual(r["group"], secret_group(r["regex"]), r["id"])


class TestBrokenRuleset(unittest.TestCase):
    """Importing detect must never raise, whatever state rules.json is in.

    rules.json is read at import time, which happens while `from clowk.detect import scan` runs
    -- before hook_prompt's bare except exists. A traceback there is a non-zero exit from the
    hook, every host treats that as a non-blocking error, and the prompt carrying the credential
    is transmitted. It then stays broken for every subsequent turn.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        shutil.copy(DETECT_PY, os.path.join(self.dir, "detect.py"))

    def _load(self, rules_json):
        """Import a fresh copy of detect.py beside the given rules.json text (None = no file)."""
        path = os.path.join(self.dir, "rules.json")
        if rules_json is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            with open(path, "w") as f:
                f.write(rules_json)
        spec = importlib.util.spec_from_file_location("clowk_detect_probe", os.path.join(self.dir, "detect.py"))
        mod = importlib.util.module_from_spec(spec)
        self.warning = io.StringIO()
        with contextlib.redirect_stderr(self.warning):
            spec.loader.exec_module(mod)
        return mod

    def _assert_degrades(self, rules_json):
        mod = self._load(rules_json)
        self.assertEqual(mod.scan("here is the key sk_" "live_4eC39HqLyjWDarjtT1zdp7dc please"), [])
        self.assertTrue(mod.RULESET_ERROR, "a disabled ruleset must be reported, not silent")
        # loud, not silent: a hook that looks healthy while scanning nothing is worse than one
        # that says so, because nothing else in clowk ever reports a broken ruleset
        self.assertIn("NOT scanning", self.warning.getvalue())
        return mod

    def test_a_missing_ruleset_degrades_instead_of_raising(self):
        self._assert_degrades(None)

    def test_a_truncated_ruleset_degrades_instead_of_raising(self):
        with open(os.path.join(os.path.dirname(DETECT_PY), "rules.json")) as f:
            self._assert_degrades(f.read()[:5000])

    def test_an_empty_ruleset_file_degrades_instead_of_raising(self):
        self._assert_degrades("")

    def test_a_json_object_instead_of_a_list_degrades_instead_of_raising(self):
        self._assert_degrades('{"github-pat": {"regex": "ghp" "_[0-9a-zA-Z]{36}"}}')

    def test_one_malformed_entry_does_not_disable_the_other_rules(self):
        good = {"id": "probe", "env": "PROBE", "regex": r"\b(sk_live_[0-9a-zA-Z]{24})\b",
                "keywords": ["sk_" "live_"], "entropy": None, "ignorecase": False,
                "confidence": "high", "group": 1}
        mod = self._load(json.dumps([good, "not-a-rule", {"id": "no-regex"}]))
        self.assertEqual([f.secret for f in mod.scan("key sk_" "live_4eC39HqLyjWDarjtT1zdp7dc here")],
                         ["sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"])

    def test_an_intact_ruleset_reports_no_error(self):
        with open(os.path.join(os.path.dirname(DETECT_PY), "rules.json")) as f:
            mod = self._load(f.read())
        self.assertEqual(mod.RULESET_ERROR, "")
        self.assertEqual(len(mod._COMPILED), len(_load_rules()))
        self.assertEqual(self.warning.getvalue(), "")   # no crying wolf on a healthy ruleset


class TestScan(unittest.TestCase):
    def test_finds_a_stripe_style_key(self):
        findings = scan("here is the key sk_" "live_4eC39HqLyjWDarjtT1zdp7dc please use it")
        secrets = [f.secret for f in findings]
        self.assertIn("sk_" "live_4eC39HqLyjWDarjtT1zdp7dc", secrets)

    def test_clean_text_yields_nothing(self):
        self.assertEqual(scan("just refactor the parser in src/main.py"), [])

    def test_deduplicates_repeated_secret(self):
        key = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"
        findings = scan(key + " and again " + key)
        self.assertEqual(len([f for f in findings if f.secret == key]), 1)


if __name__ == "__main__":
    unittest.main()
