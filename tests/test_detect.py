import json
import os
import re
import unittest

from clowk.detect import scan, secret_group

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

    def test_group_metadata_matches_what_the_resolver_derives(self):
        # rules.json is generated; a hand-edit that drops the key must not silently change tiers
        for r in _load_rules():
            if r.get("secret_group") is None:
                self.assertEqual(r["group"], secret_group(r["regex"]), r["id"])


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
