import json
import os
import unittest

from clowk.detect import _OPERATOR, classify, scan

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "rules.json")


class TestClassify(unittest.TestCase):
    def test_literal_vendor_prefix_is_high(self):
        self.assertEqual(classify(r"\b(ghp_[A-Za-z0-9]{36})\b"), "high")
        self.assertEqual(classify(r"\b(xoxb-[0-9]{10,})\b"), "high")

    def test_no_literal_prefix_is_low(self):
        self.assertEqual(classify(r"\b([A-Za-z0-9]{32})\b"), "low")

    def test_literal_inside_a_character_class_does_not_count(self):
        self.assertEqual(classify(r"[abc_-]{8,}"), "low")

    def test_a_literal_in_the_keyword_half_does_not_make_a_shape_rule_high(self):
        # hashicorp-tf-password: the only literal run is `administrator_`, and it is in the
        # KEYWORD alternation -- a branch that need not appear in the matched text at all. The
        # captured value is pure shape, so the rule must stay purgeable.
        hashicorp = (r"(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
                     r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(\"[a-z0-9=_\-]{8,20}\")"
                     r"(?:[\x60'\"\s;]|\\[nr]|$)")
        self.assertEqual(classify(hashicorp), "low")

    def test_a_literal_in_the_captured_value_still_reads_high(self):
        # typeform-api-token: `tfp_` is in the CAPTURE, so this is a genuinely pinned format.
        # This assertion is what stops the fix above from being widened into "any keyword-gated
        # rule is low", which would attach a false-positive hint to 11 pinned vendor formats.
        typeform = (r"(?:typeform)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
                    r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})"
                    r"(?:[\x60'\"\s;]|\\[nr]|$)")
        self.assertEqual(classify(typeform), "high")


def _load_rules():
    with open(RULES) as f:
        return json.load(f)


class TestRulesFile(unittest.TestCase):
    def test_every_rule_has_a_confidence(self):
        rules = _load_rules()
        self.assertTrue(all(r.get("confidence") in ("high", "low") for r in rules))

    def test_generic_api_key_is_low(self):
        rules = _load_rules()
        generic = [r for r in rules if r["id"] == "generic-api-key"]
        self.assertEqual(generic[0]["confidence"], "low")

    def test_keyword_only_literals_do_not_promote_a_shape_rule(self):
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("hashicorp-tf-password", "cohere-api-token", "new-relic-user-api-id",
                    "nytimes-access-token", "sidekiq-secret"):
            self.assertEqual(rules[rid]["confidence"], "low", rid)

    def test_rules_pinned_in_their_capture_stay_high(self):
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("typeform-api-token", "new-relic-user-api-key", "mailgun-pub-key",
                    "defined-networking-api-token", "sonar-api-token"):
            self.assertEqual(rules[rid]["confidence"], "high", rid)

    def test_the_readme_shape_only_count_is_accurate(self):
        # README tells users how many rules match on shape; a drifting number there quietly
        # misrepresents the false-positive surface.
        low = sum(1 for r in _load_rules() if r["confidence"] == "low")
        readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md")
        with open(readme, encoding="utf-8") as f:   # README has emoji; cp1252 cannot read it
            self.assertIn("%d of the %d rules" % (low, len(_load_rules())), f.read())

    def test_the_counts_detect_quotes_about_its_own_ruleset_are_accurate(self):
        """detect.py's comments quantify the ruleset, and one pair of numbers had gone stale.

        The standalone rule's preamble said "96 pin a literal vendor prefix ... the other 124 need
        keyword <operator> value". 96 came from a classify() that read a vendor prefix out of a
        rule's KEYWORD half; fixing that moved five rules high -> low, README was updated to 129,
        and this comment was not. README's number has been test-derived since. Now these are too,
        because a comment is the place a reader goes to understand WHY the code is shaped this way,
        and a wrong number there is more expensive than a wrong number in prose.
        """
        rules = _load_rules()
        high = sum(1 for r in rules if r["confidence"] == "high")
        # gitleaks' keyword=value template. Present verbatim in the rules that cannot fire on a
        # bare paste, which is the whole reason clowk adds a standalone-token rule.
        template = sum(1 for r in rules if _OPERATOR in r["regex"])
        detect_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "clowk", "detect.py")
        with open(detect_py, encoding="utf-8") as f:
            source = f.read()
        for count, what in ((high, "rules pinning a literal vendor prefix"),
                            (template, "rules carrying the keyword=value template")):
            self.assertIn("%d of the %d" % (count, len(rules)), source,
                          "detect.py does not say %d of the %d (%s)" % (count, len(rules), what))


class TestFinding(unittest.TestCase):
    def test_finding_carries_confidence(self):
        findings = scan("token sk_" "live_4eC39HqLyjWDarjtT1zdp7dc here")
        self.assertTrue(findings)
        self.assertIn(findings[0].confidence, ("high", "low"))


if __name__ == "__main__":
    unittest.main()
