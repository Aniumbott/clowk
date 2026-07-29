import json
import os
import unittest

from clowk.detect import classify, scan

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "rules.json")


class TestClassify(unittest.TestCase):
    def test_literal_vendor_prefix_is_high(self):
        self.assertEqual(classify(r"\b(ghp_[A-Za-z0-9]{36})\b"), "high")
        self.assertEqual(classify(r"\b(xoxb-[0-9]{10,})\b"), "high")

    def test_no_literal_prefix_is_low(self):
        self.assertEqual(classify(r"\b([A-Za-z0-9]{32})\b"), "low")

    def test_literal_inside_a_character_class_does_not_count(self):
        self.assertEqual(classify(r"[abc_-]{8,}"), "low")


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


class TestFinding(unittest.TestCase):
    def test_finding_carries_confidence(self):
        findings = scan("token sk_" "live_4eC39HqLyjWDarjtT1zdp7dc here")
        self.assertTrue(findings)
        self.assertIn(findings[0].confidence, ("high", "low"))


if __name__ == "__main__":
    unittest.main()
