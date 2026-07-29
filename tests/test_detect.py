import unittest

from clowk.detect import scan


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
