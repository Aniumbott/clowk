import json
import os
import stat
import tempfile
import unittest


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        import importlib

        from clowk import vault

        self.vault = importlib.reload(vault)

    def tearDown(self):
        os.environ.pop("CLOWK_VAULT", None)


class TestStore(VaultCase):
    def test_store_then_get_round_trips(self):
        key = self.vault.store("STRIPE_KEY", "sk_" "live_abc", rule="stripe", confidence="high", source="/tmp/p")
        self.assertEqual(key, "STRIPE_KEY")
        self.assertEqual(self.vault.get("STRIPE_KEY"), "sk_" "live_abc")

    def test_same_name_same_value_does_not_suffix(self):
        self.vault.store("A", "one")
        self.assertEqual(self.vault.store("A", "one"), "A")

    def test_same_name_different_value_suffixes(self):
        self.vault.store("A", "one")
        self.assertEqual(self.vault.store("A", "two"), "A_2")
        self.assertEqual(self.vault.get("A"), "one")
        self.assertEqual(self.vault.get("A_2"), "two")

    def test_names_are_sorted(self):
        self.vault.store("ZED", "one")
        self.vault.store("ALPHA", "two")
        self.vault.store("MIKE", "three")
        self.assertEqual(self.vault.names(), ["ALPHA", "MIKE", "ZED"])

    def test_file_is_owner_only_on_posix(self):
        self.vault.store("A", "one")
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(self.vault.path()).st_mode)
            self.assertEqual(mode, 0o600)

    def test_get_of_unknown_name_is_none(self):
        self.assertIsNone(self.vault.get("NOPE"))

    def test_corrupt_file_does_not_raise(self):
        with open(self.vault.path(), "w") as f:
            f.write("{not json")
        self.assertEqual(self.vault.names(), [])


class TestMetadata(VaultCase):
    def test_list_secrets_never_exposes_a_value(self):
        self.vault.store("A", "supersecret", rule="r", confidence="high", source="/p")
        listing = self.vault.list_secrets()
        self.assertNotIn("value", listing["A"])
        self.assertNotIn("supersecret", json.dumps(listing))
        self.assertEqual(listing["A"]["rule"], "r")
        self.assertEqual(listing["A"]["confidence"], "high")
        self.assertEqual(listing["A"]["sources"], ["/p"])

    def test_sources_accumulate_without_duplicates(self):
        self.vault.store("A", "one", source="/p")
        self.vault.store("A", "one", source="/p")
        self.vault.store("A", "one", source="/q")
        self.assertEqual(self.vault.list_secrets()["A"]["sources"], ["/p", "/q"])

    def test_record_use_appends_once(self):
        self.vault.store("A", "one")
        self.vault.record_use("A", "/p")
        self.vault.record_use("A", "/p")
        self.assertEqual(self.vault.list_secrets()["A"]["uses"], ["/p"])

    def test_record_use_on_unknown_name_is_a_noop(self):
        self.vault.record_use("NOPE", "/p")
        self.assertEqual(self.vault.names(), [])


class TestLifecycle(VaultCase):
    def test_clear_removes_and_reports(self):
        self.vault.store("A", "one")
        self.assertTrue(self.vault.clear("A"))
        self.assertFalse(self.vault.clear("A"))
        self.assertEqual(self.vault.names(), [])

    def test_rename_moves_value_and_metadata(self):
        self.vault.store("A", "one", source="/p")
        self.assertTrue(self.vault.rename("A", "B"))
        self.assertEqual(self.vault.get("B"), "one")
        self.assertIsNone(self.vault.get("A"))
        self.assertEqual(self.vault.list_secrets()["B"]["sources"], ["/p"])

    def test_rename_unknown_is_false(self):
        self.assertFalse(self.vault.rename("A", "B"))

    def test_rename_onto_existing_name_is_false(self):
        self.vault.store("A", "one")
        self.vault.store("B", "two")
        self.assertFalse(self.vault.rename("A", "B"))
        self.assertEqual(self.vault.get("B"), "two")


if __name__ == "__main__":
    unittest.main()
