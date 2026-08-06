import json
import os
import stat
import tempfile
import unittest

from tests import default_encoding


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


class TestStoreReportsARotation(VaultCase):
    """store returned only the final key, so its caller could not tell a suffix from a clean file.

    That is what left a rotation silent: the new value lands under NAME_2, the plain NAME still
    resolves to the revoked one, and nothing said so at the moment it happened. The storage model
    is deliberately unchanged -- nothing is overwritten and the old value survives -- so the only
    thing missing was the report.
    """

    RULE = "stripe-access-token"

    def test_the_plain_return_is_unchanged_when_no_detail_is_asked_for(self):
        self.assertEqual(self.vault.store("A", "one", rule=self.RULE), "A")
        self.assertEqual(self.vault.store("A", "two", rule=self.RULE), "A_2")

    def test_a_same_rule_clash_reports_the_name_that_still_holds_the_old_value(self):
        self.vault.store("A", "one", rule=self.RULE)
        self.assertEqual(self.vault.store("A", "two", rule=self.RULE, detail=True), ("A_2", "A"))

    def test_the_old_value_is_still_what_the_old_name_resolves_to(self):
        # The point of reporting rather than promoting: an existing $A must not change meaning
        # under anyone who already scripted against it.
        self.vault.store("A", "one", rule=self.RULE)
        self.vault.store("A", "two", rule=self.RULE)
        self.assertEqual(self.vault.get("A"), "one")
        self.assertEqual(self.vault.get("A_2"), "two")

    def test_a_first_capture_reports_nothing(self):
        self.assertEqual(self.vault.store("A", "one", rule=self.RULE, detail=True), ("A", ""))

    def test_the_same_value_again_is_not_a_rotation(self):
        self.vault.store("A", "one", rule=self.RULE)
        self.assertEqual(self.vault.store("A", "one", rule=self.RULE, detail=True), ("A", ""))

    def test_a_clash_with_a_different_kind_of_credential_is_not_a_rotation(self):
        # Two vendors' credentials can land on one env name -- GENERIC_API_KEY especially. That is
        # a name collision, and "did you rotate it?" is the wrong question to ask about it.
        self.vault.store("A", "one", rule="generic-api-key")
        self.assertEqual(self.vault.store("A", "two", rule=self.RULE, detail=True), ("A_2", ""))

    def test_a_clash_with_no_rule_recorded_either_side_is_not_a_rotation(self):
        # `clowk add` stores no rule, and an entry hand-written into the vault may have none.
        # With nothing to compare, claiming a rotation would be a guess.
        self.vault.store("A", "one")
        self.assertEqual(self.vault.store("A", "two", detail=True), ("A_2", ""))

    def test_a_second_rotation_still_points_at_the_plain_name(self):
        # A_2 is already taken, so this lands on A_3 -- but the name the user's code says, and the
        # one `clowk set` has to target, is still the plain one.
        self.vault.store("A", "one", rule=self.RULE)
        self.vault.store("A", "two", rule=self.RULE)
        self.assertEqual(self.vault.store("A", "three", rule=self.RULE, detail=True), ("A_3", "A"))


class TestUnreadableFile(VaultCase):
    """An existing-but-unparseable vault is not an empty vault.

    Treating the two the same made the next write overwrite every captured credential while
    reporting success. Refuse instead, the way install.py refuses an unparseable settings.json.
    """

    def write_raw(self, text):
        with open(self.vault.path(), "w") as f:
            f.write(text)

    def read_raw(self):
        with open(self.vault.path()) as f:
            return f.read()

    def test_an_unparseable_file_raises_instead_of_reading_as_empty(self):
        self.write_raw("{not json")
        with self.assertRaises(self.vault.VaultUnreadable):
            self.vault.names()

    def test_an_unparseable_file_is_never_overwritten(self):
        self.vault.store("KEEP_ME", "one")
        original = self.read_raw()
        self.write_raw(original + ",")  # the classic hand-edit slip
        with self.assertRaises(self.vault.VaultUnreadable):
            self.vault.store("NEW", "two")
        self.assertEqual(self.read_raw(), original + ",")

    def test_the_refusal_names_the_file_and_says_what_to_do(self):
        self.write_raw("{not json")
        with self.assertRaises(self.vault.VaultUnreadable) as caught:
            self.vault.names()
        self.assertIn(self.vault.path(), str(caught.exception))
        self.assertIn("fix or move the file", str(caught.exception))

    def test_a_json_value_that_is_not_an_object_raises(self):
        self.write_raw(json.dumps(["not", "a", "vault"]))
        with self.assertRaises(self.vault.VaultUnreadable):
            self.vault.names()

    def test_a_secrets_key_of_the_wrong_type_raises(self):
        self.write_raw(json.dumps({"version": 1, "secrets": []}))
        with self.assertRaises(self.vault.VaultUnreadable):
            self.vault.names()

    def test_undecodable_bytes_raise_rather_than_reading_as_empty(self):
        with open(self.vault.path(), "wb") as f:
            f.write(b"\xff\xfe{\x00\"a\x00")  # UTF-16-ish mangle from a bad copy
        with self.assertRaises(self.vault.VaultUnreadable):
            self.vault.names()

    def test_an_absent_file_is_an_empty_vault(self):
        self.assertFalse(os.path.exists(self.vault.path()))
        self.assertEqual(self.vault.names(), [])

    def test_a_blank_file_is_an_empty_vault(self):
        self.write_raw("   \n")
        self.assertEqual(self.vault.names(), [])
        self.assertEqual(self.vault.store("A", "one"), "A")

    def test_an_object_with_no_secrets_key_is_an_empty_vault(self):
        self.write_raw(json.dumps({"version": 1}))
        self.assertEqual(self.vault.names(), [])
        self.assertEqual(self.vault.store("A", "one"), "A")


class TestEncoding(VaultCase):
    def test_a_hand_edited_utf8_vault_reads_the_same_under_any_locale_codec(self):
        # clowk's own writes are pure ASCII, but the README invites you to read and edit this
        # file, and a source path can hold anything. Decoding it with the locale codec turned a
        # non-ASCII path into mojibake and then wrote the mojibake back.
        source = "/Users/José/proj"
        with open(self.vault.path(), "w", encoding="utf-8") as f:
            json.dump({"version": 1, "secrets": {
                "A": {"value": "one", "sources": [source], "uses": []}}}, f, ensure_ascii=False)
        with default_encoding("cp1252"):
            self.assertEqual(self.vault.names(), ["A"])
            self.assertEqual(self.vault.list_secrets()["A"]["sources"], [source])
            self.vault.record_use("A", "/p")
        self.assertEqual(self.vault.list_secrets()["A"]["sources"], [source])


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
