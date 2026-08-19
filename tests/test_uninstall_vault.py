"""Uninstall must not be quiet about the vault, in either direction.

Before this, `clowk uninstall` removed hooks, the launcher, /clowk and the skill, and said nothing
at all about ~/.clowk/vault.json. That silence reads two opposite ways and both are harmful: someone
clearing a machine keeps a plaintext file of live credentials they believe is gone, and someone who
wanted to keep their credentials has no idea whether they still exist. The vault is the only copy of
every value in it.

So: it is always mentioned, deletion always needs a typed word rather than a keystroke, a backup is
always on offer, and with no terminal to ask it keeps the vault and prints the flags.
"""
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import cli, vault


class FakeTTY(io.StringIO):
    """StringIO that claims to be a terminal, so the interactive branch is reachable in tests."""

    def isatty(self):
        return True


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.vault_path = os.path.join(self.dir, "vault.json")
        self._previous = os.environ.get("CLOWK_VAULT")
        os.environ["CLOWK_VAULT"] = self.vault_path
        self.addCleanup(self._restore)
        self.out = io.StringIO()
        self.err = io.StringIO()

    def _restore(self):
        if self._previous is None:
            os.environ.pop("CLOWK_VAULT", None)
        else:
            os.environ["CLOWK_VAULT"] = self._previous

    def seed(self, count=2):
        for i in range(count):
            vault.store("KEY_%d" % i, "sk_" + "live_" + "value%dABCDEFGHIJKLMNOP" % i,
                        rule="stripe", confidence="high", source="/repo")

    def notice(self, argv=(), stdin=None):
        return cli._vault_notice(self.out, self.err, tuple(argv), stdin or io.StringIO())


class TestItAlwaysSaysTheVaultIsStillThere(VaultCase):
    def test_the_count_and_the_path_are_both_named(self):
        self.seed(3)
        self.notice(["--keep-vault"])
        body = self.out.getvalue()
        self.assertIn("3 credentials", body)
        self.assertIn(self.vault_path, body)

    def test_it_says_removing_clowk_does_not_remove_the_file(self):
        self.seed(1)
        self.notice(["--keep-vault"])
        self.assertIn("does not remove that file", self.out.getvalue())

    def test_one_credential_is_not_described_as_credentials(self):
        self.seed(1)
        self.notice(["--keep-vault"])
        self.assertIn("1 credential,", self.out.getvalue())

    def test_an_empty_vault_says_so_and_asks_nothing(self):
        code = self.notice([])
        self.assertEqual(code, 0)
        self.assertIn("holds nothing", self.out.getvalue())


class TestWithNoTerminalItKeepsTheVault(VaultCase):
    """The dangerous default would be deleting. Keeping is recoverable; deleting is not."""

    def test_it_keeps_and_prints_the_three_flags(self):
        self.seed()
        code = self.notice([])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(self.vault_path), "the vault was removed without being asked")
        body = self.out.getvalue()
        for flag in ("--backup", "--purge", "--keep-vault"):
            self.assertIn(flag, body)


class TestBackup(VaultCase):
    def test_it_writes_every_value_at_mode_0600(self):
        self.seed(2)
        target = os.path.join(self.dir, "backup.txt")
        self.notice(["--backup", target, "--keep-vault"])
        self.assertTrue(os.path.isfile(target))
        body = open(target, encoding="utf-8").read()
        self.assertEqual(body.count("VALUE:"), 2)
        for name in vault.names():
            self.assertIn(name, body)
        if os.name != "nt":
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600,
                             "a file of live credentials was left readable by others")

    def test_it_warns_that_the_backup_is_unprotected_plaintext(self):
        self.seed(1)
        self.notice(["--backup", os.path.join(self.dir, "b.txt"), "--keep-vault"])
        body = self.out.getvalue()
        self.assertIn("in the clear", body)
        self.assertIn("deny hook", body)

    def test_backing_up_does_not_delete_anything_by_itself(self):
        self.seed(2)
        self.notice(["--backup", os.path.join(self.dir, "b.txt"), "--keep-vault"])
        self.assertTrue(os.path.isfile(self.vault_path))
        self.assertEqual(vault.count(), 2)

    def test_a_backup_that_cannot_be_written_leaves_the_vault_alone(self):
        self.seed(1)
        # a directory where a file must go
        blocked = os.path.join(self.dir, "adir")
        os.makedirs(blocked)
        code = self.notice(["--backup", blocked, "--purge"])
        self.assertEqual(code, 1)
        self.assertTrue(os.path.isfile(self.vault_path),
                        "the vault was purged even though the backup failed")


class TestPurge(VaultCase):
    def test_the_explicit_flag_deletes_without_prompting(self):
        self.seed(2)
        code = self.notice(["--purge"])
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.vault_path))
        self.assertIn("Deleted", self.out.getvalue())


class TestTheInteractiveConfirmation(VaultCase):
    def test_deleting_requires_the_word_typed_exactly(self):
        self.seed(2)
        # choose delete, then type the wrong thing, then keep
        self.notice([], FakeTTY("d\nyes\nk\n"))
        self.assertTrue(os.path.isfile(self.vault_path),
                        "a y/n style answer was enough to destroy the vault")
        self.assertIn("Not deleted", self.out.getvalue())

    def test_typing_the_word_does_delete(self):
        self.seed(2)
        self.notice([], FakeTTY("d\nDELETE\n"))
        self.assertFalse(os.path.exists(self.vault_path))

    def test_the_word_is_case_sensitive(self):
        self.seed(1)
        self.notice([], FakeTTY("d\ndelete\nk\n"))
        self.assertTrue(os.path.isfile(self.vault_path))

    def test_the_empty_answer_keeps(self):
        self.seed(1)
        self.notice([], FakeTTY("\n"))
        self.assertTrue(os.path.isfile(self.vault_path))
        self.assertIn("Kept", self.out.getvalue())

    def test_backup_then_delete_in_one_session(self):
        self.seed(2)
        target = os.path.join(self.dir, "typed-backup.txt")
        self.notice([], FakeTTY("b\n%s\nd\nDELETE\n" % target))
        self.assertTrue(os.path.isfile(target), "the backup was not written")
        self.assertEqual(open(target, encoding="utf-8").read().count("VALUE:"), 2)
        self.assertFalse(os.path.exists(self.vault_path))

    def test_an_unrecognised_answer_reprompts_rather_than_guessing(self):
        self.seed(1)
        self.notice([], FakeTTY("wat\nk\n"))
        self.assertIn("Not one of", self.out.getvalue())
        self.assertTrue(os.path.isfile(self.vault_path))


class TestTheExportIsRestorable(VaultCase):
    def test_it_tells_you_how_to_put_the_values_back(self):
        self.seed(1)
        text = vault.export_text()
        self.assertIn("clowk add", text, "an export with no restore instructions is a puzzle")

    def test_an_empty_vault_exports_nothing_rather_than_an_empty_file(self):
        self.assertIsNone(vault.export_text())
        self.assertIsNone(vault.write_export(os.path.join(self.dir, "nope.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "nope.txt")))


if __name__ == "__main__":
    unittest.main()
