import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests import default_encoding

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.dir, "deny.json")
        from clowk import vault

        self.vault = importlib.reload(vault)
        from clowk import deny

        importlib.reload(deny)
        from clowk import cli

        self.cli = importlib.reload(cli)

    def tearDown(self):
        for key in ("CLOWK_VAULT", "CLOWK_DENY", "CLOWK_VALUE"):
            os.environ.pop(key, None)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = self.cli.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()

    def deny_config(self):
        with open(os.environ["CLOWK_DENY"], encoding="utf-8") as f:
            return json.load(f)

    def deny_bytes(self):
        with open(os.environ["CLOWK_DENY"], "rb") as f:
            return f.read()


class TestList(CliCase):
    def test_empty_vault_says_so(self):
        code, out, err = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("No credentials stored", out)

    def test_list_shows_names_and_never_values(self):
        self.vault.store("STRIPE_KEY", "sk_" "live_secretvalue", rule="stripe", confidence="high", source="/p")
        code, out, err = self.run_cli("list")
        self.assertIn("STRIPE_KEY", out)
        self.assertNotIn("sk_" "live_secretvalue", out)

    def test_low_confidence_entries_are_flagged(self):
        self.vault.store("A", "v", confidence="low")
        code, out, err = self.run_cli("list")
        self.assertIn("shape-only", out)


class TestAddAndSet(CliCase):
    def test_add_reads_the_value_from_the_environment_not_argv(self):
        os.environ["CLOWK_VALUE"] = "sk_" "live_typedbyhand"
        code, out, err = self.run_cli("add", "MY_KEY")
        self.assertEqual(code, 0)
        self.assertEqual(self.vault.get("MY_KEY"), "sk_" "live_typedbyhand")
        self.assertNotIn("sk_" "live_typedbyhand", out)

    def test_add_rejects_a_value_passed_as_an_argument(self):
        code, out, err = self.run_cli("add", "MY_KEY", "sk_" "live_oops")
        self.assertEqual(code, 1)
        self.assertIn("never pass the value", err.lower())
        self.assertEqual(self.vault.names(), [])

    def test_set_replaces_an_existing_value(self):
        self.vault.store("MY_KEY", "old")
        os.environ["CLOWK_VALUE"] = "new"
        code, out, err = self.run_cli("set", "MY_KEY")
        self.assertEqual(code, 0)
        self.assertEqual(self.vault.get("MY_KEY"), "new")
        self.assertEqual(self.vault.names(), ["MY_KEY"])

    def test_set_on_unknown_name_fails(self):
        os.environ["CLOWK_VALUE"] = "new"
        code, out, err = self.run_cli("set", "NOPE")
        self.assertEqual(code, 1)

    def test_empty_value_is_rejected(self):
        os.environ["CLOWK_VALUE"] = ""
        code, out, err = self.run_cli("add", "MY_KEY")
        self.assertEqual(code, 1)


class TestLifecycle(CliCase):
    def test_clear_and_rename(self):
        self.vault.store("A", "one")
        self.assertEqual(self.run_cli("rename", "A", "B")[0], 0)
        self.assertEqual(self.vault.get("B"), "one")
        self.assertEqual(self.run_cli("clear", "B")[0], 0)
        self.assertEqual(self.vault.names(), [])

    def test_clear_unknown_returns_one(self):
        self.assertEqual(self.run_cli("clear", "NOPE")[0], 1)

    def test_uses_reports_recorded_paths(self):
        self.vault.store("A", "one", source="/p")
        self.vault.record_use("A", "/q")
        code, out, err = self.run_cli("uses", "A")
        self.assertIn("/q", out)

    def test_uses_with_no_name_lists_all(self):
        self.vault.store("A", "one", source="/p")
        code, out, err = self.run_cli("uses")
        self.assertIn("A", out)


class TestAllow(CliCase):
    def test_allow_writes_the_pattern_into_the_deny_config(self):
        code, out, err = self.run_cli("allow", "git credential fill")
        self.assertEqual(code, 0)
        cfg = self.deny_config()
        self.assertIn("git credential fill", cfg["allow"])

    def test_allow_is_idempotent(self):
        self.run_cli("allow", ".env")
        self.run_cli("allow", ".env")
        cfg = self.deny_config()
        self.assertEqual(cfg["allow"].count(".env"), 1)

    def test_allow_also_drops_a_user_added_deny_rule(self):
        with open(os.environ["CLOWK_DENY"], "w") as f:
            json.dump({"deny_paths": ["secrets.txt"], "deny_commands": ["vault read"]}, f)
        self.assertEqual(self.run_cli("allow", "secrets.txt")[0], 0)
        from clowk import deny

        self.assertIsNone(deny.check("Read", {"file_path": "/proj/secrets.txt"}))
        self.assertEqual(self.deny_config()["deny_paths"], [])
        self.assertEqual(self.deny_config()["deny_commands"], ["vault read"])


class TestAllowEncoding(CliCase):
    """The deny config is UTF-8, whatever the locale codec is.

    Reading it with the locale codec made a non-ASCII pattern raise UnicodeDecodeError, which is a
    ValueError -- so `allow` fell through to "no config at all" and overwrote the user's whole
    hand-written deny list while printing success.
    """

    def write_deny_bytes(self, raw):
        with open(os.environ["CLOWK_DENY"], "wb") as f:
            f.write(raw)

    def test_a_non_ascii_deny_rule_survives_allow(self):
        self.write_deny_bytes(json.dumps(
            {"allow": [".env"], "deny_paths": ["secrets-Łukasz.txt"], "deny_commands": ["vault read"]},
            ensure_ascii=False).encode("utf-8"))
        with default_encoding("cp1252"):
            code, out, err = self.run_cli("allow", "id_rsa")
        self.assertEqual((code, err), (0, ""))
        cfg = self.deny_config()
        self.assertEqual(cfg["deny_paths"], ["secrets-Łukasz.txt"])
        self.assertEqual(cfg["deny_commands"], ["vault read"])
        self.assertEqual(sorted(cfg["allow"]), [".env", "id_rsa"])

    def test_a_deny_config_that_is_not_utf8_is_refused_not_discarded(self):
        raw = json.dumps({"deny_paths": ["café.txt"]}, ensure_ascii=False).encode("cp1252")
        self.write_deny_bytes(raw)
        code, out, err = self.run_cli("allow", "id_rsa")
        self.assertEqual(code, 1)
        self.assertIn("UTF-8", err)
        self.assertEqual(self.deny_bytes(), raw)


class TestOutputEncoding(CliCase):
    """The CLI's own output is UTF-8, whatever the console codec is.

    Sources are the session's cwd, so one accented character in a project path is enough. On a
    strict non-UTF-8 stdout -- a real installed latin-1 locale, or any redirected stdout on
    Windows, which is what `/clowk` gets since the command body pipes the CLI -- writing that path
    raised UnicodeEncodeError mid-enumeration: exit 1, a raw traceback, and every credential
    sorting after the offending one silently missing from `clowk list`.

    This has to run the real script: the bug lives in the stream sys.stdout is, and no in-process
    StringIO can see it.
    """

    # ě is C4 8B in UTF-8 and has no cp1252 encoding at all.
    SOURCE = "/home/u/projekty/Zdeněk-app"

    def setUp(self):
        CliCase.setUp(self)
        self.vault.store("AAA_TOKEN", "v1", source=self.SOURCE)
        self.vault.store("ZZZ_TOKEN", "v2", source="/proj")

    def run_script(self, *argv):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "cp1252"
        env.pop("PYTHONUTF8", None)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(REPO_ROOT, "clowk", "cli.py")] + list(argv),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        out, err = proc.communicate(timeout=60)
        return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def assertWholeListing(self, *argv):
        code, out, err = self.run_script(*argv)
        self.assertNotIn("Traceback", err)
        self.assertEqual(code, 0, "stderr: " + err)
        self.assertIn(self.SOURCE, out)
        # The crash was in the middle of the loop, so this is the assertion that catches a
        # truncated listing rather than only a missing last line.
        self.assertIn("ZZZ_TOKEN", out)
        return out

    def test_list_survives_a_non_ascii_source_on_a_cp1252_stdout(self):
        self.assertWholeListing("list")

    def test_uses_survives_a_non_ascii_source_on_a_cp1252_stdout(self):
        self.assertWholeListing("uses")

    def test_the_switch_is_skipped_on_a_stream_that_cannot_be_reconfigured(self):
        # Tests inject StringIO, and a test runner may have replaced sys.stdout with its own
        # capture object. Neither may raise, and neither may be silently mangled.
        plain = io.StringIO()
        self.cli._use_utf8(plain, None)
        plain.write("ě")
        self.assertEqual(plain.getvalue(), "ě")

    def test_a_cp1252_stream_is_switched_to_utf8(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        self.cli._use_utf8(stream)
        self.assertEqual(stream.encoding.replace("-", "").lower(), "utf8")
        stream.write("ě")


class TestUsage(CliCase):
    def test_no_args_prints_usage_and_returns_one(self):
        code, out, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("clowk", out + err)

    def test_unknown_command_returns_one(self):
        self.assertEqual(self.run_cli("frobnicate")[0], 1)


if __name__ == "__main__":
    unittest.main()
