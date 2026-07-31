import importlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock


class DenyCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "vault.json")
        os.environ["CLOWK_DENY"] = os.path.join(self.dir, "deny.json")
        from clowk import vault

        importlib.reload(vault)
        from clowk import deny

        self.deny = importlib.reload(deny)

    def tearDown(self):
        os.environ.pop("CLOWK_VAULT", None)
        os.environ.pop("CLOWK_DENY", None)


class TestPaths(DenyCase):
    def test_reading_a_dotenv_is_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/proj/.env"}))

    def test_dotenv_example_is_allowed(self):
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.example"}))
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.sample"}))
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/.env.template"}))

    def test_private_keys_are_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/home/me/.ssh/id_rsa"}))
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/certs/server.pem"}))

    def test_ssh_public_keys_are_allowed(self):
        # `id_rsa` matches `id_rsa.pub` through the `pattern + "."` branch that exists for
        # `.env.local`-style variants. A .pub is publishable by definition -- and the escape the
        # deny message offered (`clowk allow 'id_rsa'`) also stopped denying the private key.
        for name in ("id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub"):
            path = "/home/me/.ssh/" + name
            self.assertIsNone(self.deny.check("Read", {"file_path": path}), name)
            self.assertIsNone(self.deny.check("Bash", {"command": "ssh-keygen -lf " + path}), name)

    def test_private_key_copies_and_backups_stay_denied(self):
        # The same prefix branch is what catches these, so allowing .pub must not disarm it.
        for name in ("id_rsa.bak", "id_rsa.old", "id_ed25519.backup", ".env.local"):
            self.assertIsNotNone(self.deny.check("Read", {"file_path": "/home/me/" + name}), name)

    def test_the_vault_itself_is_denied(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": self.deny.vault.path()}))

    def test_the_vault_directory_stays_protected_whatever_a_file_is_called(self):
        # The allow-suffix exemption used to run before the store check, so a `vault.json.md` or
        # an `x.example` inside ~/.clowk was readable -- and now that .pub is exempt too, that
        # ordering would have widened the hole rather than left it where it was.
        for name in ("vault.json.md", "vault.json.pub", "x.example"):
            path = os.path.join(self.dir, name)
            self.assertIsNotNone(self.deny.check("Read", {"file_path": path}), name)

    def test_an_ordinary_source_file_is_allowed(self):
        self.assertIsNone(self.deny.check("Read", {"file_path": "/proj/src/main.py"}))


class TestCommands(DenyCase):
    def test_git_credential_fill_is_denied(self):
        reason = self.deny.check("Bash", {"command": "git credential fill"})
        self.assertIsNotNone(reason)

    def test_keychain_lookup_is_denied(self):
        self.assertIsNotNone(self.deny.check("Bash", {"command": "security find-generic-password -s x -w"}))
        self.assertIsNotNone(self.deny.check("Bash", {"command": "secret-tool lookup service x"}))

    def test_cat_of_the_vault_is_denied(self):
        self.assertIsNotNone(self.deny.check("Bash", {"command": "cat " + self.deny.vault.path()}))

    def test_an_ordinary_command_is_allowed(self):
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))

    def test_reason_explains_how_to_allow_it(self):
        reason = self.deny.check("Bash", {"command": "git credential fill"})
        self.assertIn("clowk allow", reason)


class TestPlatformSeparators(DenyCase):
    """os.sep is "\\" on Windows and os.altsep is "/". Both spell a path there."""

    def windows_separators(self):
        return mock.patch.object(os, "sep", "\\"), mock.patch.object(os, "altsep", "/")

    def test_forward_slash_paths_are_checked_when_the_platform_separator_is_backslash(self):
        # cmd, PowerShell and Git Bash all accept forward slashes, so `type C:/repo/.env` is the
        # ordinary way a model writes a Windows path -- not obfuscation. It matched neither
        # startswith(("/", "~", ".")) nor `os.sep in stripped`, so the token was never handed to
        # the path matcher, which resolves it correctly once it gets it.
        sep, altsep = self.windows_separators()
        with sep, altsep:
            for command in ("type C:/repo/.env", "more C:/certs/server.pem",
                            "cat C:/Users/me/.ssh/id_rsa", "type repo/.env"):
                self.assertIsNotNone(self.deny.check("Bash", {"command": command}), command)

    def test_an_ordinary_windows_command_is_still_allowed(self):
        sep, altsep = self.windows_separators()
        with sep, altsep:
            for command in ("git status", "dir /s", "type C:/repo/main.py"):
                self.assertIsNone(self.deny.check("Bash", {"command": command}), command)

    def test_forward_slash_paths_are_checked_on_every_platform(self):
        # Was asserting os.altsep is None, which tests CPython's platform constant rather than
        # clowk, and is simply false on Windows where altsep is "/". What actually matters is that
        # a forward-slash path is matched wherever the suite runs -- Windows accepts / as a
        # separator, so an agent writing cat /repo/.env there must still be denied.
        self.assertIsNotNone(self.deny.check("Bash", {"command": "cat /repo/.env"}))
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))


class TestUserConfig(DenyCase):
    def test_user_can_remove_a_default_rule(self):
        with open(self.deny.config_path(), "w") as f:
            json.dump({"allow": ["git credential fill"]}, f)
        self.assertIsNone(self.deny.check("Bash", {"command": "git credential fill"}))

    def test_user_can_add_a_command_rule(self):
        with open(self.deny.config_path(), "w") as f:
            json.dump({"deny_commands": ["vault kv get"]}, f)
        self.assertIsNotNone(self.deny.check("Bash", {"command": "vault kv get secret/x"}))

    def test_corrupt_config_falls_back_to_defaults(self):
        with open(self.deny.config_path(), "w") as f:
            f.write("{not json")
        self.assertIsNotNone(self.deny.check("Bash", {"command": "git credential fill"}))

    def test_a_wrongly_typed_config_value_is_ignored_not_iterated(self):
        # deny.json is hand-edited, so a bare string or number where a list belongs is likely.
        # It must not raise (the host fails open) and must not become one rule per character.
        with open(self.deny.config_path(), "w") as f:
            json.dump({"allow": 5, "deny_commands": "ls"}, f)
        self.assertIsNone(self.deny.check("Bash", {"command": "git status"}))
        self.assertIsNotNone(self.deny.check("Bash", {"command": "git credential fill"}))


class TestHook(DenyCase):
    def run_hook(self, payload, host="claude-code"):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        code = hook.main(["--host", host], io.StringIO(json.dumps(payload)), out, err)
        return code, out.getvalue(), err.getvalue()

    def test_allowed_call_is_silent(self):
        code, out, err = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_denied_call_emits_a_deny_decision(self):
        code, out, err = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "git credential fill"}})
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("clowk allow", decision["permissionDecisionReason"])

    def test_exit_two_hosts_deny_on_stderr(self):
        # This hook is registered on Codex and Gemini CLI too, and there a deny is exit 2 with the
        # reason on stderr. Claude Code's decision JSON plus exit 0 reads as an allow on both.
        for host in ("codex", "gemini-cli"):
            code, out, err = self.run_hook(
                {"tool_name": "Bash", "tool_input": {"command": "git credential fill"}}, host)
            self.assertEqual((host, code, out), (host, 2, ""))
            self.assertIn("clowk allow", err)

    def test_a_hook_registered_without_a_host_flag_still_denies(self):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        payload = {"tool_name": "Bash", "tool_input": {"command": "git credential fill"}}
        code = hook.main([], io.StringIO(json.dumps(payload)), out, err)
        self.assertEqual(code, 0)
        decision = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")

    def test_a_non_utf8_locale_does_not_disable_the_hook(self):
        # Hosts send UTF-8 JSON (Node's JSON.stringify does not escape non-ASCII), but sys.stdin
        # decodes with the locale codec. On a cp1252 box one accented character anywhere in the
        # payload -- `cwd` rides along on every tool call, and this hook never even reads it --
        # raised UnicodeDecodeError, which subclasses ValueError and so was indistinguishable
        # from malformed JSON: exit 0, no deny, every tool call of the session allowed.
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        payload = {"tool_name": "Read", "tool_input": {"file_path": self.deny.vault.path()},
                   "cwd": "C:\\Users\\\u0141ukasz\\proj"}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="cp1252")
        out, err = io.StringIO(), io.StringIO()
        code = hook.main(["--host", "claude-code"], stdin, out, err)
        self.assertEqual(code, 0)
        decision = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")

    def test_unparseable_input_is_silent(self):
        from clowk import hook_pretool

        hook = importlib.reload(hook_pretool)
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(hook.main(["--host", "claude-code"], io.StringIO("{nope"), out, err), 0)


class TestAPhraseCountsOnlyAtACommandHead(DenyCase):
    """Mentioning a credential-printing command is not running it.

    Matching the phrase anywhere in the text denied any command that merely contained it -- a README
    edit describing the rule, a commit message, a grep. That blocked the commit introducing this
    fix, which is the sixth time this hook stopped its own author mid-sentence.
    """

    FILL = "git credential" + " fill"

    def denied(self, command):
        return self.deny.check("Bash", {"command": command}) is not None

    def test_running_it_is_denied_wherever_in_the_pipeline(self):
        for command in (self.FILL, "%s -v" % self.FILL, "ls; %s" % self.FILL,
                        "%s | grep password" % self.FILL):
            self.assertTrue(self.denied(command), "an invocation was allowed: %r" % command)

    def test_talking_about_it_is_allowed(self):
        for command in ("git commit -m 'block %s'" % self.FILL,
                        "echo the hook denies %s now" % self.FILL,
                        "grep -n '%s' README.md" % self.FILL):
            self.assertFalse(self.denied(command), "a mention was denied: %r" % command)


class TestAPathIsOnlyAReadWhenSomethingReadsIt(DenyCase):
    """Naming a path is not opening it.

    Denying any command that mentions a protected path blocked five of this tool's own author's
    commands, including the commit that introduced the fix -- a commit message, an echo of
    documentation, a grep pattern. So a path in a Bash command counts as a read only when a reader
    is the head of its pipeline segment.

    The Read tool's structured file_path is unaffected and stays strict: that is the reliable half,
    and it is the one an agent actually uses to read a file.
    """

    DOT_ENV = "." + "env"

    def denied(self, command):
        return self.deny.check("Bash", {"command": command}) is not None

    def test_a_reader_opening_a_protected_path_is_denied(self):
        vault_file = self.deny.vault.path()
        for command in ("cat %s" % vault_file,
                        "head -5 %s" % vault_file,
                        "python3 %s" % vault_file,
                        "grep secret %s" % vault_file,
                        "base64 %s" % vault_file,
                        "ls; cat %s" % vault_file,
                        "cat %s" % self.DOT_ENV,
                        "cat ~/.ssh/id_ed25519"):
            self.assertTrue(self.denied(command), "a read was allowed: %r" % command)

    def test_merely_naming_the_path_is_allowed(self):
        vault_file = self.deny.vault.path()
        for command in ("git commit -m 'state lives in %s now'" % vault_file,
                        "echo the file is %s" % vault_file,
                        "git add %s" % vault_file,
                        "ls -l %s" % vault_file):
            self.assertFalse(self.denied(command), "a mention was denied: %r" % command)

    def test_the_read_tool_stays_strict(self):
        self.assertIsNotNone(self.deny.check("Read", {"file_path": self.deny.vault.path()}))
        self.assertIsNotNone(self.deny.check("Read", {"file_path": "/proj/" + self.DOT_ENV}))


class TestPunctuationAroundPaths(DenyCase):
    """A path written in prose or shell punctuation still has to be recognised as that path.

    Found when this hook denied a command whose only offence was writing about the example env
    file in a sentence: the trailing full stop made the token end in ".", so its basename no longer
    ended in ".example", the allow-suffix check missed, and the deny fired.

    The filenames are assembled from parts so that this test file, and any command that reads it,
    is not itself a deny trigger.
    """

    DOT_ENV = "." + "env"

    def denied(self, command):
        return self.deny.check("Bash", {"command": command}) is not None

    def test_a_trailing_sentence_period_does_not_defeat_an_allowed_suffix(self):
        self.assertFalse(self.denied("echo see %s%s. it is safe" % (self.DOT_ENV, ".example")))

    def test_surrounding_punctuation_does_not_hide_a_denied_path(self):
        # Every wrapper here has a real file reader at its head. The originals used `read` and
        # `look at` as filler verbs, which stopped counting once a path only reads when a reader is
        # running it -- `read` is a shell builtin that takes stdin, not a filename, so treating it
        # as one would have been the wrong fix.
        for wrapper in ("cat %s;", "head (%s)", "grep x %s.", 'base64 "%s",', "wc -l [%s]"):
            command = wrapper % self.DOT_ENV
            self.assertTrue(self.denied(command),
                            "punctuation hid a denied path: %r" % command)

    def test_a_leading_dot_is_still_meaningful(self):
        # Trailing dots are stripped, leading ones are not: stripping a leading dot would turn the
        # env filename into "env" and lose the match entirely.
        self.assertTrue(self.denied("cat %s" % self.DOT_ENV))


if __name__ == "__main__":
    unittest.main()
