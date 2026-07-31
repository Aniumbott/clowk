"""End-to-end integration tests.

The per-module tests cover each unit in isolation. This file exercises whole flows -- prompt
hook -> vault -> CLI, and install -> uninstall -> back to the original file -- so a wiring bug
between two individually green units cannot ship.

Every test gets its own temp CLOWK_VAULT and CLOWK_DENY, and the clipboard is pointed at a
binary that cannot exist, so no test can reach a developer's real clipboard.

The load-bearing assertion, repeated for all three hosts: a captured credential's raw value
appears in NEITHER stdout NOR stderr. Nothing else in clowk matters if that one is false.

These tests never register hooks through the CLI. cmd_install takes no path override, so it
would rewrite the developer's real ~/.claude/settings.json; install.install() is called
directly instead, always with an explicit temp path.
"""
import io
import json
import os
import shutil
import tempfile
import unittest

from clowk import cli, clip, deny, hook_pretool, hook_prompt, install, vault

# Fake credentials, in the shapes the vendored rules recognise. None of these is live.
#
# Some are written as two adjacent literals ("sk_" "live_...") which Python joins at parse time.
# The value a test sees is unchanged; only the source text differs, and that is deliberate --
# written contiguously, GitHub push protection blocks every push of this repo, including from a
# fork. Please keep the split when editing, and split any new fixture a scanner flags the same way.
STRIPE = "sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_ROTATED = "sk_" "live_51H8xQ2LmNpQrStUvWxYz0123"
GITHUB = "ghp" "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SLACK = "xoxb" "-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

# host -> the exit code a block uses on that host
BLOCK_CODE = {"claude-code": 0, "codex": 2, "gemini-cli": 2}
ALL_HOSTS = ("claude-code", "codex", "gemini-cli")


def read_text(path):
    with open(path) as f:
        return f.read()


def files_containing(root, needle):
    """Every file under root whose bytes contain needle, sorted.

    Bytes, not text: this asks "is the value on disk anywhere", so an unreadable or
    non-UTF-8 file must still be searched rather than skipped.
    """
    blob = needle.encode("utf-8")
    hits = []
    for base, _dirs, names in os.walk(root):
        for name in names:
            found = os.path.join(base, name)
            try:
                with open(found, "rb") as f:
                    if blob in f.read():
                        hits.append(found)
            except (IOError, OSError):
                pass
    return sorted(hits)


class IntegrationCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="clowk-integration-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.settings = os.path.join(self.dir, "settings.json")
        env = (
            ("CLOWK_VAULT", os.path.join(self.dir, "vault.json")),
            ("CLOWK_DENY", os.path.join(self.dir, "deny.json")),
        )
        for key, value in env:
            os.environ[key] = value
        for key in ("CLOWK_VAULT", "CLOWK_DENY", "CLOWK_VALUE"):
            self.addCleanup(os.environ.pop, key, None)
        candidates = clip.CANDIDATES
        clip.CANDIDATES = [["clowk-no-such-clipboard-binary"]]
        self.addCleanup(setattr, clip, "CANDIDATES", candidates)

    # -- drivers ---------------------------------------------------------------

    def prompt_hook(self, payload, host="claude-code"):
        """Run the pre-transmit hook. `payload` is a dict, or raw text for malformed input."""
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        out, err = io.StringIO(), io.StringIO()
        code = hook_prompt.main(["--host", host], io.StringIO(raw), out, err)
        return code, out.getvalue(), err.getvalue()

    def tool_hook(self, payload, host="claude-code"):
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        out, err = io.StringIO(), io.StringIO()
        code = hook_pretool.main(["--host", host], io.StringIO(raw), out, err)
        return code, out.getvalue(), err.getvalue()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()

    # -- assertions ------------------------------------------------------------

    def block_reason(self, host, out, err):
        """The block text, from wherever this host carries it."""
        if host == "claude-code":
            decision = json.loads(out)
            self.assertEqual(decision["decision"], "block")
            return decision["reason"]
        return err

    def deny_reason(self, host, out, err):
        """The tool-deny text, from wherever this host carries it."""
        if host == "claude-code":
            decision = json.loads(out)["hookSpecificOutput"]
            self.assertEqual(decision["permissionDecision"], "deny")
            return decision["permissionDecisionReason"]
        return err

    def assertNoTrace(self, secret, *streams):
        """The value, and any substantial tail of it, must be absent from every stream."""
        blob = "".join(streams)
        self.assertNotIn(secret, blob)
        self.assertNotIn(secret[len(secret) // 2:], blob)


class TestFullCaptureCycle(IntegrationCase):
    """Paste a credential -> it is filed, the turn is blocked, the value never surfaces."""

    def _cycle(self, host):
        code, out, err = self.prompt_hook(
            {"prompt": "deploy with " + STRIPE + " tonight", "cwd": "/proj"}, host)
        self.assertEqual(code, BLOCK_CODE[host])

        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE)

        reason = self.block_reason(host, out, err)
        self.assertIn("deploy with $STRIPE_SECRET_KEY tonight", reason)
        self.assertIn("unclowk", reason)
        self.assertNoTrace(STRIPE, out, err)

    def test_claude_code_blocks_on_stdout_and_never_prints_the_value(self):
        self._cycle("claude-code")
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"}, "claude-code")
        self.assertEqual(err, "")  # the decision is stdout JSON; stderr must stay clean

    def test_codex_blocks_on_stderr_and_never_prints_the_value(self):
        self._cycle("codex")
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"}, "codex")
        self.assertEqual(out, "")  # exit-2 hosts read stderr; stdout must stay clean

    def test_gemini_cli_blocks_on_stderr_and_never_prints_the_value(self):
        self._cycle("gemini-cli")
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"}, "gemini-cli")
        self.assertEqual(out, "")

    def test_a_clean_prompt_passes_through_on_every_host(self):
        for host in ALL_HOSTS:
            code, out, err = self.prompt_hook({"prompt": "refactor clowk/cli.py", "cwd": "/p"}, host)
            self.assertEqual((host, code, out, err), (host, 0, "", ""))
        self.assertEqual(vault.names(), [])

    def test_the_bypass_transmits_and_stores_nothing_on_every_host(self):
        for host in ALL_HOSTS:
            code, out, err = self.prompt_hook({"prompt": "unclowk send " + STRIPE, "cwd": "/p"}, host)
            self.assertEqual((host, code, out, err), (host, 0, "", ""))
        self.assertEqual(vault.names(), [])


class TestClipboardHandoff(IntegrationCase):
    def test_the_clipboard_gets_the_rewrite_and_not_the_secret(self):
        captured = []
        original = clip.copy
        clip.copy = lambda text: captured.append(text) or True
        self.addCleanup(setattr, clip, "copy", original)

        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE + " now", "cwd": "/p"})
        self.assertEqual(len(captured), 1)
        # The rewrite, then the skill pointer. The pointer belongs in the pasted text rather than
        # only in the block reason: a blocked turn transmits nothing, so the reason never reaches
        # the model and the pointer there explained $NAME to nobody. This payload carries no
        # session_id, so the pointer is present every time -- see TestPointerOncePerSession.
        self.assertTrue(captured[0].startswith("use $STRIPE_SECRET_KEY now"))
        self.assertIn("[assistant:", captured[0])
        self.assertNotIn(STRIPE, captured[0])
        self.assertIn("already on your clipboard", self.block_reason("claude-code", out, err))

    def test_a_missing_clipboard_tool_still_blocks_and_still_prints_the_rewrite(self):
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE + " now", "cwd": "/p"})
        reason = self.block_reason("claude-code", out, err)
        self.assertIn("use $STRIPE_SECRET_KEY now", reason)
        self.assertNotIn("already on your clipboard", reason)


class TestCaptureThenCli(IntegrationCase):
    def setUp(self):
        IntegrationCase.setUp(self)
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj/alpha"})

    def test_list_shows_the_name_and_never_the_value(self):
        code, out, err = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("$STRIPE_SECRET_KEY", out)
        self.assertNoTrace(STRIPE, out, err)

    def test_list_flags_a_shape_only_match_so_it_can_be_purged(self):
        # The stripe rule has no trailing-separator literal prefix, so it is tiered "low".
        code, out, err = self.run_cli("list")
        self.assertIn("shape-only", out)

    def test_uses_reports_the_source_directory(self):
        code, out, err = self.run_cli("uses", "STRIPE_SECRET_KEY")
        self.assertEqual(code, 0)
        self.assertIn("/proj/alpha", out)
        self.assertNoTrace(STRIPE, out, err)

    def test_no_cli_command_in_the_whole_lifecycle_prints_the_value(self):
        transcript = ""
        for argv in (["list"], ["uses"], ["uses", "STRIPE_SECRET_KEY"], ["help"],
                     ["rename", "STRIPE_SECRET_KEY", "PROD_STRIPE"], ["uses", "PROD_STRIPE"],
                     ["list"], ["clear", "PROD_STRIPE"], ["list"]):
            code, out, err = self.run_cli(*argv)
            transcript += out + err
        self.assertNoTrace(STRIPE, transcript)
        self.assertIn("No credentials stored", transcript)


class TestCaptureThenRotate(IntegrationCase):
    def test_set_replaces_the_value_and_keeps_the_ledger(self):
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj/alpha"})
        before = vault.list_secrets()["STRIPE_SECRET_KEY"]

        os.environ["CLOWK_VALUE"] = STRIPE_ROTATED
        code, out, err = self.run_cli("set", "STRIPE_SECRET_KEY")
        self.assertEqual(code, 0)

        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE_ROTATED)
        after = vault.list_secrets()["STRIPE_SECRET_KEY"]
        # Rotating a value must not erase the history that tells you what the rotation touches.
        self.assertEqual(after["first_caught"], before["first_caught"])
        self.assertEqual(after["sources"], before["sources"])
        self.assertEqual(after["rule"], before["rule"])
        self.assertNoTrace(STRIPE, out, err)
        self.assertNoTrace(STRIPE_ROTATED, out, err)

    def test_set_on_a_name_that_was_never_captured_fails_and_stores_nothing(self):
        os.environ["CLOWK_VALUE"] = STRIPE_ROTATED
        code, out, err = self.run_cli("set", "NEVER_SEEN")
        self.assertEqual(code, 1)
        self.assertEqual(vault.names(), [])

    def test_the_rotated_value_is_the_one_the_deny_hook_still_protects(self):
        # The deny hook guards a directory, not a value, so "the rotated value is protected"
        # only holds if the vault file is the value's sole home on disk. Nest the vault so the
        # walk below can see a stray copy written OUTSIDE the protected directory -- rooted at
        # the vault's own directory it could not.
        os.environ["CLOWK_VAULT"] = os.path.join(self.dir, "store", "vault.json")
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"})
        os.environ["CLOWK_VALUE"] = STRIPE_ROTATED
        code, out, err = self.run_cli("set", "STRIPE_SECRET_KEY")
        self.assertEqual(code, 0)
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE_ROTATED)
        self.assertNoTrace(STRIPE_ROTATED, out, err)

        # Every on-disk holder of the rotated value is the vault file itself, so the deny
        # hook's directory guard covers all of them -- no sibling copy, no leftover .tmp.
        self.assertEqual(files_containing(self.dir, STRIPE_ROTATED), [vault.path()])
        # And the superseded value is not still lying around next to it.
        self.assertEqual(files_containing(self.dir, STRIPE), [])

        code, out, err = self.tool_hook(
            {"tool_name": "Read", "tool_input": {"file_path": vault.path()}})
        self.assertEqual(code, 0)  # a deny is expressed in stdout JSON, not in the exit code
        self.assertIn("its own store", self.deny_reason("claude-code", out, err))
        self.assertNoTrace(STRIPE_ROTATED, out, err)


class TestMultipleCredentialsInOnePrompt(IntegrationCase):
    PAIRS = (("STRIPE_SECRET_KEY", STRIPE), ("GITHUB_TOKEN", GITHUB), ("SLACK_BOT_TOKEN", SLACK))
    PROMPT = "stripe " + STRIPE + " github " + GITHUB + " slack " + SLACK

    def test_all_three_are_replaced_stored_and_none_leak(self):
        code, out, err = self.prompt_hook({"prompt": self.PROMPT, "cwd": "/proj"})
        reason = self.block_reason("claude-code", out, err)

        self.assertEqual(vault.names(), ["GITHUB_TOKEN", "SLACK_BOT_TOKEN", "STRIPE_SECRET_KEY"])
        for name, value in self.PAIRS:
            self.assertEqual(vault.get(name), value)
            self.assertIn("stored as $" + name, reason)
            self.assertNoTrace(value, out, err)
        self.assertIn(
            "stripe $STRIPE_SECRET_KEY github $GITHUB_TOKEN slack $SLACK_BOT_TOKEN", reason)

    def test_the_cli_lists_all_three_without_any_value(self):
        self.prompt_hook({"prompt": self.PROMPT, "cwd": "/proj"})
        code, out, err = self.run_cli("list")
        self.assertIn("3 stored", out)
        for name, value in self.PAIRS:
            self.assertIn("$" + name, out)
            self.assertNoTrace(value, out, err)


class TestSameNameDifferentValue(IntegrationCase):
    def test_a_second_key_of_the_same_kind_gets_a_suffixed_name(self):
        self.prompt_hook({"prompt": "first " + STRIPE, "cwd": "/a"})
        code, out, err = self.prompt_hook({"prompt": "second " + STRIPE_ROTATED, "cwd": "/b"})

        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY_2"])
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE)
        self.assertEqual(vault.get("STRIPE_SECRET_KEY_2"), STRIPE_ROTATED)

        reason = self.block_reason("claude-code", out, err)
        self.assertIn("second $STRIPE_SECRET_KEY_2", reason)
        self.assertNoTrace(STRIPE, out, err)
        self.assertNoTrace(STRIPE_ROTATED, out, err)

        # Each entry keeps its own provenance rather than merging into the first one's.
        listing = vault.list_secrets()
        self.assertEqual(listing["STRIPE_SECRET_KEY"]["sources"], ["/a"])
        self.assertEqual(listing["STRIPE_SECRET_KEY_2"]["sources"], ["/b"])

    def test_neither_value_reaches_the_cli_output(self):
        self.prompt_hook({"prompt": "first " + STRIPE, "cwd": "/a"})
        self.prompt_hook({"prompt": "second " + STRIPE_ROTATED, "cwd": "/b"})
        code, out, err = self.run_cli("list")
        self.assertNoTrace(STRIPE, out, err)
        self.assertNoTrace(STRIPE_ROTATED, out, err)

    def test_clearing_the_first_lets_the_next_capture_take_the_plain_name(self):
        self.prompt_hook({"prompt": "first " + STRIPE, "cwd": "/a"})
        self.assertEqual(self.run_cli("clear", "STRIPE_SECRET_KEY")[0], 0)
        self.prompt_hook({"prompt": "second " + STRIPE_ROTATED, "cwd": "/b"})
        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE_ROTATED)


class TestDenyHookAndVault(IntegrationCase):
    def setUp(self):
        IntegrationCase.setUp(self)
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"})

    def assertDenied(self, payload):
        code, out, err = self.tool_hook(payload)
        self.assertEqual(code, 0)  # a deny is expressed in stdout JSON, not in the exit code
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertNoTrace(STRIPE, out, err)
        return decision["permissionDecisionReason"]

    def test_a_read_of_the_vault_file_is_denied(self):
        reason = self.assertDenied({"tool_name": "Read", "tool_input": {"file_path": vault.path()}})
        self.assertIn("its own store", reason)

    def test_a_bash_cat_of_the_vault_file_is_denied(self):
        reason = self.assertDenied({"tool_name": "Bash", "tool_input": {"command": "cat " + vault.path()}})
        self.assertIn("its own store", reason)

    def test_the_vaults_own_variants_are_protected_but_its_neighbours_are_not(self):
        # Narrowed from the whole directory to the file that holds values. sessions.json and
        # deny.json sit beside the vault and contain no credential -- opaque session ids and this
        # hook's own configuration -- so denying them only blocked people diagnosing clowk.
        for suffix in (".tmp", ".bak", ".md"):
            self.assertDenied({"tool_name": "Read",
                               "tool_input": {"file_path": vault.path() + suffix}})
        self.assertIsNone(
            deny.check("Read", {"file_path": deny.config_path()}),
            "the deny config holds no credential and should be readable")

    def test_allowing_the_vault_by_name_does_not_unprotect_it(self):
        # `clowk allow` prints "the vault's own directory stays protected either way" -- check it.
        self.assertEqual(self.run_cli("allow", "vault.json")[0], 0)
        self.assertDenied({"tool_name": "Read", "tool_input": {"file_path": vault.path()}})

    def test_an_unrelated_read_is_still_allowed(self):
        code, out, err = self.tool_hook({"tool_name": "Read", "tool_input": {"file_path": "/proj/src/main.py"}})
        self.assertEqual((code, out, err), (0, "", ""))

    def test_a_denied_command_does_not_echo_a_credential_that_rode_along_with_it(self):
        self.assertDenied({"tool_name": "Bash",
                           "tool_input": {"command": "cat /proj/.env  # token " + STRIPE}})

    def test_every_host_gets_a_deny_in_the_shape_that_host_understands(self):
        # install registers this hook on all three hosts. Exit 0 with output a host cannot parse
        # is an allow, so a deny that only Claude Code understands is a no-op on the other two.
        for payload, marker in (
            ({"tool_name": "Read", "tool_input": {"file_path": vault.path()}}, "its own store"),
            ({"tool_name": "Bash", "tool_input": {"command": "git credential fill"}}, "clowk allow"),
        ):
            for host in ALL_HOSTS:
                code, out, err = self.tool_hook(payload, host)
                self.assertEqual((host, code), (host, BLOCK_CODE[host]))
                self.assertIn(marker, self.deny_reason(host, out, err))
                if host != "claude-code":
                    self.assertEqual((host, out), (host, ""))  # exit-2 hosts read stderr
                self.assertNoTrace(STRIPE, out, err)

    def test_an_allowed_call_stays_silent_on_every_host(self):
        for host in ALL_HOSTS:
            result = self.tool_hook(
                {"tool_name": "Read", "tool_input": {"file_path": "/proj/src/main.py"}}, host)
            self.assertEqual((host,) + result, (host, 0, "", ""))


class TestInstallUninstallRoundTrip(IntegrationCase):
    """A real settings.json already has hooks on these events. Nothing of the user's may be lost."""

    # Two of these groups are degenerate on purpose: a matcher with no hooks array, and a group
    # the user emptied by hand. Both are things clowk did not create and must not delete.
    MESSY = {
        "theme": "dark",
        "hooks": {
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": "echo mine"}]},
                {"matcher": "Write"},
            ],
            "PreToolUse": [
                {"matcher": "Bash|Read", "hooks": [{"type": "command", "command": "echo theirs"}]},
                {"matcher": "Edit", "hooks": []},
            ],
            "BeforeAgent": [{"hooks": [{"type": "command", "command": "echo gemini"}]}],
            "BeforeTool": [{"hooks": [{"type": "command", "command": "echo geminitool"}]}],
        },
    }

    def write_settings(self, data):
        """Write with the same encoder install uses, so a byte comparison is meaningful."""
        with open(self.settings, "w") as f:
            json.dump(data, f, indent=2)
        return read_text(self.settings)

    def _round_trip(self, host):
        original = self.write_settings(self.MESSY)

        # Two hooks everywhere, plus the SessionStart briefing where the host has a session event.
        # Derived rather than written as 2, so adding an event does not turn this red while the
        # thing it actually checks -- that uninstall restores the file byte for byte -- still holds.
        expected_hooks = 2 + (1 if install.TARGETS[host].get("session_event") else 0)
        result = install.install(host, "/opt/clowk", self.settings)
        self.assertEqual(result["added"], expected_hooks)
        registered = read_text(self.settings)
        self.assertIn("hook_prompt.py", registered)
        self.assertIn("hook_pretool.py", registered)
        self.assertIn("--host " + host, registered)
        for survivor in ("dark", "echo mine", "echo theirs", "echo gemini", "echo geminitool",
                         "Write", "Edit"):
            self.assertIn(survivor, registered)

        self.assertEqual(install.uninstall(host, self.settings)["removed"], expected_hooks)
        self.assertEqual(read_text(self.settings), original)

    def test_claude_code_round_trips_to_an_identical_file(self):
        self._round_trip("claude-code")

    def test_codex_round_trips_to_an_identical_file(self):
        self._round_trip("codex")

    def test_gemini_cli_round_trips_to_an_identical_file(self):
        self._round_trip("gemini-cli")

    def test_the_backup_holds_the_file_as_it_was_before_install(self):
        original = self.write_settings(self.MESSY)
        result = install.install("claude-code", "/opt/clowk", self.settings)
        self.assertEqual(read_text(result["backup"]), original)

    def test_installing_twice_adds_nothing_and_changes_nothing(self):
        self.write_settings(self.MESSY)
        install.install("claude-code", "/opt/clowk", self.settings)
        after_first = read_text(self.settings)
        second = install.install("claude-code", "/opt/clowk", self.settings)
        self.assertEqual(second["added"], 0)
        self.assertEqual(read_text(self.settings), after_first)

    def test_uninstalling_twice_removes_nothing_the_second_time(self):
        original = self.write_settings(self.MESSY)
        install.install("claude-code", "/opt/clowk", self.settings)
        install.uninstall("claude-code", self.settings)
        self.assertEqual(install.uninstall("claude-code", self.settings)["removed"], 0)
        self.assertEqual(read_text(self.settings), original)

    def test_the_registered_command_is_the_one_the_hook_actually_parses(self):
        # install writes `--host HOST`; _host_from must read back exactly that.
        self.write_settings(self.MESSY)
        install.install("codex", "/opt/clowk", self.settings)
        commands = [
            entry["command"]
            for groups in json.loads(read_text(self.settings))["hooks"].values()
            for group in groups
            for entry in group.get("hooks", [])
            if install.is_clowk_entry(entry)
        ]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(hook_prompt._host_from(command.split()[1:]), "codex")


class TestIdempotency(IntegrationCase):
    def test_running_the_prompt_hook_twice_does_not_duplicate_anything(self):
        payload = {"prompt": "use " + STRIPE + " again", "cwd": "/proj"}
        first = self.prompt_hook(payload)
        second = self.prompt_hook(payload)
        self.assertEqual(first, second)
        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(vault.list_secrets()["STRIPE_SECRET_KEY"]["sources"], ["/proj"])
        self.assertIn("1 stored", self.run_cli("list")[1])

    def test_the_same_secret_from_two_directories_stays_one_entry(self):
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/a"})
        self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/b"})
        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])
        self.assertEqual(vault.list_secrets()["STRIPE_SECRET_KEY"]["sources"], ["/a", "/b"])

    def test_the_same_secret_seen_by_two_hosts_stays_one_entry(self):
        for host in ALL_HOSTS:
            self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/proj"}, host)
        self.assertEqual(vault.names(), ["STRIPE_SECRET_KEY"])


class TestRobustness(IntegrationCase):
    """Every host fails open: a crash or a hang here transmits the secret. So: never raise."""

    MALFORMED = ("", "   ", "{not json", "[1, 2, 3]", '"just a string"', "null", "42")

    def test_malformed_stdin_exits_zero_and_says_nothing_on_every_host(self):
        for host in ALL_HOSTS:
            for raw in self.MALFORMED:
                code, out, err = self.prompt_hook(raw, host)
                self.assertEqual((host, repr(raw), code, out, err), (host, repr(raw), 0, "", ""))
        self.assertEqual(vault.names(), [])

    def test_an_empty_payload_exits_zero(self):
        for host in ALL_HOSTS:
            self.assertEqual(self.prompt_hook({}, host), (0, "", ""))

    def test_a_payload_with_no_prompt_key_exits_zero(self):
        for host in ALL_HOSTS:
            self.assertEqual(self.prompt_hook({"cwd": "/p", "session_id": "abc"}, host), (0, "", ""))

    def test_a_prompt_that_is_not_a_string_exits_zero(self):
        for value in (12345, None, True, [STRIPE], {"text": STRIPE}, ""):
            for host in ALL_HOSTS:
                code, out, err = self.prompt_hook({"prompt": value, "cwd": "/p"}, host)
                self.assertEqual((repr(value), code, out, err), (repr(value), 0, "", ""))
        self.assertEqual(vault.names(), [])

    def test_a_corrupt_vault_does_not_stop_a_block(self):
        # An unparseable vault is a file clowk must not overwrite -- the user's only copy of
        # everything caught so far is in it. Filing stops; blocking does not.
        with open(vault.path(), "w") as f:
            f.write("{not json")
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/p"})
        self.assertEqual(code, BLOCK_CODE["claude-code"])
        reason = self.block_reason("claude-code", out, err)
        self.assertIn("NOT filed as $STRIPE_SECRET_KEY", reason)
        self.assertIn("use $STRIPE_SECRET_KEY", reason)
        self.assertNoTrace(STRIPE, out, err)
        self.assertEqual(read_text(vault.path()), "{not json")

    def test_a_vault_holding_the_wrong_json_shape_does_not_stop_a_block(self):
        with open(vault.path(), "w") as f:
            json.dump(["not", "a", "vault"], f)
        original = read_text(vault.path())
        code, out, err = self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/p"})
        self.assertEqual(code, BLOCK_CODE["claude-code"])
        self.assertIn("NOT filed as $STRIPE_SECRET_KEY",
                      self.block_reason("claude-code", out, err))
        self.assertNoTrace(STRIPE, out, err)
        self.assertEqual(read_text(vault.path()), original)

    def test_a_corrupt_vault_makes_the_cli_refuse_rather_than_report_an_empty_vault(self):
        with open(vault.path(), "w") as f:
            f.write("{not json")
        for argv in (["list"], ["uses"], ["clear", "A"], ["rename", "A", "B"]):
            code, out, err = self.run_cli(*argv)
            self.assertEqual((argv, code), (argv, 1))
            self.assertNotIn("No credentials stored", out)
            self.assertIn("fix or move the file", err)
        os.environ["CLOWK_VALUE"] = STRIPE
        self.assertEqual(self.run_cli("add", "NEW_KEY")[0], 1)
        self.assertEqual(read_text(vault.path()), "{not json")

    def test_a_wrong_shaped_vault_makes_the_cli_refuse_too(self):
        with open(vault.path(), "w") as f:
            json.dump({"version": 1, "secrets": []}, f)
        code, out, err = self.run_cli("list")
        self.assertEqual(code, 1)
        self.assertIn("fix or move the file", err)

    def test_a_corrupt_deny_config_still_protects_the_vault(self):
        with open(deny.config_path(), "w") as f:
            f.write("{not json")
        code, out, err = self.tool_hook({"tool_name": "Read", "tool_input": {"file_path": vault.path()}})
        self.assertEqual(code, 0)
        self.assertIn("deny", out)

    def test_the_tool_hook_survives_malformed_input(self):
        for raw in self.MALFORMED:
            code, out, err = self.tool_hook(raw)
            self.assertEqual((repr(raw), code, out, err), (repr(raw), 0, "", ""))

    def test_the_tool_hook_survives_a_payload_with_odd_field_types(self):
        for payload in ({}, {"tool_name": "Read"}, {"tool_name": None, "tool_input": None},
                        {"tool_name": "Read", "tool_input": "a string"},
                        {"tool_name": "Read", "tool_input": {"file_path": 7}},
                        {"tool_name": "Bash", "tool_input": {"command": ["ls"]}}):
            code, out, err = self.tool_hook(payload)
            self.assertEqual((json.dumps(payload), code, out, err), (json.dumps(payload), 0, "", ""))

    def test_a_missing_vault_directory_is_created_on_first_capture(self):
        nested = os.path.join(self.dir, "deeper", "vault.json")
        os.environ["CLOWK_VAULT"] = nested
        self.assertEqual(self.prompt_hook({"prompt": "use " + STRIPE, "cwd": "/p"})[0], 0)
        self.assertTrue(os.path.exists(nested))
        self.assertEqual(vault.get("STRIPE_SECRET_KEY"), STRIPE)


if __name__ == "__main__":
    unittest.main()
