import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import time
import unittest

from clowk.detect import scan, secret_group

DETECT_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "detect.py")

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

    def test_sonar_token_is_captured_exactly_via_its_declared_secret_group(self):
        # gitleaks.toml declares `secretGroup = 2` for this rule; honouring it turns the safe
        # whole-match over-capture into the exact token, so $SONAR_API_TOKEN expands correctly.
        self.assertIn(SONAR_TOKEN, [f.secret for f in scan(SONAR_PROMPT)])

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

    def test_a_declared_secret_group_wins_over_the_derived_one(self):
        rules = {r["id"]: r for r in _load_rules()}
        sonar = rules["sonar-api-token"]
        self.assertEqual(sonar["secret_group"], 2)   # as declared in gitleaks.toml
        self.assertEqual(sonar["group"], 2)

    def test_group_metadata_matches_what_the_resolver_derives(self):
        # rules.json is generated; a hand-edit that drops the key must not silently change tiers
        for r in _load_rules():
            if r.get("secret_group") is None:
                self.assertEqual(r["group"], secret_group(r["regex"]), r["id"])


# gitleaks' generic keyword-proximity template opens with lazy leading context. finditer already
# tries every start offset, so it can only widen the match START -- never decide whether the
# captured value is found -- while costing up to 50 backtrack states per input character.
_LEADING_CONTEXT = re.compile(r"^(?:\(\?i:)?\[\\w\.-\]\{0,\d+\}\?")


class TestRulesetShape(unittest.TestCase):
    def test_no_rule_carries_a_redundant_leading_context_prefix(self):
        offenders = sorted(r["id"] for r in _load_rules() if _LEADING_CONTEXT.match(r["regex"]))
        self.assertEqual(offenders, [], "%d rules still carry it" % len(offenders))

    def test_the_generic_keyword_rules_still_detect_their_values(self):
        # the strip must not cost a single detection: these all rely on the template it heads
        self.assertIn("aB3xQ9zLmN4pR7tV2wY8", [f.secret for f in scan('api_key = "aB3xQ9zLmN4pR7tV2wY8"')])
        self.assertIn("0123456789abcdef0123456789abcdef01234567",
                      [f.secret for f in scan('cohere_key = "0123456789abcdef0123456789abcdef01234567"')])
        self.assertIn(SONAR_TOKEN, [f.secret for f in scan(SONAR_PROMPT)])


# A git SHA-1 is 40 hex characters, and sourcegraph-access-token's regex ends in a bare
# [a-fA-F0-9]{40} alternative -- so every commit hash matches its pattern. Its entropy floor of
# 3.0 cannot filter hex (max 4.0), which leaves the keyword gate as the ONLY thing between
# ordinary git chatter and a blocked turn.
GIT_SHA = "9f2c1b7ae4d5c60813fa27bd9e0a4c3f5d6e7a8b"
# Far from generic-api-key's 3.5 entropy floor in both directions, deliberately: a fixture that
# sits within 0.01 of the threshold tests a coincidence, not the mechanism.
LOW_ENTROPY = "x" * 40                                    # 0.0
HIGH_ENTROPY = "aB3xQ9zLmN4pR7tV2wY8kC6jH1sD5fG7wZ0uT8vE"  # 5.17

# Ordinary agent-coding prompts. Verified clean against the shipped ruleset by running scan(),
# not by picking strings that looked safe.
CLEAN_PROMPTS = [
    "git rev-parse HEAD gives %s -- is that the merge base?" % GIT_SHA,
    "the sha256 of the tarball is 4f8b2c1d9e0a3b5c7d6e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
    'the config has token = "%s" which is obviously fake' % LOW_ENTROPY,
    'api_key: "REPLACE_ME_WITH_YOUR_KEY_HERE_0000000000"',
    'password = "hunter2hunter2hunter2hunter2hunter2"',
    "set the api_key to <your-key-here> before running the seed script",
    "the request id in the log is a1b2c3d4-e5f6-7890-abcd-ef1234567890, can you trace it?",
    "our build id is Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0 -- decode it and tell me what it means",
    'in package-lock.json the entry is "integrity": "sha512-abcdefabcdefabcdefabcdefabcdef=="',
    "rename the getUserSecret helper to loadUserCredential across the auth package",
    "why does my password field lose focus when the modal closes?",
    "add an access_token column to the sessions table, nullable, with an index",
    "the docker image digest is sha256:" + "0" * 64,
    "bump the api client to 2.4.0 and regenerate the typed key map",
    "AUTH_SECRET is read from the environment; document that in the README",
    "curl -sS https://api.example.com/v1/health | jq .status",
    "grep -rn 'apiKey' src/ and tell me which modules read it directly",
    "the test asserts credentials are never logged; it fails on line 42",
]


class TestFalsePositives(unittest.TestCase):
    """The keyword gate and the entropy filter are the only two things holding false positives
    down across the vendored ruleset, roughly half of which matches on shape alone. Stubbing
    either one out used to leave the whole suite green while ordinary prompts started getting
    blocked, so regressions that break DETECTION were caught and regressions that break
    SUPPRESSION were invisible. (No count written down: test_tiers derives it from classify.)
    """

    def test_ordinary_developer_prompts_are_not_blocked(self):
        blocked = [(p, [f.rule_id for f in scan(p)]) for p in CLEAN_PROMPTS if scan(p)]
        self.assertEqual(blocked, [])

    def test_the_keyword_gate_is_what_keeps_a_git_sha_from_being_a_credential(self):
        self.assertEqual(scan("git bisect points at %s, revert it" % GIT_SHA), [])
        # ...and the gate, not the regex, is doing it: name the vendor and the same hash matches
        with_keyword = [f.rule_id for f in scan("the sourcegraph key is %s" % GIT_SHA)]
        self.assertIn("sourcegraph-access-token", with_keyword)

    def test_the_entropy_filter_drops_a_low_entropy_placeholder(self):
        self.assertEqual(scan('token = "%s"' % LOW_ENTROPY), [])
        # ...and it is the filter, not the pattern: the same shape with real entropy is kept
        self.assertIn(HIGH_ENTROPY, [f.secret for f in scan('token = "%s"' % HIGH_ENTROPY)])


GITLEAKS_TOML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "clowk", "gitleaks.toml")

# Airtable personal access token: `pat` + 14 alphanumerics + `.` + 64 hex. Split so this file
# cannot trip a secret scanner; the value the test sees is unchanged. See NOTES.md.
AIRTABLE_PAT = ("pat" "Ab3xQ9zLmN4pR7."
                "0f4a9c2e71bd8365af0e5c1d9b7263e4a8f5c0d13b6e8a24f7c9d0b1e5a38274")


class TestNoVendoredRuleIsSilentlyDropped(unittest.TestCase):
    """A rule Python cannot compile is skipped by build_rules.py, and skipping is silent enough.

    That is not hypothetical. Go's regexp supports POSIX character classes and Python's re reads
    `[[:alnum:]]` as a nested set, so airtable-personnal-access-token -- the newest rule gitleaks
    has added -- was vendored in the toml and then absent from rules.json. The count in README went
    down by one and nothing else said a word. build_rules.py now translates the class, and this
    test is what makes the next such rule fail the suite instead of disappearing.
    """

    def test_every_toml_rule_with_a_regex_survives_into_the_ruleset(self):
        with open(GITLEAKS_TOML, encoding="utf-8") as f:
            blocks = f.read().split("[[rules]]")[1:]
        declared = set()
        for b in blocks:
            mid = re.search(r'^\s*id\s*=\s*"([^"]+)"', b, re.M)
            if mid and re.search(r"^\s*regex\s*=\s*'''", b, re.M):
                declared.add(mid.group(1))
        shipped = {r["id"] for r in _load_rules()}
        self.assertEqual(sorted(declared - shipped), [],
                         "%d vendored rule(s) never reached rules.json" % len(declared - shipped))
        # A rule with no regex at all is a path-only rule (pkcs12-file matches *.p12 filenames),
        # which clowk has nothing to do with: it scans prompt text, not directory listings.
        self.assertEqual(len(declared), len(shipped))

    def test_the_rule_that_was_being_dropped_now_detects_its_token(self):
        found = [f.rule_id for f in scan("my airtable token is " + AIRTABLE_PAT)]
        self.assertIn("airtable-personnal-access-token", found)

    def test_it_needed_that_rule_because_nothing_else_reaches_the_shape(self):
        # The keyword gate is gitleaks', so the token alone stays invisible -- and clowk's
        # standalone rule cannot help: the dot in the middle ends its token.
        self.assertEqual(scan(AIRTABLE_PAT), [])


# AWS's own documented example secret access key: 40 characters, no pinnable shape. Split so this
# file cannot trip a secret scanner; the value the test sees is unchanged. See NOTES.md.
AWS_SECRET = "wJalrXUtnFEMI" "/K7MDENG/bPxRfiCYEXAMPLEKEY"


class TestAGenericMatchIsNamedFromTheLabelItMatchedOn(unittest.TestCase):
    """generic-api-key matched BECAUSE of a keyword, then threw the keyword away.

    Reported from real use: `secrate access key = <40-char AWS secret>` was filed as
    $GENERIC_API_KEY. There is no AWS secret-key rule anywhere in the vendored set and a 40-char
    base64 blob has no pinnable shape, so falling through to the generic rule is correct -- but the
    name is then the rule's name rather than the credential's, and the one thing that could have
    named it was in the text the rule had already matched.
    """

    def env_for(self, prompt):
        return [f.env for f in scan(prompt) if f.rule_id == "generic-api-key"]

    def test_the_reported_paste_is_named_from_the_users_own_words(self):
        self.assertEqual(self.env_for("secrate access key = " + AWS_SECRET), ["ACCESS_KEY"])

    def test_spelling_the_label_correctly_gives_the_full_name(self):
        # Nothing here depends on correct spelling: the name is built only out of text the regex
        # matched, and the regex matched because SOME keyword was spelled right. "secrate" is not
        # a keyword, so the match -- and the name -- begins at "access".
        self.assertEqual(self.env_for("secret access key = " + AWS_SECRET), ["SECRET_ACCESS_KEY"])
        self.assertEqual(self.env_for("aws_secret_access_key = " + AWS_SECRET),
                         ["SECRET_ACCESS_KEY"])

    def test_the_ordinary_shapes_get_the_names_a_human_would_have_typed(self):
        for prompt, name in (
                ("api_key = " + AWS_SECRET, "API_KEY"),
                ('password = "%s"' % AWS_SECRET, "PASSWORD"),
                ('{"api_key": "%s"}' % AWS_SECRET, "API_KEY"),
                ('curl -H "X-Api-Key: %s"' % AWS_SECRET, "API_KEY"),
                ("MY_API_KEY=" + AWS_SECRET, "API_KEY"),
                ("credentials.password = " + AWS_SECRET, "CREDENTIALS_PASSWORD"),
                ("auth_token: " + AWS_SECRET, "AUTH_TOKEN")):
            self.assertEqual(self.env_for(prompt), [name], prompt)

    def test_prose_between_the_label_and_the_value_is_not_part_of_the_name(self):
        """gitleaks' template allows 20 characters of `[ \\t\\w.-]` between keyword and operator.

        That is a hole a whole clause fits through, and the first version of this fix walked
        straight into it: README's own headline example, `rotate this key for me: <key>`, filed as
        $KEY_FOR_ME, and `the token for staging: <key>` as $TOKEN_FOR_STAGING. Measured, not
        imagined -- it showed up rendering the block message by hand.
        """
        for prompt, name in (
                ("rotate this key for me: " + AWS_SECRET, "KEY"),
                ("please rotate the token for staging: " + AWS_SECRET, "TOKEN"),
                ("here is the API key:\n" + AWS_SECRET, "API_KEY"),
                ("auth_token_hint=" + AWS_SECRET, "AUTH_TOKEN"),
                ("key 2fa = " + AWS_SECRET, "KEY")):
            self.assertEqual(self.env_for(prompt), [name], prompt)

    def test_the_same_paste_always_produces_the_same_name(self):
        prompt = "secret access key = " + AWS_SECRET
        self.assertEqual(self.env_for(prompt), self.env_for(prompt))

    def test_a_rule_that_names_its_vendor_keeps_that_name(self):
        # Only the generic rule is renamed, and where a vendor rule claims the value first the
        # label is never consulted: `access key = AKIA...` is AWS's, not the user's word for it.
        findings = {f.rule_id: f.env for f in scan("access key = AKIA" "IOSFODNN7EXAMPLE")}
        self.assertEqual(findings, {"aws-access-token": "AWS_ACCESS_KEY_ID"})
        findings = {f.rule_id: f.env for f in scan("the stripe key is sk_" "live_4eC39HqLyjWDarjtT1zdp7dc")}
        self.assertEqual(findings, {"stripe-access-token": "STRIPE_SECRET_KEY"})

    def test_a_bare_token_with_no_label_keeps_the_standalone_name(self):
        # The standalone rule requires no keyword and its match carries none, so there is nothing
        # that "actually matched" to derive from. Left as SECRET deliberately -- see detect.py.
        findings = [f.env for f in scan("DL" "fdfnU8pAERrHbccVspNtcq37DhhIyh")]
        self.assertEqual(findings, ["SECRET"])


class TestTheDerivedNameIsAlwaysUsable(unittest.TestCase):
    """A $NAME goes into a shell as `$(clowk get NAME)`, so junk in is not an option."""

    def test_a_name_is_always_a_shell_safe_identifier(self):
        prompts = ["api_key = " + AWS_SECRET, "access key = " + AWS_SECRET,
                   "key 2fa = " + AWS_SECRET, "secret.access-key: " + AWS_SECRET,
                   'creds["password"] = "%s"' % AWS_SECRET, "token\t=\t" + AWS_SECRET]
        for prompt in prompts:
            for f in scan(prompt):
                self.assertTrue(re.match(r"^[A-Z][A-Z0-9_]{2,}$", f.env),
                                "%r produced the name %r" % (prompt, f.env))

    def test_an_unusable_label_falls_back_to_the_rules_own_name(self):
        from clowk.detect import GENERIC_ID, label_env

        for context in ("", "= '", "2fa = ", "k = ", "hostname = ", "a" * 60 + " = ",
                        "accesskeyidentifier_credentials_authorization = "):
            self.assertEqual(label_env(context, "GENERIC_API_KEY"), "GENERIC_API_KEY", context)
        self.assertEqual(GENERIC_ID, "generic-api-key")

    def test_only_words_the_ruleset_treats_as_credential_words_reach_a_name(self):
        from clowk.detect import label_env

        # The run has to be UNBROKEN and end at the last credential word, or a clause between two
        # of them gets in: `key for the token` would be KEY_FOR_THE_TOKEN.
        self.assertEqual(label_env("key for the token = ", "F"), "TOKEN")
        self.assertEqual(label_env("secret access key = ", "F"), "SECRET_ACCESS_KEY")
        self.assertEqual(label_env("my access key for prod = ", "F"), "ACCESS_KEY")
        self.assertEqual(label_env("authorization: ", "F"), "AUTHORIZATION")


class TestAnAnsiEscapeIsATokenBoundary(unittest.TestCase):
    """`ESC[1m` glued to a value made the standalone rule swallow the escape's own tail.

    `[` is not in the token rule's negative lookbehind, so with no separator the match started at
    the `1` and the filed value was `1m<key>`. Nothing leaked -- the whole span is redacted -- but
    `clowk get` handed back a credential with two junk characters on the front, which is the same
    class of failure as the rotation bug: clowk silently returns a value that will not work.

    Terminal output is where this comes from. A user pasting a build log, a `kubectl` dump or
    anything colourised brings the escapes with it.
    """

    KEY = "DL" "fdfnU8pAERrHbccVspNtcq37DhhIyh"

    def secrets(self, text):
        return [f.secret for f in scan(text)]

    def test_every_sgr_shape_leaves_the_value_intact(self):
        for prefix in ("\x1b[1m", "\x1b[0m", "\x1b[38;5;214m", "\x1b[m", "\x1b[4;31m"):
            self.assertEqual(self.secrets(prefix + self.KEY), [self.KEY],
                             "%r glued to the value" % prefix)

    def test_escapes_on_both_sides_leave_the_value_intact(self):
        self.assertEqual(self.secrets("\x1b[1m" + self.KEY + "\x1b[0m"), [self.KEY])

    def test_a_trailing_escape_was_already_fine_and_stays_fine(self):
        self.assertEqual(self.secrets(self.KEY + "\x1b[0m"), [self.KEY])

    def test_the_escape_is_a_boundary_even_glued_to_a_word(self):
        # `foo<ESC>[1m<key>` -- the escape sequence is itself the boundary, so it must not matter
        # what precedes it. A lookbehind cannot express this: an escape sequence is variable width.
        self.assertEqual(self.secrets("x\x1b[1m" + self.KEY), [self.KEY])

    def test_a_separator_after_the_escape_was_already_fine(self):
        self.assertEqual(self.secrets("\x1b[1m " + self.KEY), [self.KEY])

    def test_the_same_characters_without_an_escape_are_still_part_of_the_token(self):
        """The precision half: only a REAL escape sequence is a boundary.

        `1m` typed literally in front of a value is part of the value -- a base64 key can begin
        with anything -- so trimming a leading `<digits>m` unconditionally would corrupt one key
        shape to fix another. The context decides, not the token.
        """
        self.assertEqual(self.secrets("1m" + self.KEY), ["1m" + self.KEY])
        self.assertEqual(self.secrets("[1m" + self.KEY), ["1m" + self.KEY])

    def test_the_escape_tail_cannot_pad_a_token_over_the_length_floor(self):
        # 19 characters is under the 20-character floor. With `1m` glued on it used to be 21 and
        # got reported; the value was never a credential clowk could hand back.
        short = "aB3xQ9zLmN4pR7tV2wY"
        self.assertEqual(len(short), 19)
        self.assertEqual(self.secrets("\x1b[1m" + short), [])


class TestGuardMetadata(unittest.TestCase):
    """rules.json is generated, and detect reads both guards with `r.get(...)` short-circuits, so
    a build-script regression that dropped these keys would silently disable both at once."""

    def test_every_rule_still_carries_its_keyword_gate(self):
        missing = [r["id"] for r in _load_rules() if not r.get("keywords")]
        self.assertEqual(missing, [])

    def test_the_two_load_bearing_guards_are_intact(self):
        rules = {r["id"]: r for r in _load_rules()}
        self.assertEqual(rules["generic-api-key"]["entropy"], 3.5)
        self.assertEqual(sorted(rules["sourcegraph-access-token"]["keywords"]),
                         ["sgp_", "sourcegraph"])


class TestKnownFalsePositives(unittest.TestCase):
    """Prompts that clowk DOES block today and arguably should not.

    Recorded rather than dropped from CLEAN_PROMPTS: quietly deleting them would turn that corpus
    into a curated snapshot that hides the real false-positive surface. If a future change fixes
    one of these, this test fails and the case moves to CLEAN_PROMPTS.
    """

    def test_naming_the_vendor_beside_a_commit_hash_blocks(self):
        # sourcegraph-access-token's bare 40-hex branch + a substring keyword gate
        self.assertTrue(scan("sourcegraph indexed our repo at commit %s" % GIT_SHA))

    def test_a_high_entropy_placeholder_still_blocks(self):
        # entropy 3.68, over generic-api-key's 3.5 floor -- flagged shape-only, at least
        findings = scan('api_key: "REPLACE_ME_WITH_YOUR_TOKEN_HERE_00000000"')
        self.assertTrue(findings)
        self.assertEqual([f.confidence for f in findings], ["low"])

    def test_the_generic_rule_out_ranks_a_vendor_rule_when_both_match(self):
        """A vendor-prefixed key written as `keyword = value` is labelled by whichever rule comes
        first in rules.json, and generic-api-key sits at index 77 of 221.

        So `github_token = ghp_...` is reported as generic-api-key, not github-pat: the vendor's
        name and its "high" tier are both lost, even though the value carries `ghp_`. Pre-existing
        and independent of how the generic rule names things -- before the label fix the same paste
        read $GENERIC_API_KEY. Recorded rather than fixed here because the fix is a rule-priority
        change (defer the generic rule to last, as clowk's own standalone rule already is), which
        alters which rule_id and which confidence tier a value is reported under and so needs its
        own measurement. This test fails when that happens, which is the point.
        """
        findings = [(f.rule_id, f.env, f.confidence)
                    for f in scan("github_token = ghp" "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")]
        self.assertEqual(findings, [("generic-api-key", "TOKEN", "low")])


class TestScanLatency(unittest.TestCase):
    """Bound scan()'s cost, because the host's answer to a slow hook is to transmit the prompt.

    Claude Code's default hook timeout is 60s and `clowk install` writes no explicit timeout, so
    a scan that runs long is killed -- and every host fails open on timeout, meaning the pasted
    credential goes to the model with no block, no vault entry and no message. Nothing else in
    the suite notices that, and rules.json is regenerated from upstream gitleaks releases, so a
    refresh could reintroduce a pathological pattern silently.

    The fixture is built from the ruleset's own keywords rather than hardcoded, so it stays a
    worst case as rules come and go: every keyword gate opens, and cost is driven by the longest
    unbroken [\\w.-] run, not by total input length. The budgets are ~17x the measured time and
    ~12x under the host timeout, so this bounds a regression without racing a busy CI box.
    """

    RUN_LENGTH = 200_000
    WORST_CASE_BUDGET = 5.0
    ORDINARY_BUDGET = 0.25    # the project's own per-run gate

    @classmethod
    def setUpClass(cls):
        keywords = sorted({k for r in _load_rules() for k in (r.get("keywords") or [])})
        run = ("aB3xQ9zLmN4pR7tV2wY8.-_" * (cls.RUN_LENGTH // 23 + 1))[:cls.RUN_LENGTH]
        cls.worst_case = " ".join(keywords) + " " + run

    def _elapsed(self, text):
        start = time.time()
        scan(text)
        return time.time() - start

    def test_a_worst_case_paste_scans_far_inside_the_host_hook_timeout(self):
        elapsed = self._elapsed(self.worst_case)
        self.assertLess(elapsed, self.WORST_CASE_BUDGET, "%.1fs on a %dKB worst-case paste"
                        % (elapsed, self.RUN_LENGTH // 1000))

    def test_an_ordinary_prompt_scans_within_the_projects_own_budget(self):
        elapsed = self._elapsed("just refactor the parser in src/main.py and rename the helper")
        self.assertLess(elapsed, self.ORDINARY_BUDGET, "%.3fs on an ordinary prompt" % elapsed)


class TestBrokenRuleset(unittest.TestCase):
    """Importing detect must never raise, whatever state rules.json is in.

    rules.json is read at import time, which happens while `from clowk.detect import scan` runs
    -- before hook_prompt's bare except exists. A traceback there is a non-zero exit from the
    hook, every host treats that as a non-blocking error, and the prompt carrying the credential
    is transmitted. It then stays broken for every subsequent turn.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        shutil.copy(DETECT_PY, os.path.join(self.dir, "detect.py"))

    def _load(self, rules_json):
        """Import a fresh copy of detect.py beside the given rules.json text (None = no file)."""
        path = os.path.join(self.dir, "rules.json")
        if rules_json is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            with open(path, "w") as f:
                f.write(rules_json)
        spec = importlib.util.spec_from_file_location("clowk_detect_probe", os.path.join(self.dir, "detect.py"))
        mod = importlib.util.module_from_spec(spec)
        self.warning = io.StringIO()
        with contextlib.redirect_stderr(self.warning):
            spec.loader.exec_module(mod)
        return mod

    def _assert_degrades(self, rules_json):
        """A broken ruleset costs the 221 vendored rules but NOT the standalone-token rule.

        This used to assert scan() returned nothing at all. That stopped being true once the
        standalone rule was added, and the new behaviour is strictly better: the standalone rule
        is clowk's own and reads no file, so a corrupt rules.json degrades detection rather than
        disabling it. Both halves are pinned here so neither can regress silently.
        """
        mod = self._load(rules_json)
        self.assertTrue(mod.RULESET_ERROR, "a disabled ruleset must be reported, not silent")
        # loud, not silent: a hook that looks healthy while scanning nothing is worse than one
        # that says so, because nothing else in clowk ever reports a broken ruleset
        self.assertIn("NOT scanning", self.warning.getvalue())

        # Gone with the vendored rules: a Slack token is lowercase, digits and dashes only, so the
        # standalone rule's mixed-case requirement cannot reach it. Only slack-bot-token could.
        slack = "xoxb" + "-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
        self.assertEqual(mod.scan("slack token " + slack), [],
                         "a vendored rule fired with the ruleset broken")

        # Still working: mixed-case high-entropy tokens, because that rule reads no file.
        generic = "DL" + "fdfnU8pAERrHbccVspNtcq37DhhIyh"
        surviving = mod.scan("here is the key " + generic)
        self.assertTrue(surviving, "a broken ruleset must not disable standalone detection too")
        self.assertEqual(surviving[0].rule_id, mod.STANDALONE_ID)
        return mod

    def test_a_missing_ruleset_degrades_instead_of_raising(self):
        self._assert_degrades(None)

    def test_a_truncated_ruleset_degrades_instead_of_raising(self):
        with open(os.path.join(os.path.dirname(DETECT_PY), "rules.json")) as f:
            self._assert_degrades(f.read()[:5000])

    def test_an_empty_ruleset_file_degrades_instead_of_raising(self):
        self._assert_degrades("")

    def test_a_json_object_instead_of_a_list_degrades_instead_of_raising(self):
        self._assert_degrades('{"github-pat": {"regex": "ghp" "_[0-9a-zA-Z]{36}"}}')

    def test_one_malformed_entry_does_not_disable_the_other_rules(self):
        good = {"id": "probe", "env": "PROBE", "regex": r"\b(sk_live_[0-9a-zA-Z]{24})\b",
                "keywords": ["sk_" "live_"], "entropy": None, "ignorecase": False,
                "confidence": "high", "group": 1}
        # a bare string, a rule with no regex, and a rule that compiles but has no id/env --
        # the last one would otherwise pass compile and raise KeyError inside scan() instead
        broken = ["not-a-rule", {"id": "no-regex"}, {"regex": r"\b(zz_[0-9]{6})\b"}]
        mod = self._load(json.dumps([good] + broken))
        self.assertEqual([f.secret for f in mod.scan("key sk_" "live_4eC39HqLyjWDarjtT1zdp7dc here")],
                         ["sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"])
        self.assertEqual(mod.scan("zz_123456"), [])   # the id-less rule is dropped, not fatal

    def test_an_intact_ruleset_reports_no_error(self):
        with open(os.path.join(os.path.dirname(DETECT_PY), "rules.json")) as f:
            mod = self._load(f.read())
        self.assertEqual(mod.RULESET_ERROR, "")
        self.assertEqual(len(mod._COMPILED), len(_load_rules()))
        self.assertEqual(self.warning.getvalue(), "")   # no crying wolf on a healthy ruleset


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
