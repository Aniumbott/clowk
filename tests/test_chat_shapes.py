"""Detection measured against how humans actually hand credentials to an agent.

The vendored gitleaks ruleset is built to scan source code and config files, where a credential
appears as `key = value`. clowk's job is a chat prompt, where people write "here's the api key -
VALUE" or paste the value with no context at all. That mismatch was not caught until the tool was
used for real: a 32-char key sent as "API key - VALUE" went straight through.

These two sets are the regression guard for that. POSITIVES are ways a credential really arrives;
NEGATIVES are ordinary prompts that must never be blocked, because a tool that blocks a git SHA or
a UUID gets uninstalled within a day.

The negatives matter as much as the positives. Recall is easy to buy by lowering the entropy floor
or dropping the charset test; the reason those knobs sit where they do is this list.
"""
import base64
import os
import unittest

from clowk.detect import scan

# Synthetic, and split so this file cannot trip a secret scanner. See NOTES.md.
GENERIC = "DL" + "fdfnU8pAERrHbccVspNtcq37DhhIyh"        # 32 chars, no vendor prefix
GH = "ghp" + "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
STRIPE = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
SLACK = "xoxb" + "-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

# Every one of these is a credential reaching the model if it is missed.
POSITIVES = [
    # prefix-less credential in natural language -- 9 of these 10 were missed before the
    # standalone-token rule existed, and the first is the exact prompt that exposed it.
    ("prose dash", "testing the clowk by sending this API key - " + GENERIC),
    ("prose copula", "my api key is " + GENERIC),
    ("prose bare", "here's the api key " + GENERIC),
    ("prose use-this", "use this token " + GENERIC + " for the request"),
    ("prose newline", "here is the API key:\n" + GENERIC),
    ("prose newline bare", "API key\n" + GENERIC),
    ("prose quoted", 'the secret is "' + GENERIC + '"'),
    ("prose parenthetical", "auth token (" + GENERIC + ") should work now"),
    ("no context at all", GENERIC),
    ("no context, greeting", "here you go\n\n" + GENERIC),
    # keyword+operator shapes, which the vendored rules already handled
    ("assignment", "api_key = " + GENERIC),
    ("colon", "api_key: " + GENERIC),
    ("json", '{"api_key": "' + GENERIC + '"}'),
    ("dotenv", "MY_API_KEY=" + GENERIC),
    ("curl header", 'curl -H "X-Api-Key: ' + GENERIC + '" https://api.example.com/v1'),
    ("curl bearer", 'curl -H "Authorization: Bearer ' + GENERIC + '" https://x.dev'),
    # vendor-prefixed, which the pinned-prefix rules catch in any phrasing including none.
    # No count written down here: it has drifted twice already, and test_tiers derives it.
    ("prefixed in prose", "deploy with this token - " + GH),
    ("prefixed alone", GH),
    ("prefixed stripe", "the stripe key is " + STRIPE),
    ("prefixed slack", "slack bot token " + SLACK),
    # the shape found in a real transcript, which the shipped ruleset missed: keyword, whitespace,
    # then a 64-char value on the next line
    ("keyword then newline", "jwt_secret\n" + "tEB3pBmNzGhzGB11Y9Jhn6KN6mSZ2uQINTudYB6TzNNsU9j9IYZBF9pK1x2Y"),
]

# Every one of these is a blocked legitimate prompt if it matches.
NEGATIVES = [
    ("git sha", "revert commit 9f2c1b7ae4d5c8f0a3b6d9e2c5f8a1b4d7e0c3f6 please"),
    ("short sha", "cherry-pick 3a45ba6 onto main"),
    ("uuid", "the request id was 7c9e6679-7425-40de-944b-e07fc1f90ae7"),
    ("sha256", "checksum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("md5", "the md5 is 5d41402abc4b2a76b9719d911017c592 for that file"),
    ("npm integrity", 'integrity "sha512-oGMAgGoQdBXbZqNG0Ze56CHjDZ1IDYOwGYxYjO5KLSlz5HiNQ9udIXsPZ61VWaHGZ5XW"'),
    ("base64 image", 'src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"'),
    ("docker digest", "image@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"),
    ("long path", "read /Users/me/Library/Application Support/Code/User/workspaceStorage/a1b2c3d4e5f6/state.vscdb"),
    ("stack trace", 'File "/opt/homebrew/lib/python3.14/site-packages/urllib3/connectionpool.py", line 789'),
    ("log line", "2026-07-30T09:14:22Z INFO request_id=a3f9c2e81b7d4056 status=200 dur=41ms"),
    ("css classes", 'className="flex items-center justify-between gap-4 rounded-lg px-3"'),
    ("minified js", "function a(b,c){return b.xQ9zLmN4pR7tV2wY8kJ3hG6fD1sA0(c)}"),
    ("env var name", "set ANTHROPIC_API_KEY in your shell profile before running it"),
    ("branch name", "checkout feature/add-rate-limiting-to-the-api-v2 branch"),
    ("long slug", "deploy to my-really-long-application-name-staging-2 now"),
    ("prose key 1", "the key insight was denormalising the join table entirely"),
    ("prose key 2", "rotate the api key rotation runbook is in Notion somewhere"),
    ("prose key 3", "our secret sauce is understanding compiler optimisation passes"),
    ("prose key 4", "please refactor the token parser in src/lexer/tokenizer.py"),
    ("prose key 5", "add an api key field to the account settings form component"),
    ("prose key 6", "this api key expired months ago and nobody noticed anything"),
    ("prose key 7", "auth middleware should short circuit before database queries"),
    # Hex in its ordinary roles. These matter more since the hex gate stopped being an entropy
    # floor: an absolute floor rejected 19% of ALL 32-char hex, digest or secret, so some of this
    # corpus used to be suppressed by luck rather than by the keyword gate. Verified by running
    # scan(), not by eye.
    ("git show", "run git show 9f2c1b7ae4d5c60813fa27bd9e0a4c3f5d6e7a8b and explain the diff"),
    ("short sha 12", "the fix landed in 3a45ba6c1f2d, backport it to 2.3"),
    ("etag", 'the response had ETag: "a1b2c3d4e5f60718" -- why does it change every request?'),
    ("nix hash", 'sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";'),
    ("checksums line", "SHA256 (dist/clowk.tar.gz) = 5d41402abc4b2a76b9719d911017c5925d41402a"),
    ("cargo rev", 'the Cargo.lock has rev = "9f2c1b7ae4d5c60813fa27bd9e0a4c3f5d6e7a8b" for it'),
    ("packfile", "objects/pack/pack-9f2c1b7ae4d5c60813fa27bd9e0a4c3f5d6e7a8b.idx is corrupt"),
    ("colour hex", "change the button colour to #1a2b3c and the border to #ff00aa"),
    ("ipv6", "the pod address is fe80::1ff:fe23:4567:890a, can you curl it?"),
]

# Agent-harness ids. Mixed case, high entropy, and not credentials. Before these were excluded,
# 79 of 704 real prompts matched -- every one a tool-use id echoed back inside a notification the
# user never typed. Blocking those would have wedged the session.
INFRASTRUCTURE_IDS = [
    "toolu_01JG3sQwuidFyk1gwjQUgYus",
    "msg_01XyZaBcDeFgHiJkLmNoPqRs",
    "req_9aBcDeFgHiJkLmNoPqRsTuVw",
    "run_30486712100aBcDeFgHiJkLm",
    "wf_1f7ded93e89aBcDeFgHiJkLmN",
]


class TestCredentialsAreCaught(unittest.TestCase):
    def test_every_realistic_paste_is_detected(self):
        missed = [label for label, text in POSITIVES if not scan(text)]
        self.assertEqual(missed, [], "these credential pastes went through undetected: %s" % missed)


class TestOrdinaryPromptsPassThrough(unittest.TestCase):
    def test_no_legitimate_prompt_is_blocked(self):
        blocked = [(label, [f.rule_id for f in scan(text)])
                   for label, text in NEGATIVES if scan(text)]
        self.assertEqual(blocked, [], "these ordinary prompts would be blocked: %s" % blocked)

    def test_harness_ids_are_not_credentials(self):
        for token in INFRASTRUCTURE_IDS:
            self.assertEqual(scan(token), [], "%r was treated as a credential" % token)
            self.assertEqual(scan("finished " + token + " ok"), [],
                             "%r in a sentence was treated as a credential" % token)


class TestStandaloneRuleShape(unittest.TestCase):
    """The knobs the negatives above are holding in place."""

    def test_a_vendor_rule_wins_the_label_over_the_generic_one(self):
        findings = {f.secret: f.rule_id for f in scan(GH)}
        self.assertEqual(findings[GH], "github-pat")

    def test_the_standalone_rule_is_low_confidence(self):
        findings = [f for f in scan(GENERIC) if f.secret == GENERIC]
        self.assertTrue(findings)
        self.assertEqual(findings[0].confidence, "low")

    def test_too_short_is_ignored(self):
        self.assertEqual(scan("aB3xQ9zLmN4pR7tV"), [])   # 16 chars, under the floor

    def test_single_case_is_ignored_however_random(self):
        self.assertEqual(scan("qwrtpsdfghjklzxcvbnmqwrtpsdfg"), [])

    def test_low_entropy_is_ignored_however_long(self):
        self.assertEqual(scan("Aaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), [])



class TestLongKeys(unittest.TestCase):
    """Key sizes beyond the obvious 32-char case.

    A 64-character cap -- the first guess -- silently missed everything from 512 bits up, including
    a Rails secret_key_base at 128 hex chars and any base64-encoded 512-bit secret at 86. These
    build real random keys rather than fixtures, so a shape that only works for one hand-picked
    sample cannot pass.
    """

    def test_base64_secrets_are_caught_at_every_common_size(self):
        for bits in (128, 256, 512, 1024, 2048):
            caught = sum(
                1 for _ in range(60)
                if scan(base64.b64encode(os.urandom(bits // 8)).decode())
            )
            # Not 60/60: a short token can fall under the entropy floor by chance, and the floor
            # is where it is for precision. 128-bit is the worst case at ~96%.
            self.assertGreater(caught, 50, "%d-bit base64 keys caught only %d/60" % (bits, caught))

    def test_hex_secrets_of_128_bits_and_up_are_caught_every_time_with_a_keyword(self):
        """Every sample at every shipped key size, because hex no longer faces a base64 floor.

        These asserted 39/40 and ~82% while the gate was gitleaks' absolute entropy number. Hex
        has 16 symbols, so it caps at 4.0 bits against floors calibrated for alphabets reaching
        6.0 -- measured cost, behind a keyword: 18.95% of random 128-bit keys (1621/2000 caught),
        5.2% of 160-bit, and 1 in 4,650 of 256-bit. detect now also accepts 8 distinct hex digits,
        so the tail is gone and this can assert all of it rather than tolerating a coin flip.

        Hex-only tokens remain unclassifiable STANDING ALONE -- 64 hex chars is a sha256 digest
        and a 256-bit HMAC secret at once -- so a keyword is still what makes them reachable.
        """
        for nbytes in (16, 20, 32, 64, 128):
            caught = sum(1 for _ in range(40)
                         if scan("webhook_secret = " + os.urandom(nbytes).hex()))
            self.assertEqual(caught, 40,
                             "%d-bit hex caught only %d/40 with a keyword" % (nbytes * 8, caught))

    def test_128_bit_hex_is_caught_every_time_now(self):
        """The case the entropy floor lost, at the sample size that made the loss visible.

        Over 100,000 random 128-bit hex strings the smallest distinct-symbol count was 9, against
        a gate of 8 -- so full recall here is a property of the gate, not luck with 300 draws.
        """
        caught = sum(1 for _ in range(300)
                     if scan("webhook_secret = " + os.urandom(16).hex()))
        self.assertEqual(caught, 300, "128-bit hex recall regressed to %d/300" % caught)

    def test_hex_under_128_bits_still_faces_the_vendored_floor(self):
        """The limit that stayed, deliberately, and the fixture is exact rather than sampled.

        Both values are 16 hex characters. The first clears gitleaks' 3.5 floor on its own; the
        second does not, and the symbol count does not rescue it because 64 bits is under the
        length the count applies to. Dropping that condition took 64-bit hex from 9% caught to
        99.4% -- and took the repo's own 1800-line log fixture from 168 findings to 1782, because
        a 16-hex `auth_token_hint=` sits one keyword away from every log line anyone pastes. That
        feeds hook_prompt.capture(), whose redaction is O(findings x prompt length): a 2 MB paste
        went from 3.2s to 46.0s against a 60s host hook timeout, past which every host fails open.
        128 bits is the smallest key size anyone ships, so this costs recall only in theory.
        """
        self.assertTrue(scan("webhook_secret = 0123456789abcdef"))      # entropy 4.00, 16 digits
        self.assertEqual(scan("webhook_secret = a1b2a1b2a1b2a1b2"), [])  # entropy 2.00, 4 digits

    def test_bare_hashes_are_still_not_credentials(self):
        # The other side of that trade, and the reason hex stays excluded when it stands alone.
        for nbytes in (20, 16, 32, 64):
            self.assertEqual(scan(os.urandom(nbytes).hex()), [],
                             "a bare %d-byte hex digest was treated as a credential" % nbytes)

    def test_a_base64_token_starting_with_a_symbol_is_still_matched(self):
        # + and / are in the base64 alphabet, so ~3% of keys start with one. Requiring an
        # alphanumeric first character made those unmatchable rather than merely trimmed.
        for tok in ("+" + "aB3xQ9zLmN4pR7tV2wY8kJ3hG6fD1sA0", "/" + "aB3xQ9zLmN4pR7tV2wY8kJ3hG6fD1sA0"):
            self.assertTrue(scan(tok), "a key starting with %r was missed" % tok[0])


class TestHexSymbolFloor(unittest.TestCase):
    """What replaced the entropy floor for hex, and what it still throws away.

    Swapping an entropy floor for a distinct-symbol count buys full recall on random hex. The
    thing it must not buy is placeholders: every one of these reaches or exceeds the floor's
    length while repeating a handful of symbols, so a gate that only counted characters -- or one
    that scaled the floor by the observed alphabet, which was tried -- would file them all.
    """

    # (value, distinct symbols) -- what a human types when they mean "put the real one here".
    REPETITIVE = [
        ("a" * 32, 1), ("0" * 32, 1), ("f" * 40, 1), ("0" * 64, 1),
        ("ab" * 16, 2), ("abc" * 11, 3), ("deadbeef" * 4, 5), ("cafebabe" * 8, 5),
        ("aaaaaaaabbbbbbbbccccccccdddddddd", 4), ("0" * 63 + "1", 2),
    ]

    def test_repetitive_hex_placeholders_are_still_rejected_beside_a_keyword(self):
        for value, distinct in self.REPETITIVE:
            self.assertEqual(scan('webhook_secret = "%s"' % value), [],
                             "%r (%d distinct symbols) was filed as a credential"
                             % (value[:16] + "...", distinct))

    def test_a_sequential_hex_run_is_accepted_and_always_was(self):
        """The concession the symbol count makes -- and it costs nothing, which is why it stands.

        "1234567890abcdef" doubled uses all 16 symbols equally, so its Shannon entropy is the
        maximum 4.0 and gitleaks' 3.5 floor already passed it. The symbol count does not widen
        this case; it inherits it. Nothing weaker than a per-symbol frequency model separates a
        keyboard walk from a key, and that is a far bigger change than the miss it would prevent.
        """
        self.assertTrue(scan('webhook_secret = "%s"' % ("1234567890abcdef" * 2)))
        self.assertTrue(scan('webhook_secret = "%s"' % ("0123456789abcdef" * 4)))

    def test_mixed_case_hex_is_counted_case_insensitively(self):
        # "AbAbAb..." has 4 case-sensitive symbols and 2 hex digits. Counting the hex digits is
        # the stricter reading, and the one that matches what the value actually encodes.
        self.assertEqual(scan('webhook_secret = "%s"' % ("AbAb" * 8)), [])

    def test_the_symbol_count_is_added_to_the_vendored_floor_not_substituted_for_it(self):
        """The rules that need a permissive floor are exactly the ones hex-only by construction.

        adobe-client-id matches `[a-f0-9]{32}` and gitleaks gives it a floor of 2.0, which this
        value clears at exactly 2.00 with four distinct digits. cloudflare-api-key (37 hex),
        discord-client-secret and linear-client-secret (32) are the same story. Replacing their
        floor with a symbol count instead of adding one would drop them -- a real Cloudflare key
        with 7 distinct digits is unlikely, but the vendor set that floor deliberately and clowk
        has no measurement saying otherwise. Additive cannot regress recall; a swap can.
        """
        self.assertTrue(scan('adobe_client_id = "%s"' % ("abcd" * 8)),
                        "the hex gate stopped being additive, so a low-floor hex rule lost a match")

    def test_the_symbol_count_applies_only_to_hex_not_to_every_alphabet(self):
        # A base64-ish value keeps gitleaks' own floor: 8 distinct symbols is trivial there, so
        # letting hex's gate stand in for it would drop the vendored threshold across the board.
        low_entropy_base64ish = "Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_"     # 6 distinct, entropy 2.5
        self.assertEqual(scan('api_key = "%s"' % low_entropy_base64ish), [])


if __name__ == "__main__":
    unittest.main()
