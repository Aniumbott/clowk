import json
import os
import re
import unittest

from clowk.detect import _OPERATOR, classify, scan

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clowk", "rules.json")


class TestClassify(unittest.TestCase):
    def test_literal_vendor_prefix_is_high(self):
        self.assertEqual(classify(r"\b(ghp_[A-Za-z0-9]{36})\b"), "high")
        self.assertEqual(classify(r"\b(xoxb-[0-9]{10,})\b"), "high")

    def test_no_literal_prefix_is_low(self):
        self.assertEqual(classify(r"\b([A-Za-z0-9]{32})\b"), "low")

    def test_literal_inside_a_character_class_does_not_count(self):
        self.assertEqual(classify(r"[abc_-]{8,}"), "low")

    def test_a_literal_in_the_keyword_half_does_not_make_a_shape_rule_high(self):
        # hashicorp-tf-password: the only literal run is `administrator_`, and it is in the
        # KEYWORD alternation -- a branch that need not appear in the matched text at all. The
        # captured value is pure shape, so the rule must stay purgeable.
        hashicorp = (r"(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
                     r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(\"[a-z0-9=_\-]{8,20}\")"
                     r"(?:[\x60'\"\s;]|\\[nr]|$)")
        self.assertEqual(classify(hashicorp), "low")

    def test_a_literal_in_the_captured_value_still_reads_high(self):
        # typeform-api-token: `tfp_` is in the CAPTURE, so this is a genuinely pinned format.
        # This assertion is what stops the fix above from being widened into "any keyword-gated
        # rule is low", which would attach a false-positive hint to 11 pinned vendor formats.
        typeform = (r"(?:typeform)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
                    r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})"
                    r"(?:[\x60'\"\s;]|\\[nr]|$)")
        self.assertEqual(classify(typeform), "high")


class TestAPinnedPrefixNeedsNoTrailingSeparator(unittest.TestCase):
    """`AKIA` is a pinned vendor format, and clowk called it a shape-only guess.

    The old test was `[A-Za-z0-9]{2,}[_-]` searched anywhere in a rule's value half, so it only
    recognised a prefix that ENDS in `_` or `-`. `ghp_`, `xoxb-` and `sk_live_` read high;
    `AKIA`, `AIza`, `LTAI`, `dapi` and `sha256~` read low -- and a low tier prints
    "shape-only guess, `clowk clear NAME` if wrong" beside a live AWS root key.
    """

    AWS = r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"

    def test_aws_access_key_id_is_pinned(self):
        self.assertEqual(classify(self.AWS), "high")

    def test_other_separatorless_vendor_prefixes_are_pinned_too(self):
        for regex in (r"\b(AIza[\w-]{35})(?:[\x60'\"\s;]|\\[nr]|$)",       # gcp-api-key
                      r"\b(LTAI[a-z0-9]{20})(?:[\x60'\"\s;]|\\[nr]|$)",   # alibaba-access-key-id
                      r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b",                  # databricks-api-token
                      r"\b(sha256~[\w-]{43})(?:[^\w-]|\Z)"):              # openshift-user-token
            self.assertEqual(classify(regex), "high", regex)

    def test_three_fixed_characters_is_the_floor_the_old_test_already_had(self):
        # `[A-Za-z0-9]{2,}[_-]` was three characters too, so nothing gets cheaper here -- only
        # the requirement that the third one be a separator goes away.
        self.assertEqual(classify(r"\b(ab_[a-z0-9]{32})\b"), "high")
        self.assertEqual(classify(r"\b(ab[a-z0-9]{32})\b"), "low")


class TestOnlyTheSecretGroupsOwnContentCounts(unittest.TestCase):
    """The anchor, which is what makes "3 fixed characters" safe to accept without a separator.

    A literal run of three ANYWHERE in the value half would read `curl`, `kind:`, `secret` and
    `gems.contribsys.com` as pinned prefixes -- in all three of those rules the literal sits
    OUTSIDE the group that holds the credential, so a match carries no vendor evidence at all in
    the value clowk actually files. Measured: those three were the only false highs a
    position-blind version of this test produced across the shipped ruleset.
    """

    def test_a_literal_before_the_group_does_not_pin_it(self):
        # curl-auth-user: group 1 opens with `"`, and `curl` is outside it
        curl = (r"\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})"
                r"(\"(:[^\"]{3,}|[^:\"]{3,}:)\")")
        self.assertEqual(classify(curl), "low")

    def test_a_literal_before_a_class_led_group_does_not_pin_it(self):
        # kubernetes-secret-yaml: `kind:`/`secret` are outside a group opening with [\w.-]+
        k8s = (r"(?:\bkind:[ \t]*[\"']?\bsecret\b[\"']?(?s:.){0,200}?\bdata:(?s:.){0,100}?\s+"
               r"([\w.-]+:[ \t]*[a-z0-9+/]{10,}={0,3}))")
        self.assertEqual(classify(k8s), "low")

    def test_a_vendor_hostname_after_the_group_does_not_pin_it(self):
        # sidekiq-sensitive-url: the credential is two hex runs; the domain follows it
        sidekiq = (r"\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@"
                   r"(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)")
        self.assertEqual(classify(sidekiq), "low")


class TestAnAlternationPinsOnlyWhenEveryBranchDoes(unittest.TestCase):
    """A branch that does not pin is a match that carries no marker, so the rule does not either."""

    def test_all_branches_pinned_reads_high(self):
        # aws-access-token: A3T, AKIA, ASIA, ABIA, ACCA -- every branch opens with three or more
        self.assertEqual(classify(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"), "high")

    def test_one_unpinned_branch_reads_low(self):
        # vault-service-token: `hvs.` pins, but the `s.` branch fixes a single character, so a
        # match need not carry three. sourcegraph-access-token is the same story with a branch
        # that is a bare 40-hex run -- i.e. every git SHA in existence.
        vault = r"\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:[\x60'\"\s;]|\\[nr]|$)"
        self.assertEqual(classify(vault), "low")
        sourcegraph = (r"\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}"
                       r"|[a-fA-F0-9]{40})\b")
        self.assertEqual(classify(sourcegraph), "low")


class TestTheDeclaredSecretGroupIsWhatGetsClassified(unittest.TestCase):
    """gitleaks' `secretGroup = N` overrides which group holds the value, so it must steer this too.

    sonar-api-token declares group 2 and its leftmost capture is `(login|token)`, so classifying
    the whole pattern reads the keyword `sonar` as a pinned prefix -- the exact false high the
    hashicorp case above exists to prevent. Group 2 is `(?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40}`, whose
    vendor prefix is OPTIONAL: `sonar.login = <40 chars of anything>` matches with no marker at all.
    """

    SONAR = (r"(?:sonar[_.-]?(login|token))(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
             r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}"
             r"((?:squ_|sqp_|sqa_)?[a-z0-9=_\-]{40})(?:[\x60'\"\s;]|\\[nr]|$)")

    def test_the_declared_group_decides(self):
        self.assertEqual(classify(self.SONAR, 2), "low")

    def test_an_optional_prefix_pins_nothing(self):
        self.assertEqual(classify(r"\b((?:squ_)?[a-z0-9]{40})\b"), "low")


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

    def test_keyword_only_literals_do_not_promote_a_shape_rule(self):
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("hashicorp-tf-password", "cohere-api-token", "new-relic-user-api-id",
                    "nytimes-access-token", "sidekiq-secret"):
            self.assertEqual(rules[rid]["confidence"], "low", rid)

    def test_rules_pinned_in_their_capture_stay_high(self):
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("typeform-api-token", "new-relic-user-api-key", "mailgun-pub-key",
                    "defined-networking-api-token"):
            self.assertEqual(rules[rid]["confidence"], "high", rid)

    def test_the_separatorless_vendor_formats_are_no_longer_called_shape_only(self):
        """The rules that stopped mislabelling a real vendor credential.

        Every one of these pins a literal in the value it captures and used to read "low" only
        because the literal does not end in `_` or `-`. aws-access-token is the one a user
        reported: a live `AKIA...` key came back annotated "shape-only guess, clowk clear
        AWS_ACCESS_KEY_ID if wrong", which is advice to delete a working credential.
        """
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("aws-access-token", "gcp-api-key", "alibaba-access-key-id",
                    "databricks-api-token", "openshift-user-token", "facebook-page-access-token",
                    "airtable-personnal-access-token", "grafana-api-key", "gitlab-rrt",
                    "github-app-token", "harness-api-key", "private-key", "slack-user-token",
                    "slack-webhook-url", "microsoft-teams-webhook", "easypost-api-token",
                    "artifactory-api-key", "dynatrace-api-token", "vault-batch-token",
                    "yandex-api-key", "intra42-client-secret", "lob-api-key",
                    "clickhouse-cloud-api-secret-key", "aws-amazon-bedrock-api-key-long-lived",
                    "artifactory-reference-token", "easypost-test-api-token"):
            self.assertEqual(rules[rid]["confidence"], "high", rid)

    def test_the_rules_whose_literal_is_not_in_their_value_stopped_claiming_high(self):
        """The other half of the same fix, and it moves three rules the other way.

        Each of these read "high" off a literal that is not in the credential clowk files:
        `curl` before the captured header value, `sonar` in the keyword half, and -- for
        sourcegraph-access-token -- a pattern one branch of which is a bare 40-hex run, so every
        commit hash it blocks was being reported as a confident vendor match.
        """
        rules = {r["id"]: r for r in _load_rules()}
        for rid in ("curl-auth-header", "curl-auth-user", "sonar-api-token",
                    "sourcegraph-access-token", "kubernetes-secret-yaml",
                    "sidekiq-sensitive-url"):
            self.assertEqual(rules[rid]["confidence"], "low", rid)

    def test_every_shipped_confidence_is_what_classify_derives(self):
        """rules.json is generated, and a hand-edit or a stale build must not change a tier.

        The same guard test_detect makes for `group`. It is also what lets every count in the
        docs and in this file be derived from the file rather than written down.
        """
        for r in _load_rules():
            self.assertEqual(r["confidence"], classify(r["regex"], r["group"]), r["id"])

    def test_no_whole_match_rule_carries_the_generic_keyword_template(self):
        """The keyword-half protection, now enforced structurally rather than by splitting.

        classify reads the secret GROUP's own content, so for the 163 rules that capture their
        value the keyword half is excluded by construction -- a strictly stronger guard than
        splitting the pattern on its operator, which is what used to do this job. For a rule whose
        secret is the whole match there is no keyword half to exclude: whatever leading literal it
        has is inside the value clowk files. That holds only while no whole-match rule carries
        gitleaks' `keyword <operator> value` template, which is true of all 221 today and is the
        one assumption a ruleset refresh could break -- so it fails here rather than silently
        promoting `password = "localdevonly1"` to a confident match.
        """
        template = re.compile(r"\[\\s'\"\]\{0,3\}\(\?:=\|>")
        offenders = sorted(r["id"] for r in _load_rules()
                           if not r["group"] and template.search(r["regex"]))
        self.assertEqual(offenders, [])

    def test_the_readme_shape_only_count_is_accurate(self):
        # README tells users how many rules match on shape; a drifting number there quietly
        # misrepresents the false-positive surface.
        low = sum(1 for r in _load_rules() if r["confidence"] == "low")
        readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md")
        with open(readme, encoding="utf-8") as f:   # README has emoji; cp1252 cannot read it
            self.assertIn("%d of the %d rules" % (low, len(_load_rules())), f.read())

    def test_the_counts_detect_quotes_about_its_own_ruleset_are_accurate(self):
        """detect.py's comments quantify the ruleset, and its numbers went stale twice.

        The standalone rule's preamble said "96 pin a literal vendor prefix"; a classify() that
        read a vendor prefix out of a rule's KEYWORD half was the cause, fixing it moved five rules
        high -> low, README was updated to 129 and the comment was not. The second correction --
        classify no longer requiring a pinned prefix to end in `_` or `-` -- moved 26 rules the
        other way and 3 back. Every count in the repo derives from the ruleset now, and the ruleset
        derives from classify (test_every_shipped_confidence_is_what_classify_derives), so there is
        one place a tier can be wrong and no place a number can silently disagree with it.
        """
        rules = _load_rules()
        high = sum(1 for r in rules if r["confidence"] == "high")
        # gitleaks' keyword=value template. Present verbatim in the rules that cannot fire on a
        # bare paste, which is the whole reason clowk adds a standalone-token rule.
        template = sum(1 for r in rules if _OPERATOR in r["regex"])
        detect_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "clowk", "detect.py")
        with open(detect_py, encoding="utf-8") as f:
            source = f.read()
        for count, what in ((high, "rules pinning a literal vendor prefix"),
                            (template, "rules carrying the keyword=value template")):
            self.assertIn("%d of the %d" % (count, len(rules)), source,
                          "detect.py does not say %d of the %d (%s)" % (count, len(rules), what))


class TestFinding(unittest.TestCase):
    def test_finding_carries_confidence(self):
        findings = scan("token sk_" "live_4eC39HqLyjWDarjtT1zdp7dc here")
        self.assertTrue(findings)
        self.assertIn(findings[0].confidence, ("high", "low"))


if __name__ == "__main__":
    unittest.main()
