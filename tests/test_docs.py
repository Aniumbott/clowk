"""Documentation claims, checked against the code and manifests that ship with them.

For a tool whose whole value is that a user believes what it says, a sentence that is no longer
true is a real defect. These are the cheapest place to notice one.
"""
import json
import os
import unittest
import xml.dom.minidom

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def record_use_callers():
    """Shipped modules that call vault.record_use, ignoring its own definition."""
    callers = []
    for name in sorted(os.listdir(os.path.join(ROOT, "clowk"))):
        if not name.endswith(".py"):
            continue
        text = read("clowk", name)
        if name == "vault.py":
            text = text.replace("def record_use", "")
        if "record_use" in text:
            callers.append(name)
    return callers


class TestSlashCommandIsInstallable(unittest.TestCase):
    """`/clowk` is advertised in README, plugin.json and the CLI's own banner.

    `clowk install` registers hooks and touches nothing else, and commands/clowk.md resolves
    ${CLAUDE_PLUGIN_ROOT} -- so the command is reachable only through a plugin install. Following
    README's Install section alone left `/clowk` an unknown command, and the natural workaround
    (copying the file into ~/.claude/commands/) failed with `python3 "/clowk/cli.py"` because the
    variable is only set for a plugin. If the command needs a plugin, README has to say so.
    """

    def setUp(self):
        self.readme = read("README.md")
        self.command = read("commands", "clowk.md")
        self.market = json.loads(read(".claude-plugin", "marketplace.json"))

    def test_a_command_that_needs_a_plugin_root_has_a_documented_plugin_install(self):
        self.assertIn("CLAUDE_PLUGIN_ROOT", self.command)  # the premise, not the assertion
        self.assertIn("/plugin marketplace add", self.readme)

    def test_the_documented_install_names_the_marketplace_that_actually_ships(self):
        plugin = self.market["plugins"][0]["name"]
        self.assertIn("/plugin install %s@%s" % (plugin, self.market["name"]), self.readme)


class TestTheUsedByLedgerClaimMatchesTheCode(unittest.TestCase):
    """`clowk uses` prints a used-by list. Whether the docs may promise one depends on the code.

    This started as the inverse test: vault.record_use had no shipped caller, so `used by` always
    read "(nothing recorded yet)", and every surface had to avoid claiming otherwise -- the honesty
    pass had missed plugin.json, the card a stranger reads, and the CLI's usage banner that
    `clowk help` and `/clowk` print. `clowk get` now records each use, so the promise is honest and
    the test flips: the docs must claim the ledger, and if the caller is ever removed they must stop.
    """

    # Any phrasing that promises the `uses` list is filled. One of these must appear while a caller
    # exists, and none may appear once the last one goes.
    CLAIMS = ("what has drawn on it", "what has used it", "what uses it", "what depends on")

    def setUp(self):
        self.callers = record_use_callers()

    def surfaces(self):
        from clowk import cli

        return {
            "README.md": read("README.md"),
            "plugin.json": read(".claude-plugin", "plugin.json"),
            "marketplace.json": read(".claude-plugin", "marketplace.json"),
            "commands/clowk.md": read("commands", "clowk.md"),
            "the CLI's usage banner": cli.__doc__,
        }

    def test_the_docs_promise_a_filled_ledger_exactly_when_the_code_fills_one(self):
        readme = read("README.md").lower()
        claimed = [c for c in self.CLAIMS if c in readme]
        if self.callers:
            self.assertTrue(claimed,
                            "record_use is wired (%s) but README still describes an empty ledger"
                            % ", ".join(self.callers))
        else:
            self.assertFalse(claimed, "README promises a used-by ledger nothing fills")

    def test_no_surface_claims_a_ledger_once_the_last_caller_goes(self):
        if self.callers:
            self.skipTest("record_use is wired (%s)" % ", ".join(self.callers))
        for label, text in self.surfaces().items():
            for phrase in self.CLAIMS:
                self.assertNotIn(phrase, text.lower(),
                                 "%s claims a used-by ledger clowk never fills" % label)

    # What DESIGN.md said for four commits after `clowk get` began calling record_use. The ledger
    # tests only ever read README and the manifests, so the one file whose whole job is explaining
    # why the design is this shape kept describing a gap the code had closed.
    STALE_GAP = ("no shipped code path calls it", "until that is wired")

    def test_design_does_not_describe_a_gap_the_code_has_closed(self):
        if not self.callers:
            self.skipTest("record_use has no caller, so describing the gap is accurate")
        design = read("DESIGN.md").lower()
        for phrase in self.STALE_GAP:
            self.assertNotIn(phrase, design,
                             "DESIGN.md calls record_use unwired, but %s calls it"
                             % ", ".join(self.callers))

    def test_both_manifests_make_the_same_accurate_claim(self):
        for name in ("plugin.json", "marketplace.json"):
            blob = json.loads(read(".claude-plugin", name))
            description = blob.get("description") or blob["plugins"][0]["description"]
            self.assertIn("records where each one came from", description, name)


class TestTheReadmeCountsTheTestsThatExist(unittest.TestCase):
    """README's "N tests" has now gone stale three times and been corrected by hand three times.

    It is the only remaining number in the repo that was written down rather than derived, and the
    fix is the same one applied to the confidence-tier counts: derive it, so the suite fails instead
    of the sentence quietly becoming untrue. Counted by the loader rather than by parsing files, so
    it stays right however the tests are organised.
    """

    def suite_size(self):
        loader = unittest.defaultTestLoader
        suite = loader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT)
        self.assertEqual(loader.errors, [], "a test module failed to import")

        def count(node):
            if isinstance(node, unittest.TestSuite):
                return sum(count(child) for child in node)
            return 1

        return count(suite)

    def test_the_readme_test_count_is_the_real_one(self):
        total = self.suite_size()
        self.assertIn("# %d tests" % total, read("README.md"),
                      "README does not say '# %d tests'" % total)


class TestTheShippedSvgsAreValidAndCurrent(unittest.TestCase):
    """The diagram is a claim surface like any other, and a broken one fails invisibly.

    XML forbids `--` inside a comment. An SVG with one is invalid, and every renderer that matters
    shows a broken-image icon rather than an error -- which is how it shipped once, in a logo whose
    comment explained the design in prose. Nothing in CI would have caught it.

    The diagram also prints three facts that drift on their own: the rule count, the version, and
    the launcher path `clowk install` writes. It went stale before by describing a `clowk run` that
    had been deleted, so the fix is to make the numbers derive from the code that owns them.
    """

    SVGS = ("clowk-architecture.svg", "clowk-logo.svg", "clowk-logo-dark.svg")

    def setUp(self):
        self.diagram = read("clowk-architecture.svg")

    def test_every_shipped_svg_parses(self):
        for name in self.SVGS:
            try:
                xml.dom.minidom.parseString(read(name).encode("utf-8"))
            except Exception as exc:                      # noqa: BLE001 -- any parse failure is the bug
                self.fail("%s is not valid XML, so it renders as a broken image: %s" % (name, exc))

    # clowk's own rules, which live in code rather than in rules.json and so cannot be counted
    # from it. Named individually because the count went stale the moment a third one landed.
    OWN_RULES = ("uri_findings", "kv_findings", "standalone_findings")

    def test_the_diagram_counts_the_rules_the_ruleset_actually_has(self):
        from clowk import detect

        # The vendored gitleaks set plus clowk's own three. README words it the same way.
        for name in self.OWN_RULES:
            self.assertTrue(callable(getattr(detect, name, None)),
                            "detect.%s is gone, so the diagram's rule count is wrong" % name)
        total = len(detect.RULES) + len(self.OWN_RULES)
        self.assertIn("%d rules" % total, self.diagram,
                      "the diagram's rule count is not %d" % total)

    def test_the_diagram_names_the_shipped_version(self):
        version = json.loads(read(".claude-plugin", "plugin.json"))["version"]
        self.assertIn(version, self.diagram,
                      "the diagram does not name version %s" % version)

    def test_the_diagram_names_the_launcher_install_really_writes(self):
        from clowk import install

        # The tail only: launcher_path() is absolute and CLOWK_BIN can override it, but the
        # directory is the part a reader has to put on their PATH.
        self.assertIn(".local/bin/clowk", self.diagram)
        self.assertIn(os.path.join(".local", "bin"), install.launcher_path())


if __name__ == "__main__":
    unittest.main()
