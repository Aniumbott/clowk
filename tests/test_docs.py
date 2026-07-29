"""Documentation claims, checked against the code and manifests that ship with them.

For a tool whose whole value is that a user believes what it says, a sentence that is no longer
true is a real defect. These are the cheapest place to notice one.
"""
import json
import os
import unittest

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


class TestNothingClaimsAFilledUsedByLedger(unittest.TestCase):
    """DESIGN.md: "Until that is wired, do not describe clowk as recording what depends on a
    credential."

    vault.record_use has no shipped caller, so `used by` always reads "(nothing recorded yet)".
    README says so and marketplace.json says "records where each one came from" -- but the honesty
    pass missed plugin.json, whose description is the card a stranger reads, and the CLI's own usage
    banner, which `clowk help` and `/clowk` print.
    """

    # Each of these describes the empty `uses` list, not the `sources` list clowk really fills.
    # Kept narrow on purpose: "records what" alone catches README's honest "NOTES.md records what
    # is verified per host".
    FORBIDDEN = ("what depends on", "what has used it", "what uses it")

    def setUp(self):
        callers = record_use_callers()
        if callers:
            self.skipTest("record_use is wired up now (%s) -- revisit this copy deliberately"
                          % ", ".join(callers))

    def surfaces(self):
        from clowk import cli

        return {
            "README.md": read("README.md"),
            "plugin.json": read(".claude-plugin", "plugin.json"),
            "marketplace.json": read(".claude-plugin", "marketplace.json"),
            "commands/clowk.md": read("commands", "clowk.md"),
            "the CLI's usage banner": cli.__doc__,
        }

    def test_no_user_facing_surface_says_clowk_records_what_uses_a_credential(self):
        for label, text in self.surfaces().items():
            for phrase in self.FORBIDDEN:
                self.assertNotIn(phrase, text.lower(),
                                 "%s claims a used-by ledger clowk never fills" % label)

    def test_both_manifests_make_the_same_accurate_claim(self):
        for name in ("plugin.json", "marketplace.json"):
            blob = json.loads(read(".claude-plugin", name))
            description = blob.get("description") or blob["plugins"][0]["description"]
            self.assertIn("records where each one came from", description, name)


if __name__ == "__main__":
    unittest.main()
