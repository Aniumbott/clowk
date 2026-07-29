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


if __name__ == "__main__":
    unittest.main()
