"""The README, `--help` and the protocol must describe the same set of commands.

Docs drift is invisible until someone follows the docs; this test makes it a red
suite instead.  It is deliberately about *sets*, not wording: the prose is allowed to
change freely, a missing command is not.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from ghlab import cli, mcp, protocol

README = Path(__file__).resolve().parents[1] / "README.md"
# `| `name` | required / optional | what it does |` -- the command table
ROW = re.compile(r"^\| `([A-Za-z_][A-Za-z0-9_-]*)` \|", re.M)


class CommandTableTest(unittest.TestCase):
    def setUp(self):
        self.text = README.read_text(encoding="utf-8")
        self.rows = ROW.findall(self.text)

    def test_every_protocol_command_has_a_row(self):
        documented = set(self.rows)
        missing = [
            name
            for name in protocol.COMMAND_NAMES
            if name not in documented and name.replace("_", "-") not in documented
        ]
        self.assertEqual(missing, [], "README has no row for these commands")

    def test_no_row_names_something_the_cli_cannot_run(self):
        parser = cli.build_parser()
        choices = set(parser._subparsers._group_actions[0].choices)
        local = set(choices)
        unknown = [
            row
            for row in self.rows
            if not row.startswith("ghlab_") and row not in local | set(protocol.SPECS)
        ]
        self.assertEqual(unknown, [], "README documents commands that do not exist")

    def test_a_documented_mcp_tool_exists(self):
        # the README lists a subset on purpose; a name that is not a tool is drift
        known = {t["name"] for t in mcp.TOOLS}
        unknown = sorted({row for row in self.rows if row.startswith("ghlab_")} - known)
        self.assertEqual(unknown, [])


class HelpCoversCommandsTest(unittest.TestCase):
    def test_every_protocol_command_is_listed_in_help(self):
        listed = {name for _title, group in cli._HELP_GROUPS for name in group}
        missing = sorted(name for name in protocol.SPECS if name.replace("_", "-") not in listed)
        self.assertEqual(missing, [], "commands the help text does not advertise")

    def test_the_aliases_are_mentioned(self):
        epilog = cli.build_parser().epilog
        self.assertIn("set_type", epilog)
        self.assertIn("cross_xref", epilog)


if __name__ == "__main__":
    unittest.main()
