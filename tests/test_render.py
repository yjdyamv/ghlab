"""Tests for the graph renderers (pure Python, no JVM) and the focus binary."""

import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from ghlab import cli, protocol, render

GRAPH = {
    "binary": "notepad.exe",
    "direction": "calling",
    "root": "entry",
    "nodes": [
        {"name": "entry", "addr": "1400019d0", "size": 18},
        {"name": "FUN_140001850", "addr": "140001850", "size": 344},
        {"name": "FUN_140001fc4", "addr": "140001fc4", "size": 183},
    ],
    "edges": [
        {"from": "entry", "to": "FUN_140001850"},
        {"from": "entry", "to": "FUN_140001fc4"},
    ],
}


class RenderTest(unittest.TestCase):
    def test_dot_lists_every_node_and_edge(self):
        text = render.dot(GRAPH)
        self.assertTrue(text.startswith("digraph calls {"))
        self.assertIn('"entry" -> "FUN_140001850";', text)
        self.assertIn("FUN_140001fc4 (183b)", text)

    def test_mermaid_uses_short_ids(self):
        text = render.mermaid(GRAPH)
        self.assertTrue(text.startswith("flowchart LR"))
        self.assertIn('n0["entry (18b)"]', text)
        self.assertIn("n0 --> n1", text)
        self.assertEqual(len([ln for ln in text.splitlines() if "-->" in ln]), 2)

    def test_svg_is_well_formed_and_contains_labels(self):
        text = render.svg(GRAPH)
        root = ET.fromstring(text)
        self.assertTrue(root.tag.endswith("svg"))
        self.assertIn("FUN_140001850 (344b)", text)
        rects = [el for el in root.iter() if el.tag.endswith("rect")]
        self.assertGreaterEqual(len(rects), len(GRAPH["nodes"]) + 1)  # +background

    def test_renderers_are_registered(self):
        self.assertEqual(sorted(render.RENDERERS), ["dot", "mermaid", "svg"])

    def test_graph_spec_takes_format_and_out(self):
        spec = protocol.SPECS["graph"]
        self.assertIn("format", spec.optional)
        self.assertIn("out", spec.optional)
        self.assertIn("sig", protocol.SPECS["decompile"].optional)


class FocusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = cli.FOCUS_FILE
        cli.FOCUS_FILE = Path(self.tmp.name) / "focus"

    def tearDown(self):
        cli.FOCUS_FILE = self.old
        self.tmp.cleanup()

    def test_no_focus_is_none(self):
        self.assertIsNone(cli.read_focus())

    def test_write_then_read(self):
        cli.write_focus("notepad.exe")
        self.assertEqual(cli.read_focus(), "notepad.exe")

    def test_use_command_persists_and_reports(self):
        code = cli.main(["use", "sample.exe"])
        self.assertEqual(code, 0)
        self.assertEqual(cli.read_focus(), "sample.exe")

    def test_dash_without_focus_explains_itself(self):
        code = cli.main(["digest", "-"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
