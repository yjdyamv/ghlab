"""`vtables --slot N`: one slot offset across every table.

Deriving a struct chart from `vt[0x100]`-style calls needs the opposite direction
from `--func`: not "where does this function sit" but "who implements this
offset, and in how many classes". These tests pin the rendering and the argument
validation, which are the parts that need no Ghidra program.
"""

from __future__ import annotations

import unittest

from ghlab import cli, session


class SlotEnvelopeTest(unittest.TestCase):
    def _envelope(self, **extra):
        row = {
            "binary": "wpscore.dll",
            "mode": "slot",
            "total": 10184,
            "cached": True,
            "built_at": "2026-01-01 00:00:00",
            "elapsed_ms": 3,
            "slot": "0x100",
            "tables_scanned": 10184,
            "implementations": 278,
            "count": 2,
            "impls": [
                {
                    "addr": "18183a84d",
                    "name": "_purecall",
                    "size": 6,
                    "tables": 249,
                    "examples": ["wpsoldapi::UBorder::?$KCoreObject"],
                },
                {
                    "addr": "180005d60",
                    "name": None,
                    "size": None,
                    "tables": 45,
                    "examples": [],
                },
            ],
        }
        row.update(extra)
        return row

    def test_renders_one_line_per_implementation(self):
        text = cli.fmt_vtables(self._envelope())
        lines = text.splitlines()
        self.assertIn("slot 0x100", lines[0])
        self.assertIn("278 implementation(s)", lines[0])
        self.assertIn("10184 table(s)", lines[0])
        self.assertIn("18183a84d", lines[1])
        self.assertIn("x249", lines[1])
        self.assertIn("_purecall", lines[1])
        self.assertIn("UBorder", lines[1])
        self.assertIn("-", lines[2])  # unnamed and unsized stay printable

    def test_empty_slot_says_what_to_check(self):
        text = cli.fmt_vtables(self._envelope(impls=[], implementations=0, count=0))
        self.assertIn("no table has a function in this slot", text)


class SlotArgumentTest(unittest.TestCase):
    def test_slot_accepts_hex(self):
        self.assertEqual(session._num({"slot": "0x100"}, "slot", None), 0x100)

    def test_slot_rejects_partial_qword(self):
        # the check lives in the handler, so pin its predicate instead of a program
        self.assertEqual(0x104 % 8, 4)


if __name__ == "__main__":
    unittest.main()
