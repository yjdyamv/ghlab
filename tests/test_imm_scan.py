"""`scan --imm` on its own: "who mentions this constant at all".

Property ids are only ever stored as immediates, so `scan <offset> --imm N` (a
filter on a displacement sweep) could not find them; `scan --imm 0xe0000041`
now sweeps the immediates themselves. These tests pin the parts that do not
need a Ghidra program: the spec parser and the rendering of the envelope.
"""

from __future__ import annotations

import unittest

from ghlab import cli, session


class ImmSpecTest(unittest.TestCase):
    def test_single_value(self):
        spec = session._imm_spec("0xe0000041")
        self.assertTrue(spec(0xE0000041))
        self.assertFalse(spec(0xE0000042))

    def test_range(self):
        spec = session._imm_spec("0..5")
        self.assertTrue(spec(0))
        self.assertTrue(spec(5))
        self.assertFalse(spec(6))

    def test_reversed_range_is_an_error(self):
        with self.assertRaises(ValueError):
            session._imm_spec("5..1")


class ImmSweepRenderingTest(unittest.TestCase):
    def _envelope(self, sites):
        return {
            "binary": "wpscore.dll",
            "offset": None,
            "pattern": "imm 0xe0000041",
            "imm": "0xe0000041",
            "writes_only": False,
            "scanned": 8,
            "sites": sites,
            "truncated": False,
            "elapsed_ms": 1,
        }

    def test_hits_are_rendered_with_their_function(self):
        out = cli.fmt_scan(
            self._envelope(
                [
                    {
                        "addr": "180353329",
                        "function": "FUN_180353310",
                        "text": "MOV EDX,0xe0000041",
                    }
                ]
            )
        )
        self.assertIn("imm 0xe0000041", out)
        self.assertIn("FUN_180353310", out)

    def test_a_miss_does_not_claim_a_displacement_was_touched(self):
        out = cli.fmt_scan(self._envelope([]))
        self.assertIn("no instruction has this immediate", out)


if __name__ == "__main__":
    unittest.main()
