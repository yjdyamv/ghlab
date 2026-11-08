"""Unit tests for the claim grammar behind `ghlab note -a` / `ghlab verify`.

These run without the daemon and without Ghidra: everything under test here is
pure Python, which is why the parse/compare helpers live outside the JVM section.
"""

import unittest

from ghlab import session


class ClaimParsingTest(unittest.TestCase):
    def test_equals(self):
        spec = session._parse_claim("const=0x41")
        self.assertEqual((spec["kind"], spec["op"], spec["value"]), ("const", "=", "0x41"))

    def test_comparisons(self):
        for raw, op, value in (
            ("size>=200", ">=", "200"),
            ("size<=16", "<=", "16"),
            ("size>7", ">", "7"),
            ("size<7", "<", "7"),
        ):
            spec = session._parse_claim(raw)
            self.assertEqual((spec["kind"], spec["op"], spec["value"]), ("size", op, value))

    def test_kind_is_case_insensitive(self):
        self.assertEqual(session._parse_claim("CONST=1")["kind"], "const")

    def test_rejects_garbage(self):
        for raw in ("", "const", "   "):
            with self.assertRaises(ValueError):
                session._parse_claim(raw)

    def test_claim_int_accepts_hex_and_decimal(self):
        self.assertEqual(session._claim_int("0x10"), 16)
        self.assertEqual(session._claim_int(" 16 "), 16)


class CompareTest(unittest.TestCase):
    def test_all_operators(self):
        self.assertTrue(session._compare(5, "=", 5))
        self.assertFalse(session._compare(5, "=", 6))
        self.assertTrue(session._compare(5, ">=", 5))
        self.assertTrue(session._compare(5, "<=", 5))
        self.assertTrue(session._compare(6, ">", 5))
        self.assertTrue(session._compare(4, "<", 5))


class ConstViewsTest(unittest.TestCase):
    def test_high_bit_constant_matches_negative_scalar(self):
        # Ghidra hands back (HKEY)0xffffffff80000001 as a negative long.
        self.assertIn(0xFFFFFFFF80000001, session._const_views(-0x7FFFFFFF))

    def test_plain_constant_stays_itself(self):
        views = session._const_views(4)
        self.assertIn(4, views)

    def test_32_bit_view(self):
        self.assertIn(0x80000001, session._const_views(-0x7FFFFFFF))


class HexAddrTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(session._hex_addr("0x1400019d0"), 0x1400019D0)
        self.assertEqual(session._hex_addr("1400019d0"), 0x1400019D0)

    def test_not_addresses(self):
        for text in ("entry", "FUN_1400019d0", "dead", ""):
            self.assertIsNone(session._hex_addr(text), text)


class StatusTest(unittest.TestCase):
    def test_pass_fail_unknown(self):
        self.assertEqual(session._claims_status([{"ok": True}]), "pass")
        self.assertEqual(session._claims_status([{"ok": True}, {"ok": False}]), "fail")
        self.assertEqual(session._claims_status([{"ok": None}]), "unknown")
        self.assertEqual(session._claims_status([{"ok": True}, {"ok": None}]), "unknown")


if __name__ == "__main__":
    unittest.main()
