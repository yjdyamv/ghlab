"""Spellings an agent actually types: `0x120`, `1_024`, `FUN_181323F10`.

Both costs were real: `--size 0x120` came back as `argument --size: invalid int
value: '0x120'`, and a hex-uppercase function name came back as
`function not found (did you mean FUN_181323f10, ...)` — a suggestion the caller
had already given, just in different case.
"""

from __future__ import annotations

import argparse
import unittest

from ghlab import cli, session


class IntArgTest(unittest.TestCase):
    def test_hex_is_accepted(self):
        self.assertEqual(cli._int_arg("0x120"), 0x120)

    def test_decimals_and_underscores_are_accepted(self):
        self.assertEqual(cli._int_arg("1_024"), 1024)
        self.assertEqual(cli._int_arg(" 64 "), 64)

    def test_leading_zero_stays_decimal(self):
        self.assertEqual(cli._int_arg("012"), 12)

    def test_a_word_is_still_refused(self):
        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            cli._int_arg("all")
        self.assertIn("invalid int value", str(ctx.exception))

    def test_the_bytes_parser_takes_hex(self):
        args = cli.build_parser().parse_args(["bytes", "x.dll", "0x1000", "--size", "0x120"])
        self.assertEqual(args.size, 0x120)


class NameVariantTest(unittest.TestCase):
    def test_hex_tail_gets_both_cases(self):
        got = session._name_variants("FUN_181323F10")
        self.assertIn("FUN_181323f10", got)
        self.assertIn("fun_181323f10", got)

    def test_a_plain_name_gets_case_folds_only(self):
        got = session._name_variants("MainWndProc")
        self.assertIn("mainwndproc", got)
        self.assertIn("MAINWNDPROC", got)

    def test_the_original_spelling_is_not_repeated(self):
        self.assertNotIn("FUN_181323f10", session._name_variants("FUN_181323f10"))


class FakeSym:
    def __init__(self, name):
        self._name = name

    def getName(self, fully_qualified=False):
        return self._name


class FakeTable:
    """A case-sensitive name index, like Ghidra's, plus a walk nobody should reach."""

    def __init__(self, *names):
        self.names = set(names)
        self.walked = False

    def getGlobalSymbols(self, text):
        return [FakeSym(text)] if text in self.names else []

    def getSymbols(self, text):
        return []  # the global index already answered

    def getAllSymbols(self, include_params):
        self.walked = True
        return [FakeSym(name) for name in sorted(self.names)]


class FakeProgram:
    def __init__(self, table):
        self._table = table

    def getSymbolTable(self):
        return self._table


class SymbolLookupTest(unittest.TestCase):
    def test_exact_still_wins(self):
        table = FakeTable("FUN_181323f10")
        got = session._symbols_named(FakeProgram(table), "FUN_181323f10")
        self.assertEqual([str(s.getName()) for s in got], ["FUN_181323f10"])

    def test_uppercase_hex_falls_back_to_the_ghidra_spelling(self):
        table = FakeTable("FUN_181323f10")
        got = session._symbols_named(FakeProgram(table), "FUN_181323F10")
        self.assertEqual([str(s.getName()) for s in got], ["FUN_181323f10"])

    def test_a_real_miss_still_misses(self):
        table = FakeTable("FUN_181323f10")
        self.assertEqual(session._symbols_named(FakeProgram(table), "FUN_99999999"), [])
        self.assertTrue(table.walked, "the walk is the last resort and must still happen")

    def test_variant_hits_do_not_pay_for_the_walk(self):
        table = FakeTable("FUN_181323f10")
        session._symbols_named(FakeProgram(table), "FUN_181323F10")
        self.assertFalse(table.walked)


class NumArgTest(unittest.TestCase):
    def test_hex_strings_are_numbers_too(self):
        self.assertEqual(session._num({"size": "0x120"}, "size", 64), 0x120)

    def test_a_word_still_names_the_argument(self):
        with self.assertRaises(ValueError) as ctx:
            session._num({"size": "huge"}, "size", 64)
        self.assertEqual(str(ctx.exception), "size must be a number, got 'huge'")


if __name__ == "__main__":
    unittest.main()
