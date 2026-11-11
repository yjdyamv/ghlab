"""`exports` lists what a binary offers to callers, with demangled C++ names.

No Ghidra here: the symbol table is faked, and the demangler path is exercised by
installing a fake `ghidra.app.util.demangler` module for the duration of a test.
"""

import sys
import types
import unittest
from unittest import mock

from ghlab import session


class FakeSymbol:
    def __init__(self, name: str, addr: str, exported: bool = True):
        self.name = name
        self.addr = addr
        self.exported = exported

    def getName(self) -> str:
        return self.name

    def getAddress(self) -> str:
        return self.addr

    def isExternalEntryPoint(self) -> bool:
        return self.exported


class FakeSymbolTable:
    def __init__(self, symbols):
        self.symbols = symbols

    def getAllSymbols(self, _include_locals: bool):
        return self.symbols


class FakeProgram:
    def __init__(self, symbols):
        self.table = FakeSymbolTable(symbols)

    def getSymbolTable(self) -> FakeSymbolTable:
        return self.table


def fake_demangler(signature: str, fail: bool = False):
    """Install a stand-in for ghidra.app.util.demangler and return the cleanup."""
    pkg = types.ModuleType("ghidra")
    util = types.ModuleType("ghidra.app.util")
    demangler = types.ModuleType("ghidra.app.util.demangler")

    class DemanglerUtil:
        @staticmethod
        def demangle(*_args):
            if fail:
                raise RuntimeError("boom")
            return types.SimpleNamespace(getSignature=lambda: signature)

    demangler.DemanglerUtil = DemanglerUtil
    return mock.patch.dict(
        sys.modules,
        {
            "ghidra": pkg,
            "ghidra.app": types.ModuleType("ghidra.app"),
            "ghidra.app.util": util,
            "ghidra.app.util.demangler": demangler,
        },
    )


class DemangleTest(unittest.TestCase):
    def test_a_plain_c_name_is_not_attempted(self):
        self.assertIsNone(session._demangle(None, "DllMain"))

    def test_a_mangled_name_is_rendered_readably(self):
        with fake_demangler("ns::Widget::Draw(int)"):
            self.assertEqual(
                session._demangle(None, "_ZN2ns6Widget4DrawEi"), "ns::Widget::Draw(int)"
            )

    def test_the_msvc_prefix_is_also_handled(self):
        with fake_demangler("void __cdecl f(int)"):
            self.assertEqual(session._demangle(None, "?f@@YAXH@Z"), "void __cdecl f(int)")

    def test_a_demangler_that_raises_is_not_fatal(self):
        with fake_demangler("", fail=True):
            self.assertIsNone(session._demangle(None, "_Z3foov"))


class ExportsCommandTest(unittest.TestCase):
    def run_cmd(self, payload: dict, symbols) -> dict:
        program = FakeProgram(symbols)
        with mock.patch.object(session, "_entry", lambda _name: {"program": program}):
            return session.cmd_exports({"binary": "x.dll", **payload})

    def test_only_external_entry_points_are_listed(self):
        out = self.run_cmd(
            {},
            [
                FakeSymbol("DllMain", "0x180001000"),
                FakeSymbol("helper", "0x180002000", exported=False),
            ],
        )
        self.assertEqual([r["name"] for r in out["exports"]], ["DllMain"])
        self.assertEqual(out["total"], 1)

    def test_rows_sort_by_readable_name_and_count_demangled(self):
        with fake_demangler("zeta::f()"):
            out = self.run_cmd(
                {},
                [FakeSymbol("_ZN4zeta1fEv", "0x1000"), FakeSymbol("Alpha", "0x2000")],
            )
        self.assertEqual([r["name"] for r in out["exports"]], ["Alpha", "_ZN4zeta1fEv"])
        self.assertEqual(out["exports"][1]["demangled"], "zeta::f()")
        self.assertEqual(out["demangled"], 1)

    def test_match_filters_on_either_form(self):
        with fake_demangler("zeta::f()"):
            out = self.run_cmd(
                {"match": "zeta::"},
                [FakeSymbol("_ZN4zeta1fEv", "0x1000"), FakeSymbol("Alpha", "0x2000")],
            )
        self.assertEqual([r["name"] for r in out["exports"]], ["_ZN4zeta1fEv"])

    def test_the_limit_is_reported_as_truncation(self):
        out = self.run_cmd(
            {"limit": 1},
            [FakeSymbol("A", "0x1000"), FakeSymbol("B", "0x2000")],
        )
        self.assertEqual(len(out["exports"]), 1)
        self.assertEqual(out["total"], 2)
        self.assertTrue(out["truncated"])

    def test_duplicate_names_appear_once(self):
        out = self.run_cmd(
            {},
            [FakeSymbol("Same", "0x1000"), FakeSymbol("Same", "0x1000")],
        )
        self.assertEqual(len(out["exports"]), 1)

    def test_a_binary_with_no_exports_says_so(self):
        out = self.run_cmd({}, [])
        self.assertEqual(out["exports"], [])
        self.assertEqual(out["total"], 0)


if __name__ == "__main__":
    unittest.main()
