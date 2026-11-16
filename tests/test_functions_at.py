"""`functions -a ADDR` answers "which function owns this address" directly.

The roster is paged (`limit` defaults to 60 server-side), so asking a listing
for one address quietly returns whichever function happened to sort early.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ghlab import cli, session


class _Addr:
    def __init__(self, value: int) -> None:
        self._value = value

    def compareTo(self, other: _Addr) -> int:
        return (self._value > other._value) - (self._value < other._value)

    def subtract(self, other: _Addr) -> int:
        return self._value - other._value

    def __str__(self) -> str:
        return f"{self._value:x}"


class _Body:
    def __init__(self, size: int) -> None:
        self._size = size

    def getNumAddresses(self) -> int:
        return self._size


class _Fn:
    def __init__(self, addr: int, name: str, size: int = 16) -> None:
        self._addr = _Addr(addr)
        self._name = name
        self._size = size

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> _Addr:
        return self._addr

    def getBody(self) -> _Body:
        return _Body(self._size)

    def getPrototypeString(self, a: bool, b: bool) -> str:
        return f"undefined {self._name}()"

    def isThunk(self) -> bool:
        return False

    def isExternal(self) -> bool:
        return False


class _FM:
    def __init__(self, fns, containing=None) -> None:
        self._fns = fns
        self._containing = containing

    def getFunctions(self, forward: bool):
        return iter(self._fns)

    def getFunctionContaining(self, addr):
        return self._containing


class _Space:
    def getAddress(self, value: int) -> _Addr:
        return _Addr(int(value))


class _AF:
    def getDefaultAddressSpace(self) -> _Space:
        return _Space()


class _Program:
    def __init__(self, fns, containing=None) -> None:
        self._fm = _FM(fns, containing)

    def getFunctionManager(self) -> _FM:
        return self._fm

    def getAddressFactory(self) -> _AF:
        return _AF()


class FunctionAtTest(unittest.TestCase):
    def _entry(self, program):
        return {"program": program, "api": mock.Mock()}

    def test_containing_wins_without_walking_the_roster(self):
        target = _Fn(0x1000, "FUN_1000", 0x40)
        program = _Program([_Fn(0x9000, "FUN_9000")], containing=target)
        hit = session._function_covering(program, _Addr(0x1010))
        self.assertIs(hit, target)

    def test_falls_back_to_the_last_function_starting_below(self):
        fns = [_Fn(0x1000, "FUN_1000", 0x40), _Fn(0x2000, "FUN_2000", 0x40)]
        hit = session._function_covering(_Program(fns), _Addr(0x2010))
        self.assertEqual(str(hit.getName()), "FUN_2000")

    def test_a_far_away_address_is_not_claimed(self):
        fns = [_Fn(0x1000, "FUN_1000", 0x40)]
        self.assertIsNone(session._function_covering(_Program(fns), _Addr(0x900000)))


class FunctionsAtCommandTest(unittest.TestCase):
    def _run(self, program, at):
        entry = {"program": program, "api": mock.Mock()}
        with mock.patch.object(session, "_entry", return_value=entry):
            return session.cmd_functions({"binary": "x.dll", "at": at})

    def test_at_returns_exactly_one_function(self):
        fns = [_Fn(0x1000, "FUN_1000", 0x40), _Fn(0x2000, "FUN_2000", 0x40)]
        got = self._run(_Program(fns), "0x2010")
        self.assertEqual(got["matched"], 1)
        self.assertEqual([f["name"] for f in got["functions"]], ["FUN_2000"])

    def test_at_miss_reports_the_address_instead_of_an_empty_list(self):
        got = self._run(_Program([_Fn(0x1000, "FUN_1000", 0x40)]), "0x900000")
        self.assertEqual(got["matched"], 0)
        self.assertIn("no function contains", got["note"])

    def test_listing_flags_truncation(self):
        fns = [_Fn(0x1000 + i * 0x10, f"FUN_{0x1000 + i * 0x10:x}") for i in range(5)]
        entry = {"program": _Program(fns), "api": mock.Mock()}
        with mock.patch.object(session, "_entry", return_value=entry):
            got = session.cmd_functions({"binary": "x.dll", "limit": 2})
        self.assertEqual(got["matched"], 5)
        self.assertTrue(got["truncated"])


class FormatterTest(unittest.TestCase):
    def test_at_hit_names_the_owner(self):
        text = cli.fmt_functions(
            {
                "addr": "1809f120e",
                "matched": 1,
                "functions": [{"addr": "1809f1130", "size": 2085, "name": "FUN_1809f1130"}],
            }
        )
        self.assertEqual(
            text.splitlines()[0], "# 1809f120e is inside FUN_1809f1130"
        )

    def test_at_miss_prints_the_reason(self):
        text = cli.fmt_functions(
            {"addr": "900000", "matched": 0, "functions": [], "note": "no function contains 900000"}
        )
        self.assertEqual(text, "# 900000: no function contains 900000")

    def test_listing_says_when_it_was_cut(self):
        text = cli.fmt_functions(
            {"matched": 900, "truncated": True, "functions": [{"addr": "1000", "size": 4, "name": "f"}]}
        )
        self.assertIn("[truncated; raise -n]", text.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
