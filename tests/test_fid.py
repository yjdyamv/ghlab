"""`fid`: FunctionID name matching, reported as a diff of the program's own names.

The JVM half (`ClassSearcher`, the analyzer lifecycle) cannot run here; what is
tested is everything that decides *what the user is told*: the snapshot, the diff,
the refusal paths, and the two formats.
"""

from __future__ import annotations

import unittest
from unittest import mock

from ghlab import cli, protocol, session


class FakeFn:
    def __init__(self, addr: str, name: str) -> None:
        self.addr = addr
        self.name = name

    def getEntryPoint(self) -> str:
        return self.addr

    def getName(self) -> str:
        return self.name


class FakeIter:
    def __init__(self, items: list[FakeFn]) -> None:
        self.items = list(items)
        self.at = 0

    def hasNext(self) -> bool:
        return self.at < len(self.items)

    def next(self) -> FakeFn:
        item = self.items[self.at]
        self.at += 1
        return item


class FakeFunctions:
    def __init__(self, items: list[FakeFn]) -> None:
        self.items = items
        self.forwarded: list[bool] = []

    def getFunctions(self, forward: bool) -> FakeIter:
        self.forwarded.append(forward)
        return FakeIter(self.items)


class FakeProgram:
    def __init__(self, items: list[FakeFn], name: str = "fw.bin") -> None:
        self.functions = FakeFunctions(items)
        self.name = name

    def getFunctionManager(self) -> FakeFunctions:
        return self.functions

    def getName(self) -> str:
        return self.name


class SnapshotTest(unittest.TestCase):
    def test_snapshot_maps_entry_point_to_name(self):
        program = FakeProgram([FakeFn("0x401000", "FUN_00401000"), FakeFn("0x401100", "start")])
        snap, truncated = session._name_snapshot(program)
        self.assertEqual(snap, {"0x401000": "FUN_00401000", "0x401100": "start"})
        self.assertFalse(truncated)
        self.assertEqual(program.functions.forwarded, [True])

    def test_the_limit_is_reported_not_silent(self):
        program = FakeProgram([FakeFn(f"0x{i:x}", f"FUN_{i:x}") for i in range(5)])
        snap, truncated = session._name_snapshot(program, limit=3)
        self.assertEqual(len(snap), 3)
        self.assertTrue(truncated)

    def test_exactly_at_the_limit_is_not_truncation(self):
        program = FakeProgram([FakeFn(f"0x{i:x}", f"FUN_{i:x}") for i in range(3)])
        snap, truncated = session._name_snapshot(program, limit=3)
        self.assertEqual(len(snap), 3)
        self.assertFalse(truncated)  # nothing was left behind


class DiffTest(unittest.TestCase):
    def test_only_changed_names_are_reported(self):
        before = {"0x1": "FUN_00000001", "0x2": "keep", "0x3": "gone"}
        after = {"0x1": "memcpy", "0x2": "keep"}
        self.assertEqual(
            session._renamed(before, after),
            [{"addr": "0x1", "was": "FUN_00000001", "now": "memcpy"}],
        )

    def test_a_function_that_vanished_is_not_a_rename(self):
        self.assertEqual(session._renamed({"0x1": "a"}, {}), [])


class CommandTest(unittest.TestCase):
    def _call(self, params: dict) -> dict:
        entry = mock.MagicMock()
        entry.__getitem__.side_effect = lambda key: {
            "program": FakeProgram([]),
            "decomp": None,
        }[key]
        with (
            mock.patch.object(session, "_entry", return_value=entry),
            mock.patch.object(
                session, "_fid_libraries", return_value=["/u/FunctionID/msvcrts.fidb"]
            ),
            mock.patch.object(session, "_run_fid_analyzer", return_value="FidAnalyzer"),
            mock.patch.object(session, "_save", return_value="project.save"),
        ):
            return session.cmd_fid(params)

    def test_list_needs_no_binary(self):
        out = self._call({"list": True})
        self.assertEqual(out["count"], 1)
        self.assertTrue(out["libraries"][0].endswith("msvcrts.fidb"))

    def test_no_binary_and_no_list_says_what_to_do(self):
        with self.assertRaises(ValueError) as ctx:
            session.cmd_fid({})
        self.assertIn("binary", str(ctx.exception))
        self.assertIn("list=yes", str(ctx.exception))

    def test_no_installed_library_is_a_refusal_not_zero_matches(self):
        with (
            mock.patch.object(session, "_fid_libraries", return_value=[]),
            mock.patch.object(session, "_entry"),
            self.assertRaises(ValueError) as ctx,
        ):
            session.cmd_fid({"binary": "fw.bin"})
        self.assertIn(".fidb", str(ctx.exception))

    def test_renames_are_saved_and_counted(self):
        program = FakeProgram([FakeFn("0x401000", "FUN_00401000")])
        snapshots = [({"0x401000": "FUN_00401000"}, False), ({"0x401000": "memcpy"}, False)]
        with (
            mock.patch.object(session, "_entry", return_value={"program": program}),
            mock.patch.object(session, "_fid_libraries", return_value=["a.fidb"]),
            mock.patch.object(session, "_run_fid_analyzer", return_value="FidAnalyzer"),
            mock.patch.object(session, "_name_snapshot", side_effect=snapshots),
            mock.patch.object(session, "_save", return_value="project.save") as save,
        ):
            out = session.cmd_fid({"binary": "fw.bin", "limit": 10})
        self.assertEqual(out["renamed"], 1)
        self.assertEqual(
            out["functions"], [{"addr": "0x401000", "was": "FUN_00401000", "now": "memcpy"}]
        )
        self.assertEqual(out["saved_via"], "project.save")
        save.assert_called_once()

    def test_no_change_means_no_save(self):
        with (
            mock.patch.object(session, "_entry", return_value={"program": FakeProgram([])}),
            mock.patch.object(session, "_fid_libraries", return_value=["a.fidb"]),
            mock.patch.object(session, "_run_fid_analyzer", return_value="FidAnalyzer"),
            mock.patch.object(session, "_name_snapshot", return_value=({}, False)),
            mock.patch.object(session, "_save") as save,
        ):
            out = session.cmd_fid({"binary": "fw.bin"})
        self.assertEqual(out["renamed"], 0)
        self.assertNotIn("saved_via", out)
        save.assert_not_called()

    def test_fid_is_a_mutation_for_the_readonly_switch(self):
        self.assertIn("fid", session.MUTATING)
        self.assertTrue(session._mutates("fid", {}))


class ProtocolTest(unittest.TestCase):
    def test_fid_takes_optional_parameters(self):
        spec, params = protocol.validate({"cmd": "fid", "binary": "fw.bin", "list": True})
        self.assertEqual(spec.name, "fid")
        self.assertTrue(params["list"])

    def test_fid_alone_is_valid_so_list_can_be_asked(self):
        spec, _ = protocol.validate({"cmd": "fid"})
        self.assertEqual(spec.name, "fid")

    def test_a_typo_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "fid", "libraries": True})


class FormatTest(unittest.TestCase):
    def test_list_format_names_the_next_step_when_empty(self):
        text = cli.fmt_fid({"libraries": [], "count": 0})
        self.assertIn("FunctionID databases: 0", text)
        self.assertIn("ghlab fid", text)

    def test_result_format_shows_before_and_after(self):
        text = cli.fmt_fid(
            {
                "binary": "fw.bin",
                "analyzer": "FidAnalyzer",
                "libraries": ["a.fidb"],
                "scanned": 12,
                "renamed": 1,
                "functions": [{"addr": "0x401000", "was": "FUN_00401000", "now": "memcpy"}],
                "elapsed_ms": 41,
                "saved_via": "project.save",
            }
        )
        self.assertIn("0x401000  memcpy   (was FUN_00401000)", text)
        self.assertIn("saved via project.save", text)

    def test_cli_accepts_the_list_flag(self):
        args = cli.build_parser().parse_args(["fid", "--list"])
        self.assertTrue(args.list)
        self.assertIsNone(args.binary)

    def test_cli_takes_a_binary_and_a_limit(self):
        args = cli.build_parser().parse_args(["fid", "fw.bin", "-n", "5"])
        self.assertEqual(args.binary, "fw.bin")
        self.assertEqual(args.limit, 5)


if __name__ == "__main__":
    unittest.main()
